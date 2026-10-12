package api

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"sort"
	"strings"

	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

// Export/import archives. The file names follow MinIO's ("iam-assets/...",
// "<bucket>/..."); the contents are NanoIO's own JSON, so an archive moves
// between NanoIO servers, not between NanoIO and MinIO.

func init() {
	r := madminRegister
	r("export-iam", "GET", "admin:ExportIAM", (*Server).madminExportIAM)
	r("import-iam", "PUT", "admin:ImportIAM", (*Server).madminImportIAM)
	r("import-iam-v2", "PUT", "admin:ImportIAM", (*Server).madminImportIAM)
	r("export-bucket-metadata", "GET", "admin:ExportBucketMetadata", (*Server).madminExportBucketMeta)
	r("import-bucket-metadata", "PUT", "admin:ImportBucketMetadata", (*Server).madminImportBucketMeta)
}

func zipJSON(zw *zip.Writer, name string, v any) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	return json.NewEncoder(w).Encode(v)
}

func (s *Server) madminExportIAM(q *request) {
	if !s.iamReady(q) {
		return
	}
	snap := s.iam.Snapshot()
	users := map[string]iam.UserEntry{}
	svc := map[string]iam.UserEntry{}
	for _, u := range snap.Users {
		switch {
		case u.Kind == "sts":
			continue // temporary credentials are not exported
		case u.Kind == "svcacct":
			svc[u.AccessKey] = u
		default:
			users[u.AccessKey] = u
		}
	}
	groups := map[string]iam.GroupEntry{}
	for _, g := range snap.Groups {
		groups[g.Name] = g
	}
	pol := map[string]json.RawMessage{}
	for n, d := range snap.Policies {
		if !iam.IsCanned(n) {
			pol[n] = d
		}
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, v := range map[string]any{"iam-assets/policies.json": pol, "iam-assets/users.json": users,
		"iam-assets/groups.json": groups, "iam-assets/svcaccts.json": svc} {
		if err := zipJSON(zw, name, v); err != nil {
			s.madminErr(q, err)
			return
		}
	}
	if err := zw.Close(); err != nil {
		s.madminErr(q, err)
		return
	}
	h := q.w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="`+"nanoio-iam-info.zip"+`"`)
	q.w.WriteHeader(http.StatusOK)
	q.w.Write(buf.Bytes())
}

func (s *Server) madminImportIAM(q *request) {
	if !s.iamReady(q) {
		return
	}
	body, err := readAllLimited(q, 32<<20)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		s.madminErr(q, madminBad("the body is not a zip archive"))
		return
	}
	read := func(name string, v any) error {
		for _, f := range zr.File {
			if f.Name != name {
				continue
			}
			rc, err := f.Open()
			if err != nil {
				return err
			}
			defer rc.Close()
			return json.NewDecoder(io.LimitReader(rc, 16<<20)).Decode(v)
		}
		return nil
	}
	var pol map[string]json.RawMessage
	var users, svc map[string]iam.UserEntry
	var groups map[string]iam.GroupEntry
	for name, v := range map[string]any{"iam-assets/policies.json": &pol, "iam-assets/users.json": &users,
		"iam-assets/groups.json": &groups, "iam-assets/svcaccts.json": &svc} {
		if err := read(name, v); err != nil {
			s.madminErr(q, madminBad("invalid "+name+": "+err.Error()))
			return
		}
	}
	type ent struct {
		Name  string `json:"name,omitempty"`
		Error string `json:"error,omitempty"`
	}
	res := struct {
		Skipped struct {
			Policies, Users, Groups, ServiceAccounts []string
		} `json:"skipped"`
		Added struct {
			Policies        []string `json:"policies,omitempty"`
			Users           []string `json:"users,omitempty"`
			Groups          []string `json:"groups,omitempty"`
			ServiceAccounts []string `json:"serviceAccounts,omitempty"`
		} `json:"added"`
		Failed struct {
			Policies        []ent `json:"policies,omitempty"`
			Users           []ent `json:"users,omitempty"`
			Groups          []ent `json:"groups,omitempty"`
			ServiceAccounts []ent `json:"serviceAccounts,omitempty"`
		} `json:"failed"`
	}{}
	sorted := func(m map[string]struct{}) []string {
		out := make([]string, 0, len(m))
		for k := range m {
			out = append(out, k)
		}
		sort.Strings(out)
		return out
	}
	keys := func(n int, f func(add func(string))) []string {
		m := map[string]struct{}{}
		f(func(k string) { m[k] = struct{}{} })
		return sorted(m)
	}
	for _, n := range keys(len(pol), func(add func(string)) {
		for k := range pol {
			add(k)
		}
	}) {
		if iam.IsCanned(n) || s.iam.IsStatic("policy", n) {
			res.Skipped.Policies = append(res.Skipped.Policies, n)
			continue
		}
		if _, err := iam.ParsePolicy(pol[n]); err != nil {
			res.Failed.Policies = append(res.Failed.Policies, ent{n, err.Error()})
			continue
		}
		if s.saveIAM(q, &iamDoc{Kind: "policy", Name: n, Policy: pol[n]}) {
			res.Added.Policies = append(res.Added.Policies, n)
		} else {
			return
		}
	}
	known := map[string]bool{}
	for _, u := range s.iam.Snapshot().Users {
		known[u.AccessKey] = true
	}
	for _, n := range keys(len(users), func(add func(string)) {
		for k := range users {
			add(k)
		}
	}) {
		u := users[n]
		u.AccessKey = n
		if n == s.iam.Root() || s.iam.IsStatic("user", n) || u.Kind != "" {
			res.Skipped.Users = append(res.Skipped.Users, n)
			continue
		}
		if bad := s.unknownPolicy(u.Policies); bad != "" {
			u.Policies = nil
		}
		if err := (iam.Credential{AccessKey: n, SecretKey: u.SecretKey}).Validate(); err != nil {
			res.Failed.Users = append(res.Failed.Users, ent{n, err.Error()})
			continue
		}
		if !s.saveIAM(q, &iamDoc{Kind: "user", Name: n, User: &u}) {
			return
		}
		known[n] = true
		res.Added.Users = append(res.Added.Users, n)
	}
	for _, n := range keys(len(groups), func(add func(string)) {
		for k := range groups {
			add(k)
		}
	}) {
		g := groups[n]
		g.Name = n
		if s.iam.IsStatic("group", n) {
			res.Skipped.Groups = append(res.Skipped.Groups, n)
			continue
		}
		var mem []string
		for _, m := range g.Members {
			if known[m] {
				mem = append(mem, m)
			}
		}
		g.Members = mem
		if bad := s.unknownPolicy(g.Policies); bad != "" {
			g.Policies = nil
		}
		if !s.saveIAM(q, &iamDoc{Kind: "group", Name: n, Group: &g}) {
			return
		}
		res.Added.Groups = append(res.Added.Groups, n)
	}
	for _, n := range keys(len(svc), func(add func(string)) {
		for k := range svc {
			add(k)
		}
	}) {
		u := svc[n]
		u.AccessKey, u.Kind = n, "svcacct"
		if (u.Parent != s.iam.Root() && !known[u.Parent]) || s.iam.IsStatic("user", n) || n == s.iam.Root() {
			res.Skipped.ServiceAccounts = append(res.Skipped.ServiceAccounts, n)
			continue
		}
		if !s.saveIAM(q, &iamDoc{Kind: "user", Name: n, User: &u}) {
			return
		}
		res.Added.ServiceAccounts = append(res.Added.ServiceAccounts, n)
	}
	s.writeJSONOK(q, res)
}

// bucketMetaKinds are the documents exported; replication targets (which
// hold remote credentials) and the rules that point at them stay out.
var bucketMetaKinds = []string{confEncryption, confPolicy, confACL, confCORS, confTagging, confNotification, confLifecycle}

func (s *Server) madminExportBucketMeta(q *request) {
	var names []string
	if b := q.query.Get("bucket"); b != "" {
		names = []string{b}
	} else {
		bl, err := s.st.ListBuckets(q.ctx())
		if err != nil {
			s.madminErr(q, err)
			return
		}
		for _, b := range bl {
			if b.Name != sysBucket {
				names = append(names, b.Name)
			}
		}
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, b := range names {
		v, err := s.st.GetBucketVersioning(q.ctx(), b)
		if errors.Is(err, storage.ErrBucketNotFound) {
			s.madminFail(q, http.StatusNotFound, "NoSuchBucket", "The specified bucket does not exist")
			return
		}
		if err != nil {
			s.madminErr(q, err)
			return
		}
		lock, _ := s.st.GetBucketObjectLock(q.ctx(), b)
		meta := map[string]any{"versioning": string(v.State), "objectLock": lock.Enabled}
		if lock.Default != nil {
			meta["objectLockDefault"] = lock.Default
		}
		if err := zipJSON(zw, b+"/bucket-metadata.json", meta); err != nil {
			s.madminErr(q, err)
			return
		}
		for _, kind := range bucketMetaKinds {
			raw, err := s.confRaw(q.ctx(), b, kind)
			if err != nil {
				s.madminErr(q, err)
				return
			}
			if raw == nil {
				continue
			}
			w, err := zw.Create(b + "/" + kind)
			if err != nil {
				s.madminErr(q, err)
				return
			}
			w.Write(raw)
		}
	}
	if err := zw.Close(); err != nil {
		s.madminErr(q, err)
		return
	}
	h := q.w.Header()
	h.Set("Content-Type", "application/zip")
	h.Set("Content-Disposition", `attachment; filename="nanoio-bucket-metadata.zip"`)
	q.w.WriteHeader(http.StatusOK)
	q.w.Write(buf.Bytes())
}

func (s *Server) madminImportBucketMeta(q *request) {
	body, err := readAllLimited(q, 64<<20)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		s.madminErr(q, madminBad("the body is not a zip archive"))
		return
	}
	type status struct {
		IsSet bool   `json:"isSet"`
		Err   string `json:"error,omitempty"`
	}
	type bstatus struct {
		ObjectLock   status `json:"olock"`
		Versioning   status `json:"versioning"`
		Policy       status `json:"policy"`
		Tagging      status `json:"tagging"`
		SSEConfig    status `json:"sse"`
		Lifecycle    status `json:"lifecycle"`
		Notification status `json:"notification"`
		Quota        status `json:"quota"`
		Cors         status `json:"cors"`
		Err          string `json:"error,omitempty"`
	}
	out := map[string]*bstatus{}
	only := q.query.Get("bucket")
	// Buckets first (with their lock and versioning), then documents.
	files := map[string]*zip.File{}
	var buckets []string
	for _, f := range zr.File {
		b, name, ok := strings.Cut(f.Name, "/")
		if !ok || b == "" || name == "" || (only != "" && b != only) || b == sysBucket {
			continue
		}
		files[f.Name] = f
		if name == "bucket-metadata.json" {
			buckets = append(buckets, b)
		}
	}
	sort.Strings(buckets)
	readFile := func(f *zip.File) ([]byte, error) {
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		defer rc.Close()
		return io.ReadAll(io.LimitReader(rc, maxConfSize))
	}
	for _, b := range buckets {
		st := &bstatus{}
		out[b] = st
		raw, err := readFile(files[b+"/bucket-metadata.json"])
		var meta struct {
			Versioning        string                    `json:"versioning"`
			ObjectLock        bool                      `json:"objectLock"`
			ObjectLockDefault *storage.DefaultRetention `json:"objectLockDefault"`
		}
		if err == nil {
			err = json.Unmarshal(raw, &meta)
		}
		if err != nil {
			st.Err = err.Error()
			continue
		}
		if err := s.st.MakeBucket(q.ctx(), b, storage.MakeBucketOptions{ObjectLock: meta.ObjectLock}); err != nil && !errors.Is(err, storage.ErrBucketExists) {
			st.Err = err.Error()
			continue
		}
		if meta.ObjectLock {
			st.ObjectLock.IsSet = true
			if meta.ObjectLockDefault != nil {
				if err := s.st.SetBucketObjectLock(q.ctx(), b, storage.ObjectLockConfig{Enabled: true, Default: meta.ObjectLockDefault}); err != nil {
					st.ObjectLock = status{Err: err.Error()}
				}
			}
		}
		if meta.Versioning != "" {
			if err := s.st.SetBucketVersioning(q.ctx(), b, storage.VersioningState(meta.Versioning)); err != nil {
				st.Versioning.Err = err.Error()
			} else {
				st.Versioning.IsSet = true
			}
		}
		for _, kind := range bucketMetaKinds {
			f := files[b+"/"+kind]
			if f == nil {
				continue
			}
			var dst *status
			switch kind {
			case confEncryption:
				dst = &st.SSEConfig
			case confPolicy:
				dst = &st.Policy
			case confCORS:
				dst = &st.Cors
			case confTagging:
				dst = &st.Tagging
			case confNotification:
				dst = &st.Notification
			case confLifecycle:
				dst = &st.Lifecycle
			default:
				dst = &status{}
			}
			data, err := readFile(f)
			if err == nil {
				err = wellFormedConf(kind, data)
			}
			if err == nil {
				err = s.confPut(q.ctx(), b, kind, data)
			}
			if err != nil {
				dst.Err = err.Error()
			} else {
				dst.IsSet = true
			}
		}
	}
	s.writeJSONOK(q, map[string]any{"buckets": out})
}

// wellFormedConf is a cheap guard on imported documents: they must be
// well-formed JSON or XML. (The documents are re-validated by their
// consumers on use; this keeps obvious garbage out of the store.)
func wellFormedConf(kind string, data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("empty document")
	}
	switch kind {
	case confPolicy, confCORS, confACL, confTagging:
		if bytes.HasPrefix(bytes.TrimSpace(data), []byte("{")) {
			if !json.Valid(data) {
				return errors.New("malformed JSON")
			}
			return nil
		}
	}
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		_, err := d.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return errors.New("malformed document: " + err.Error())
		}
	}
}
