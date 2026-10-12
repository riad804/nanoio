package api

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"nanoio/internal/identity/ldap"
)

func init() {
	r := madminRegister
	r("idp-config/", "GET PUT POST DELETE", "admin:ConfigUpdate", (*Server).madminIDPConfig)
	r("idp/ldap/policy/attach", "POST", "admin:AttachUserOrGroupPolicy", func(s *Server, q *request) { s.madminLDAPPolicy(q, true) })
	r("idp/ldap/policy/detach", "POST", "admin:AttachUserOrGroupPolicy", func(s *Server, q *request) { s.madminLDAPPolicy(q, false) })
	r("idp/ldap/policy-entities", "GET", "admin:ListUserPolicies", (*Server).madminLDAPEntities)
	r("idp/ldap/list-access-keys", "GET", "admin:ListServiceAccounts", (*Server).madminLDAPAccessKeys)
}

// idpTypes maps mc's type names to config sub-systems.
var idpTypes = map[string]string{"openid": "identity_openid", "ldap": "identity_ldap"}

const idpDefaultName = "_"

func (s *Server) madminIDPConfig(q *request) {
	rest := strings.TrimPrefix(strings.TrimPrefix(q.r.URL.Path, madminPrefix), "idp-config/")
	typ, name, _ := strings.Cut(rest, "/")
	sub, ok := idpTypes[typ]
	if !ok {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "invalid IDP type "+typ)
		return
	}
	if name != "" && name != idpDefaultName {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument",
			"NanoIO supports a single "+typ+" identity provider (the default configuration)")
		return
	}
	c := s.cfg()
	switch q.r.Method {
	case http.MethodGet:
		kv := c.Target(q.ctx(), sub, "")
		if name == "" { // list
			out := []map[string]any{}
			if len(kv) > 0 {
				out = append(out, map[string]any{"type": typ, "name": idpDefaultName, "enabled": true})
			}
			s.writeEncrypted(q, out)
			return
		}
		if len(kv) == 0 {
			s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchConfigTarget", "the "+typ+" identity provider is not configured")
			return
		}
		keys := make([]string, 0, len(kv))
		for k := range kv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		secret := map[string]bool{}
		for _, k := range configSubs[sub].Keys {
			secret[k.Name] = k.Secret
		}
		info := []map[string]any{}
		for _, k := range keys {
			v := kv[k]
			if secret[k] && v != "" {
				v = "*redacted*"
			}
			info = append(info, map[string]any{"key": k, "value": v, "isCfg": true, "isEnv": false})
		}
		s.writeEncrypted(q, map[string]any{"type": typ, "name": idpDefaultName, "info": info})
	case http.MethodPut, http.MethodPost:
		pt, err := s.readEncrypted(q)
		if err != nil {
			s.madminErr(q, err)
			return
		}
		line := sub + " " + strings.TrimSpace(string(pt))
		if s.applyConfigLines(q, line, false) {
			q.w.Header().Set("x-minio-config-applied", "true")
			q.w.WriteHeader(http.StatusOK)
		}
	case http.MethodDelete:
		c.mu.Lock()
		c.cacheAt = time.Time{}
		c.mu.Unlock()
		cur, err := c.load(q.ctx())
		if err != nil {
			s.madminErr(q, err)
			return
		}
		if _, ok := cur.Subs[sub][""]; !ok {
			s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchConfigTarget", "the "+typ+" identity provider is not configured")
			return
		}
		next := cloneConfig(cur)
		delete(next.Subs, sub)
		if err := c.save(q.ctx(), next, cur); err != nil {
			s.madminErr(q, err)
			return
		}
		q.w.Header().Set("x-minio-config-applied", "true")
		q.w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) madminLDAPPolicy(q *request, attach bool) {
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var req struct {
		Policies []string `json:"policies"`
		User     string   `json:"user"`
		Group    string   `json:"group"`
	}
	if json.Unmarshal(pt, &req) != nil || len(req.Policies) == 0 || (req.User == "") == (req.Group == "") {
		s.madminErr(q, madminBad("exactly one of user and group and at least one policy are required"))
		return
	}
	dn := req.User
	isGroup := false
	if req.Group != "" {
		dn, isGroup = req.Group, true
	}
	norm, err := ldap.NormalizeDN(dn)
	if err != nil || norm == "" {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "not a valid distinguished name: "+dn)
		return
	}
	if attach {
		if bad := s.unknownPolicy(req.Policies); bad != "" {
			s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchPolicy", "policy "+bad+" does not exist")
			return
		}
	}
	s.idpMu.Lock()
	defer s.idpMu.Unlock()
	m, err := s.readLDAPMap(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	tbl := m.Users
	if isGroup {
		tbl = m.Groups
	}
	set := map[string]bool{}
	for _, p := range tbl[norm] {
		set[p] = true
	}
	var changed []string
	for _, p := range req.Policies {
		if attach && !set[p] {
			set[p] = true
			changed = append(changed, p)
		}
		if !attach && set[p] {
			delete(set, p)
			changed = append(changed, p)
		}
	}
	if len(changed) == 0 {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminPolicyChangeAlreadyApplied", "The specified policy change is already in effect.")
		return
	}
	next := make([]string, 0, len(set))
	for p := range set {
		next = append(next, p)
	}
	sort.Strings(next)
	if len(next) == 0 {
		delete(tbl, norm)
	} else {
		tbl[norm] = next
	}
	if err := s.writeLDAPMap(q.ctx(), m); err != nil {
		s.madminErr(q, err)
		return
	}
	// Credentials already issued re-resolve their policies on the next
	// cache refresh; drop the local cache so this node does at once.
	s.iam.ForgetAll()
	resp := map[string]any{"updatedAt": time.Now().UTC()}
	if attach {
		resp["policiesAttached"] = changed
	} else {
		resp["policiesDetached"] = changed
	}
	s.writeEncrypted(q, resp)
}

func (s *Server) madminLDAPEntities(q *request) {
	m, err := s.readLDAPMap(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	type grp struct {
		Group    string   `json:"group"`
		Policies []string `json:"policies"`
	}
	type usr struct {
		User     string   `json:"user"`
		Policies []string `json:"policies"`
	}
	type pol struct {
		Policy string   `json:"policy"`
		Users  []string `json:"users"`
		Groups []string `json:"groups"`
	}
	norm := func(l []string) map[string]bool {
		o := map[string]bool{}
		for _, v := range l {
			if n, err := ldap.NormalizeDN(v); err == nil {
				o[n] = true
			} else {
				o[v] = true
			}
		}
		return o
	}
	wu, wg, wp := norm(q.query["user"]), norm(q.query["group"]), toSet(q.query["policy"])
	all := len(wu)+len(wg)+len(wp) == 0
	res := struct {
		Timestamp      time.Time `json:"timestamp"`
		UserMappings   []usr     `json:"userMappings,omitempty"`
		GroupMappings  []grp     `json:"groupMappings,omitempty"`
		PolicyMappings []pol     `json:"policyMappings,omitempty"`
	}{Timestamp: time.Now().UTC()}
	byPol := map[string]*pol{}
	get := func(p string) *pol {
		if byPol[p] == nil {
			byPol[p] = &pol{Policy: p}
		}
		return byPol[p]
	}
	for _, dn := range sortedKeys(m.Users) {
		for _, p := range m.Users[dn] {
			get(p).Users = append(get(p).Users, dn)
		}
		if all || wu[dn] {
			res.UserMappings = append(res.UserMappings, usr{dn, m.Users[dn]})
		}
	}
	for _, dn := range sortedKeys(m.Groups) {
		for _, p := range m.Groups[dn] {
			get(p).Groups = append(get(p).Groups, dn)
		}
		if all || wg[dn] {
			res.GroupMappings = append(res.GroupMappings, grp{dn, m.Groups[dn]})
		}
	}
	names := make([]string, 0, len(byPol))
	for n := range byPol {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if all || wp[n] {
			res.PolicyMappings = append(res.PolicyMappings, *byPol[n])
		}
	}
	s.writeEncrypted(q, res)
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// madminLDAPAccessKeys lists the temporary credentials of a directory user.
func (s *Server) madminLDAPAccessKeys(q *request) {
	dn := q.query.Get("userDN")
	es := &eventStore{st: s.st}
	names, err := es.List(q.ctx(), stsPrefix, 100000)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	want, _ := ldap.NormalizeDN(dn)
	sts := []map[string]any{}
	for _, n := range names {
		ak := strings.TrimSuffix(strings.TrimPrefix(n, stsPrefix), ".json")
		d, err := s.stsGet(q.ctx(), ak)
		if err != nil || d == nil || d.Entry.Provider != "ldap" {
			continue
		}
		have, _ := ldap.NormalizeDN(d.Entry.ProviderUser)
		if dn != "" && have != want {
			continue
		}
		sts = append(sts, map[string]any{"accessKey": ak, "expiration": d.Entry.Expiry, "accountStatus": "on", "parentUser": d.Entry.ProviderUser})
	}
	s.writeEncrypted(q, map[string]any{"serviceAccounts": []any{}, "stsKeys": sts})
}
