package api

import (
	"encoding/json"
	"encoding/xml"
	"errors"
	"net/http"
	"strings"

	"nanoio/internal/iam"
	"nanoio/internal/storage"
)

// aclKey is the reserved user-defined key holding an object's ACL (a JSON
// list of grants). Nothing derived from it is ever returned as a header.
const aclKey = "x-nanoio-internal-acl"

// internalPrefix is the reserved namespace of every internal metadata key;
// clients may not send headers in it.
const internalPrefix = "x-nanoio-internal-"

type aclDoc struct {
	Grants []iam.Grant `json:"grants"`
}

var (
	errMalformedACL   = &APIError{"MalformedACLError", "The XML you provided was not well-formed or did not validate against our published schema.", http.StatusBadRequest}
	errUnsupportedACL = &APIError{"NotImplemented", "Only the canned ACLs private, public-read, public-read-write and authenticated-read, and grants to users and the AllUsers and AuthenticatedUsers groups, are supported.", http.StatusNotImplemented}
)

func invalidACL(msg string) *APIError {
	return &APIError{"InvalidArgument", msg, http.StatusBadRequest}
}

// bucketACL returns the bucket's grants (nil for private).
func (s *Server) bucketACL(q *request, bucket string) ([]iam.Grant, error) {
	v, err := s.confParsed(q.r.Context(), bucket, confACL, func(b []byte) (any, error) {
		var d aclDoc
		if err := json.Unmarshal(b, &d); err != nil {
			return nil, err
		}
		return d.Grants, nil
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.([]iam.Grant), nil
}

// objectACL returns the grants of one object version (nil for private or if
// the object does not exist).
func (s *Server) objectACL(q *request, bucket, key, versionID string) ([]iam.Grant, error) {
	info, err := s.st.StatObject(q.r.Context(), bucket, key, storage.GetOptions{VersionID: versionID})
	var dm *storage.DeleteMarkerError
	switch {
	case errors.As(err, &dm), errors.Is(err, storage.ErrObjectNotFound), errors.Is(err, storage.ErrVersionNotFound),
		errors.Is(err, storage.ErrBucketNotFound), errors.Is(err, storage.ErrIsDeleteMarker),
		errors.Is(err, storage.ErrInvalidVersionID):
		return nil, nil
	case err != nil:
		return nil, err
	}
	return grantsOf(info.UserDefined), nil
}

func grantsOf(ud map[string]string) []iam.Grant {
	raw, ok := ud[aclKey]
	if !ok {
		return nil
	}
	var d aclDoc
	if json.Unmarshal([]byte(raw), &d) != nil {
		return nil
	}
	return d.Grants
}

// aclDecision folds a bucket's and an object's ACL into the decision as
// ordinary policy statements. ACLs only ever add Allows.
func (s *Server) aclDecision(q *request, req iam.Request, who iam.Principal) (bool, error) {
	if iam.BucketACLActions(req.Action) {
		grants, err := s.bucketACL(q, req.Bucket)
		if err != nil {
			return false, err
		}
		if len(grants) > 0 {
			if a, _ := iam.EvaluateStatements(iam.ACLStatements(req.Bucket, "", grants), req, who); a {
				return true, nil
			}
		}
	}
	if req.Key != "" && iam.ObjectACLActions(req.Action) {
		grants, err := s.objectACL(q, req.Bucket, req.Key, q.query.Get("versionId"))
		if err != nil {
			return false, err
		}
		if len(grants) > 0 {
			if a, _ := iam.EvaluateStatements(iam.ACLStatements(req.Bucket, req.Key, grants), req, who); a {
				return true, nil
			}
		}
	}
	return false, nil
}

// ----- parsing ---------------------------------------------------------

var grantHeaders = []struct{ header, perm string }{
	{"x-amz-grant-read", iam.PermRead},
	{"x-amz-grant-write", iam.PermWrite},
	{"x-amz-grant-read-acp", iam.PermReadACP},
	{"x-amz-grant-write-acp", iam.PermWriteACP},
	{"x-amz-grant-full-control", iam.PermFullControl},
}

// ownerID is the single owner's canonical ID; a grant to it is implicit.
const ownerID = "nanoio"

// aclFromHeaders parses x-amz-acl and the x-amz-grant-* headers. present is
// false when none is sent. The two forms are mutually exclusive, as in S3.
func aclFromHeaders(h http.Header) (grants []iam.Grant, present bool, err *APIError) {
	canned := h.Get("x-amz-acl")
	var hdrGrants []iam.Grant
	for _, gh := range grantHeaders {
		v := h.Get(gh.header)
		if v == "" {
			continue
		}
		for _, part := range splitGrantee(v) {
			k, val, ok := strings.Cut(part, "=")
			val = strings.Trim(strings.TrimSpace(val), `"`)
			if !ok || val == "" {
				return nil, true, invalidACL("Invalid grantee in " + gh.header + ".")
			}
			switch strings.ToLower(strings.TrimSpace(k)) {
			case "id":
				hdrGrants = append(hdrGrants, iam.Grant{User: val, Perm: gh.perm})
			case "uri":
				hdrGrants = append(hdrGrants, iam.Grant{Group: val, Perm: gh.perm})
			default:
				return nil, true, errUnsupportedACL
			}
		}
	}
	switch {
	case canned != "" && len(hdrGrants) > 0:
		return nil, true, invalidACL("Specifying both Canned ACLs and Header Grants is not allowed.")
	case canned != "":
		g, e := iam.CannedGrants(canned)
		if e != nil {
			return nil, true, invalidACL("The canned ACL " + canned + " is not supported.")
		}
		return g, true, nil
	case len(hdrGrants) > 0:
		g, aerr := normalizeGrants(hdrGrants)
		return g, true, aerr
	}
	return nil, false, nil
}

func splitGrantee(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normalizeGrants validates grantees and drops grants to the owner, whose
// full control is implicit.
func normalizeGrants(in []iam.Grant) ([]iam.Grant, *APIError) {
	var out []iam.Grant
	for _, g := range in {
		if !iam.ValidPerm(g.Perm) {
			return nil, errMalformedACL
		}
		switch {
		case g.Group != "":
			if g.Group != iam.GroupAllUsers && g.Group != iam.GroupAuthenticatedUsers {
				return nil, invalidACL("Invalid group URI " + g.Group + ".")
			}
		case g.User == ownerID:
			continue
		case g.User == "":
			return nil, errMalformedACL
		case strings.ContainsAny(g.User, "*?:/ \t\"") || len(g.User) > 128:
			return nil, invalidACL("Invalid grantee ID " + g.User + ".")
		}
		out = append(out, g)
	}
	return out, nil
}

type aclGranteeXML struct {
	TypeNS string `xml:"http://www.w3.org/2001/XMLSchema-instance type,attr"`
	Type   string `xml:"type,attr"`
	ID     string `xml:"ID"`
	URI    string `xml:"URI"`
	Email  string `xml:"EmailAddress"`
}

type aclPolicyRequest struct {
	XMLName xml.Name `xml:"AccessControlPolicy"`
	Grants  []struct {
		Grantee    aclGranteeXML `xml:"Grantee"`
		Permission string        `xml:"Permission"`
	} `xml:"AccessControlList>Grant"`
}

func grantsFromXML(body []byte) ([]iam.Grant, *APIError) {
	var req aclPolicyRequest
	if err := xml.Unmarshal(body, &req); err != nil {
		return nil, errMalformedACL
	}
	var in []iam.Grant
	for _, g := range req.Grants {
		typ := g.Grantee.TypeNS
		if typ == "" {
			typ = g.Grantee.Type
		}
		switch {
		case g.Grantee.Email != "" || typ == "AmazonCustomerByEmail":
			return nil, errUnsupportedACL
		case typ == "Group" || (typ == "" && g.Grantee.URI != ""):
			in = append(in, iam.Grant{Group: strings.TrimSpace(g.Grantee.URI), Perm: g.Permission})
		case typ == "CanonicalUser" || (typ == "" && g.Grantee.ID != ""):
			in = append(in, iam.Grant{User: strings.TrimSpace(g.Grantee.ID), Perm: g.Permission})
		default:
			return nil, errMalformedACL
		}
	}
	return normalizeGrants(in)
}

// ----- rendering -------------------------------------------------------

type aclGranteeOut struct {
	XSI         string `xml:"xmlns:xsi,attr"`
	Type        string `xml:"xsi:type,attr"`
	ID          string `xml:"ID,omitempty"`
	DisplayName string `xml:"DisplayName,omitempty"`
	URI         string `xml:"URI,omitempty"`
}

type aclGrantOut struct {
	Grantee    aclGranteeOut `xml:"Grantee"`
	Permission string        `xml:"Permission"`
}

type accessControlPolicy struct {
	XMLName xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ AccessControlPolicy"`
	Owner   ownerEntry    `xml:"Owner"`
	Grants  []aclGrantOut `xml:"AccessControlList>Grant"`
}

func renderACL(grants []iam.Grant) *accessControlPolicy {
	const xsi = "http://www.w3.org/2001/XMLSchema-instance"
	out := &accessControlPolicy{Owner: placeholderOwner}
	out.Grants = append(out.Grants, aclGrantOut{
		Grantee:    aclGranteeOut{XSI: xsi, Type: "CanonicalUser", ID: ownerID, DisplayName: placeholderOwner.DisplayName},
		Permission: iam.PermFullControl,
	})
	for _, g := range grants {
		o := aclGrantOut{Permission: g.Perm}
		if g.Group != "" {
			o.Grantee = aclGranteeOut{XSI: xsi, Type: "Group", URI: g.Group}
		} else {
			o.Grantee = aclGranteeOut{XSI: xsi, Type: "CanonicalUser", ID: g.User, DisplayName: g.User}
		}
		out.Grants = append(out.Grants, o)
	}
	return out
}

// ----- handlers --------------------------------------------------------

// grantsFromRequest takes the ACL a PutBucketAcl / PutObjectAcl request
// carries: a header form or an XML body, not both.
func (s *Server) grantsFromRequest(q *request) ([]iam.Grant, *APIError, error) {
	grants, present, aerr := aclFromHeaders(q.r.Header)
	if aerr != nil {
		return nil, aerr, nil
	}
	body, err := s.readBody(q, 256<<10)
	if err != nil {
		return nil, nil, err
	}
	hasBody := len(strings.TrimSpace(string(body))) > 0
	switch {
	case present && hasBody:
		return nil, invalidACL("Specifying both an ACL header and a request body is not allowed."), nil
	case present:
		return grants, nil, nil
	case hasBody:
		g, aerr := grantsFromXML(body)
		return g, aerr, nil
	}
	return nil, &APIError{"MissingSecurityHeader", "Your request was missing a required header.", http.StatusBadRequest}, nil
}

func (s *Server) bucketACLOp(q *request) {
	switch q.r.Method {
	case http.MethodGet:
		if !s.authorize(q, "s3:GetBucketAcl", q.bucket, "", nil) || !s.requireBucket(q) {
			return
		}
		grants, err := s.bucketACL(q, q.bucket)
		if err != nil {
			s.fail(q, err)
			return
		}
		s.writeXML(q, http.StatusOK, renderACL(grants))
	case http.MethodPut:
		if !s.authorize(q, "s3:PutBucketAcl", q.bucket, "", nil) {
			return
		}
		grants, aerr, err := s.grantsFromRequest(q)
		if err != nil {
			s.fail(q, err)
			return
		}
		if aerr != nil {
			s.fail(q, aerr)
			return
		}
		if !s.requireBucket(q) {
			return
		}
		if len(grants) == 0 {
			s.confDrop(q.ctx(), q.bucket, confACL)
		} else {
			data, _ := json.Marshal(aclDoc{Grants: grants})
			if err := s.confPut(q.ctx(), q.bucket, confACL, data); err != nil {
				s.fail(q, err)
				return
			}
		}
		q.w.WriteHeader(http.StatusOK)
	default:
		s.fail(q, errBadMethod)
	}
}

func (s *Server) objectACLOp(q *request) {
	vid := q.query.Get("versionId")
	switch q.r.Method {
	case http.MethodGet:
		action := "s3:GetObjectAcl"
		if vid != "" {
			action = "s3:GetObjectVersionAcl"
		}
		if !s.authorize(q, action, q.bucket, q.key, nil) {
			return
		}
		info, err := s.st.StatObject(q.ctx(), q.bucket, q.key, storage.GetOptions{VersionID: vid})
		if err != nil {
			s.fail(q, err)
			return
		}
		if info.VersionID != "" {
			q.w.Header().Set("x-amz-version-id", info.VersionID)
		}
		s.writeXML(q, http.StatusOK, renderACL(grantsOf(info.UserDefined)))
	case http.MethodPut:
		action := "s3:PutObjectAcl"
		if vid != "" {
			action = "s3:PutObjectVersionAcl"
		}
		if !s.authorize(q, action, q.bucket, q.key, nil) {
			return
		}
		grants, aerr, err := s.grantsFromRequest(q)
		if err != nil {
			s.fail(q, err)
			return
		}
		if aerr != nil {
			s.fail(q, aerr)
			return
		}
		info, err := s.st.StatObject(q.ctx(), q.bucket, q.key, storage.GetOptions{VersionID: vid})
		if err != nil {
			s.fail(q, err)
			return
		}
		ud := make(map[string]string, len(info.UserDefined)+1)
		for k, v := range info.UserDefined {
			ud[k] = v
		}
		delete(ud, aclKey)
		if len(grants) > 0 {
			data, _ := json.Marshal(aclDoc{Grants: grants})
			ud[aclKey] = string(data)
		}
		upd, err := s.st.UpdateObjectMetadata(q.ctx(), q.bucket, q.key, storage.UpdateMetaOptions{
			VersionID: info.VersionID, UserDefined: ud, IfETag: info.ETag,
		})
		if err != nil {
			s.fail(q, err)
			return
		}
		if upd.VersionID != "" {
			q.w.Header().Set("x-amz-version-id", upd.VersionID)
		}
		q.w.WriteHeader(http.StatusOK)
	default:
		s.fail(q, errBadMethod)
	}
}

// applyACLHeaders records the ACL a write carries (x-amz-acl or grant
// headers) in the object's metadata, after authorising s3:PutObjectAcl as S3
// does. It reports false after writing a response.
func (s *Server) applyACLHeaders(q *request, opts *storage.PutOptions) bool {
	grants, present, aerr := aclFromHeaders(q.r.Header)
	if aerr != nil {
		s.fail(q, aerr)
		return false
	}
	if !present {
		return true
	}
	if !s.authorize(q, "s3:PutObjectAcl", q.bucket, q.key, nil) {
		return false
	}
	if len(grants) == 0 {
		return true // an explicit private ACL is the default
	}
	data, _ := json.Marshal(aclDoc{Grants: grants})
	ud := make(map[string]string, len(opts.UserDefined)+1)
	for k, v := range opts.UserDefined {
		ud[k] = v
	}
	ud[aclKey] = string(data)
	opts.UserDefined = ud
	return true
}
