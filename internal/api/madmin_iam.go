package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"nanoio/internal/iam"
)

func iamRequest(action string) iam.Request { return iam.Request{Action: action} }

func init() {
	r := madminRegister
	r("add-user", "PUT", "admin:CreateUser", (*Server).madminAddUser)
	r("remove-user", "DELETE", "admin:DeleteUser", (*Server).madminRemoveUser)
	r("list-users", "GET", "admin:ListUsers", (*Server).madminListUsers)
	r("user-info", "GET", "admin:GetUser", (*Server).madminUserInfo)
	r("set-user-status", "PUT", "admin:EnableUser", (*Server).madminSetUserStatus)
	r("groups", "GET", "admin:ListGroups", (*Server).madminListGroups)
	r("group", "GET", "admin:GetGroup", (*Server).madminGroupInfo)
	r("update-group-members", "PUT", "admin:AddUserToGroup", (*Server).madminUpdateGroupMembers)
	r("set-group-status", "PUT", "admin:EnableGroup", (*Server).madminSetGroupStatus)
	r("list-canned-policies", "GET", "admin:ListUserPolicies", (*Server).madminListPolicies)
	r("info-canned-policy", "GET", "admin:GetPolicy", (*Server).madminInfoPolicy)
	r("add-canned-policy", "PUT", "admin:CreatePolicy", (*Server).madminAddPolicy)
	r("remove-canned-policy", "DELETE", "admin:DeletePolicy", (*Server).madminRemovePolicy)
	r("set-user-or-group-policy", "PUT", "admin:AttachUserOrGroupPolicy", (*Server).madminSetPolicy)
	r("idp/builtin/policy/attach", "POST", "admin:AttachUserOrGroupPolicy", (*Server).madminAttachPolicy)
	r("idp/builtin/policy/detach", "POST", "admin:AttachUserOrGroupPolicy", (*Server).madminDetachPolicy)
	r("idp/builtin/policy-entities", "GET", "admin:ListUserPolicies", (*Server).madminPolicyEntities)
	r("add-service-account", "PUT", "admin:CreateServiceAccount", (*Server).madminAddServiceAccount)
	r("update-service-account", "POST", "admin:UpdateServiceAccount", (*Server).madminUpdateServiceAccount)
	r("delete-service-account", "DELETE", "admin:RemoveServiceAccount", (*Server).madminDeleteServiceAccount)
	r("list-service-accounts", "GET", "admin:ListServiceAccounts", (*Server).madminListServiceAccounts)
	r("info-service-account", "GET", "admin:ListServiceAccounts", (*Server).madminInfoServiceAccount)
	r("info-access-key", "GET", "admin:ListServiceAccounts", (*Server).madminInfoAccessKey)
	r("list-access-keys-bulk", "GET", "admin:ListServiceAccounts", (*Server).madminListAccessKeysBulk)
}

func (s *Server) iamReady(q *request) bool {
	if s.iamrt == nil || s.iam == nil {
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented", "runtime IAM is not enabled")
		return false
	}
	return true
}

// dynUser returns the runtime document of a user, nil when there is none.
func (s *Server) dynUser(q *request, ak string) (*iamDoc, bool) {
	d, err := s.iamrt.readDoc(q.ctx(), iamDocName("user", ak))
	if err != nil {
		s.madminErr(q, err)
		return nil, false
	}
	if d != nil && d.Deleted {
		d = nil
	}
	return d, true
}

func (s *Server) dynGroup(q *request, name string) (*iamDoc, bool) {
	d, err := s.iamrt.readDoc(q.ctx(), iamDocName("group", name))
	if err != nil {
		s.madminErr(q, err)
		return nil, false
	}
	if d != nil && d.Deleted {
		d = nil
	}
	return d, true
}

func (s *Server) saveIAM(q *request, d *iamDoc) bool {
	d.Updated, d.Origin = time.Now().UnixNano(), s.siteID()
	if _, err := s.iamrt.apply(q.ctx(), d, false); err != nil {
		s.madminErr(q, err)
		return false
	}
	return true
}

type madminUserInfo struct {
	AuthInfo   *madminUserAuthInfo `json:"userAuthInfo,omitempty"`
	SecretKey  string              `json:"secretKey,omitempty"`
	PolicyName string              `json:"policyName,omitempty"`
	Status     string              `json:"status"`
	MemberOf   []string            `json:"memberOf,omitempty"`
	UpdatedAt  time.Time           `json:"updatedAt,omitempty"`
}

type madminUserAuthInfo struct {
	Type             string `json:"type"`
	AuthServer       string `json:"authServer,omitempty"`
	AuthServerUserID string `json:"authServerUserID,omitempty"`
}

func statusOf(s string) string {
	if s == "" {
		return "enabled"
	}
	return s
}

func (s *Server) userView(e iam.UserEntry, snap *iam.File) madminUserInfo {
	v := madminUserInfo{PolicyName: strings.Join(e.Policies, ","), Status: statusOf(e.Status),
		AuthInfo: &madminUserAuthInfo{Type: "builtin", AuthServerUserID: e.AccessKey}}
	for _, g := range snap.Groups {
		for _, m := range g.Members {
			if m == e.AccessKey {
				v.MemberOf = append(v.MemberOf, g.Name)
			}
		}
	}
	sort.Strings(v.MemberOf)
	return v
}

func (s *Server) madminAddUser(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var req struct {
		SecretKey string `json:"secretKey"`
		Policy    string `json:"policy"`
		Status    string `json:"status"`
	}
	if err := json.Unmarshal(pt, &req); err != nil {
		s.madminErr(q, madminBad("invalid request"))
		return
	}
	if ak == s.iam.Root() {
		s.madminFail(q, http.StatusBadRequest, "XMinioInvalidIAMCredentials", "the root user cannot be modified")
		return
	}
	if s.iam.IsStatic("user", ak) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", ak+" is defined by the IAM file and cannot be changed at run time")
		return
	}
	cur, ok := s.dynUser(q, ak)
	if !ok {
		return
	}
	entry := iam.UserEntry{AccessKey: ak, SecretKey: req.SecretKey, Status: req.Status}
	if cur != nil && cur.User != nil {
		if cur.User.Kind != "" {
			s.madminFail(q, http.StatusBadRequest, "XMinioInvalidIAMCredentials", ak+" is a service account")
			return
		}
		entry.Policies = cur.User.Policies
		if entry.SecretKey == "" {
			entry.SecretKey = cur.User.SecretKey
		}
	}
	if entry.Status != "" && entry.Status != "enabled" && entry.Status != "disabled" {
		s.madminFail(q, http.StatusBadRequest, "XMinioInvalidIAMCredentials", "status must be enabled or disabled")
		return
	}
	if err := (iam.Credential{AccessKey: ak, SecretKey: entry.SecretKey}).Validate(); err != nil {
		s.madminFail(q, http.StatusBadRequest, "XMinioInvalidIAMCredentials", err.Error())
		return
	}
	if req.Policy != "" {
		entry.Policies = splitList(req.Policy)
	}
	if bad := s.unknownPolicy(entry.Policies); bad != "" {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchPolicy", "policy "+bad+" does not exist")
		return
	}
	if entry.Status == "enabled" {
		entry.Status = ""
	}
	if s.saveIAM(q, &iamDoc{Kind: "user", Name: ak, User: &entry}) {
		s.madminOK(q)
	}
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func (s *Server) madminRemoveUser(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	if s.iam.IsStatic("user", ak) || ak == s.iam.Root() {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", ak+" cannot be removed at run time")
		return
	}
	cur, ok := s.dynUser(q, ak)
	if !ok {
		return
	}
	if cur == nil || cur.User == nil {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchUser", "The specified user does not exist.")
		return
	}
	// Its service accounts and group memberships go with it.
	snap := s.iam.Snapshot()
	for _, e := range snap.Users {
		if e.Parent == ak && !s.iam.IsStatic("user", e.AccessKey) {
			s.saveIAM(q, &iamDoc{Kind: "user", Name: e.AccessKey, Deleted: true})
		}
	}
	for _, g := range snap.Groups {
		for i, m := range g.Members {
			if m == ak && !s.iam.IsStatic("group", g.Name) {
				ng := g
				ng.Members = append(append([]string(nil), g.Members[:i]...), g.Members[i+1:]...)
				s.saveIAM(q, &iamDoc{Kind: "group", Name: g.Name, Group: &ng})
				break
			}
		}
	}
	if s.saveIAM(q, &iamDoc{Kind: "user", Name: ak, Deleted: true}) {
		s.madminOK(q)
	}
}

func (s *Server) madminListUsers(q *request) {
	if !s.iamReady(q) {
		return
	}
	snap := s.iam.Snapshot()
	out := map[string]madminUserInfo{}
	for _, e := range snap.Users {
		if e.Kind != "" || e.Parent != "" {
			continue
		}
		out[e.AccessKey] = s.userView(e, &snap)
	}
	s.writeEncrypted(q, out)
}

func (s *Server) madminUserInfo(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	// A caller may always read their own entry.
	snap := s.iam.Snapshot()
	for _, e := range snap.Users {
		if e.AccessKey == ak && e.Kind == "" && e.Parent == "" {
			s.writeJSONOK(q, s.userView(e, &snap))
			return
		}
	}
	s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchUser", "The specified user does not exist.")
}

func (s *Server) madminSetUserStatus(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak, status := q.query.Get("accessKey"), q.query.Get("status")
	if status != "enabled" && status != "disabled" {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "status must be enabled or disabled")
		return
	}
	if ak == s.iam.Root() || s.iam.IsStatic("user", ak) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", ak+" cannot be changed at run time")
		return
	}
	cur, ok := s.dynUser(q, ak)
	if !ok {
		return
	}
	if cur == nil || cur.User == nil {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchUser", "The specified user does not exist.")
		return
	}
	u := *cur.User
	u.Status = status
	if status == "enabled" {
		u.Status = ""
	}
	if s.saveIAM(q, &iamDoc{Kind: "user", Name: ak, User: &u}) {
		s.madminOK(q)
	}
}

// ----- groups -----------------------------------------------------------------------------------

func (s *Server) madminListGroups(q *request) {
	if !s.iamReady(q) {
		return
	}
	snap := s.iam.Snapshot()
	names := []string{}
	for _, g := range snap.Groups {
		names = append(names, g.Name)
	}
	sort.Strings(names)
	s.writeJSONOK(q, names)
}

type madminGroupDesc struct {
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	Members   []string  `json:"members"`
	Policy    string    `json:"policy"`
	UpdatedAt time.Time `json:"updatedAt,omitempty"`
}

func (s *Server) madminGroupInfo(q *request) {
	if !s.iamReady(q) {
		return
	}
	name := q.query.Get("group")
	snap := s.iam.Snapshot()
	for _, g := range snap.Groups {
		if g.Name == name {
			m := g.Members
			if m == nil {
				m = []string{}
			}
			s.writeJSONOK(q, madminGroupDesc{Name: g.Name, Status: statusOf(g.Status), Members: m, Policy: strings.Join(g.Policies, ",")})
			return
		}
	}
	s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchGroup", "The specified group does not exist.")
}

func (s *Server) madminUpdateGroupMembers(q *request) {
	if !s.iamReady(q) {
		return
	}
	var req struct {
		Group    string   `json:"group"`
		Members  []string `json:"members"`
		Status   string   `json:"groupStatus"`
		IsRemove bool     `json:"isRemove"`
	}
	if err := s.readJSONBody(q, &req); err != nil {
		s.madminErr(q, err)
		return
	}
	if req.Group == "" || strings.ContainsAny(req.Group, "/ ") {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "a group needs a name without '/' or spaces")
		return
	}
	if s.iam.IsStatic("group", req.Group) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", req.Group+" is defined by the IAM file")
		return
	}
	cur, ok := s.dynGroup(q, req.Group)
	if !ok {
		return
	}
	var g iam.GroupEntry
	if cur != nil && cur.Group != nil {
		g = *cur.Group
	} else if req.IsRemove {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchGroup", "The specified group does not exist.")
		return
	}
	g.Name = req.Group
	if req.IsRemove && len(req.Members) == 0 {
		// An empty remove deletes the group, which must have no members.
		if cur == nil || cur.Group == nil {
			s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchGroup", "The specified group does not exist.")
			return
		}
		if len(g.Members) > 0 {
			s.madminFail(q, http.StatusConflict, "XMinioAdminGroupNotEmpty", "The specified group is not empty - cannot remove it.")
			return
		}
		if s.saveIAM(q, &iamDoc{Kind: "group", Name: g.Name, Deleted: true}) {
			s.madminOK(q)
		}
		return
	}
	have := map[string]bool{}
	for _, m := range g.Members {
		have[m] = true
	}
	snap := s.iam.Snapshot()
	users := map[string]bool{}
	for _, u := range snap.Users {
		users[u.AccessKey] = true
	}
	for _, m := range req.Members {
		switch {
		case req.IsRemove:
			delete(have, m)
		default:
			if !users[m] {
				s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchUser", "user "+m+" does not exist")
				return
			}
			have[m] = true
		}
	}
	g.Members = g.Members[:0]
	for m := range have {
		g.Members = append(g.Members, m)
	}
	sort.Strings(g.Members)
	if req.Status != "" {
		g.Status = req.Status
		if g.Status == "enabled" {
			g.Status = ""
		}
	}
	if s.saveIAM(q, &iamDoc{Kind: "group", Name: g.Name, Group: &g}) {
		s.madminOK(q)
	}
}

func (s *Server) madminSetGroupStatus(q *request) {
	if !s.iamReady(q) {
		return
	}
	name, status := q.query.Get("group"), q.query.Get("status")
	if status != "enabled" && status != "disabled" {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "status must be enabled or disabled")
		return
	}
	if s.iam.IsStatic("group", name) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", name+" is defined by the IAM file")
		return
	}
	cur, ok := s.dynGroup(q, name)
	if !ok {
		return
	}
	if cur == nil || cur.Group == nil {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchGroup", "The specified group does not exist.")
		return
	}
	g := *cur.Group
	g.Status = status
	if status == "enabled" {
		g.Status = ""
	}
	if s.saveIAM(q, &iamDoc{Kind: "group", Name: name, Group: &g}) {
		s.madminOK(q)
	}
}

// ----- policies -----------------------------------------------------------------------------------

func (s *Server) madminListPolicies(q *request) {
	if !s.iamReady(q) {
		return
	}
	snap := s.iam.Snapshot()
	out := map[string]json.RawMessage{}
	for n, d := range snap.Policies {
		out[n] = d
	}
	s.writeJSONOK(q, out)
}

func (s *Server) madminInfoPolicy(q *request) {
	if !s.iamReady(q) {
		return
	}
	name := q.query.Get("name")
	snap := s.iam.Snapshot()
	doc, ok := snap.Policies[name]
	if !ok {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchPolicy", "The canned policy does not exist.")
		return
	}
	if q.query.Get("v") != "2" {
		q.w.Header().Set("Content-Type", "application/json")
		q.w.WriteHeader(http.StatusOK)
		q.w.Write(doc)
		return
	}
	info := struct {
		PolicyName string
		Policy     json.RawMessage
		CreateDate time.Time `json:",omitempty"`
		UpdateDate time.Time `json:",omitempty"`
	}{PolicyName: name, Policy: doc}
	if d, err := s.iamrt.readDoc(q.ctx(), iamDocName("policy", name)); err == nil && d != nil {
		info.UpdateDate = time.Unix(0, d.Updated).UTC()
		info.CreateDate = info.UpdateDate
	}
	s.writeJSONOK(q, info)
}

func (s *Server) madminAddPolicy(q *request) {
	if !s.iamReady(q) {
		return
	}
	name := q.query.Get("name")
	body := make([]byte, 0)
	buf, err := readAllLimited(q, 1<<20)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	body = append(body, buf...)
	if name == "" || strings.ContainsAny(name, "/ ") {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "a policy needs a name without '/' or spaces")
		return
	}
	if iam.IsCanned(name) || s.iam.IsStatic("policy", name) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "the built-in or file-defined policy "+name+" cannot be replaced")
		return
	}
	if _, err := iam.ParsePolicy(body); err != nil {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminMalformedPolicy", "invalid policy: "+err.Error())
		return
	}
	if s.saveIAM(q, &iamDoc{Kind: "policy", Name: name, Policy: json.RawMessage(body)}) {
		s.madminOK(q)
	}
}

func (s *Server) madminRemovePolicy(q *request) {
	if !s.iamReady(q) {
		return
	}
	name := q.query.Get("name")
	if iam.IsCanned(name) || s.iam.IsStatic("policy", name) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "the built-in or file-defined policy "+name+" cannot be removed")
		return
	}
	if _, ok := s.iam.Snapshot().Policies[name]; !ok {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchPolicy", "The canned policy does not exist.")
		return
	}
	if users := s.iam.PolicyUsers(name); len(users) > 0 {
		s.madminFail(q, http.StatusConflict, "XMinioAdminPolicyInUse", "The policy is attached to "+strings.Join(users, ", ")+".")
		return
	}
	if s.saveIAM(q, &iamDoc{Kind: "policy", Name: name, Deleted: true}) {
		s.madminOK(q)
	}
}

// setEntityPolicies replaces the policies attached to a user or group.
func (s *Server) setEntityPolicies(q *request, entity string, isGroup bool, policies []string) bool {
	if bad := s.unknownPolicy(policies); bad != "" {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchPolicy", "policy "+bad+" does not exist")
		return false
	}
	if isGroup {
		if s.iam.IsStatic("group", entity) {
			s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", entity+" is defined by the IAM file")
			return false
		}
		cur, ok := s.dynGroup(q, entity)
		if !ok {
			return false
		}
		if cur == nil || cur.Group == nil {
			s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchGroup", "The specified group does not exist.")
			return false
		}
		g := *cur.Group
		g.Policies = policies
		return s.saveIAM(q, &iamDoc{Kind: "group", Name: entity, Group: &g})
	}
	if s.iam.IsStatic("user", entity) {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", entity+" is defined by the IAM file")
		return false
	}
	cur, ok := s.dynUser(q, entity)
	if !ok {
		return false
	}
	if cur == nil || cur.User == nil {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchUser", "The specified user does not exist.")
		return false
	}
	u := *cur.User
	u.Policies = policies
	return s.saveIAM(q, &iamDoc{Kind: "user", Name: entity, User: &u})
}

func (s *Server) madminSetPolicy(q *request) {
	if !s.iamReady(q) {
		return
	}
	entity := q.query.Get("userOrGroup")
	isGroup := q.query.Get("isGroup") == "true"
	if s.setEntityPolicies(q, entity, isGroup, splitList(q.query.Get("policyName"))) {
		s.madminOK(q)
	}
}

func (s *Server) entityPolicies(entity string, isGroup bool) []string {
	snap := s.iam.Snapshot()
	if isGroup {
		for _, g := range snap.Groups {
			if g.Name == entity {
				return g.Policies
			}
		}
		return nil
	}
	for _, u := range snap.Users {
		if u.AccessKey == entity {
			return u.Policies
		}
	}
	return nil
}

func (s *Server) madminAttachPolicy(q *request) { s.madminAssociate(q, true) }
func (s *Server) madminDetachPolicy(q *request) { s.madminAssociate(q, false) }

func (s *Server) madminAssociate(q *request, attach bool) {
	if !s.iamReady(q) {
		return
	}
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
	entity, isGroup := req.User, false
	if req.Group != "" {
		entity, isGroup = req.Group, true
	}
	cur := s.entityPolicies(entity, isGroup)
	set := map[string]bool{}
	for _, p := range cur {
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
	next := make([]string, 0, len(set))
	for p := range set {
		next = append(next, p)
	}
	sort.Strings(next)
	if len(changed) == 0 {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminPolicyChangeAlreadyApplied", "The specified policy change is already in effect.")
		return
	}
	if !s.setEntityPolicies(q, entity, isGroup, next) {
		return
	}
	resp := struct {
		PoliciesAttached []string  `json:"policiesAttached,omitempty"`
		PoliciesDetached []string  `json:"policiesDetached,omitempty"`
		UpdatedAt        time.Time `json:"updatedAt"`
	}{UpdatedAt: time.Now().UTC()}
	if attach {
		resp.PoliciesAttached = changed
	} else {
		resp.PoliciesDetached = changed
	}
	s.writeEncrypted(q, resp)
}

func (s *Server) madminPolicyEntities(q *request) {
	if !s.iamReady(q) {
		return
	}
	snap := s.iam.Snapshot()
	wantUser := toSet(q.query["user"])
	wantGroup := toSet(q.query["group"])
	wantPolicy := toSet(q.query["policy"])
	type groupEnt struct {
		Group    string   `json:"group"`
		Policies []string `json:"policies"`
	}
	type userEnt struct {
		User             string     `json:"user"`
		Policies         []string   `json:"policies"`
		MemberOfMappings []groupEnt `json:"memberOfMappings,omitempty"`
	}
	type polEnt struct {
		Policy string   `json:"policy"`
		Users  []string `json:"users"`
		Groups []string `json:"groups"`
	}
	res := struct {
		Timestamp      time.Time  `json:"timestamp"`
		UserMappings   []userEnt  `json:"userMappings,omitempty"`
		GroupMappings  []groupEnt `json:"groupMappings,omitempty"`
		PolicyMappings []polEnt   `json:"policyMappings,omitempty"`
	}{Timestamp: time.Now().UTC()}
	all := len(wantUser)+len(wantGroup)+len(wantPolicy) == 0
	pol := map[string]*polEnt{}
	for _, u := range snap.Users {
		if u.Kind != "" || u.Parent != "" {
			continue
		}
		for _, p := range u.Policies {
			if pol[p] == nil {
				pol[p] = &polEnt{Policy: p}
			}
			pol[p].Users = append(pol[p].Users, u.AccessKey)
		}
		if all || wantUser[u.AccessKey] {
			ue := userEnt{User: u.AccessKey, Policies: u.Policies}
			for _, g := range snap.Groups {
				for _, m := range g.Members {
					if m == u.AccessKey {
						ue.MemberOfMappings = append(ue.MemberOfMappings, groupEnt{g.Name, g.Policies})
					}
				}
			}
			res.UserMappings = append(res.UserMappings, ue)
		}
	}
	for _, g := range snap.Groups {
		for _, p := range g.Policies {
			if pol[p] == nil {
				pol[p] = &polEnt{Policy: p}
			}
			pol[p].Groups = append(pol[p].Groups, g.Name)
		}
		if all || wantGroup[g.Name] {
			res.GroupMappings = append(res.GroupMappings, groupEnt{g.Name, g.Policies})
		}
	}
	names := make([]string, 0, len(pol))
	for n := range pol {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if all || wantPolicy[n] {
			res.PolicyMappings = append(res.PolicyMappings, *pol[n])
		}
	}
	s.writeEncrypted(q, res)
}

func toSet(l []string) map[string]bool {
	m := map[string]bool{}
	for _, v := range l {
		m[v] = true
	}
	return m
}

// ----- service accounts ---------------------------------------------------------------------------

func randomSecret(n int) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func randomAccessKey() string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 20)
	rand.Read(b)
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b)
}

func newToken() string {
	var b [24]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) svcInfo(e iam.UserEntry) map[string]any {
	st := statusOf(e.Status)
	if st == "enabled" {
		st = "on"
	} else {
		st = "off"
	}
	m := map[string]any{"parentUser": e.Parent, "accountStatus": st, "impliedPolicy": len(e.SessionPolicy) == 0,
		"accessKey": e.AccessKey}
	if e.Name != "" {
		m["name"] = e.Name
	}
	if e.Description != "" {
		m["description"] = e.Description
	}
	// Clients dereference the expiry unconditionally; the epoch means none.
	m["expiration"] = time.Unix(0, 0).UTC()
	if !e.Expiry.IsZero() {
		m["expiration"] = e.Expiry
	}
	return m
}

func (s *Server) madminAddServiceAccount(q *request) {
	if !s.iamReady(q) {
		return
	}
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var req struct {
		Policy      json.RawMessage `json:"policy"`
		TargetUser  string          `json:"targetUser"`
		AccessKey   string          `json:"accessKey"`
		SecretKey   string          `json:"secretKey"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Expiration  *time.Time      `json:"expiration"`
		Comment     string          `json:"comment"`
	}
	if json.Unmarshal(pt, &req) != nil {
		s.madminErr(q, madminBad("invalid request"))
		return
	}
	parent := q.who
	if req.TargetUser != "" && req.TargetUser != q.who {
		if !s.madminAllowed(q, "admin:CreateServiceAccount") {
			s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
			return
		}
		parent = req.TargetUser
	}
	// A service account belongs to an existing user (or root), never to
	// another derived credential.
	if parent != s.iam.Root() {
		found := false
		for _, u := range s.iam.Snapshot().Users {
			if u.AccessKey == parent && u.Kind == "" && u.Parent == "" {
				found = true
			}
		}
		if !found {
			s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchUser", "The specified parent user does not exist.")
			return
		}
	}
	ak, sk := req.AccessKey, req.SecretKey
	if ak == "" {
		ak = randomAccessKey()
	}
	if sk == "" {
		sk = randomSecret(40)
	}
	if err := (iam.Credential{AccessKey: ak, SecretKey: sk}).Validate(); err != nil {
		s.madminFail(q, http.StatusBadRequest, "XMinioInvalidIAMCredentials", err.Error())
		return
	}
	if ak == s.iam.Root() || s.iam.IsStatic("user", ak) {
		s.madminFail(q, http.StatusConflict, "XMinioAdminServiceAccountAlreadyExists", "that access key is taken")
		return
	}
	for _, u := range s.iam.Snapshot().Users {
		if u.AccessKey == ak {
			s.madminFail(q, http.StatusConflict, "XMinioAdminServiceAccountAlreadyExists", "that access key is taken")
			return
		}
	}
	entry := iam.UserEntry{AccessKey: ak, SecretKey: sk, Kind: "svcacct", Parent: parent, Name: req.Name,
		Description: req.Description}
	if entry.Description == "" {
		entry.Description = req.Comment
	}
	if len(req.Policy) > 0 && string(req.Policy) != "null" {
		if _, err := iam.ParsePolicy(req.Policy); err != nil {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminMalformedPolicy", "invalid session policy: "+err.Error())
			return
		}
		entry.SessionPolicy = req.Policy
	}
	if req.Expiration != nil && !req.Expiration.IsZero() && req.Expiration.Unix() != 0 {
		if !req.Expiration.After(time.Now()) {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "the expiration time should be in the future")
			return
		}
		entry.Expiry = req.Expiration.UTC()
	}
	if !s.saveIAM(q, &iamDoc{Kind: "user", Name: ak, User: &entry}) {
		return
	}
	creds := map[string]any{"accessKey": ak, "secretKey": sk}
	if !entry.Expiry.IsZero() {
		creds["expiration"] = entry.Expiry
	} else {
		creds["expiration"] = time.Unix(0, 0).UTC()
	}
	s.writeEncrypted(q, map[string]any{"credentials": creds})
}

// svcEntry finds a service account by access key.
func (s *Server) svcEntry(ak string) (iam.UserEntry, bool) {
	for _, u := range s.iam.Snapshot().Users {
		if u.AccessKey == ak && u.Kind == "svcacct" {
			return u, true
		}
	}
	return iam.UserEntry{}, false
}

// mayManage reports whether the caller owns the service account or is an
// admin allowed to manage others'.
func (s *Server) mayManage(q *request, e iam.UserEntry, action string) bool {
	return e.Parent == q.who || s.madminAllowed(q, action)
}

func (s *Server) madminUpdateServiceAccount(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	e, ok := s.svcEntry(ak)
	if !ok || !s.mayManage(q, e, "admin:UpdateServiceAccount") {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminServiceAccountNotFound", "The specified service account does not exist.")
		return
	}
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var req struct {
		NewPolicy      json.RawMessage `json:"newPolicy"`
		NewSecretKey   string          `json:"newSecretKey"`
		NewStatus      string          `json:"newStatus"`
		NewName        string          `json:"newName"`
		NewDescription string          `json:"newDescription"`
		NewExpiration  *time.Time      `json:"newExpiration"`
	}
	if json.Unmarshal(pt, &req) != nil {
		s.madminErr(q, madminBad("invalid request"))
		return
	}
	if req.NewSecretKey != "" {
		if err := (iam.Credential{AccessKey: ak, SecretKey: req.NewSecretKey}).Validate(); err != nil {
			s.madminFail(q, http.StatusBadRequest, "XMinioInvalidIAMCredentials", err.Error())
			return
		}
		e.SecretKey = req.NewSecretKey
	}
	switch req.NewStatus {
	case "":
	case "on", "enabled":
		e.Status = ""
	case "off", "disabled":
		e.Status = "disabled"
	default:
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "status must be on or off")
		return
	}
	if len(req.NewPolicy) > 0 && string(req.NewPolicy) != "null" {
		if _, err := iam.ParsePolicy(req.NewPolicy); err != nil {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminMalformedPolicy", "invalid session policy: "+err.Error())
			return
		}
		e.SessionPolicy = req.NewPolicy
	}
	if req.NewName != "" {
		e.Name = req.NewName
	}
	if req.NewDescription != "" {
		e.Description = req.NewDescription
	}
	if req.NewExpiration != nil {
		if req.NewExpiration.IsZero() || req.NewExpiration.Unix() == 0 {
			e.Expiry = time.Time{}
		} else if !req.NewExpiration.After(time.Now()) {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "the expiration time should be in the future")
			return
		} else {
			e.Expiry = req.NewExpiration.UTC()
		}
	}
	if s.saveIAM(q, &iamDoc{Kind: "user", Name: ak, User: &e}) {
		q.w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) madminDeleteServiceAccount(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	if d, err := s.stsGet(q.ctx(), ak); err == nil && d != nil {
		// A temporary credential: revoking it is deleting its document.
		if !s.madminAllowed(q, "admin:RemoveServiceAccount") {
			s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
			return
		}
		(&eventStore{st: s.st}).Delete(q.ctx(), stsName(ak))
		s.iam.Forget(ak)
		q.w.WriteHeader(http.StatusNoContent)
		return
	}
	e, ok := s.svcEntry(ak)
	if !ok || !s.mayManage(q, e, "admin:RemoveServiceAccount") {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminServiceAccountNotFound", "The specified service account does not exist.")
		return
	}
	if s.saveIAM(q, &iamDoc{Kind: "user", Name: ak, Deleted: true}) {
		q.w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) madminListServiceAccounts(q *request) {
	if !s.iamReady(q) {
		return
	}
	user := q.query.Get("user")
	if user == "" {
		user = q.who
	}
	if user != q.who && !s.madminAllowed(q, "admin:ListServiceAccounts") {
		s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
		return
	}
	accts := []map[string]any{}
	for _, u := range s.iam.Snapshot().Users {
		if u.Kind == "svcacct" && u.Parent == user {
			accts = append(accts, s.svcInfo(u))
		}
	}
	s.writeEncrypted(q, map[string]any{"accounts": accts})
}

func (s *Server) madminInfoServiceAccount(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	e, ok := s.svcEntry(ak)
	if !ok || !s.mayManage(q, e, "admin:ListServiceAccounts") {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminServiceAccountNotFound", "The specified service account does not exist.")
		return
	}
	m := s.svcInfo(e)
	delete(m, "accessKey")
	m["policy"] = string(e.SessionPolicy)
	s.writeEncrypted(q, m)
}

func (s *Server) madminInfoAccessKey(q *request) {
	if !s.iamReady(q) {
		return
	}
	ak := q.query.Get("accessKey")
	snap := s.iam.Snapshot()
	for _, u := range snap.Users {
		if u.AccessKey != ak {
			continue
		}
		if u.Kind == "" && u.Parent == "" {
			if u.AccessKey != q.who && !s.madminAllowed(q, "admin:ListServiceAccounts") {
				break
			}
			m := map[string]any{"AccessKey": ak, "parentUser": ak, "accountStatus": "on", "impliedPolicy": true,
				"userType": "Regular", "userProvider": "builtin"}
			s.writeEncrypted(q, m)
			return
		}
		if !s.mayManage(q, u, "admin:ListServiceAccounts") {
			break
		}
		m := s.svcInfo(u)
		delete(m, "accessKey")
		m["AccessKey"] = ak
		m["policy"] = string(u.SessionPolicy)
		if u.Kind == "sts" {
			m["userType"] = "STS"
		} else {
			m["userType"] = "Service Account"
		}
		m["userProvider"] = "builtin"
		if u.Provider != "" {
			m["userProvider"] = u.Provider
		}
		s.writeEncrypted(q, m)
		return
	}
	s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchAccessKey", "The specified access key does not exist.")
}

func (s *Server) madminListAccessKeysBulk(q *request) {
	if !s.iamReady(q) {
		return
	}
	users := q.query["users"]
	all := q.query.Get("all") == "true"
	listType := q.query.Get("listType")
	if listType == "" {
		listType = "all"
	}
	snap := s.iam.Snapshot()
	if all {
		users = nil
		for _, u := range snap.Users {
			if u.Kind == "" && u.Parent == "" {
				users = append(users, u.AccessKey)
			}
		}
		users = append(users, s.iam.Root())
	} else if len(users) == 0 {
		users = []string{q.who}
	}
	out := map[string]any{}
	for _, name := range users {
		if name != q.who && !s.madminAllowed(q, "admin:ListServiceAccounts") {
			s.madminFail(q, http.StatusForbidden, "XMinioAdminAccessDenied", "Access Denied.")
			return
		}
		entry := map[string]any{"serviceAccounts": []map[string]any{}, "stsKeys": []map[string]any{}}
		var svc, sts []map[string]any
		for _, u := range snap.Users {
			if u.Parent != name {
				continue
			}
			info := s.svcInfo(u)
			if u.Kind == "sts" {
				sts = append(sts, info)
			} else {
				svc = append(svc, info)
			}
		}
		if svc == nil {
			svc = []map[string]any{}
		}
		if sts == nil {
			sts = []map[string]any{}
		}
		if listType == "sts-only" {
			svc = []map[string]any{}
		}
		if listType == "svcacc-only" {
			sts = []map[string]any{}
		}
		entry["serviceAccounts"], entry["stsKeys"] = svc, sts
		out[name] = entry
	}
	s.writeEncrypted(q, out)
}
