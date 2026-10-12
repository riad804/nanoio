package api

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/iam"
	"nanoio/internal/identity/ldap"
	"nanoio/internal/identity/oidc"
)

// The STS endpoint: POST / with an Action form field. AssumeRole and
// GetCallerIdentity are signed with the caller's long-lived credentials;
// AssumeRoleWithWebIdentity and AssumeRoleWithLDAPIdentity are authenticated
// by the token or password in the request itself and are not signed.

const stsNS = "https://sts.amazonaws.com/doc/2011-06-15/"

type stsError struct {
	status int
	code   string
	msg    string
}

func (e *stsError) Error() string { return e.code + ": " + e.msg }

// isSTSRequest tells an STS call from an S3 service-level POST on "/".
func isSTSRequest(r *http.Request) bool {
	if r.Method != http.MethodPost || r.URL.Path != "/" {
		return false
	}
	if r.URL.Query().Get("Action") != "" {
		return true
	}
	ct := r.Header.Get("Content-Type")
	return strings.HasPrefix(ct, "application/x-www-form-urlencoded")
}

func (s *Server) stsFail(w http.ResponseWriter, id string, e *stsError) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(e.status)
	type errBody struct {
		Type    string `xml:"Type"`
		Code    string `xml:"Code"`
		Message string `xml:"Message"`
	}
	xml.NewEncoder(w).Encode(struct {
		XMLName   xml.Name `xml:"ErrorResponse"`
		Xmlns     string   `xml:"xmlns,attr"`
		Error     errBody  `xml:"Error"`
		RequestID string   `xml:"RequestId"`
	}{Xmlns: stsNS, Error: errBody{"Sender", e.code, e.msg}, RequestID: id})
}

func (s *Server) serveSTS(w http.ResponseWriter, r *http.Request) {
	id := newRequestID()
	w.Header().Set("Server", "NanoIO")
	w.Header().Set("x-amz-request-id", id)
	if s.iam == nil || s.iamrt == nil {
		s.stsFail(w, id, &stsError{http.StatusNotImplemented, "NotImplemented", "temporary credentials need runtime IAM, which is not enabled"})
		return
	}
	// The form is read before authentication: a signed form's body hash is
	// part of the signature, so the verifier needs the raw body.
	body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
	if err != nil {
		s.stsFail(w, id, &stsError{http.StatusBadRequest, "InvalidParameterValue", "unreadable request body"})
		return
	}
	r.Body = io.NopCloser(strings.NewReader(string(body)))
	form, err := url.ParseQuery(string(body))
	if err != nil {
		s.stsFail(w, id, &stsError{http.StatusBadRequest, "MalformedPolicyDocument", "malformed form"})
		return
	}
	for k, v := range r.URL.Query() {
		if _, dup := form[k]; !dup {
			form[k] = v
		}
	}
	if v := form.Get("Version"); v != "" && v != "2011-06-15" {
		s.stsFail(w, id, &stsError{http.StatusBadRequest, "InvalidAction", "unsupported STS version"})
		return
	}
	var res any
	var serr *stsError
	ctx := r.Context()
	switch action := form.Get("Action"); action {
	case "AssumeRole":
		res, serr = s.stsAssumeRole(ctx, r, form, id)
	case "GetCallerIdentity":
		res, serr = s.stsCallerIdentity(r, id)
	case "AssumeRoleWithWebIdentity":
		res, serr = s.stsWebIdentity(ctx, form, id)
	case "AssumeRoleWithLDAPIdentity":
		res, serr = s.stsLDAP(ctx, form, id)
	default:
		serr = &stsError{http.StatusBadRequest, "InvalidAction", "unsupported action " + strconv.Quote(action)}
	}
	if serr != nil {
		s.log.Info("sts request refused", "id", id, "action", form.Get("Action"), "code", serr.code)
		s.stsFail(w, id, serr)
		return
	}
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	xml.NewEncoder(w).Encode(res)
}

// authSigned authenticates a signed STS request.
func (s *Server) authSigned(r *http.Request) (*auth.Result, *stsError) {
	a := s.stsAuth
	if a == nil {
		a = s.authn
	}
	if s.noAuth || a == nil {
		return nil, &stsError{http.StatusForbidden, "AccessDenied", "this action requires signed credentials"}
	}
	res, err := a.Authenticate(r)
	if err != nil {
		if errors.Is(err, auth.ErrAnonymous) {
			return nil, &stsError{http.StatusForbidden, "AccessDenied", "Access Denied."}
		}
		ae, _, _ := classify(err)
		return nil, &stsError{ae.Status, ae.Code, ae.Message}
	}
	if err := s.sessionOK(r, res.AccessKey); err != nil {
		return nil, &stsError{http.StatusForbidden, "InvalidClientTokenId", "The security token included in the request is invalid."}
	}
	return res, nil
}

type stsCreds struct {
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type stsMeta struct {
	RequestID string `xml:"RequestId"`
}

type assumedUser struct {
	ARN           string `xml:"Arn"`
	AssumedRoleID string `xml:"AssumedRoleId"`
}

func duration(form url.Values, def, max time.Duration) (time.Duration, *stsError) {
	v := form.Get("DurationSeconds")
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || time.Duration(n)*time.Second < stsMinDur || time.Duration(n)*time.Second > max {
		return 0, &stsError{http.StatusBadRequest, "InvalidParameterValue",
			fmt.Sprintf("DurationSeconds must be between %d and %d", int(stsMinDur.Seconds()), int(max.Seconds()))}
	}
	return time.Duration(n) * time.Second, nil
}

func sessionPolicy(form url.Values) (json.RawMessage, *stsError) {
	p := form.Get("Policy")
	if p == "" {
		return nil, nil
	}
	if len(p) > 2048 {
		return nil, &stsError{http.StatusBadRequest, "PackedPolicyTooLarge", "the session policy exceeds 2048 characters"}
	}
	if _, err := iam.ParsePolicy([]byte(p)); err != nil {
		return nil, &stsError{http.StatusBadRequest, "MalformedPolicyDocument", "invalid session policy: " + err.Error()}
	}
	return json.RawMessage(p), nil
}

// issue creates and stores a temporary credential.
func (s *Server) issue(ctx context.Context, e iam.UserEntry, life time.Duration) (iam.UserEntry, *stsError) {
	e.Kind = "sts"
	e.AccessKey = randomAccessKey()
	e.SecretKey = randomSecret(40)
	e.Token = newToken() + newToken()
	e.Expiry = time.Now().Add(life).UTC().Truncate(time.Second)
	if err := s.stsPut(ctx, e); err != nil {
		s.log.Error("could not store a temporary credential", "err", err)
		return e, &stsError{http.StatusInternalServerError, "InternalFailure", "could not issue credentials"}
	}
	return e, nil
}

func credsOf(e iam.UserEntry) stsCreds {
	return stsCreds{e.AccessKey, e.SecretKey, e.Token, e.Expiry.UTC().Format(time.RFC3339)}
}

func (s *Server) stsAssumeRole(ctx context.Context, r *http.Request, form url.Values, id string) (any, *stsError) {
	res, serr := s.authSigned(r)
	if serr != nil {
		return nil, serr
	}
	// Derived credentials may not mint more credentials: it would let a
	// narrowed or short-lived credential escape its limits.
	if s.iam.IsDerived(res.AccessKey) {
		return nil, &stsError{http.StatusForbidden, "AccessDenied", "temporary credentials and service accounts cannot assume a role"}
	}
	life, serr := duration(form, stsDefDur, stsMaxDur)
	if serr != nil {
		return nil, serr
	}
	sp, serr := sessionPolicy(form)
	if serr != nil {
		return nil, serr
	}
	e, serr := s.issue(ctx, iam.UserEntry{Parent: res.AccessKey, SessionPolicy: sp, Provider: "builtin", ProviderUser: res.AccessKey}, life)
	if serr != nil {
		return nil, serr
	}
	return struct {
		XMLName xml.Name `xml:"AssumeRoleResponse"`
		Xmlns   string   `xml:"xmlns,attr"`
		Result  struct {
			Credentials stsCreds    `xml:"Credentials"`
			User        assumedUser `xml:"AssumedRoleUser"`
		} `xml:"AssumeRoleResult"`
		Meta stsMeta `xml:"ResponseMetadata"`
	}{Xmlns: stsNS, Result: struct {
		Credentials stsCreds    `xml:"Credentials"`
		User        assumedUser `xml:"AssumedRoleUser"`
	}{credsOf(e), assumedUser{"arn:minio:sts:::assumed-role/" + res.AccessKey + "/" + e.AccessKey, e.AccessKey}}, Meta: stsMeta{id}}, nil
}

func (s *Server) stsCallerIdentity(r *http.Request, id string) (any, *stsError) {
	res, serr := s.authSigned(r)
	if serr != nil {
		return nil, serr
	}
	arn := "arn:minio:iam:::user/" + res.AccessKey
	return struct {
		XMLName xml.Name `xml:"GetCallerIdentityResponse"`
		Xmlns   string   `xml:"xmlns,attr"`
		Result  struct {
			Arn     string `xml:"Arn"`
			UserID  string `xml:"UserId"`
			Account string `xml:"Account"`
		} `xml:"GetCallerIdentityResult"`
		Meta stsMeta `xml:"ResponseMetadata"`
	}{Xmlns: stsNS, Result: struct {
		Arn     string `xml:"Arn"`
		UserID  string `xml:"UserId"`
		Account string `xml:"Account"`
	}{arn, res.AccessKey, "nanoio"}, Meta: stsMeta{id}}, nil
}

func (s *Server) stsWebIdentity(ctx context.Context, form url.Values, id string) (any, *stsError) {
	prov, kv, err := s.oidcProvider(ctx)
	if err != nil {
		s.log.Error("openid configuration is invalid", "err", err)
		return nil, &stsError{http.StatusInternalServerError, "InternalFailure", "the OpenID provider is misconfigured"}
	}
	if prov == nil {
		return nil, &stsError{http.StatusBadRequest, "InvalidParameterValue", "OpenID identity is not configured on this server"}
	}
	tok := form.Get("WebIdentityToken")
	if tok == "" {
		tok = form.Get("Token")
	}
	if tok == "" {
		return nil, &stsError{http.StatusBadRequest, "InvalidParameterValue", "WebIdentityToken is required"}
	}
	vctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	claims, err := prov.Verify(vctx, tok)
	if err != nil {
		code := "InvalidIdentityToken"
		if errors.Is(err, oidc.ErrExpired) {
			code = "ExpiredToken"
		}
		s.log.Info("web identity token rejected", "err", err)
		return nil, &stsError{http.StatusBadRequest, code, "the web identity token is not valid"}
	}
	claim := kv["claim_name"]
	if claim == "" {
		claim = "policy"
	}
	var pols []string
	for _, p := range claims.Strings(claim) {
		if s.policyExists(p) {
			pols = append(pols, p)
		}
	}
	if len(pols) == 0 && kv["role_policy"] != "" && s.policyExists(kv["role_policy"]) {
		pols = []string{kv["role_policy"]}
	}
	if len(pols) == 0 {
		return nil, &stsError{http.StatusForbidden, "AccessDenied",
			"the token carries no policy (claim " + strconv.Quote(claim) + ") that exists on this server"}
	}
	// The credential never outlives the token that earned it.
	remaining := time.Until(claims.Expiry())
	def := stsDefDur
	if remaining > 0 && remaining < def {
		def = remaining
	}
	life, serr := duration(form, def, stsMaxDur)
	if serr != nil {
		return nil, serr
	}
	if remaining > 0 && life > remaining {
		life = remaining
	}
	if life < time.Second {
		return nil, &stsError{http.StatusBadRequest, "ExpiredToken", "the web identity token is about to expire"}
	}
	sp, serr := sessionPolicy(form)
	if serr != nil {
		return nil, serr
	}
	e, serr := s.issue(ctx, iam.UserEntry{Policies: pols, SessionPolicy: sp, Provider: "openid", ProviderUser: claims.Subject(),
		Name: form.Get("RoleSessionName")}, life)
	if serr != nil {
		return nil, serr
	}
	aud, _ := claims["aud"].(string)
	return struct {
		XMLName xml.Name `xml:"AssumeRoleWithWebIdentityResponse"`
		Xmlns   string   `xml:"xmlns,attr"`
		Result  struct {
			Credentials stsCreds    `xml:"Credentials"`
			Subject     string      `xml:"SubjectFromWebIdentityToken"`
			Audience    string      `xml:"Audience"`
			Provider    string      `xml:"Provider"`
			User        assumedUser `xml:"AssumedRoleUser"`
		} `xml:"AssumeRoleWithWebIdentityResult"`
		Meta stsMeta `xml:"ResponseMetadata"`
	}{Xmlns: stsNS, Result: struct {
		Credentials stsCreds    `xml:"Credentials"`
		Subject     string      `xml:"SubjectFromWebIdentityToken"`
		Audience    string      `xml:"Audience"`
		Provider    string      `xml:"Provider"`
		User        assumedUser `xml:"AssumedRoleUser"`
	}{credsOf(e), claims.Subject(), aud, "openid", assumedUser{"arn:minio:sts:::assumed-role/" + claims.Subject() + "/" + e.AccessKey, e.AccessKey}},
		Meta: stsMeta{id}}, nil
}

func (s *Server) stsLDAP(ctx context.Context, form url.Values, id string) (any, *stsError) {
	cl, _, err := s.ldapClient(ctx)
	if err != nil {
		s.log.Error("ldap configuration is invalid", "err", err)
		return nil, &stsError{http.StatusInternalServerError, "InternalFailure", "the LDAP provider is misconfigured"}
	}
	if cl == nil {
		return nil, &stsError{http.StatusBadRequest, "InvalidParameterValue", "LDAP identity is not configured on this server"}
	}
	user, pass := form.Get("LDAPUsername"), form.Get("LDAPPassword")
	if !s.logins.allow(user) {
		return nil, &stsError{http.StatusTooManyRequests, "Throttling", "too many failed sign-in attempts for this user; try again later"}
	}
	actx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	u, err := cl.Authenticate(actx, user, pass)
	switch {
	case errors.Is(err, ldap.ErrInvalidCredentials):
		s.logins.fail(user)
		return nil, &stsError{http.StatusForbidden, "AccessDenied", "invalid LDAP credentials"}
	case err != nil:
		s.log.Warn("ldap sign-in failed", "user", user, "err", err)
		return nil, &stsError{http.StatusServiceUnavailable, "ServiceUnavailable", "the directory could not be reached"}
	}
	s.logins.reset(user)
	pols, err := s.ldapPolicies(ctx, u)
	if err != nil {
		return nil, &stsError{http.StatusInternalServerError, "InternalFailure", "could not resolve policies"}
	}
	if len(pols) == 0 {
		return nil, &stsError{http.StatusForbidden, "AccessDenied", "no policy is attached to this user or their groups"}
	}
	life, serr := duration(form, stsDefDur, stsMaxDur)
	if serr != nil {
		return nil, serr
	}
	sp, serr := sessionPolicy(form)
	if serr != nil {
		return nil, serr
	}
	e, serr := s.issue(ctx, iam.UserEntry{Policies: pols, SessionPolicy: sp, Provider: "ldap", ProviderUser: u.DN, Name: user}, life)
	if serr != nil {
		return nil, serr
	}
	return struct {
		XMLName xml.Name `xml:"AssumeRoleWithLDAPIdentityResponse"`
		Xmlns   string   `xml:"xmlns,attr"`
		Result  struct {
			Credentials stsCreds    `xml:"Credentials"`
			User        assumedUser `xml:"AssumedRoleUser"`
		} `xml:"AssumeRoleWithLDAPIdentityResult"`
		Meta stsMeta `xml:"ResponseMetadata"`
	}{Xmlns: stsNS, Result: struct {
		Credentials stsCreds    `xml:"Credentials"`
		User        assumedUser `xml:"AssumedRoleUser"`
	}{credsOf(e), assumedUser{"arn:minio:sts:::assumed-role/" + u.DN + "/" + e.AccessKey, e.AccessKey}}, Meta: stsMeta{id}}, nil
}

// loginLimiter slows password guessing through the STS endpoint: after
// loginMaxFails failures for one login name within loginWindow, further
// attempts for that name are refused until the window passes. It is
// per node and in memory; the directory's own lockout policy still applies.
// (A name that does not exist counts like any other, so the limiter does
// not reveal which accounts exist.)
type loginLimiter struct {
	mu sync.Mutex
	m  map[string]*loginState
}

type loginState struct {
	fails int
	first time.Time
}

const (
	loginMaxFails  = 10
	loginWindow    = time.Minute
	loginMaxTracks = 10000
)

func (l *loginLimiter) allow(name string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	st := l.m[strings.ToLower(name)]
	if st == nil {
		return true
	}
	if time.Since(st.first) > loginWindow {
		delete(l.m, strings.ToLower(name))
		return true
	}
	return st.fails < loginMaxFails
}

func (l *loginLimiter) fail(name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.m == nil || len(l.m) >= loginMaxTracks {
		l.m = map[string]*loginState{}
	}
	k := strings.ToLower(name)
	st := l.m[k]
	if st == nil || time.Since(st.first) > loginWindow {
		st = &loginState{first: time.Now()}
		l.m[k] = st
	}
	st.fails++
}

func (l *loginLimiter) reset(name string) {
	l.mu.Lock()
	delete(l.m, strings.ToLower(name))
	l.mu.Unlock()
}
