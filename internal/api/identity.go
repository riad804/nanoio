package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"nanoio/internal/auth"
	"nanoio/internal/event"
	"nanoio/internal/iam"
	"nanoio/internal/identity/ldap"
	"nanoio/internal/identity/oidc"
)

// Identity federation: LDAP and OpenID Connect sign-in, exchanged for
// temporary credentials by the STS endpoint (sts.go).
//
// Temporary credentials are one document each under stsPrefix in the system
// bucket. Every node resolves them lazily (iam.Store.SetResolver) and caches
// the answer for a TTL. That TTL is the bound on how long a credential
// revoked elsewhere - or whose LDAP account was removed - keeps working on a
// node that has it cached; for LDAP it is the identity_ldap cache_ttl.

const (
	stsPrefix    = "_sts/"
	ldapMapDoc   = "_idp/ldap-policies.json"
	defaultTTL   = 60 * time.Second // LDAP revalidation interval
	oidcCacheTTL = 15 * time.Second // how long a node trusts a resolved OIDC credential
	stsMinDur    = 15 * time.Minute
	stsMaxDur    = 12 * time.Hour
	stsDefDur    = time.Hour
)

func init() {
	registerConfigSub(&cfgSub{Name: "identity_ldap", Desc: "enable LDAP SSO support",
		Keys: []cfgKey{
			{Name: "server_addr", Desc: "AD/LDAP server address, host:port or ldap(s)://host:port", Type: "address"},
			{Name: "server_insecure", Desc: "allow plain LDAP without StartTLS (on|off)", Type: "on|off", Optional: true},
			{Name: "server_starttls", Desc: "use StartTLS on a plain connection (on|off)", Type: "on|off", Optional: true},
			{Name: "tls_skip_verify", Desc: "trust any server certificate (on|off)", Type: "on|off", Optional: true},
			{Name: "tls_ca", Desc: "PEM file of CA certificates that verify the server", Type: "path", Optional: true},
			{Name: "lookup_bind_dn", Desc: "DN of the service account that searches the directory", Type: "string"},
			{Name: "lookup_bind_password", Desc: "password of the lookup account", Type: "string", Secret: true},
			{Name: "user_dn_search_base_dn", Desc: "base DN of the user search", Type: "string"},
			{Name: "user_dn_search_filter", Desc: "user search filter, %s is the login name", Type: "string"},
			{Name: "group_search_base_dn", Desc: "base DN of the group search", Type: "string", Optional: true},
			{Name: "group_search_filter", Desc: "group search filter, %s is the login name, %d the user DN", Type: "string", Optional: true},
			{Name: "cache_ttl", Desc: "how long a directory lookup is trusted, e.g. 1m: an account removed from the directory keeps access up to this long", Type: "duration", Optional: true},
		}, Validate: validateLDAP})
	registerConfigSub(&cfgSub{Name: "identity_openid", Desc: "enable OpenID SSO support",
		Keys: []cfgKey{
			{Name: "config_url", Desc: "OpenID discovery document URL", Type: "url"},
			{Name: "client_id", Desc: "client ID the ID token must be issued for", Type: "string"},
			{Name: "client_secret", Desc: "client secret (kept for clients that need it)", Type: "string", Optional: true, Secret: true},
			{Name: "claim_name", Desc: "claim holding the policy name(s); default policy", Type: "string", Optional: true},
			{Name: "role_policy", Desc: "policy granted when the token carries no policy claim", Type: "string", Optional: true},
		}, Validate: validateOIDC})
}

func onOff(v string) (bool, error) {
	switch strings.ToLower(v) {
	case "", "off", "false", "0":
		return false, nil
	case "on", "true", "1":
		return true, nil
	}
	return false, fmt.Errorf("%q must be on or off", v)
}

func validateLDAP(kv map[string]string) error {
	_, err := ldapConfig(kv)
	return err
}

func ldapConfig(kv map[string]string) (ldap.Config, error) {
	var c ldap.Config
	var err error
	c.ServerAddr = kv["server_addr"]
	if c.Insecure, err = onOff(kv["server_insecure"]); err != nil {
		return c, fmt.Errorf("server_insecure: %w", err)
	}
	if c.StartTLS, err = onOff(kv["server_starttls"]); err != nil {
		return c, fmt.Errorf("server_starttls: %w", err)
	}
	if c.SkipVerify, err = onOff(kv["tls_skip_verify"]); err != nil {
		return c, fmt.Errorf("tls_skip_verify: %w", err)
	}
	c.CAFile = kv["tls_ca"]
	c.LookupBindDN, c.LookupBindPassword = kv["lookup_bind_dn"], kv["lookup_bind_password"]
	c.UserBaseDN, c.UserFilter = kv["user_dn_search_base_dn"], kv["user_dn_search_filter"]
	c.GroupBaseDN, c.GroupFilter = kv["group_search_base_dn"], kv["group_search_filter"]
	if v := kv["cache_ttl"]; v != "" {
		if _, err := parseTTL(v); err != nil {
			return c, err
		}
	}
	// New validates the rest (and does not connect).
	if _, err := ldap.New(c); err != nil {
		return c, err
	}
	return c, nil
}

func parseTTL(v string) (time.Duration, error) {
	d, err := time.ParseDuration(v)
	if err != nil {
		return 0, fmt.Errorf("cache_ttl: %w", err)
	}
	if d < time.Second || d > 24*time.Hour {
		return 0, errors.New("cache_ttl must be between 1s and 24h")
	}
	return d, nil
}

func validateOIDC(kv map[string]string) error {
	if kv["config_url"] == "" || kv["client_id"] == "" {
		return errors.New("config_url and client_id are required")
	}
	_, err := oidc.New(oidc.Config{ConfigURL: kv["config_url"], ClientID: kv["client_id"]})
	return err
}

// oidcMinRefresh is the shortest interval between key-set fetches (zero
// means the package default); tests shorten it.
var oidcMinRefresh time.Duration

// ----- providers -------------------------------------------------------------------------------

type idpState struct {
	mu sync.Mutex
	// The active LDAP and OIDC providers, rebuilt when their configuration
	// changes (compared by fingerprint).
	ldapFP  string
	ldap    *ldap.Client
	ldapTTL time.Duration
	oidcFP  string
	oidc    *oidc.Provider
	oidcKV  map[string]string
}

func fingerprint(kv map[string]string) string {
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k + "\x00" + kv[k] + "\x01")
	}
	return b.String()
}

// ldapClient returns the configured LDAP client, nil when none is.
func (s *Server) ldapClient(ctx context.Context) (*ldap.Client, time.Duration, error) {
	kv := s.cfg().Target(ctx, "identity_ldap", "")
	st := &s.idp
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(kv) == 0 {
		st.ldap, st.ldapFP = nil, ""
		return nil, 0, nil
	}
	if fp := fingerprint(kv); fp != st.ldapFP || st.ldap == nil {
		c, err := ldapConfig(kv)
		if err != nil {
			return nil, 0, err
		}
		cl, err := ldap.New(c)
		if err != nil {
			return nil, 0, err
		}
		ttl := defaultTTL
		if v := kv["cache_ttl"]; v != "" {
			ttl, _ = parseTTL(v)
		}
		st.ldap, st.ldapFP, st.ldapTTL = cl, fp, ttl
	}
	return st.ldap, st.ldapTTL, nil
}

func (s *Server) oidcProvider(ctx context.Context) (*oidc.Provider, map[string]string, error) {
	kv := s.cfg().Target(ctx, "identity_openid", "")
	st := &s.idp
	st.mu.Lock()
	defer st.mu.Unlock()
	if len(kv) == 0 {
		st.oidc, st.oidcFP, st.oidcKV = nil, "", nil
		return nil, nil, nil
	}
	if fp := fingerprint(kv); fp != st.oidcFP || st.oidc == nil {
		p, err := oidc.New(oidc.Config{ConfigURL: kv["config_url"], ClientID: kv["client_id"], MinRefresh: oidcMinRefresh})
		if err != nil {
			return nil, nil, err
		}
		st.oidc, st.oidcFP, st.oidcKV = p, fp, kv
	}
	return st.oidc, st.oidcKV, nil
}

// ----- LDAP policy mappings ----------------------------------------------------------------------

type ldapMap struct {
	Users  map[string][]string `json:"users"`  // normalised DN -> policies
	Groups map[string][]string `json:"groups"` // normalised DN -> policies
}

func (s *Server) readLDAPMap(ctx context.Context) (*ldapMap, error) {
	es := &eventStore{st: s.st}
	b, err := es.Get(ctx, ldapMapDoc)
	m := &ldapMap{Users: map[string][]string{}, Groups: map[string][]string{}}
	if errors.Is(err, event.ErrSharedNotFound) {
		return m, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, m); err != nil {
		return nil, err
	}
	if m.Users == nil {
		m.Users = map[string][]string{}
	}
	if m.Groups == nil {
		m.Groups = map[string][]string{}
	}
	return m, nil
}

func (s *Server) writeLDAPMap(ctx context.Context, m *ldapMap) error {
	b, _ := json.Marshal(m)
	return (&eventStore{st: s.st}).Put(ctx, ldapMapDoc, b)
}

// ldapPolicies resolves the policies of a directory user: those attached to
// the user's DN plus those of each of their groups, existing ones only.
func (s *Server) ldapPolicies(ctx context.Context, u ldap.User) ([]string, error) {
	m, err := s.readLDAPMap(ctx)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	add := func(l []string) {
		for _, p := range l {
			set[p] = true
		}
	}
	if n, err := ldap.NormalizeDN(u.DN); err == nil {
		add(m.Users[n])
	}
	for _, g := range u.Groups {
		if n, err := ldap.NormalizeDN(g); err == nil {
			add(m.Groups[n])
		}
	}
	out := make([]string, 0, len(set))
	for p := range set {
		if s.policyExists(p) {
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out, nil
}

func (s *Server) policyExists(name string) bool {
	if s.iam == nil {
		return false
	}
	return s.unknownPolicy([]string{name}) == ""
}

// ----- temporary credential store -------------------------------------------------------------

type stsDoc struct {
	Entry iam.UserEntry `json:"entry"`
	// SessionName is what the caller supplied (display only).
	Created time.Time `json:"created"`
}

func stsName(ak string) string { return stsPrefix + ak + ".json" }

func (s *Server) stsPut(ctx context.Context, e iam.UserEntry) error {
	b, err := json.Marshal(stsDoc{Entry: e, Created: time.Now().UTC()})
	if err != nil {
		return err
	}
	return (&eventStore{st: s.st}).Put(ctx, stsName(e.AccessKey), b)
}

func (s *Server) stsGet(ctx context.Context, ak string) (*stsDoc, error) {
	b, err := (&eventStore{st: s.st}).Get(ctx, stsName(ak))
	if errors.Is(err, event.ErrSharedNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var d stsDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// stsResolve is the iam.Resolver for temporary credentials. For an LDAP
// credential it asks the directory again each time the cached answer
// expires, so a removed or re-grouped user is noticed within the TTL.
func (s *Server) stsResolve(ak string) (iam.UserEntry, time.Duration, bool) {
	if len(ak) != 20 || strings.ToUpper(ak) != ak {
		return iam.UserEntry{}, 0, false // not shaped like an issued key: skip the storage read
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	d, err := s.stsGet(ctx, ak)
	if err != nil {
		// Storage trouble: do not cache for long, and deny meanwhile.
		return iam.UserEntry{}, time.Second, false
	}
	if d == nil {
		return iam.UserEntry{}, 0, false
	}
	e := d.Entry
	if !e.Expiry.IsZero() && !time.Now().Before(e.Expiry) {
		return iam.UserEntry{}, 0, false
	}
	switch e.Provider {
	case "ldap":
		cl, ttl, err := s.ldapClient(ctx)
		if err != nil || cl == nil {
			// LDAP was unconfigured or is broken: fail closed.
			return iam.UserEntry{}, time.Second, false
		}
		u, err := cl.Lookup(ctx, e.ProviderUser)
		if err != nil {
			if errors.Is(err, ldap.ErrUserNotFound) {
				(&eventStore{st: s.st}).Delete(ctx, stsName(ak))
				return iam.UserEntry{}, 0, false
			}
			s.log.Warn("ldap revalidation failed; denying the credential for now", "user", e.ProviderUser, "err", err)
			return iam.UserEntry{}, time.Second, false
		}
		pol, err := s.ldapPolicies(ctx, u)
		if err != nil {
			return iam.UserEntry{}, time.Second, false
		}
		e.Policies = pol
		return e, ttl, true
	default:
		return e, oidcCacheTTL, true
	}
}

// sessionOK enforces the session token of a temporary credential. A
// credential that carries a token must present exactly it, in the header or
// (presigned) the query; a long-lived one must not be sent with a token.
func (s *Server) sessionOK(r *http.Request, accessKey string) error {
	if s.iam == nil || accessKey == "" {
		return nil
	}
	want, ok := s.iam.Token(accessKey)
	if !ok {
		return nil // unknown to the store: authorisation will deny it
	}
	got := r.Header.Get("X-Amz-Security-Token")
	if got == "" {
		got = r.URL.Query().Get("X-Amz-Security-Token")
	}
	if want == "" {
		if got != "" {
			return auth.ErrInvalidToken
		}
		return nil
	}
	if subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
		return auth.ErrInvalidToken
	}
	return nil
}

// stsSweepLoop removes expired temporary credential documents.
func (s *Server) stsSweepLoop(ctx context.Context) {
	defer s.bg.Done()
	t := time.NewTicker(30 * time.Minute)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		es := &eventStore{st: s.st}
		names, err := es.List(ctx, stsPrefix, 100000)
		if err != nil {
			continue
		}
		for _, n := range names {
			ak := strings.TrimSuffix(strings.TrimPrefix(n, stsPrefix), ".json")
			d, err := s.stsGet(ctx, ak)
			if err != nil || d == nil {
				continue
			}
			if !d.Entry.Expiry.IsZero() && time.Since(d.Entry.Expiry) > time.Hour {
				es.Delete(ctx, n)
			}
		}
	}
}
