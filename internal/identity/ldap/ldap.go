// Package ldap authenticates users against an LDAP directory and resolves
// their groups, using github.com/go-ldap/ldap/v3.
//
// Authentication is search-then-bind: a service account (the "lookup bind")
// finds the user's DN with a configured filter, then the user's own
// password is verified by binding as that DN. An empty password is refused
// before any bind, because LDAP treats a bind with a DN and an empty
// password as an anonymous bind that succeeds.
package ldap

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	goldap "github.com/go-ldap/ldap/v3"
)

// Errors a caller may test with errors.Is.
var (
	ErrInvalidCredentials = errors.New("ldap: invalid credentials")
	ErrUserNotFound       = errors.New("ldap: user not found")
	ErrAmbiguousUser      = errors.New("ldap: the user filter matched more than one entry")
)

// Config describes the directory and how to search it.
type Config struct {
	// ServerAddr is host:port, or a ldap:// or ldaps:// URL.
	ServerAddr string
	// TLS options: Insecure uses plain LDAP without StartTLS (never over an
	// untrusted network); StartTLS upgrades a plain connection; SkipVerify
	// disables certificate verification; CAFile adds trusted roots.
	Insecure   bool
	StartTLS   bool
	SkipVerify bool
	CAFile     string

	LookupBindDN       string
	LookupBindPassword string

	// UserBaseDN and UserFilter locate a user by login name; %s in the
	// filter is replaced by the escaped name.
	UserBaseDN string
	UserFilter string
	// GroupBaseDN and GroupFilter find a user's groups; %s is the login
	// name and %d the user's DN (both escaped). Optional.
	GroupBaseDN string
	GroupFilter string

	Timeout time.Duration
}

// User is a directory user as the server needs it.
type User struct {
	DN       string
	Username string
	Groups   []string // group DNs
}

// Client talks to one directory. It opens a connection per operation.
type Client struct {
	cfg  Config
	tlsc *tls.Config
	addr string
	tls  bool // ldaps
}

// New validates the configuration.
func New(cfg Config) (*Client, error) {
	if cfg.ServerAddr == "" {
		return nil, errors.New("ldap: server_addr is required")
	}
	if cfg.UserBaseDN == "" || !strings.Contains(cfg.UserFilter, "%s") {
		return nil, errors.New("ldap: user_dn_search_base_dn and a user_dn_search_filter containing %s are required")
	}
	if cfg.LookupBindDN == "" {
		return nil, errors.New("ldap: lookup_bind_dn is required")
	}
	if (cfg.GroupBaseDN == "") != (cfg.GroupFilter == "") {
		return nil, errors.New("ldap: group_search_base_dn and group_search_filter go together")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	c := &Client{cfg: cfg}
	addr := cfg.ServerAddr
	if strings.Contains(addr, "://") {
		u, err := url.Parse(addr)
		if err != nil {
			return nil, err
		}
		c.tls = u.Scheme == "ldaps"
		addr = u.Host
		if u.Port() == "" {
			if c.tls {
				addr = net.JoinHostPort(u.Hostname(), "636")
			} else {
				addr = net.JoinHostPort(u.Hostname(), "389")
			}
		}
	} else if _, _, err := net.SplitHostPort(addr); err != nil {
		return nil, fmt.Errorf("ldap: server_addr %q must be host:port", cfg.ServerAddr)
	}
	c.addr = addr
	host, _, _ := net.SplitHostPort(addr)
	c.tlsc = &tls.Config{ServerName: host, InsecureSkipVerify: cfg.SkipVerify, MinVersion: tls.VersionTLS12}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("ldap: no certificates in tls_ca")
		}
		c.tlsc.RootCAs = pool
	}
	if !c.tls && !cfg.StartTLS && !cfg.Insecure {
		return nil, errors.New("ldap: a plain ldap:// connection needs server_starttls=on or server_insecure=on")
	}
	return c, nil
}

func (c *Client) dial(ctx context.Context) (*goldap.Conn, error) {
	d := &net.Dialer{Timeout: c.cfg.Timeout}
	nc, err := d.DialContext(ctx, "tcp", c.addr)
	if err != nil {
		return nil, err
	}
	var conn *goldap.Conn
	if c.tls {
		conn = goldap.NewConn(tls.Client(nc, c.tlsc), true)
	} else {
		conn = goldap.NewConn(nc, false)
	}
	conn.SetTimeout(c.cfg.Timeout)
	conn.Start()
	if !c.tls && c.cfg.StartTLS {
		if err := conn.StartTLS(c.tlsc); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

func (c *Client) serviceConn(ctx context.Context) (*goldap.Conn, error) {
	conn, err := c.dial(ctx)
	if err != nil {
		return nil, err
	}
	if err := conn.Bind(c.cfg.LookupBindDN, c.cfg.LookupBindPassword); err != nil {
		conn.Close()
		return nil, fmt.Errorf("ldap: lookup bind: %w", err)
	}
	return conn, nil
}

// findUser locates exactly one entry for a login name.
func (c *Client) findUser(conn *goldap.Conn, username string) (string, error) {
	filter := strings.ReplaceAll(c.cfg.UserFilter, "%s", goldap.EscapeFilter(username))
	res, err := conn.Search(goldap.NewSearchRequest(c.cfg.UserBaseDN, goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases, 2, int(c.cfg.Timeout/time.Second), false, filter, []string{"dn"}, nil))
	if err != nil {
		return "", err
	}
	switch len(res.Entries) {
	case 0:
		return "", ErrUserNotFound
	case 1:
		return res.Entries[0].DN, nil
	}
	return "", ErrAmbiguousUser
}

func (c *Client) groups(conn *goldap.Conn, username, dn string) ([]string, error) {
	if c.cfg.GroupFilter == "" {
		return nil, nil
	}
	f := strings.ReplaceAll(c.cfg.GroupFilter, "%s", goldap.EscapeFilter(username))
	f = strings.ReplaceAll(f, "%d", goldap.EscapeFilter(dn))
	res, err := conn.Search(goldap.NewSearchRequest(c.cfg.GroupBaseDN, goldap.ScopeWholeSubtree,
		goldap.NeverDerefAliases, 0, int(c.cfg.Timeout/time.Second), false, f, []string{"dn"}, nil))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, e.DN)
	}
	return out, nil
}

// Authenticate verifies a login name and password.
func (c *Client) Authenticate(ctx context.Context, username, password string) (User, error) {
	if username == "" || password == "" {
		return User{}, ErrInvalidCredentials
	}
	svc, err := c.serviceConn(ctx)
	if err != nil {
		return User{}, err
	}
	defer svc.Close()
	dn, err := c.findUser(svc, username)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			// Indistinguishable from a wrong password.
			return User{}, ErrInvalidCredentials
		}
		return User{}, err
	}
	// Verify the password on a separate connection, so the service
	// connection keeps its identity for the group search.
	uc, err := c.dial(ctx)
	if err != nil {
		return User{}, err
	}
	defer uc.Close()
	if err := uc.Bind(dn, password); err != nil {
		var le *goldap.Error
		if errors.As(err, &le) && le.ResultCode == goldap.LDAPResultInvalidCredentials {
			return User{}, ErrInvalidCredentials
		}
		return User{}, err
	}
	groups, err := c.groups(svc, username, dn)
	if err != nil {
		return User{}, err
	}
	return User{DN: dn, Username: username, Groups: groups}, nil
}

// Lookup re-resolves a user known by DN without its password: used to
// revalidate a credential that was issued earlier. ErrUserNotFound means
// the account is gone from the directory (or no longer matches the user
// filter) and the credential must stop working.
func (c *Client) Lookup(ctx context.Context, dn string) (User, error) {
	svc, err := c.serviceConn(ctx)
	if err != nil {
		return User{}, err
	}
	defer svc.Close()
	// Re-run the user search constrained to this DN so that the same
	// filter decides whether the account is still a valid login.
	res, err := svc.Search(goldap.NewSearchRequest(dn, goldap.ScopeBaseObject, goldap.NeverDerefAliases, 1,
		int(c.cfg.Timeout/time.Second), false, "(objectClass=*)", []string{"dn", "uid", "cn", "sAMAccountName"}, nil))
	if err != nil {
		var le *goldap.Error
		if errors.As(err, &le) && le.ResultCode == goldap.LDAPResultNoSuchObject {
			return User{}, ErrUserNotFound
		}
		return User{}, err
	}
	if len(res.Entries) != 1 {
		return User{}, ErrUserNotFound
	}
	e := res.Entries[0]
	username := firstNonEmpty(e.GetAttributeValue("uid"), e.GetAttributeValue("sAMAccountName"), e.GetAttributeValue("cn"))
	// Confirm the entry is still selected by the user filter below the
	// user base (a moved or reclassified entry is no longer a login).
	if username != "" {
		found, err := c.findUser(svc, username)
		if err != nil || !strings.EqualFold(found, dn) {
			return User{}, ErrUserNotFound
		}
	}
	groups, err := c.groups(svc, username, dn)
	if err != nil {
		return User{}, err
	}
	return User{DN: e.DN, Username: username, Groups: groups}, nil
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

// Check proves the lookup bind works.
func (c *Client) Check(ctx context.Context) error {
	conn, err := c.serviceConn(ctx)
	if err != nil {
		return err
	}
	return conn.Close()
}

// NormalizeDN returns a canonical form of a DN for comparison: attribute
// types and values lower-cased, no insignificant whitespace.
func NormalizeDN(dn string) (string, error) {
	d, err := goldap.ParseDN(dn)
	if err != nil {
		return "", err
	}
	var parts []string
	for _, rdn := range d.RDNs {
		var attrs []string
		for _, a := range rdn.Attributes {
			attrs = append(attrs, strings.ToLower(a.Type)+"="+strings.ToLower(strings.TrimSpace(a.Value)))
		}
		parts = append(parts, strings.Join(attrs, "+"))
	}
	return strings.Join(parts, ","), nil
}
