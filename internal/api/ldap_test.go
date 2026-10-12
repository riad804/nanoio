package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	goldap "github.com/go-ldap/ldap/v3"

	"nanoio/internal/madmincrypt"
)

// startOpenLDAP runs an OpenLDAP container and returns its host:port and
// the admin connection. The test is skipped when Docker is not available
// (or NANOIO_TEST_LDAP=off).
func startOpenLDAP(t *testing.T) (string, *goldap.Conn) {
	t.Helper()
	if strings.EqualFold(os.Getenv("NANOIO_TEST_LDAP"), "off") {
		t.Skip("NANOIO_TEST_LDAP=off")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker is not available")
	}
	if err := exec.Command("docker", "image", "inspect", "osixia/openldap:1.5.0").Run(); err != nil {
		t.Skip("image osixia/openldap:1.5.0 is not present (docker pull it to run this test)")
	}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	name := fmt.Sprintf("nanoio-ldap-%d", time.Now().UnixNano())
	out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:389", port),
		"-e", "LDAP_ORGANISATION=Example", "-e", "LDAP_DOMAIN=example.org", "-e", "LDAP_ADMIN_PASSWORD=adminpass",
		"-e", "LDAP_TLS=false", "osixia/openldap:1.5.0").CombinedOutput()
	if err != nil {
		t.Skipf("cannot start the OpenLDAP container: %v: %s", err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	var conn *goldap.Conn
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		c, err := goldap.Dial("tcp", addr)
		if err == nil {
			if err = c.Bind("cn=admin,dc=example,dc=org", "adminpass"); err == nil {
				conn = c
				break
			}
			c.Close()
		}
		time.Sleep(time.Second)
	}
	if conn == nil {
		t.Fatal("OpenLDAP did not become ready")
	}
	t.Cleanup(func() { conn.Close() })
	return addr, conn
}

func ldapAdd(t *testing.T, c *goldap.Conn, dn string, attrs map[string][]string) {
	t.Helper()
	r := goldap.NewAddRequest(dn, nil)
	for k, v := range attrs {
		r.Attribute(k, v)
	}
	if err := c.Add(r); err != nil {
		t.Fatalf("add %s: %v", dn, err)
	}
}

const ldapBase = "dc=example,dc=org"

func TestSTSLDAPAgainstOpenLDAP(t *testing.T) {
	addr, dir := startOpenLDAP(t)
	ldapAdd(t, dir, "ou=people,"+ldapBase, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"people"}})
	ldapAdd(t, dir, "ou=groups,"+ldapBase, map[string][]string{"objectClass": {"organizationalUnit"}, "ou": {"groups"}})
	person := func(uid, pw string) string {
		dn := "uid=" + uid + ",ou=people," + ldapBase
		ldapAdd(t, dir, dn, map[string][]string{"objectClass": {"inetOrgPerson"}, "uid": {uid}, "cn": {uid}, "sn": {uid},
			"userPassword": {pw}})
		return dn
	}
	alice := person("alice", "alice-pass")
	bob := person("bob", "bob-pass")
	person("carol", "carol-pass")
	ldapAdd(t, dir, "cn=readers,ou=groups,"+ldapBase, map[string][]string{"objectClass": {"groupOfNames"}, "cn": {"readers"},
		"member": {alice, bob}})
	readersDN := "cn=readers,ou=groups," + ldapBase

	const ttl = 2 * time.Second
	e := fedServe(t)
	e.mb("ldapbkt")
	e.put("/ldapbkt/doc.txt", "document", nil)
	e.setConfig("identity_ldap server_addr=" + addr + " server_insecure=on lookup_bind_dn=cn=admin," + ldapBase +
		" lookup_bind_password=adminpass user_dn_search_base_dn=ou=people," + ldapBase + " user_dn_search_filter=(uid=%s)" +
		" group_search_base_dn=ou=groups," + ldapBase + " group_search_filter=(&(objectClass=groupOfNames)(member=%d))" +
		" cache_ttl=" + ttl.String())

	// The lookup password is a secret: it must not come back in reads.
	resp, enc := e.madminDo("GET", "get-config-kv", url.Values{"key": {"identity_ldap"}}, nil)
	plain, err := madmincrypt.Decrypt(rootSK, bytes.NewReader(enc))
	if resp.StatusCode != 200 || err != nil {
		t.Fatalf("get-config-kv: %d %v", resp.StatusCode, err)
	}
	if strings.Contains(string(plain), "adminpass") || !strings.Contains(string(plain), "server_addr="+addr) {
		t.Errorf("config read-back leaks the lookup password or lost settings: %s", plain)
	}

	attach := func(group string, policies ...string) {
		body, _ := json.Marshal(map[string]any{"policies": policies, "group": group})
		resp, rb := e.madminDo("POST", "idp/ldap/policy/attach", nil, body)
		if resp.StatusCode != 200 {
			t.Fatalf("attach: %d %s", resp.StatusCode, rb)
		}
	}
	login := func(user, pass string) (*stsCredsOut, int, string) {
		resp, rb := e.sts(nil, url.Values{"Action": {"AssumeRoleWithLDAPIdentity"}, "Version": {"2011-06-15"},
			"LDAPUsername": {user}, "LDAPPassword": {pass}})
		if resp.StatusCode != 200 {
			return nil, resp.StatusCode, string(rb)
		}
		c := parseCreds(t, rb)
		return &c, 200, ""
	}

	// Without a mapping nobody gets anything.
	if _, st, _ := login("alice", "alice-pass"); st != 403 {
		t.Fatalf("login with no policy mapping: %d", st)
	}
	attach(readersDN, "readonly")

	t.Run("bind, group mapping, and refusal of bad logins", func(t *testing.T) {
		c, st, msg := login("alice", "alice-pass")
		if c == nil {
			t.Fatalf("alice: %d %s", st, msg)
		}
		if st := e.asTemp(*c, true, "GET", "/ldapbkt/doc.txt", ""); st != 200 {
			t.Errorf("alice reads: %d", st)
		}
		if st := e.asTemp(*c, true, "PUT", "/ldapbkt/x.txt", "x"); st != 403 {
			t.Errorf("alice writes: %d", st)
		}
		for name, tc := range map[string][2]string{
			"wrong password":   {"alice", "nope"},
			"empty password":   {"alice", ""},
			"unknown user":     {"mallory", "x"},
			"injection":        {"*)(uid=*", "x"},
			"user in no group": {"carol", "carol-pass"},
		} {
			if _, st, _ := login(tc[0], tc[1]); st != 403 {
				t.Errorf("%s: status %d, want 403", name, st)
			}
		}
	})

	t.Run("a user attached directly by DN", func(t *testing.T) {
		body, _ := json.Marshal(map[string]any{"policies": []string{"readwrite"}, "user": "uid=carol,ou=people," + ldapBase})
		if resp, rb := e.madminDo("POST", "idp/ldap/policy/attach", nil, body); resp.StatusCode != 200 {
			t.Fatalf("attach user: %d %s", resp.StatusCode, rb)
		}
		c, st, msg := login("carol", "carol-pass")
		if c == nil {
			t.Fatalf("carol: %d %s", st, msg)
		}
		if st := e.asTemp(*c, true, "PUT", "/ldapbkt/carol.txt", "x"); st != 200 {
			t.Errorf("carol writes: %d", st)
		}
	})

	t.Run("a removed user loses access within the cache TTL", func(t *testing.T) {
		c, st, msg := login("bob", "bob-pass")
		if c == nil {
			t.Fatalf("bob: %d %s", st, msg)
		}
		if st := e.asTemp(*c, true, "GET", "/ldapbkt/doc.txt", ""); st != 200 {
			t.Fatalf("bob reads before removal: %d", st)
		}
		if err := dir.Del(goldap.NewDelRequest(bob, nil)); err != nil {
			t.Fatal(err)
		}
		removed := time.Now()
		var denied time.Duration
		for time.Since(removed) < ttl+5*time.Second {
			if e.asTemp(*c, true, "GET", "/ldapbkt/doc.txt", "") == 403 {
				denied = time.Since(removed)
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if denied == 0 {
			t.Fatalf("bob still had access %s after removal (cache_ttl %s)", time.Since(removed), ttl)
		}
		// Allowed slack: the revalidation interval plus the directory round trip.
		if denied > ttl+3*time.Second {
			t.Errorf("revoked after %s, more than cache_ttl %s allows", denied, ttl)
		}
		t.Logf("removed user denied after %s (cache_ttl %s)", denied.Round(time.Millisecond), ttl)
		// And cannot sign in again.
		if _, st, _ := login("bob", "bob-pass"); st != 403 {
			t.Errorf("removed user logged in: %d", st)
		}
	})

	t.Run("losing a group removes its policy within the TTL", func(t *testing.T) {
		c, st, msg := login("alice", "alice-pass")
		if c == nil {
			t.Fatalf("alice: %d %s", st, msg)
		}
		if st := e.asTemp(*c, true, "GET", "/ldapbkt/doc.txt", ""); st != 200 {
			t.Fatalf("alice reads: %d", st)
		}
		mod := goldap.NewModifyRequest(readersDN, nil)
		mod.Delete("member", []string{alice})
		// groupOfNames requires at least one member: add a placeholder first.
		mod.Add("member", []string{"uid=carol,ou=people," + ldapBase})
		if err := dir.Modify(mod); err != nil {
			t.Fatal(err)
		}
		deadline := time.Now().Add(ttl + 5*time.Second)
		for time.Now().Before(deadline) {
			if e.asTemp(*c, true, "GET", "/ldapbkt/doc.txt", "") == 403 {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatal("alice kept the group's policy after leaving the group")
	})

}
