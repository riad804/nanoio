package postgresql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"nanoio/internal/event"
)

// startPostgres runs a throwaway real PostgreSQL server (initdb + pg_ctl),
// or skips when the binaries are not installed.
func startPostgres(t *testing.T) string {
	t.Helper()
	initdb, err1 := exec.LookPath("initdb")
	pgctl, err2 := exec.LookPath("pg_ctl")
	if err1 != nil || err2 != nil {
		t.Skip("initdb/pg_ctl are not installed")
	}
	if os.Geteuid() == 0 {
		t.Skip("PostgreSQL refuses to run as root")
	}
	dir := t.TempDir()
	data := filepath.Join(dir, "data")
	if out, err := exec.Command(initdb, "-D", data, "-A", "trust", "-U", "nanoio", "-E", "UTF8").CombinedOutput(); err != nil {
		t.Fatalf("initdb: %v\n%s", err, out)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	sock, err := os.MkdirTemp("", "pgsock")
	if err != nil {
		t.Fatal(err)
	}
	opts := fmt.Sprintf("-p %d -k %s -c listen_addresses=127.0.0.1 -c fsync=off", port, sock)
	if out, err := exec.Command(pgctl, "-D", data, "-o", opts, "-l", filepath.Join(dir, "log"), "-w", "-t", "60", "start").CombinedOutput(); err != nil {
		logs, _ := os.ReadFile(filepath.Join(dir, "log"))
		t.Fatalf("pg_ctl start: %v\n%s\n%s", err, out, logs)
	}
	t.Cleanup(func() {
		exec.Command(pgctl, "-D", data, "-m", "immediate", "stop").Run()
		os.RemoveAll(sock)
	})
	return fmt.Sprintf("postgres://nanoio@127.0.0.1:%d/postgres?sslmode=disable", port)
}

func ev(name, key string) *event.Event {
	return &event.Event{Name: name, Bucket: "b", Key: key, Time: time.Now().UTC(), Size: 4, ETag: "etag"}
}

func TestAgainstRealPostgreSQL(t *testing.T) {
	dsn := startPostgres(t)
	check, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	ctx := context.Background()

	ns, err := Factory("pg", json.RawMessage(`{"connectionString":"`+dsn+`","table":"bucket_state"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer ns.Target.Close()
	if err := ns.Target.(event.Checker).Check(ctx); err != nil {
		t.Fatal(err)
	}
	send := func(s event.Spec, evs ...*event.Event) {
		t.Helper()
		if err := s.Target.Send(ctx, evs); err != nil {
			t.Fatal(err)
		}
	}
	send(ns, ev(event.ObjectCreatedPut, "a"), ev(event.ObjectCreatedPut, "c"), ev(event.ObjectCreatedPut, "d"))
	send(ns, ev(event.ObjectCreatedCopy, "a"), ev(event.ObjectRemovedDelete, "c"), ev(event.ObjectAccessedGet, "d"))
	send(ns, ev(event.ObjectCreatedPut, "a")) // upsert of an existing key

	rows, err := check.Query("SELECT key, value->'Records'->0->>'eventName' FROM bucket_state ORDER BY key")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var k, n string
		if err := rows.Scan(&k, &n); err != nil {
			t.Fatal(err)
		}
		got = append(got, k+"="+n)
	}
	rows.Close()
	if strings.Join(got, ",") != "b/a=s3:ObjectCreated:Put,b/d=s3:ObjectCreated:Put" {
		t.Fatalf("namespace table = %v", got)
	}

	ac, err := Factory("pg2", json.RawMessage(`{"connectionString":"`+dsn+`","table":"bucket_log","format":"access"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer ac.Target.Close()
	send(ac, ev(event.ObjectCreatedPut, "a"), ev(event.ObjectAccessedGet, "a"), ev(event.ObjectRemovedDelete, "a"))
	var n int
	var firstName string
	if err := check.QueryRow("SELECT count(*) FROM bucket_log").Scan(&n); err != nil || n != 3 {
		t.Fatalf("access rows = %d (%v), want 3", n, err)
	}
	if err := check.QueryRow("SELECT event_data->'Event'->0->>'eventName' FROM bucket_log ORDER BY event_time, ctid LIMIT 1").Scan(&firstName); err != nil || firstName != "s3:ObjectCreated:Put" {
		t.Errorf("first access row = %q (%v)", firstName, err)
	}

	// A failing statement rolls the whole batch back.
	if _, err := check.Exec("ALTER TABLE bucket_log ADD CONSTRAINT only_puts CHECK (event_data->'Event'->0->>'eventName' = 's3:ObjectCreated:Put') NOT VALID"); err != nil {
		t.Fatal(err)
	}
	before := n
	if err := ac.Target.Send(ctx, []*event.Event{ev(event.ObjectCreatedPut, "z"), ev(event.ObjectRemovedDelete, "z")}); err == nil {
		t.Fatal("constraint violation was not reported")
	}
	check.QueryRow("SELECT count(*) FROM bucket_log").Scan(&n)
	if n != before {
		t.Errorf("rows = %d after a failed batch, want %d (rolled back)", n, before)
	}
}

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no connection": `{"table":"t"}`, "garbage": `{"connectionString":"postgres://%zz","table":"t"}`,
		"no table": `{"connectionString":"postgres://h/db"}`, "bad table": `{"connectionString":"postgres://h/db","table":"a.b"}`,
		"bad format": `{"connectionString":"postgres://h/db","table":"t","format":"x"}`,
	} {
		if _, err := Factory("p", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	// A password in a bad connection string must not be echoed back.
	_, err := Factory("p", json.RawMessage(`{"connectionString":"postgres://u:hunter2@h:notaport/db","table":"t"}`))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("err = %v; it must be refused without echoing the password", err)
	}
}
