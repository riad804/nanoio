package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"nanoio/internal/event"
)

func TestConfigValidation(t *testing.T) {
	for name, cfg := range map[string]string{
		"no dsn": `{"table":"t"}`, "bad dsn": `{"dsn":"not a dsn","table":"t"}`,
		"no table": `{"dsn":"u:p@tcp(h:3306)/db"}`, "table with injection": `{"dsn":"u:p@tcp(h:3306)/db","table":"t; DROP"}`,
		"bad format": `{"dsn":"u:p@tcp(h:3306)/db","table":"t","format":"x"}`,
		"unknown":    `{"dsn":"u:p@tcp(h:3306)/db","table":"t","schema":"x"}`,
	} {
		if _, err := Factory("m", json.RawMessage(cfg)); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	spec, err := Factory("m", json.RawMessage(`{"dsn":"u:p@tcp(127.0.0.1:1)/db","table":"events","format":"access"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	if spec.Delivery.BatchSize != 100 {
		t.Errorf("batch default = %d", spec.Delivery.BatchSize)
	}
}

// The statements are the part of this target no fake can vouch for, so they
// are pinned here and are exercised against a real server only by
// TestAgainstRealMySQL, which needs NANOIO_TEST_MYSQL_DSN.
func TestDialectStatements(t *testing.T) {
	for _, s := range []string{Dialect.CreateNamespace, Dialect.CreateAccess, Dialect.Upsert, Dialect.Delete, Dialect.Insert} {
		if strings.Count(s, "%s") != 1 {
			t.Errorf("statement %q must name the table exactly once", s)
		}
	}
	if !strings.Contains(Dialect.Upsert, "ON DUPLICATE KEY UPDATE") || strings.Count(Dialect.Upsert, "?") != 2 {
		t.Errorf("upsert = %q", Dialect.Upsert)
	}
}

// TestAgainstRealMySQL runs only when NANOIO_TEST_MYSQL_DSN names a server
// (for example "root:pw@tcp(127.0.0.1:3306)/test"); there is no MySQL server
// in the default test environment.
func TestAgainstRealMySQL(t *testing.T) {
	dsn := os.Getenv("NANOIO_TEST_MYSQL_DSN")
	if dsn == "" {
		t.Skip("NANOIO_TEST_MYSQL_DSN is not set")
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	table := fmt.Sprintf("nanoio_test_%d", time.Now().UnixNano())
	defer db.Exec("DROP TABLE IF EXISTS " + table)
	spec, err := Factory("m", json.RawMessage(`{"dsn":"`+dsn+`","table":"`+table+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer spec.Target.Close()
	ctx := context.Background()
	mk := func(name, key string) *event.Event {
		return &event.Event{Name: name, Bucket: "b", Key: key, Time: time.Now().UTC()}
	}
	if err := spec.Target.Send(ctx, []*event.Event{mk(event.ObjectCreatedPut, "a"), mk(event.ObjectCreatedPut, "a"),
		mk(event.ObjectCreatedPut, "c"), mk(event.ObjectRemovedDelete, "c")}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM " + table).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d (%v), want 1", n, err)
	}
}
