// Package sqlbase is the database/sql half of the MySQL and PostgreSQL
// targets: the namespace and access formats, batching in a transaction, and
// lazy table creation. The driver packages supply the dialect.
package sqlbase

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"nanoio/internal/event"
	"nanoio/internal/event/target/targetutil"
)

// Dialect holds the SQL that differs between databases. Every statement uses
// the dialect's own placeholder syntax; the table name is substituted in by
// Target (it is validated, never taken from an event).
type Dialect struct {
	// CreateNamespace and CreateAccess are the CREATE TABLE IF NOT EXISTS
	// statements, with %s for the table name.
	CreateNamespace string
	CreateAccess    string
	// Upsert (key, value), Delete (key) and Insert (time, data).
	Upsert string
	Delete string
	Insert string
}

// TableName is a conservative SQL identifier; it is interpolated into
// statements, so nothing else is accepted.
var TableName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// Config is the part of a SQL target's configuration the base needs.
type Config struct {
	Table  string
	Format string
	// CreateTable is whether to create the table on first use.
	CreateTable bool
}

// Target writes events to one table.
type Target struct {
	db      *sql.DB
	format  targetutil.Format
	table   string
	d       Dialect
	create  bool
	timeout time.Duration

	mu      sync.Mutex
	created bool
}

// New builds a target over an open (lazy) *sql.DB.
func New(db *sql.DB, d Dialect, c Config, timeout time.Duration) (*Target, error) {
	if !TableName.MatchString(c.Table) {
		return nil, errors.New("table must be a plain SQL identifier (letters, digits, underscore)")
	}
	f, err := targetutil.ParseFormat(c.Format)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(5 * time.Minute)
	return &Target{db: db, format: f, table: c.Table, d: d, create: c.CreateTable, timeout: timeout}, nil
}

func (t *Target) stmt(s string) string { return strings.ReplaceAll(s, "%s", t.table) }

func (t *Target) ensureTable(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.created || !t.create {
		return nil
	}
	ddl := t.d.CreateNamespace
	if t.format == targetutil.Access {
		ddl = t.d.CreateAccess
	}
	if _, err := t.db.ExecContext(ctx, t.stmt(ddl)); err != nil {
		return fmt.Errorf("create table %s: %w", t.table, err)
	}
	t.created = true
	return nil
}

// Send applies the events in one transaction.
func (t *Target) Send(ctx context.Context, events []*event.Event) error {
	if err := t.ensureTable(ctx); err != nil {
		return err
	}
	tx, err := t.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if t.format == targetutil.Access {
		for _, e := range events {
			if _, err := tx.ExecContext(ctx, t.stmt(t.d.Insert), e.Time.UTC(), string(targetutil.AccessEntry(e))); err != nil {
				return err
			}
		}
		return tx.Commit()
	}
	n := 0
	for _, op := range targetutil.NamespaceOps(events) {
		var err error
		if op.Delete {
			_, err = tx.ExecContext(ctx, t.stmt(t.d.Delete), op.Key)
		} else {
			_, err = tx.ExecContext(ctx, t.stmt(t.d.Upsert), op.Key, string(op.Value))
		}
		if err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return nil
	}
	return tx.Commit()
}

// Check pings the database.
func (t *Target) Check(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return t.db.PingContext(ctx)
}

// Close closes the connection pool.
func (t *Target) Close() error { return t.db.Close() }
