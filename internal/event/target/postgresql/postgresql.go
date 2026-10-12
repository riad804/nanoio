// Package postgresql writes notifications to a PostgreSQL table.
//
// Configuration:
//
//	connectionString   libpq URL or key=value string, required, e.g.
//	                   "postgres://user:pass@host:5432/db?sslmode=require"
//	table              required, letters/digits/underscore
//	format             "namespace" (default) or "access"
//	createTable        create the table if missing (default true)
//	+ the shared delivery keys
//
// TLS is requested in the connection string (sslmode, sslrootcert, ...).
//
// Namespace: (key VARCHAR PRIMARY KEY, value JSONB), upserted on create and
// deleted on removal. Access: (event_time TIMESTAMPTZ, event_data JSONB),
// one row per event.
package postgresql

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"

	"nanoio/internal/event"
	"nanoio/internal/event/target/sqlbase"
)

// Type is the target type name.
const Type = "postgresql"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	ConnectionString string `json:"connectionString"`
	Table            string `json:"table"`
	Format           string `json:"format"`
	CreateTable      *bool  `json:"createTable"`
}

// Dialect is PostgreSQL's SQL.
var Dialect = sqlbase.Dialect{
	CreateNamespace: "CREATE TABLE IF NOT EXISTS %s (key VARCHAR NOT NULL PRIMARY KEY, value JSONB NOT NULL)",
	CreateAccess:    "CREATE TABLE IF NOT EXISTS %s (event_time TIMESTAMP WITH TIME ZONE NOT NULL, event_data JSONB NOT NULL)",
	Upsert:          "INSERT INTO %s (key, value) VALUES ($1, $2::jsonb) ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
	Delete:          "DELETE FROM %s WHERE key = $1",
	Insert:          "INSERT INTO %s (event_time, event_data) VALUES ($1, $2::jsonb)",
}

// Factory builds the target from its JSON configuration.
func Factory(id string, raw json.RawMessage) (event.Spec, error) {
	var c Config
	if err := event.DecodeConfig(raw, &c); err != nil {
		return event.Spec{}, err
	}
	if err := c.Delivery.Validate(); err != nil {
		return event.Spec{}, err
	}
	if c.ConnectionString == "" {
		return event.Spec{}, errors.New("connectionString is required")
	}
	cc, err := pgx.ParseConfig(c.ConnectionString)
	if err != nil {
		// pgx's message includes the string; do not echo a password.
		return event.Spec{}, errors.New("connectionString is not a valid PostgreSQL connection string")
	}
	d := c.Delivery.Defaults(100)
	cc.ConnectTimeout = d.Timeout.D()
	// Text protocol: the values are JSON strings cast server-side, and it
	// keeps working through connection poolers in transaction mode.
	cc.DefaultQueryExecMode = pgx.QueryExecModeSimpleProtocol
	create := c.CreateTable == nil || *c.CreateTable
	t, err := sqlbase.New(stdlib.OpenDB(*cc), Dialect, sqlbase.Config{Table: c.Table, Format: c.Format, CreateTable: create}, d.Timeout.D())
	if err != nil {
		return event.Spec{}, fmt.Errorf("%w", err)
	}
	return event.Spec{Target: t, Delivery: d}, nil
}
