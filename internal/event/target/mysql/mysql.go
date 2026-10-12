// Package mysql writes notifications to a MySQL (or MariaDB) table.
//
// Configuration:
//
//	dsn          go-sql-driver DSN, e.g.
//	             "user:pass@tcp(host:3306)/dbname", required
//	table        required, letters/digits/underscore
//	format       "namespace" (default) or "access"
//	createTable  create the table if missing (default true)
//	tls          {enable, skipVerify, ca, cert, key}: registers a TLS
//	             configuration and adds tls=<name> to the DSN
//	+ the shared delivery keys
//
// Namespace: (key_name VARBINARY(1100) PRIMARY KEY, value JSON), upserted on
// create and deleted on removal. Access: (event_time DATETIME(3), event_data
// JSON), one row per event.
package mysql

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sync/atomic"

	mysqldrv "github.com/go-sql-driver/mysql"

	"nanoio/internal/event"
	"nanoio/internal/event/target/sqlbase"
)

// Type is the target type name.
const Type = "mysql"

// Config is the target's configuration.
type Config struct {
	event.Delivery
	DSN         string    `json:"dsn"`
	Table       string    `json:"table"`
	Format      string    `json:"format"`
	CreateTable *bool     `json:"createTable"`
	TLS         event.TLS `json:"tls"`
}

// Dialect is MySQL's SQL.
var Dialect = sqlbase.Dialect{
	CreateNamespace: "CREATE TABLE IF NOT EXISTS %s (key_name VARBINARY(1100) NOT NULL, value JSON NOT NULL, PRIMARY KEY (key_name))",
	CreateAccess:    "CREATE TABLE IF NOT EXISTS %s (event_time DATETIME(3) NOT NULL, event_data JSON NOT NULL)",
	Upsert:          "INSERT INTO %s (key_name, value) VALUES (?, ?) ON DUPLICATE KEY UPDATE value = VALUES(value)",
	Delete:          "DELETE FROM %s WHERE key_name = ?",
	Insert:          "INSERT INTO %s (event_time, event_data) VALUES (?, ?)",
}

var tlsSeq atomic.Uint64

// Factory builds the target from its JSON configuration.
func Factory(id string, raw json.RawMessage) (event.Spec, error) {
	var c Config
	if err := event.DecodeConfig(raw, &c); err != nil {
		return event.Spec{}, err
	}
	if err := c.Delivery.Validate(); err != nil {
		return event.Spec{}, err
	}
	if c.DSN == "" {
		return event.Spec{}, errors.New("dsn is required")
	}
	mc, err := mysqldrv.ParseDSN(c.DSN)
	if err != nil {
		return event.Spec{}, fmt.Errorf("dsn: %w", err)
	}
	// The driver's default location is UTC, which is what event times use.
	if tc, err := c.TLS.Config(hostOf(mc.Addr)); err != nil {
		return event.Spec{}, err
	} else if tc != nil {
		name := fmt.Sprintf("nanoio-%s-%d", id, tlsSeq.Add(1))
		if err := mysqldrv.RegisterTLSConfig(name, tc); err != nil {
			return event.Spec{}, err
		}
		mc.TLSConfig = name
	}
	d := c.Delivery.Defaults(100)
	mc.Timeout, mc.ReadTimeout, mc.WriteTimeout = d.Timeout.D(), d.Timeout.D(), d.Timeout.D()
	conn, err := mysqldrv.NewConnector(mc)
	if err != nil {
		return event.Spec{}, err
	}
	create := c.CreateTable == nil || *c.CreateTable
	t, err := sqlbase.New(sql.OpenDB(conn), Dialect, sqlbase.Config{Table: c.Table, Format: c.Format, CreateTable: create}, d.Timeout.D())
	if err != nil {
		return event.Spec{}, err
	}
	return event.Spec{Target: t, Delivery: d}, nil
}

func hostOf(addr string) string {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
	}
	return addr
}
