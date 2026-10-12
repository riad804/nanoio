package sqlbase

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"nanoio/internal/event"
)

// recorder is a database/sql driver that records statements and arguments
// and can be told to fail.
type recorder struct {
	mu      sync.Mutex
	stmts   []string
	failOn  string
	commits int
	rolls   int
}

type rconn struct{ r *recorder }
type rtx struct{ r *recorder }
type rstmt struct {
	r *recorder
	q string
}

func (r *recorder) Open(string) (driver.Conn, error)   { return &rconn{r}, nil }
func (c *rconn) Prepare(q string) (driver.Stmt, error) { return &rstmt{c.r, q}, nil }
func (c *rconn) Close() error                          { return nil }
func (c *rconn) Begin() (driver.Tx, error)             { return &rtx{c.r}, nil }
func (t *rtx) Commit() error                           { t.r.mu.Lock(); t.r.commits++; t.r.mu.Unlock(); return nil }
func (t *rtx) Rollback() error                         { t.r.mu.Lock(); t.r.rolls++; t.r.mu.Unlock(); return nil }
func (s *rstmt) Close() error                          { return nil }
func (s *rstmt) NumInput() int                         { return -1 }
func (s *rstmt) Query([]driver.Value) (driver.Rows, error) {
	return nil, io.EOF
}
func (s *rstmt) Exec(args []driver.Value) (driver.Result, error) {
	s.r.mu.Lock()
	defer s.r.mu.Unlock()
	line := s.q
	for _, a := range args {
		line += fmt.Sprintf(" | %v", a)
	}
	s.r.stmts = append(s.r.stmts, line)
	if s.r.failOn != "" && strings.Contains(s.q, s.r.failOn) {
		return nil, errors.New("simulated database failure")
	}
	return driver.RowsAffected(1), nil
}

var drvSeq int
var drvMu sync.Mutex

func newRecorder(t *testing.T) (*recorder, *sql.DB) {
	t.Helper()
	drvMu.Lock()
	drvSeq++
	name := fmt.Sprintf("recorder%d", drvSeq)
	drvMu.Unlock()
	r := &recorder{}
	sql.Register(name, r)
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	return r, db
}

var testDialect = Dialect{
	CreateNamespace: "CREATE NS %s",
	CreateAccess:    "CREATE ACCESS %s",
	Upsert:          "UPSERT %s",
	Delete:          "DELETE %s",
	Insert:          "INSERT %s",
}

func ev(name, key string) *event.Event {
	return &event.Event{Name: name, Bucket: "b", Key: key, Time: time.Unix(0, 0).UTC()}
}

func TestNamespaceBatchIsOneTransaction(t *testing.T) {
	r, db := newRecorder(t)
	tgt, err := New(db, testDialect, Config{Table: "events", CreateTable: true}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	err = tgt.Send(context.Background(), []*event.Event{
		ev(event.ObjectCreatedPut, "a"), ev(event.ObjectAccessedGet, "a"), ev(event.ObjectRemovedDelete, "a")})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.stmts) != 3 || r.stmts[0] != "CREATE NS events" ||
		!strings.HasPrefix(r.stmts[1], "UPSERT events | b/a | {") || r.stmts[2] != "DELETE events | b/a" {
		t.Fatalf("statements = %q", r.stmts)
	}
	if r.commits != 1 {
		t.Errorf("commits = %d, want 1", r.commits)
	}
	// The table is created once.
	tgt.Send(context.Background(), []*event.Event{ev(event.ObjectCreatedPut, "x")})
	creates := 0
	for _, s := range r.stmts {
		if strings.HasPrefix(s, "CREATE") {
			creates++
		}
	}
	if creates != 1 {
		t.Errorf("CREATE ran %d times", creates)
	}
}

func TestAccessFormatAndRollback(t *testing.T) {
	r, db := newRecorder(t)
	tgt, err := New(db, testDialect, Config{Table: "log", Format: "access", CreateTable: false}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer tgt.Close()
	if err := tgt.Send(context.Background(), []*event.Event{ev(event.ObjectCreatedPut, "a"), ev(event.ObjectAccessedGet, "a")}); err != nil {
		t.Fatal(err)
	}
	if len(r.stmts) != 2 || !strings.HasPrefix(r.stmts[0], "INSERT log | 1970-01-01 00:00:00 +0000 UTC | {") {
		t.Fatalf("statements = %q", r.stmts)
	}

	r.failOn = "INSERT"
	r.stmts, r.commits, r.rolls = nil, 0, 0
	err = tgt.Send(context.Background(), []*event.Event{ev(event.ObjectCreatedPut, "a")})
	if err == nil || r.commits != 0 || r.rolls == 0 {
		t.Errorf("a failed statement must roll the batch back: err=%v commits=%d rollbacks=%d", err, r.commits, r.rolls)
	}
}

func TestOnlyAccessEventsInNamespaceFormatTouchNothing(t *testing.T) {
	r, db := newRecorder(t)
	tgt, _ := New(db, testDialect, Config{Table: "t"}, time.Second)
	defer tgt.Close()
	if err := tgt.Send(context.Background(), []*event.Event{ev(event.ObjectAccessedGet, "a")}); err != nil {
		t.Fatal(err)
	}
	if len(r.stmts) != 0 {
		t.Errorf("statements = %q", r.stmts)
	}
}

func TestTableNameIsValidated(t *testing.T) {
	_, db := newRecorder(t)
	for _, bad := range []string{"", "a-b", "a b", "x;DROP TABLE y", "1abc", "t\"", strings.Repeat("a", 64), "schema.t"} {
		if _, err := New(db, testDialect, Config{Table: bad}, time.Second); err == nil {
			t.Errorf("table name %q accepted", bad)
		}
	}
	if _, err := New(db, testDialect, Config{Table: "Events_2"}, time.Second); err != nil {
		t.Errorf("valid table name refused: %v", err)
	}
}
