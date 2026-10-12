package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"nanoio/internal/event"
)

// Runtime configuration (mc admin config ...).
//
// Only subsystems that something in NanoIO actually reads are accepted; a
// value NanoIO would store and ignore is refused instead, so "set succeeded"
// always means "in effect". Each subsystem registers a schema (known keys,
// secrets, validation) and, optionally, a change hook.

type cfgKey struct {
	Name     string
	Desc     string
	Type     string // string, bool, duration, list, url
	Optional bool
	Secret   bool // redacted when read back
}

type cfgSub struct {
	Name     string
	Desc     string
	Keys     []cfgKey
	Validate func(kv map[string]string) error
}

var (
	configSubs   = map[string]*cfgSub{}
	configHooks  []func(s *Server)
	configDocKey = "_config/config.json"
	configHist   = "_config/history/"
)

func registerConfigSub(c *cfgSub) { configSubs[c.Name] = c }

// onConfigChange registers a callback run after the configuration changed
// (also after a restore, and after another node's change is observed).
func onConfigChange(f func(s *Server)) { configHooks = append(configHooks, f) }

// configDoc: subsystem -> target ("" is the default target) -> key -> value.
type configDoc struct {
	Subs map[string]map[string]map[string]string `json:"subs"`
}

type configRuntime struct {
	s  *Server
	es *eventStore
	mu sync.Mutex

	cache   *configDoc
	cacheAt time.Time
}

const configCacheTTL = 3 * time.Second

func (s *Server) cfg() *configRuntime {
	s.cfgOnce.Do(func() { s.cfgrt = &configRuntime{s: s, es: &eventStore{st: s.st}} })
	return s.cfgrt
}

func (c *configRuntime) load(ctx context.Context) (*configDoc, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache != nil && time.Since(c.cacheAt) < configCacheTTL {
		return c.cache, nil
	}
	d, err := c.read(ctx)
	if err != nil {
		return nil, err
	}
	c.cache, c.cacheAt = d, time.Now()
	return d, nil
}

func (c *configRuntime) read(ctx context.Context) (*configDoc, error) {
	b, err := c.es.Get(ctx, configDocKey)
	if errors.Is(err, event.ErrSharedNotFound) {
		return &configDoc{Subs: map[string]map[string]map[string]string{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var d configDoc
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, err
	}
	if d.Subs == nil {
		d.Subs = map[string]map[string]map[string]string{}
	}
	return &d, nil
}

// Target returns the key/value settings of subsys[:target] (nil when none).
func (c *configRuntime) Target(ctx context.Context, subsys, target string) map[string]string {
	d, err := c.load(ctx)
	if err != nil {
		return nil
	}
	return d.Subs[subsys][target]
}

// Targets lists the configured targets of a subsystem.
func (c *configRuntime) Targets(ctx context.Context, subsys string) map[string]map[string]string {
	d, err := c.load(ctx)
	if err != nil {
		return nil
	}
	return d.Subs[subsys]
}

func (c *configRuntime) save(ctx context.Context, d *configDoc, prev *configDoc) error {
	// Keep the previous state for `mc admin config history/restore`.
	var id [8]byte
	rand.Read(id[:])
	hid := fmt.Sprintf("%019d-%s", time.Now().UnixNano(), hex.EncodeToString(id[:]))
	pb, _ := json.Marshal(prev)
	if err := c.es.Put(ctx, configHist+hid+".json", pb); err != nil {
		return err
	}
	b, _ := json.Marshal(d)
	if err := c.es.Put(ctx, configDocKey, b); err != nil {
		return err
	}
	c.mu.Lock()
	c.cache, c.cacheAt = d, time.Now()
	c.mu.Unlock()
	for _, h := range configHooks {
		h(c.s)
	}
	return nil
}

func cloneConfig(d *configDoc) *configDoc {
	n := &configDoc{Subs: map[string]map[string]map[string]string{}}
	for s, ts := range d.Subs {
		n.Subs[s] = map[string]map[string]string{}
		for t, kv := range ts {
			m := map[string]string{}
			for k, v := range kv {
				m[k] = v
			}
			n.Subs[s][t] = m
		}
	}
	return n
}

// parseKVLine reads `subsys[:target] k=v k2="v 2"`.
func parseKVLine(line string) (subsys, target string, kv map[string]string, err error) {
	line = strings.TrimSpace(line)
	head, rest, _ := strings.Cut(line, " ")
	subsys, target, _ = strings.Cut(head, ":")
	if subsys == "" {
		return "", "", nil, errors.New("missing sub-system")
	}
	kv = map[string]string{}
	rest = strings.TrimSpace(rest)
	for rest != "" {
		eq := strings.IndexByte(rest, '=')
		if eq <= 0 {
			return "", "", nil, fmt.Errorf("expected key=value near %q", rest)
		}
		key := strings.TrimSpace(rest[:eq])
		if strings.ContainsAny(key, " \t\"") {
			return "", "", nil, fmt.Errorf("invalid key %q", key)
		}
		rest = rest[eq+1:]
		var val string
		if strings.HasPrefix(rest, `"`) {
			end := strings.Index(rest[1:], `"`)
			if end < 0 {
				return "", "", nil, errors.New("unterminated quote")
			}
			val, rest = rest[1:1+end], rest[end+2:]
		} else {
			val, rest, _ = strings.Cut(rest, " ")
		}
		kv[key] = val
		rest = strings.TrimSpace(rest)
	}
	return subsys, target, kv, nil
}

func quoteVal(v string) string {
	if v == "" || strings.ContainsAny(v, " \t\"") {
		return `"` + strings.ReplaceAll(v, `"`, `'`) + `"`
	}
	return v
}

// formatTarget renders one subsystem target as a config line.
func formatTarget(subsys, target string, kv map[string]string, redact bool) string {
	sub := configSubs[subsys]
	var b strings.Builder
	b.WriteString(subsys)
	if target != "" {
		b.WriteString(":" + target)
	}
	keys := make([]string, 0, len(kv))
	for k := range kv {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := kv[k]
		if redact && sub != nil {
			for _, ck := range sub.Keys {
				if ck.Name == k && ck.Secret && v != "" {
					v = "*redacted*"
				}
			}
		}
		b.WriteString(" " + k + "=" + quoteVal(v))
	}
	return b.String()
}

func (c *configRuntime) validateTarget(subsys string, kv map[string]string) error {
	sub, ok := configSubs[subsys]
	if !ok {
		names := make([]string, 0, len(configSubs))
		for n := range configSubs {
			names = append(names, n)
		}
		sort.Strings(names)
		return fmt.Errorf("unsupported sub-system %q (supported: %s)", subsys, strings.Join(names, ", "))
	}
	known := map[string]bool{}
	for _, k := range sub.Keys {
		known[k.Name] = true
	}
	for k := range kv {
		if !known[k] {
			return fmt.Errorf("unknown key %q for sub-system %s", k, subsys)
		}
	}
	if sub.Validate != nil {
		return sub.Validate(kv)
	}
	return nil
}

func init() {
	r := madminRegister
	r("get-config-kv", "GET", "admin:ConfigUpdate", (*Server).madminGetConfigKV)
	r("set-config-kv", "PUT", "admin:ConfigUpdate", (*Server).madminSetConfigKV)
	r("del-config-kv", "DELETE", "admin:ConfigUpdate", (*Server).madminDelConfigKV)
	r("help-config-kv", "GET", "admin:ConfigUpdate", (*Server).madminHelpConfigKV)
	r("config", "GET PUT", "admin:ConfigUpdate", (*Server).madminConfig)
	r("list-config-history-kv", "GET", "admin:ConfigUpdate", (*Server).madminListConfigHistory)
	r("restore-config-history-kv", "PUT", "admin:ConfigUpdate", (*Server).madminRestoreConfigHistory)
	r("clear-config-history-kv", "DELETE", "admin:ConfigUpdate", (*Server).madminClearConfigHistory)
}

func (s *Server) madminGetConfigKV(q *request) {
	d, err := s.cfg().load(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	key := q.query.Get("key")
	subsys, target, _ := strings.Cut(key, ":")
	var lines []string
	subs := make([]string, 0, len(d.Subs))
	for n := range d.Subs {
		subs = append(subs, n)
	}
	sort.Strings(subs)
	for _, n := range subs {
		if subsys != "" && n != subsys {
			continue
		}
		targets := make([]string, 0, len(d.Subs[n]))
		for t := range d.Subs[n] {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		for _, t := range targets {
			if key != "" && strings.Contains(key, ":") && t != target {
				continue
			}
			lines = append(lines, formatTarget(n, t, d.Subs[n][t], true))
		}
	}
	if subsys != "" {
		if _, ok := configSubs[subsys]; !ok {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminConfigError", "unsupported sub-system "+subsys)
			return
		}
		if len(lines) == 0 {
			lines = append(lines, subsys+func() string {
				if target != "" {
					return ":" + target
				}
				return ""
			}())
		}
	}
	sk, ok := s.callerSecret(q)
	if !ok {
		s.madminFail(q, http.StatusInternalServerError, "XMinioAdminInternalError", "cannot determine the caller's secret key")
		return
	}
	s.writeEncryptedRaw(q, sk, []byte(strings.Join(lines, "\n")))
}

// applyConfigLines merges `subsys[:target] k=v ...` lines into the config.
func (s *Server) applyConfigLines(q *request, text string, replace bool) bool {
	c := s.cfg()
	c.mu.Lock()
	prevAt := c.cacheAt
	c.cacheAt = time.Time{} // force a fresh read for the read-modify-write
	c.mu.Unlock()
	_ = prevAt
	cur, err := c.load(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return false
	}
	next := cloneConfig(cur)
	if replace {
		next = &configDoc{Subs: map[string]map[string]map[string]string{}}
	}
	for _, line := range strings.Split(text, "\n") {
		if t := strings.TrimSpace(line); t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		subsys, target, kv, err := parseKVLine(line)
		if err != nil {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminConfigBadJSON", err.Error())
			return false
		}
		if next.Subs[subsys] == nil {
			next.Subs[subsys] = map[string]map[string]string{}
		}
		m := next.Subs[subsys][target]
		if m == nil {
			m = map[string]string{}
		}
		for k, v := range kv {
			if v == "" {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		if err := c.validateTarget(subsys, m); err != nil {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminConfigError", err.Error())
			return false
		}
		next.Subs[subsys][target] = m
	}
	if err := c.save(q.ctx(), next, cur); err != nil {
		s.madminErr(q, err)
		return false
	}
	return true
}

func (s *Server) madminSetConfigKV(q *request) {
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	if s.applyConfigLines(q, string(pt), false) {
		q.w.Header().Set("x-minio-config-applied", "true")
		q.w.WriteHeader(http.StatusOK)
	}
}

func (s *Server) madminDelConfigKV(q *request) {
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	subsys, target, _ := strings.Cut(strings.TrimSpace(string(pt)), ":")
	if _, ok := configSubs[subsys]; !ok {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminConfigError", "unsupported sub-system "+subsys)
		return
	}
	c := s.cfg()
	c.mu.Lock()
	c.cacheAt = time.Time{}
	c.mu.Unlock()
	cur, err := c.load(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	if _, ok := cur.Subs[subsys][target]; !ok {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminConfigNoQuorum", "there is no such configuration to remove")
		return
	}
	next := cloneConfig(cur)
	delete(next.Subs[subsys], target)
	if len(next.Subs[subsys]) == 0 {
		delete(next.Subs, subsys)
	}
	if err := c.save(q.ctx(), next, cur); err != nil {
		s.madminErr(q, err)
		return
	}
	q.w.Header().Set("x-minio-config-applied", "true")
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) madminHelpConfigKV(q *request) {
	subsys := q.query.Get("subSys")
	type kv struct {
		Key             string `json:"key"`
		Description     string `json:"description"`
		Optional        bool   `json:"optional"`
		Type            string `json:"type"`
		MultipleTargets bool   `json:"multipleTargets"`
	}
	type help struct {
		SubSys          string `json:"subSys"`
		Description     string `json:"description"`
		MultipleTargets bool   `json:"multipleTargets"`
		KeysHelp        []kv   `json:"keysHelp"`
	}
	if subsys == "" {
		names := make([]string, 0, len(configSubs))
		for n := range configSubs {
			names = append(names, n)
		}
		sort.Strings(names)
		h := help{KeysHelp: []kv{}}
		for _, n := range names {
			h.KeysHelp = append(h.KeysHelp, kv{Key: n, Description: configSubs[n].Desc, Optional: true, Type: "string", MultipleTargets: true})
		}
		s.writeJSONOK(q, h)
		return
	}
	sub, ok := configSubs[subsys]
	if !ok {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminConfigError", "unsupported sub-system "+subsys)
		return
	}
	h := help{SubSys: sub.Name, Description: sub.Desc, MultipleTargets: true, KeysHelp: []kv{}}
	for _, k := range sub.Keys {
		if key := q.query.Get("key"); key != "" && key != k.Name {
			continue
		}
		h.KeysHelp = append(h.KeysHelp, kv{Key: k.Name, Description: k.Desc, Optional: k.Optional, Type: k.Type, MultipleTargets: true})
	}
	s.writeJSONOK(q, h)
}

// madminConfig exports (GET) or replaces (PUT) the entire configuration.
func (s *Server) madminConfig(q *request) {
	if q.r.Method == http.MethodPut {
		pt, err := s.readEncrypted(q)
		if err != nil {
			s.madminErr(q, err)
			return
		}
		if s.applyConfigLines(q, string(pt), true) {
			q.w.WriteHeader(http.StatusOK)
		}
		return
	}
	d, err := s.cfg().load(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var lines []string
	subs := make([]string, 0, len(d.Subs))
	for n := range d.Subs {
		subs = append(subs, n)
	}
	sort.Strings(subs)
	for _, n := range subs {
		targets := make([]string, 0, len(d.Subs[n]))
		for t := range d.Subs[n] {
			targets = append(targets, t)
		}
		sort.Strings(targets)
		for _, t := range targets {
			lines = append(lines, formatTarget(n, t, d.Subs[n][t], false))
		}
	}
	sk, _ := s.callerSecret(q)
	s.writeEncryptedRaw(q, sk, []byte(strings.Join(lines, "\n")))
}

func (s *Server) madminListConfigHistory(q *request) {
	count := 10
	if v := q.query.Get("count"); v != "" {
		fmt.Sscanf(v, "%d", &count)
	}
	c := s.cfg()
	names, err := c.es.List(q.ctx(), configHist, 1000)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	type entry struct {
		RestoreID  string    `json:"restoreId"`
		CreateTime time.Time `json:"createTime"`
		Data       string    `json:"data"`
	}
	out := []entry{}
	for i := len(names) - 1; i >= 0 && len(out) < count; i-- {
		b, err := c.es.Get(q.ctx(), names[i])
		if err != nil {
			continue
		}
		var d configDoc
		if json.Unmarshal(b, &d) != nil {
			continue
		}
		id := strings.TrimSuffix(strings.TrimPrefix(names[i], configHist), ".json")
		var ns int64
		fmt.Sscanf(id, "%d", &ns)
		var lines []string
		subs := make([]string, 0, len(d.Subs))
		for n := range d.Subs {
			subs = append(subs, n)
		}
		sort.Strings(subs)
		for _, n := range subs {
			for t, kv := range d.Subs[n] {
				lines = append(lines, formatTarget(n, t, kv, true))
			}
		}
		out = append(out, entry{RestoreID: id, CreateTime: time.Unix(0, ns).UTC(), Data: strings.Join(lines, "\n")})
	}
	s.writeEncrypted(q, out)
}

func (s *Server) madminRestoreConfigHistory(q *request) {
	id := q.query.Get("restoreId")
	if id == "" || strings.ContainsAny(id, "/.") {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "invalid restore id")
		return
	}
	c := s.cfg()
	b, err := c.es.Get(q.ctx(), configHist+id+".json")
	if errors.Is(err, event.ErrSharedNotFound) {
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchConfigHistory", "no such configuration history entry")
		return
	}
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var d configDoc
	if err := json.Unmarshal(b, &d); err != nil {
		s.madminErr(q, err)
		return
	}
	if d.Subs == nil {
		d.Subs = map[string]map[string]map[string]string{}
	}
	cur, err := c.read(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	if err := c.save(q.ctx(), &d, cur); err != nil {
		s.madminErr(q, err)
		return
	}
	q.w.WriteHeader(http.StatusOK)
}

func (s *Server) madminClearConfigHistory(q *request) {
	id := q.query.Get("restoreId")
	c := s.cfg()
	if id == "all" {
		names, err := c.es.List(q.ctx(), configHist, 100000)
		if err != nil {
			s.madminErr(q, err)
			return
		}
		for _, n := range names {
			c.es.Delete(q.ctx(), n)
		}
	} else if id == "" || strings.ContainsAny(id, "/.") {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminInvalidArgument", "invalid restore id")
		return
	} else {
		c.es.Delete(q.ctx(), configHist+id+".json")
	}
	q.w.WriteHeader(http.StatusOK)
}
