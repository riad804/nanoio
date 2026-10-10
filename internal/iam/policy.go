// Package iam holds NanoIO's identities and authorisation: the root
// credential, file-defined users, and an evaluator for a subset of AWS IAM
// policy documents. State is embedded (one JSON file, no external store).
package iam

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Policy is a parsed identity-based IAM policy document.
type Policy struct {
	Version    string
	Statements []Statement
}

// Statement is one policy statement. Exactly one of Actions/NotActions and
// one of Resources/NotResources is set.
type Statement struct {
	SID          string
	Allow        bool
	Actions      []string
	NotActions   []string
	Resources    []string
	NotResources []string
	Conditions   []Condition
}

// Condition is one operator/key pair with its values.
type Condition struct {
	Operator string
	Key      string // lower-case
	Values   []string
}

// Request is what is being authorised.
type Request struct {
	// Action is an S3 IAM action such as "s3:GetObject".
	Action string
	// Bucket is empty for service-level actions (ListAllMyBuckets).
	Bucket string
	// Key is empty for bucket-level actions.
	Key string
	// Context holds condition keys, lower-case: "aws:sourceip",
	// "aws:securetransport", "s3:prefix", "s3:delimiter", "s3:max-keys".
	Context map[string]string
}

// ARN returns the resource ARN the request targets.
func (r Request) ARN() string {
	switch {
	case r.Bucket == "":
		return "arn:aws:s3:::*"
	case r.Key == "":
		return "arn:aws:s3:::" + r.Bucket
	}
	return "arn:aws:s3:::" + r.Bucket + "/" + r.Key
}

// stringList decodes a JSON string or array of strings.
type stringList []string

func (l *stringList) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) > 0 && b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		*l = []string{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(b, &ss); err != nil {
		return errors.New("must be a string or an array of strings")
	}
	*l = ss
	return nil
}

type rawStatement struct {
	Sid          string                       `json:"Sid"`
	Effect       string                       `json:"Effect"`
	Action       stringList                   `json:"Action"`
	NotAction    stringList                   `json:"NotAction"`
	Resource     stringList                   `json:"Resource"`
	NotResource  stringList                   `json:"NotResource"`
	Condition    map[string]map[string]scalar `json:"Condition"`
	Principal    json.RawMessage              `json:"Principal"`
	NotPrincipal json.RawMessage              `json:"NotPrincipal"`
}

// scalar decodes a condition value: string, number, bool, or an array of
// those, flattened to strings.
type scalar []string

func (s *scalar) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	add := func(x any) error {
		switch t := x.(type) {
		case string:
			*s = append(*s, t)
		case bool:
			*s = append(*s, strconv.FormatBool(t))
		case float64:
			*s = append(*s, strconv.FormatFloat(t, 'f', -1, 64))
		default:
			return errors.New("condition values must be strings, numbers or booleans")
		}
		return nil
	}
	if arr, ok := v.([]any); ok {
		for _, x := range arr {
			if err := add(x); err != nil {
				return err
			}
		}
		return nil
	}
	return add(v)
}

// Supported condition operators. Anything else is rejected at parse time:
// silently ignoring a Deny condition would fail open.
var conditionOperators = map[string]bool{
	"StringEquals": true, "StringNotEquals": true,
	"StringEqualsIgnoreCase": true, "StringNotEqualsIgnoreCase": true,
	"StringLike": true, "StringNotLike": true,
	"Bool":      true,
	"IpAddress": true, "NotIpAddress": true,
	"NumericEquals": true, "NumericNotEquals": true,
	"NumericLessThan": true, "NumericLessThanEquals": true,
	"NumericGreaterThan": true, "NumericGreaterThanEquals": true,
}

func negatedOperator(op string) bool {
	return strings.HasPrefix(op, "Not") || strings.Contains(op, "NotEquals") || strings.Contains(op, "NotLike")
}

// ParsePolicy parses and validates a policy document. It is strict: unknown
// fields, unsupported actions, resources, condition operators and policy
// variables are errors, so a policy never means less than it says.
func ParsePolicy(data []byte) (*Policy, error) {
	var raw struct {
		Version   string          `json:"Version"`
		ID        string          `json:"Id"`
		Statement json.RawMessage `json:"Statement"`
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if dec.More() {
		return nil, errors.New("policy: trailing data after the document")
	}
	switch raw.Version {
	case "2012-10-17", "2008-10-17":
	case "":
		return nil, errors.New(`policy: "Version" is required`)
	default:
		return nil, fmt.Errorf("policy: unsupported Version %q", raw.Version)
	}
	if len(raw.Statement) == 0 {
		return nil, errors.New(`policy: "Statement" is required`)
	}
	var stmts []json.RawMessage
	if b := bytes.TrimSpace(raw.Statement); len(b) > 0 && b[0] == '[' {
		if err := json.Unmarshal(b, &stmts); err != nil {
			return nil, fmt.Errorf("policy: Statement: %w", err)
		}
	} else {
		stmts = []json.RawMessage{b}
	}
	if len(stmts) == 0 {
		return nil, errors.New("policy: Statement must not be empty")
	}
	p := &Policy{Version: raw.Version}
	for i, sb := range stmts {
		st, err := parseStatement(sb)
		if err != nil {
			return nil, fmt.Errorf("policy: statement %d: %w", i, err)
		}
		p.Statements = append(p.Statements, st)
	}
	return p, nil
}

func parseStatement(b json.RawMessage) (Statement, error) {
	var r rawStatement
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Statement{}, err
	}
	if len(r.Principal) > 0 || len(r.NotPrincipal) > 0 {
		return Statement{}, errors.New("Principal and NotPrincipal are not allowed in an identity policy")
	}
	st := Statement{SID: r.Sid,
		Actions: r.Action, NotActions: r.NotAction, Resources: r.Resource, NotResources: r.NotResource}
	switch r.Effect {
	case "Allow":
		st.Allow = true
	case "Deny":
	default:
		return Statement{}, fmt.Errorf(`Effect must be "Allow" or "Deny", got %q`, r.Effect)
	}
	if (len(st.Actions) == 0) == (len(st.NotActions) == 0) {
		return Statement{}, errors.New("exactly one of Action and NotAction is required")
	}
	if (len(st.Resources) == 0) == (len(st.NotResources) == 0) {
		return Statement{}, errors.New("exactly one of Resource and NotResource is required")
	}
	for _, a := range append(append([]string(nil), st.Actions...), st.NotActions...) {
		if a != "*" && !strings.HasPrefix(strings.ToLower(a), "s3:") {
			return Statement{}, fmt.Errorf("action %q: only s3:* actions are supported", a)
		}
		if a == "" || strings.ContainsAny(a, " \t") {
			return Statement{}, fmt.Errorf("action %q is malformed", a)
		}
	}
	for _, res := range append(append([]string(nil), st.Resources...), st.NotResources...) {
		if res != "*" && !strings.HasPrefix(res, "arn:aws:s3:::") {
			return Statement{}, fmt.Errorf("resource %q: only arn:aws:s3::: resources are supported", res)
		}
		if err := checkVariables(res); err != nil {
			return Statement{}, fmt.Errorf("resource %q: %w", res, err)
		}
	}
	for op, keys := range r.Condition {
		if !conditionOperators[op] {
			return Statement{}, fmt.Errorf("condition operator %q is not supported", op)
		}
		for k, vals := range keys {
			if len(vals) == 0 {
				return Statement{}, fmt.Errorf("condition %s/%s has no values", op, k)
			}
			c := Condition{Operator: op, Key: strings.ToLower(k), Values: vals}
			if err := validateCondition(c); err != nil {
				return Statement{}, err
			}
			st.Conditions = append(st.Conditions, c)
		}
	}
	return st, nil
}

func validateCondition(c Condition) error {
	for _, v := range c.Values {
		if err := checkVariables(v); err != nil {
			return fmt.Errorf("condition %s/%s: %w", c.Operator, c.Key, err)
		}
		switch c.Operator {
		case "IpAddress", "NotIpAddress":
			if _, err := parseIPOrCIDR(v); err != nil {
				return fmt.Errorf("condition %s/%s: %q is not an IP address or CIDR", c.Operator, c.Key, v)
			}
		case "Bool":
			if v != "true" && v != "false" {
				return fmt.Errorf("condition Bool/%s: %q is not true or false", c.Key, v)
			}
		default:
			if strings.HasPrefix(c.Operator, "Numeric") {
				if _, err := strconv.ParseFloat(v, 64); err != nil {
					return fmt.Errorf("condition %s/%s: %q is not a number", c.Operator, c.Key, v)
				}
			}
		}
	}
	return nil
}

// checkVariables allows only ${aws:username}.
func checkVariables(s string) error {
	for {
		i := strings.Index(s, "${")
		if i < 0 {
			return nil
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return errors.New("unterminated ${ variable")
		}
		if name := strings.ToLower(s[i+2 : i+j]); name != "aws:username" {
			return fmt.Errorf("policy variable ${%s} is not supported (only ${aws:username})", s[i+2:i+j])
		}
		s = s[i+j+1:]
	}
}

func parseIPOrCIDR(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		return netip.ParsePrefix(s)
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// substitute expands ${aws:username}.
func substitute(s, username string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	for _, v := range []string{"${aws:username}", "${AWS:USERNAME}", "${aws:Username}"} {
		s = strings.ReplaceAll(s, v, username)
	}
	return s
}

// glob matches s against a pattern where '*' is any run and '?' any single
// character. It is iterative with a single backtrack point, so hostile
// patterns cannot cause exponential time.
func glob(pattern, s string, foldCase bool) bool {
	if foldCase {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == s[i]) && pattern[p] != '*':
			p++
			i++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// matches reports whether the statement applies to the request.
func (st *Statement) matches(req Request, username string) bool {
	hit := func(patterns []string, value string, fold bool) bool {
		for _, p := range patterns {
			if glob(substitute(p, username), value, fold) {
				return true
			}
		}
		return false
	}
	if len(st.Actions) > 0 {
		if !hit(st.Actions, req.Action, true) {
			return false
		}
	} else if hit(st.NotActions, req.Action, true) {
		return false
	}
	arn := req.ARN()
	if len(st.Resources) > 0 {
		if !hit(st.Resources, arn, false) {
			return false
		}
	} else if hit(st.NotResources, arn, false) {
		return false
	}
	for _, c := range st.Conditions {
		if !c.holds(req.Context, username) {
			return false
		}
	}
	return true
}

// holds evaluates one condition. A key absent from the request context
// makes positive operators false and negated operators true, as in AWS.
func (c Condition) holds(ctx map[string]string, username string) bool {
	val, present := ctx[c.Key]
	if c.Key == "aws:username" && !present {
		val, present = username, true
	}
	neg := negatedOperator(c.Operator)
	if !present {
		return neg
	}
	any := false
	for _, want := range c.Values {
		want = substitute(want, username)
		if c.matchOne(val, want) {
			any = true
			break
		}
	}
	if neg {
		return !any
	}
	return any
}

// matchOne tests val against one policy value using the positive form of
// the operator; negation is applied by the caller.
func (c Condition) matchOne(val, want string) bool {
	switch c.Operator {
	case "StringEquals", "StringNotEquals":
		return val == want
	case "StringEqualsIgnoreCase", "StringNotEqualsIgnoreCase":
		return strings.EqualFold(val, want)
	case "StringLike", "StringNotLike":
		return glob(want, val, false)
	case "Bool":
		return strings.EqualFold(val, want)
	case "IpAddress", "NotIpAddress":
		pfx, err := parseIPOrCIDR(want)
		if err != nil {
			return false
		}
		addr, err := netip.ParseAddr(val)
		return err == nil && pfx.Contains(addr.Unmap())
	}
	// Numeric operators.
	a, err1 := strconv.ParseFloat(val, 64)
	b, err2 := strconv.ParseFloat(want, 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch c.Operator {
	case "NumericEquals", "NumericNotEquals":
		return a == b
	case "NumericLessThan":
		return a < b
	case "NumericLessThanEquals":
		return a <= b
	case "NumericGreaterThan":
		return a > b
	case "NumericGreaterThanEquals":
		return a >= b
	}
	return false
}

// Evaluate applies the AWS evaluation order: an explicit Deny wins, then an
// Allow, otherwise the request is implicitly denied.
func (p *Policy) Evaluate(req Request, username string) (allow, deny bool) {
	for i := range p.Statements {
		st := &p.Statements[i]
		if !st.matches(req, username) {
			continue
		}
		if st.Allow {
			allow = true
		} else {
			deny = true
		}
	}
	return allow, deny
}
