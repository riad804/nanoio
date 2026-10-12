package iam

import (
	"strings"
	"testing"
)

func TestParsePolicyAccepts(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		stmt int
	}{
		{"action and resource as strings", `{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}}`, 1},
		{"arrays and multiple statements", `{"Version":"2012-10-17","Statement":[
			{"Sid":"a","Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":["arn:aws:s3:::b/*"]},
			{"Sid":"b","Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}`, 2},
		{"old version string", `{"Version":"2008-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, 1},
		{"NotAction and NotResource", `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","NotAction":"s3:Get*","NotResource":"arn:aws:s3:::pub/*"}]}`, 1},
		{"star action", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}`, 1},
		{"conditions", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b",
			"Condition":{"StringLike":{"s3:prefix":["home/${aws:username}/*","shared/*"]},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"},
			"Bool":{"aws:SecureTransport":true},"NumericLessThanEquals":{"s3:max-keys":100}}}]}`, 1},
		{"policy id is tolerated", `{"Version":"2012-10-17","Id":"p1","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`, 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(tt.doc))
			if err != nil {
				t.Fatal(err)
			}
			if len(p.Statements) != tt.stmt {
				t.Errorf("statements = %d, want %d", len(p.Statements), tt.stmt)
			}
		})
	}
}

func TestParsePolicyRejects(t *testing.T) {
	stmt := func(s string) string { return `{"Version":"2012-10-17","Statement":[` + s + `]}` }
	tests := []struct {
		name string
		doc  string
		want string
	}{
		{"not json", `{`, "policy:"},
		{"empty", ``, "policy:"},
		{"trailing data", `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]} {}`, "trailing"},
		{"no version", `{"Statement":[]}`, "Version"},
		{"wrong version", `{"Version":"2020-01-01","Statement":[]}`, "Version"},
		{"no statement", `{"Version":"2012-10-17"}`, "Statement"},
		{"empty statements", `{"Version":"2012-10-17","Statement":[]}`, "empty"},
		{"unknown top-level field", `{"Version":"2012-10-17","Statement":[],"Extra":1}`, "unknown field"},
		{"unknown statement field", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Typo":1}`), "unknown field"},
		{"bad effect", stmt(`{"Effect":"allow","Action":"s3:*","Resource":"*"}`), "Effect"},
		{"missing effect", stmt(`{"Action":"s3:*","Resource":"*"}`), "Effect"},
		{"no action", stmt(`{"Effect":"Allow","Resource":"*"}`), "Action"},
		{"action and notaction", stmt(`{"Effect":"Allow","Action":"s3:*","NotAction":"s3:Get*","Resource":"*"}`), "Action"},
		{"no resource", stmt(`{"Effect":"Allow","Action":"s3:*"}`), "Resource"},
		{"resource and notresource", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","NotResource":"*"}`), "Resource"},
		{"principal in identity policy", stmt(`{"Effect":"Allow","Principal":"*","Action":"s3:*","Resource":"*"}`), "Principal"},
		{"notprincipal", stmt(`{"Effect":"Allow","NotPrincipal":"*","Action":"s3:*","Resource":"*"}`), "Principal"},
		{"non-s3 action", stmt(`{"Effect":"Allow","Action":"ec2:*","Resource":"*"}`), "only s3"},
		{"unknown action family", stmt(`{"Effect":"Allow","Action":"iam:CreateUser","Resource":"*"}`), "supported"},
		{"non-s3 resource", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:ec2:::x"}`), "arn:aws:s3"},
		{"action not a string", stmt(`{"Effect":"Allow","Action":5,"Resource":"*"}`), "string"},
		{"unsupported operator", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"ForAllValues:StringLike":{"s3:prefix":"a"}}}`), "not supported"},
		{"IfExists operator", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEqualsIfExists":{"s3:prefix":"a"}}}`), "not supported"},
		{"date operator", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"DateLessThan":{"aws:CurrentTime":"2030-01-01T00:00:00Z"}}}`), "not supported"},
		{"bad cidr", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"IpAddress":{"aws:SourceIp":"10.0.0.0/99"}}}`), "CIDR"},
		{"bad bool", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"Bool":{"aws:SecureTransport":"maybe"}}}`), "true or false"},
		{"bad number", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"NumericEquals":{"s3:max-keys":"lots"}}}`), "number"},
		{"empty condition values", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"*","Condition":{"StringEquals":{"s3:prefix":[]}}}`), "no values"},
		{"unsupported variable", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::${aws:userid}/*"}`), "not supported"},
		{"unterminated variable", stmt(`{"Effect":"Allow","Action":"s3:*","Resource":"arn:aws:s3:::${aws:username"}`), "unterminated"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := ParsePolicy([]byte(tt.doc))
			if err == nil {
				t.Fatalf("accepted: %+v", p)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not mention %q", err, tt.want)
			}
		})
	}
}

func TestGlob(t *testing.T) {
	tests := []struct {
		pattern, s string
		fold, want bool
	}{
		{"*", "", false, true},
		{"*", "anything/at/all", false, true},
		{"abc", "abc", false, true},
		{"abc", "abd", false, false},
		{"abc", "ab", false, false},
		{"a?c", "abc", false, true},
		{"a?c", "ac", false, false},
		{"a*c", "ac", false, true},
		{"a*c", "abbbc", false, true},
		{"a*c", "abbbcd", false, false},
		{"*.txt", "dir/file.txt", false, true},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::b/k/e/y", false, true},
		{"arn:aws:s3:::b/*", "arn:aws:s3:::b", false, false},
		{"arn:aws:s3:::b*", "arn:aws:s3:::bucket/k", false, true},
		{"**", "x", false, true},
		{"a*b*c", "aXbYc", false, true},
		{"a*b*c", "aXcYb", false, false},
		{"S3:Get*", "s3:getobject", true, true},
		{"S3:Get*", "s3:getobject", false, false},
		{"*a", "baaa", false, true},
		{"?", "", false, false},
		{"", "", false, true},
		{"", "x", false, false},
		// A literal '*' in the subject is matched by a wildcard, not treated as one.
		{"a*c", "a*c", false, true},
		{"abc", "a*c", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"|"+tt.s, func(t *testing.T) {
			if got := glob(tt.pattern, tt.s, tt.fold); got != tt.want {
				t.Errorf("glob(%q, %q, fold=%v) = %v, want %v", tt.pattern, tt.s, tt.fold, got, tt.want)
			}
		})
	}
	// Pathological patterns finish quickly (no exponential backtracking).
	long := strings.Repeat("a", 5000)
	if glob(strings.Repeat("a*", 200)+"b", long, false) {
		t.Error("pathological pattern matched")
	}
}

func mustPolicy(t *testing.T, doc string) *Policy {
	t.Helper()
	p, err := ParsePolicy([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEvaluate(t *testing.T) {
	policy := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"arn:aws:s3:::data/*"},
		{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::data"},
		{"Effect":"Deny","Action":"s3:*","Resource":"arn:aws:s3:::data/secret/*"},
		{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}`)
	tests := []struct {
		name        string
		req         Request
		allow, deny bool
	}{
		{"get object", Request{Action: "s3:GetObject", Bucket: "data", Key: "a.txt"}, true, false},
		{"put object", Request{Action: "s3:PutObject", Bucket: "data", Key: "dir/a.txt"}, true, false},
		{"action is case-insensitive", Request{Action: "S3:GETOBJECT", Bucket: "data", Key: "a"}, true, false},
		{"delete not granted", Request{Action: "s3:DeleteObject", Bucket: "data", Key: "a"}, false, false},
		{"other bucket", Request{Action: "s3:GetObject", Bucket: "other", Key: "a"}, false, false},
		{"object rule does not cover the bucket", Request{Action: "s3:GetObject", Bucket: "data"}, false, false},
		{"list bucket", Request{Action: "s3:ListBucket", Bucket: "data"}, true, false},
		{"list bucket on other bucket", Request{Action: "s3:ListBucket", Bucket: "other"}, false, false},
		{"explicit deny under allow", Request{Action: "s3:GetObject", Bucket: "data", Key: "secret/x"}, true, true},
		{"deny prefix boundary", Request{Action: "s3:GetObject", Bucket: "data", Key: "secrets/x"}, true, false},
		{"list all my buckets", Request{Action: "s3:ListAllMyBuckets"}, true, false},
		{"resource is case-sensitive", Request{Action: "s3:GetObject", Bucket: "DATA", Key: "a"}, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, deny := policy.Evaluate(tt.req, "alice")
			if allow != tt.allow || deny != tt.deny {
				t.Errorf("allow=%v deny=%v, want %v %v", allow, deny, tt.allow, tt.deny)
			}
		})
	}
}

func TestEvaluateNotActionNotResource(t *testing.T) {
	p := mustPolicy(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","NotAction":["s3:DeleteObject","s3:DeleteBucket"],"Resource":"*"},
		{"Effect":"Deny","Action":"s3:PutObject","NotResource":"arn:aws:s3:::scratch/*"}]}`)
	tests := []struct {
		name        string
		req         Request
		allow, deny bool
	}{
		{"get allowed by NotAction", Request{Action: "s3:GetObject", Bucket: "b", Key: "k"}, true, false},
		{"delete excluded", Request{Action: "s3:DeleteObject", Bucket: "b", Key: "k"}, false, false},
		{"put outside scratch denied", Request{Action: "s3:PutObject", Bucket: "b", Key: "k"}, true, true},
		{"put inside scratch fine", Request{Action: "s3:PutObject", Bucket: "scratch", Key: "k"}, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, d := p.Evaluate(tt.req, "u")
			if a != tt.allow || d != tt.deny {
				t.Errorf("allow=%v deny=%v, want %v %v", a, d, tt.allow, tt.deny)
			}
		})
	}
}

func TestConditions(t *testing.T) {
	list := func(op, key, values string) *Policy {
		return mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b",
			"Condition":{"`+op+`":{"`+key+`":`+values+`}}}]}`)
	}
	ctx := func(kv ...string) map[string]string {
		m := map[string]string{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i]] = kv[i+1]
		}
		return m
	}
	tests := []struct {
		name   string
		policy *Policy
		ctx    map[string]string
		want   bool
	}{
		{"StringEquals hit", list("StringEquals", "s3:prefix", `"home/"`), ctx("s3:prefix", "home/"), true},
		{"StringEquals miss", list("StringEquals", "s3:prefix", `"home/"`), ctx("s3:prefix", "etc/"), false},
		{"StringEquals key absent", list("StringEquals", "s3:prefix", `"home/"`), ctx(), false},
		{"StringEquals any of several", list("StringEquals", "s3:prefix", `["a/","b/"]`), ctx("s3:prefix", "b/"), true},
		{"StringNotEquals miss means true", list("StringNotEquals", "s3:prefix", `"secret/"`), ctx("s3:prefix", "pub/"), true},
		{"StringNotEquals hit", list("StringNotEquals", "s3:prefix", `"secret/"`), ctx("s3:prefix", "secret/"), false},
		{"StringNotEquals key absent is true", list("StringNotEquals", "s3:prefix", `"secret/"`), ctx(), true},
		{"StringNotEquals none of several", list("StringNotEquals", "s3:prefix", `["a/","b/"]`), ctx("s3:prefix", "b/"), false},
		{"StringLike hit", list("StringLike", "s3:prefix", `"home/*"`), ctx("s3:prefix", "home/alice/x"), true},
		{"StringLike miss", list("StringLike", "s3:prefix", `"home/*"`), ctx("s3:prefix", "work/x"), false},
		{"StringNotLike", list("StringNotLike", "s3:prefix", `"tmp/*"`), ctx("s3:prefix", "tmp/x"), false},
		{"StringEqualsIgnoreCase", list("StringEqualsIgnoreCase", "s3:delimiter", `"/"`), ctx("s3:delimiter", "/"), true},
		{"condition key is case-insensitive", list("StringEquals", "S3:Prefix", `"a"`), ctx("s3:prefix", "a"), true},
		{"Bool true", list("Bool", "aws:SecureTransport", `"true"`), ctx("aws:securetransport", "true"), true},
		{"Bool false required", list("Bool", "aws:SecureTransport", `true`), ctx("aws:securetransport", "false"), false},
		{"IpAddress in cidr", list("IpAddress", "aws:SourceIp", `"10.0.0.0/8"`), ctx("aws:sourceip", "10.1.2.3"), true},
		{"IpAddress outside cidr", list("IpAddress", "aws:SourceIp", `"10.0.0.0/8"`), ctx("aws:sourceip", "192.168.1.1"), false},
		{"IpAddress single host", list("IpAddress", "aws:SourceIp", `"203.0.113.7"`), ctx("aws:sourceip", "203.0.113.7"), true},
		{"IpAddress v4-mapped v6", list("IpAddress", "aws:SourceIp", `"10.0.0.0/8"`), ctx("aws:sourceip", "::ffff:10.1.1.1"), true},
		{"IpAddress ipv6 cidr", list("IpAddress", "aws:SourceIp", `"2001:db8::/32"`), ctx("aws:sourceip", "2001:db8::1"), true},
		{"IpAddress unparsable source", list("IpAddress", "aws:SourceIp", `"10.0.0.0/8"`), ctx("aws:sourceip", "garbage"), false},
		{"NotIpAddress outside", list("NotIpAddress", "aws:SourceIp", `"10.0.0.0/8"`), ctx("aws:sourceip", "8.8.8.8"), true},
		{"NotIpAddress inside", list("NotIpAddress", "aws:SourceIp", `"10.0.0.0/8"`), ctx("aws:sourceip", "10.0.0.1"), false},
		{"NumericLessThanEquals ok", list("NumericLessThanEquals", "s3:max-keys", `100`), ctx("s3:max-keys", "100"), true},
		{"NumericLessThanEquals over", list("NumericLessThanEquals", "s3:max-keys", `100`), ctx("s3:max-keys", "101"), false},
		{"NumericGreaterThan", list("NumericGreaterThan", "s3:max-keys", `"5"`), ctx("s3:max-keys", "6"), true},
		{"Numeric non-number in request", list("NumericEquals", "s3:max-keys", `5`), ctx("s3:max-keys", "five"), false},
		{"policy variable in condition", list("StringLike", "s3:prefix", `"home/${aws:username}/*"`), ctx("s3:prefix", "home/alice/f"), true},
		{"policy variable other user", list("StringLike", "s3:prefix", `"home/${aws:username}/*"`), ctx("s3:prefix", "home/bob/f"), false},
		{"aws:username key", list("StringEquals", "aws:username", `"alice"`), ctx(), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			allow, _ := tt.policy.Evaluate(Request{Action: "s3:ListBucket", Bucket: "b", Context: tt.ctx}, "alice")
			if allow != tt.want {
				t.Errorf("allow = %v, want %v", allow, tt.want)
			}
		})
	}

	t.Run("all keys and operators must hold", func(t *testing.T) {
		p := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::b",
			"Condition":{"StringEquals":{"s3:prefix":"a/","s3:delimiter":"/"},"IpAddress":{"aws:SourceIp":"10.0.0.0/8"}}}]}`)
		req := func(prefix, delim, ip string) Request {
			return Request{Action: "s3:ListBucket", Bucket: "b",
				Context: map[string]string{"s3:prefix": prefix, "s3:delimiter": delim, "aws:sourceip": ip}}
		}
		if a, _ := p.Evaluate(req("a/", "/", "10.0.0.1"), "u"); !a {
			t.Error("all conditions hold but denied")
		}
		for _, r := range []Request{req("b/", "/", "10.0.0.1"), req("a/", "", "10.0.0.1"), req("a/", "/", "1.1.1.1")} {
			if a, _ := p.Evaluate(r, "u"); a {
				t.Errorf("allowed with a failing condition: %+v", r.Context)
			}
		}
	})
	t.Run("deny with unmet condition does not apply", func(t *testing.T) {
		p := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:*","Resource":"*",
			"Condition":{"Bool":{"aws:SecureTransport":"false"}}}]}`)
		if _, d := p.Evaluate(Request{Action: "s3:GetObject", Bucket: "b", Key: "k",
			Context: map[string]string{"aws:securetransport": "true"}}, "u"); d {
			t.Error("deny applied although its condition is false")
		}
		if _, d := p.Evaluate(Request{Action: "s3:GetObject", Bucket: "b", Key: "k",
			Context: map[string]string{"aws:securetransport": "false"}}, "u"); !d {
			t.Error("deny did not apply when its condition holds")
		}
	})
}

func TestVariableSubstitutionInResources(t *testing.T) {
	p := mustPolicy(t, `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":
		["arn:aws:s3:::home/${aws:username}","arn:aws:s3:::home/${aws:username}/*"]}]}`)
	for _, tt := range []struct {
		user, key string
		want      bool
	}{
		{"alice", "alice/file", true},
		{"alice", "bob/file", false},
		{"bob", "bob/file", true},
		{"alice", "alice", true},
		{"alice", "alicex/file", false},
	} {
		a, _ := p.Evaluate(Request{Action: "s3:GetObject", Bucket: "home", Key: tt.key}, tt.user)
		if a != tt.want {
			t.Errorf("user %s key %s: allow=%v, want %v", tt.user, tt.key, a, tt.want)
		}
	}
}

func TestRequestARN(t *testing.T) {
	tests := []struct {
		req  Request
		want string
	}{
		{Request{}, "arn:aws:s3:::*"},
		{Request{Bucket: "b"}, "arn:aws:s3:::b"},
		{Request{Bucket: "b", Key: "a/b.txt"}, "arn:aws:s3:::b/a/b.txt"},
		{Request{Bucket: "b", Key: "dir/"}, "arn:aws:s3:::b/dir/"},
	}
	for _, tt := range tests {
		if got := tt.req.ARN(); got != tt.want {
			t.Errorf("ARN() = %q, want %q", got, tt.want)
		}
	}
}
