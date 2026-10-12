package iam

import (
	"strings"
	"testing"
)

func TestParseBucketPolicy(t *testing.T) {
	st := func(s string) string { return `{"Version":"2012-10-17","Statement":[` + s + `]}` }
	good := []string{
		st(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		st(`{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:*","Resource":["arn:aws:s3:::b","arn:aws:s3:::b/*"]}`),
		st(`{"Effect":"Deny","Principal":{"AWS":["arn:aws:iam::nanoio:user/alice","bob","arn:aws:iam::nanoio:root"]},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"}`),
		st(`{"Effect":"Deny","NotPrincipal":{"AWS":"alice"},"Action":"s3:*","Resource":"arn:aws:s3:::b/*"}`),
		st(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:user/team-*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/${aws:username}/*"}`),
		`{"Version":"2012-10-17","Statement":{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/x"}}`,
	}
	for i, doc := range good {
		if _, err := ParseBucketPolicy([]byte(doc), "b"); err != nil {
			t.Errorf("good %d: %v", i, err)
		}
	}
	bad := map[string]string{
		"no principal":          st(`{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"both":                  st(`{"Effect":"Allow","Principal":"*","NotPrincipal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"string not star":       st(`{"Effect":"Allow","Principal":"alice","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"foreign arn":           st(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111122223333:user/x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"bad nanoio arn":        st(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:group/x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"federated":             st(`{"Effect":"Allow","Principal":{"Federated":"x"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"other bucket":          st(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::c/*"}`),
		"bucket prefix":         st(`{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::bb/*"}`),
		"notresource":           st(`{"Effect":"Deny","Principal":"*","Action":"s3:*","NotResource":"arn:aws:s3:::c/*"}`),
		"empty aws":             st(`{"Effect":"Allow","Principal":{"AWS":[]},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"variable in principal": st(`{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:user/${aws:username}"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}`),
		"too big":               `{"Version":"2012-10-17","Id":"` + strings.Repeat("x", MaxBucketPolicySize) + `","Statement":[]}`,
	}
	for name, doc := range bad {
		if _, err := ParseBucketPolicy([]byte(doc), "b"); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// An identity policy still refuses a Principal.
	if _, err := ParsePolicy([]byte(good[0])); err == nil {
		t.Error("identity policy accepted a Principal")
	}
}

func TestBucketPolicyPrincipalMatching(t *testing.T) {
	p, err := ParseBucketPolicy([]byte(`{"Version":"2012-10-17","Statement":[
	  {"Sid":"star","Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/pub/*"},
	  {"Sid":"alice","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:user/alice"},"Action":"s3:PutObject","Resource":"arn:aws:s3:::b/*"},
	  {"Sid":"team","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:user/team-*"},"Action":"s3:ListBucket","Resource":"arn:aws:s3:::b"},
	  {"Sid":"bare","Effect":"Allow","Principal":{"AWS":"carol"},"Action":"s3:DeleteObject","Resource":"arn:aws:s3:::b/*"},
	  {"Sid":"root","Effect":"Allow","Principal":{"AWS":"arn:aws:iam::nanoio:root"},"Action":"s3:GetBucketPolicy","Resource":"arn:aws:s3:::b"},
	  {"Sid":"notbob","Effect":"Deny","NotPrincipal":{"AWS":"bob"},"Action":"s3:GetObjectAcl","Resource":"arn:aws:s3:::b/*"}
	]}`), "b")
	if err != nil {
		t.Fatal(err)
	}
	anon := Principal{Anonymous: true}
	user := func(k string) Principal { return Principal{AccessKey: k} }
	tests := []struct {
		name        string
		who         Principal
		action      string
		bucket, key string
		allow, deny bool
	}{
		{"anonymous matches *", anon, "s3:GetObject", "b", "pub/x", true, false},
		{"anonymous does not match a named user", anon, "s3:PutObject", "b", "x", false, false},
		{"alice by ARN", user("alice"), "s3:PutObject", "b", "x", true, false},
		{"mallory is not alice", user("mallory"), "s3:PutObject", "b", "x", false, false},
		{"wildcard principal", user("team-red"), "s3:ListBucket", "b", "", true, false},
		{"wildcard principal miss", user("red-team"), "s3:ListBucket", "b", "", false, false},
		{"bare access key", user("carol"), "s3:DeleteObject", "b", "x", true, false},
		{"root by ARN", Principal{AccessKey: "admin", Root: true}, "s3:GetBucketPolicy", "b", "", true, false},
		{"a user is not root", user("admin"), "s3:GetBucketPolicy", "b", "", false, false},
		{"NotPrincipal denies others", user("alice"), "s3:GetObjectAcl", "b", "x", false, true},
		{"NotPrincipal spares the exception", user("bob"), "s3:GetObjectAcl", "b", "x", false, false},
		{"NotPrincipal denies anonymous", anon, "s3:GetObjectAcl", "b", "x", false, true},
		{"action case is insensitive", user("alice"), "S3:putobject", "b", "x", true, false},
		{"resource is case sensitive", anon, "s3:GetObject", "b", "PUB/x", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, d := p.Evaluate(Request{Action: tt.action, Bucket: tt.bucket, Key: tt.key}, tt.who)
			if a != tt.allow || d != tt.deny {
				t.Errorf("allow=%v deny=%v, want allow=%v deny=%v", a, d, tt.allow, tt.deny)
			}
		})
	}
}
