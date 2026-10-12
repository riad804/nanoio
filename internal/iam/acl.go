package iam

import (
	"fmt"
	"strings"
)

// ACL group URIs.
const (
	GroupAllUsers           = "http://acs.amazonaws.com/groups/global/AllUsers"
	GroupAuthenticatedUsers = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"
)

// ACL permissions.
const (
	PermRead        = "READ"
	PermWrite       = "WRITE"
	PermReadACP     = "READ_ACP"
	PermWriteACP    = "WRITE_ACP"
	PermFullControl = "FULL_CONTROL"
)

// Grant gives one grantee one permission. Exactly one of User (an access
// key) and Group (a group URI) is set.
type Grant struct {
	User  string `json:"user,omitempty"`
	Group string `json:"group,omitempty"`
	Perm  string `json:"perm"`
}

// ValidPerm reports whether p is an ACL permission.
func ValidPerm(p string) bool {
	switch p {
	case PermRead, PermWrite, PermReadACP, PermWriteACP, PermFullControl:
		return true
	}
	return false
}

// CannedGrants expands a canned ACL into grants. The owner's implicit
// FULL_CONTROL is not included. object selects the object form: for an
// object, public-read-write grants READ and WRITE as S3 documents but only
// READ has any effect on a single object.
func CannedGrants(name string) ([]Grant, error) {
	switch name {
	case "private", "":
		return nil, nil
	case "public-read":
		return []Grant{{Group: GroupAllUsers, Perm: PermRead}}, nil
	case "public-read-write":
		return []Grant{{Group: GroupAllUsers, Perm: PermRead}, {Group: GroupAllUsers, Perm: PermWrite}}, nil
	case "authenticated-read":
		return []Grant{{Group: GroupAuthenticatedUsers, Perm: PermRead}}, nil
	}
	return nil, fmt.Errorf("unsupported canned ACL %q", name)
}

// ACLStatements maps grants to policy statements, so an ACL is evaluated by
// the one policy engine and never by a second authorisation path. For a
// bucket (key == "") READ allows listing, WRITE allows creating and deleting
// objects in it, READ_ACP and WRITE_ACP allow reading and replacing the
// bucket's ACL. For an object READ allows reading it, READ_ACP and
// WRITE_ACP reading and replacing its ACL; WRITE has no object-level
// meaning.
func ACLStatements(bucket, key string, grants []Grant) []Statement {
	var actions func(perm string) []string
	var resource string
	if key == "" {
		resource = "arn:aws:s3:::" + bucket
		actions = func(perm string) []string {
			switch perm {
			case PermRead:
				return []string{"s3:ListBucket", "s3:ListBucketVersions", "s3:ListBucketMultipartUploads"}
			case PermReadACP:
				return []string{"s3:GetBucketAcl"}
			case PermWriteACP:
				return []string{"s3:PutBucketAcl"}
			}
			return nil
		}
	} else {
		resource = "arn:aws:s3:::" + bucket + "/" + key
		actions = func(perm string) []string {
			switch perm {
			case PermRead:
				return []string{"s3:GetObject", "s3:GetObjectVersion"}
			case PermReadACP:
				return []string{"s3:GetObjectAcl", "s3:GetObjectVersionAcl"}
			case PermWriteACP:
				return []string{"s3:PutObjectAcl", "s3:PutObjectVersionAcl"}
			}
			return nil
		}
	}
	var out []Statement
	add := func(g Grant, acts []string, res string, literal bool) {
		if len(acts) == 0 {
			return
		}
		st := Statement{Allow: true, Actions: acts, Resources: []string{res}, LiteralResources: literal, LiteralPrincipals: true}
		switch {
		case g.Group == GroupAllUsers:
			st.Principals = []string{"*"}
		case g.Group == GroupAuthenticatedUsers:
			st.Principals, st.AuthenticatedOnly = []string{"*"}, true
		case g.User != "":
			st.Principals = []string{g.User}
		default:
			return
		}
		out = append(out, st)
	}
	for _, g := range grants {
		perms := []string{g.Perm}
		if g.Perm == PermFullControl {
			perms = []string{PermRead, PermWrite, PermReadACP, PermWriteACP}
		}
		for _, p := range perms {
			add(g, actions(p), resource, true)
			if key == "" && p == PermWrite {
				// Writing to a bucket is about the objects in it.
				add(g, []string{"s3:PutObject", "s3:DeleteObject", "s3:DeleteObjectVersion",
					"s3:AbortMultipartUpload"}, "arn:aws:s3:::"+bucket+"/*", false)
			}
		}
	}
	return out
}

// EvaluateStatements applies pre-built statements to a request, with the
// same semantics as a bucket policy.
func EvaluateStatements(sts []Statement, req Request, who Principal) (allow, deny bool) {
	return (&BucketPolicy{Statements: sts}).Evaluate(req, who)
}

// ObjectACLActions lists the actions whose authorisation consults an
// object's ACL.
func ObjectACLActions(action string) bool {
	switch strings.ToLower(action) {
	case "s3:getobject", "s3:getobjectversion", "s3:getobjectacl", "s3:getobjectversionacl",
		"s3:putobjectacl", "s3:putobjectversionacl":
		return true
	}
	return false
}

// BucketACLActions lists the actions whose authorisation consults a bucket's
// ACL.
func BucketACLActions(action string) bool {
	switch strings.ToLower(action) {
	case "s3:listbucket", "s3:listbucketversions", "s3:listbucketmultipartuploads",
		"s3:putobject", "s3:deleteobject", "s3:deleteobjectversion", "s3:abortmultipartupload",
		"s3:getbucketacl", "s3:putbucketacl":
		return true
	}
	return false
}
