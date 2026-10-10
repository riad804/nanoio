package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	now    = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	signer = Signer{AccessKey: "alice", SecretKey: "alice-secret-key-1234"}
)

func verifier() *Verifier {
	return &Verifier{
		Provider: staticCreds{"alice": "alice-secret-key-1234"},
		Region:   "us-east-1",
		Now:      func() time.Time { return now },
	}
}

// newReq builds a server-style request: RequestURI and Host are set the way
// net/http's server sets them.
func newReq(method, target string, hdr map[string]string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Host = "localhost:9000"
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	return r
}

func TestHeaderAuthRoundTrip(t *testing.T) {
	targets := []struct{ name, method, target string }{
		{"service", "GET", "/"},
		{"bucket", "PUT", "/bucket"},
		{"object", "GET", "/bucket/key.txt"},
		{"nested key", "PUT", "/bucket/a/b/c.txt"},
		{"space in key", "GET", "/bucket/a%20b"},
		{"plus in key", "GET", "/bucket/a%2Bb"},
		{"literal plus in path", "GET", "/bucket/a+b"},
		{"unicode key", "GET", "/bucket/%E6%97%A5%E6%9C%AC%E8%AA%9E.txt"},
		{"tilde and symbols", "GET", "/bucket/~user/$a&b=c"},
		{"double slash in key", "GET", "/bucket/a//b"},
		{"dot dot in key", "GET", "/bucket/a/../b"},
		{"percent in key", "GET", "/bucket/100%25"},
		{"folder placeholder", "PUT", "/bucket/dir/"},
		{"query", "GET", "/bucket?list-type=2&prefix=a%20b&delimiter=%2F"},
		{"query out of order", "GET", "/bucket?z=1&a=2&m=3"},
		{"valueless subresource", "POST", "/bucket?delete"},
		{"repeated and empty params", "GET", "/bucket?a=2&a=1&b="},
		{"encoded query keys", "GET", "/bucket?prefix=%C3%BC&max-keys=5"},
	}
	for _, tt := range targets {
		t.Run(tt.name, func(t *testing.T) {
			r := newReq(tt.method, tt.target, nil)
			signer.Sign(r, emptySHA256, now)
			res, err := verifier().Authenticate(r)
			if err != nil {
				t.Fatalf("Authenticate: %v", err)
			}
			if res.AccessKey != "alice" || res.Presigned || res.Chunk != nil || res.PayloadHash != emptySHA256 {
				t.Errorf("result = %+v", res)
			}
		})
	}
	t.Run("with signed metadata and content headers", func(t *testing.T) {
		r := newReq("PUT", "/bucket/k", map[string]string{
			"Content-Type": "text/plain", "Content-MD5": "1B2M2Y8AsgTpgAmY7PhCfg==",
			"X-Amz-Meta-Owner": "alice", "x-amz-storage-class": "STANDARD",
		})
		signer.Sign(r, PayloadUnsigned, now)
		res, err := verifier().Authenticate(r)
		if err != nil || res.PayloadHash != PayloadUnsigned {
			t.Errorf("Authenticate = %+v, %v", res, err)
		}
	})
	t.Run("date header fallback", func(t *testing.T) {
		r := newReq("GET", "/bucket/k", nil)
		signer.Sign(r, emptySHA256, now)
		// Re-sign with a Date header instead of X-Amz-Date.
		r.Header.Del("X-Amz-Date")
		r.Header.Set("Date", now.Format(http.TimeFormat))
		r.Header.Del("Authorization")
		authz := manualHeaderAuth(r, signer, "date;host;x-amz-content-sha256", now, now.Format(amzDateLayout))
		r.Header.Set("Authorization", authz)
		if _, err := verifier().Authenticate(r); err != nil {
			t.Errorf("Date header auth: %v", err)
		}
	})
}

// manualHeaderAuth signs an arbitrary header list, for cases Signer.Sign
// does not produce.
func manualHeaderAuth(r *http.Request, s Signer, signedList string, t time.Time, amzDate string) string {
	region, service := s.regionService()
	date := t.UTC().Format(scopeDateLayout)
	signed := strings.Split(signedList, ";")
	hdrs, _ := canonicalHeaders(requestHeaders(r), signed)
	creq := canonicalRequest(r.Method, canonicalURIS3(r.URL.Path), canonicalQuery(rawQueryOf(r), nil), hdrs, signed,
		r.Header.Get("X-Amz-Content-Sha256"))
	scope := scopeString(date, region, service)
	sig := hexMAC(signingKey(s.SecretKey, date, region, service), stringToSign(amzDate, scope, creq))
	return Algorithm + " Credential=" + s.AccessKey + "/" + scope + ", SignedHeaders=" + signedList + ", Signature=" + sig
}

func TestHeaderAuthRejects(t *testing.T) {
	good := func() *http.Request {
		r := newReq("GET", "/bucket/key?x=1", nil)
		signer.Sign(r, emptySHA256, now)
		return r
	}
	replaceAuthz := func(old, new string) func(*http.Request) {
		return func(r *http.Request) {
			a := r.Header.Get("Authorization")
			if !strings.Contains(a, old) {
				panic("test bug: " + old + " not in " + a)
			}
			r.Header.Set("Authorization", strings.Replace(a, old, new, 1))
		}
	}
	tests := []struct {
		name   string
		mutate func(*http.Request)
		verif  func(*Verifier)
		want   error
	}{
		{"anonymous", func(r *http.Request) { r.Header.Del("Authorization") }, nil, ErrAnonymous},
		{"sigv2 header", func(r *http.Request) { r.Header.Set("Authorization", "AWS alice:abc=") }, nil, ErrUnsupportedAlgorithm},
		{"ecdsa algorithm", func(r *http.Request) { r.Header.Set("Authorization", "AWS4-ECDSA-P256-SHA256 Credential=a") }, nil, ErrUnsupportedAlgorithm},
		{"sigv2 presigned", func(r *http.Request) {
			r.Header.Del("Authorization")
			r.URL.RawQuery = "AWSAccessKeyId=alice&Signature=x&Expires=1"
			r.RequestURI = "/bucket/key?" + r.URL.RawQuery
		}, nil, ErrUnsupportedAlgorithm},
		{"unknown access key", replaceAuthz("Credential=alice/", "Credential=mallory/"), nil, ErrInvalidAccessKeyID},
		{"signature flipped", func(r *http.Request) {
			a := r.Header.Get("Authorization")
			c := byte('0')
			if a[len(a)-1] == '0' {
				c = '1'
			}
			r.Header.Set("Authorization", a[:len(a)-1]+string(c))
		}, nil, ErrSignatureDoesNotMatch},
		{"signature truncated", func(r *http.Request) {
			a := r.Header.Get("Authorization")
			r.Header.Set("Authorization", a[:len(a)-4])
		}, nil, ErrSignatureDoesNotMatch},
		{"x-amz header added after signing", func(r *http.Request) {
			r.Header.Set("X-Amz-Meta-Late", "added after signing")
		}, nil, ErrUnsignedHeaders},
		{"tampered path", func(r *http.Request) { r.URL.Path = "/bucket/other" }, nil, ErrSignatureDoesNotMatch},
		{"tampered query", func(r *http.Request) {
			r.RequestURI = "/bucket/key?x=2"
			r.URL.RawQuery = "x=2"
		}, nil, ErrSignatureDoesNotMatch},
		{"extra query param", func(r *http.Request) {
			r.RequestURI = "/bucket/key?x=1&y=2"
			r.URL.RawQuery = "x=1&y=2"
		}, nil, ErrSignatureDoesNotMatch},
		{"tampered method", func(r *http.Request) { r.Method = "DELETE" }, nil, ErrSignatureDoesNotMatch},
		{"tampered host", func(r *http.Request) { r.Host = "evil.example" }, nil, ErrSignatureDoesNotMatch},
		{"tampered payload hash", func(r *http.Request) {
			r.Header.Set("X-Amz-Content-Sha256", strings.Repeat("a", 64))
		}, nil, ErrSignatureDoesNotMatch},
		{"missing payload hash header", func(r *http.Request) { r.Header.Del("X-Amz-Content-Sha256") }, nil, ErrMissingSecurityHeader},
		{"invalid payload hash value", func(r *http.Request) { r.Header.Set("X-Amz-Content-Sha256", "not-a-hash") }, nil, ErrInvalidPayloadHash},
		{"security token", func(r *http.Request) { r.Header.Set("X-Amz-Security-Token", "tok") }, nil, ErrInvalidToken},
		{"missing both date headers", func(r *http.Request) { r.Header.Del("X-Amz-Date") }, nil, ErrMissingSecurityHeader},
		{"malformed x-amz-date", func(r *http.Request) { r.Header.Set("X-Amz-Date", "2026-10-10") }, nil, ErrAuthHeaderMalformed},
		{"time 16 minutes ahead", nil, func(v *Verifier) { v.Now = func() time.Time { return now.Add(16 * time.Minute) } }, ErrRequestTimeTooSkewed},
		{"time 16 minutes behind", nil, func(v *Verifier) { v.Now = func() time.Time { return now.Add(-16 * time.Minute) } }, ErrRequestTimeTooSkewed},
		{"credential with four parts", replaceAuthz("/us-east-1/s3/aws4_request", "/s3/aws4_request"), nil, ErrAuthHeaderMalformed},
		{"wrong terminator", replaceAuthz("aws4_request", "aws5_request"), nil, ErrAuthHeaderMalformed},
		{"wrong service", replaceAuthz("/s3/aws4_request", "/ec2/aws4_request"), nil, ErrAuthHeaderMalformed},
		{"wrong region", replaceAuthz("/us-east-1/", "/eu-west-1/"), nil, ErrAuthHeaderMalformed},
		{"scope date differs from request date", replaceAuthz("/20261010/", "/20261009/"), nil, ErrAuthHeaderMalformed},
		{"host not signed", func(r *http.Request) {
			r.Header.Set("Authorization", manualHeaderAuth(r, signer, "x-amz-content-sha256;x-amz-date", now, now.Format(amzDateLayout)))
		}, nil, ErrAuthHeaderMalformed},
		{"signed header absent from request", func(r *http.Request) {
			r.Header.Set("Authorization", strings.Replace(r.Header.Get("Authorization"), "SignedHeaders=", "SignedHeaders=content-md5;", 1))
		}, nil, ErrSignatureDoesNotMatch},
		{"fields missing", func(r *http.Request) {
			r.Header.Set("Authorization", Algorithm+" Credential=alice/20261010/us-east-1/s3/aws4_request")
		}, nil, ErrAuthHeaderMalformed},
		{"garbage fields", func(r *http.Request) { r.Header.Set("Authorization", Algorithm+" hello") }, nil, ErrAuthHeaderMalformed},
		{"header and query auth together", func(r *http.Request) {
			r.RequestURI += "&X-Amz-Algorithm=" + Algorithm
			r.URL.RawQuery += "&X-Amz-Algorithm=" + Algorithm
		}, nil, ErrAmbiguousAuth},
		{"unsigned x-amz header", func(r *http.Request) { r.Header.Set("X-Amz-Copy-Source", "/other/obj") }, nil, ErrUnsignedHeaders},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good()
			if tt.mutate != nil {
				tt.mutate(r)
			}
			v := verifier()
			if tt.verif != nil {
				tt.verif(v)
			}
			res, err := v.Authenticate(r)
			if !errors.Is(err, tt.want) {
				t.Fatalf("error = %v, want %v", err, tt.want)
			}
			if res != nil {
				t.Errorf("failed authentication returned a result: %+v", res)
			}
		})
	}

	t.Run("exactly 15 minutes of skew is accepted", func(t *testing.T) {
		v := verifier()
		v.Now = func() time.Time { return now.Add(15 * time.Minute) }
		if _, err := v.Authenticate(good()); err != nil {
			t.Errorf("15m skew: %v", err)
		}
	})
	t.Run("wrong secret", func(t *testing.T) {
		v := verifier()
		v.Provider = staticCreds{"alice": "a-different-secret-key"}
		if _, err := v.Authenticate(good()); !errors.Is(err, ErrSignatureDoesNotMatch) {
			t.Errorf("error = %v", err)
		}
	})
	t.Run("any region accepted when none configured", func(t *testing.T) {
		v := verifier()
		v.Region = ""
		r := newReq("GET", "/bucket/k", nil)
		Signer{AccessKey: "alice", SecretKey: "alice-secret-key-1234", Region: "ap-south-1"}.Sign(r, emptySHA256, now)
		if _, err := v.Authenticate(r); err != nil {
			t.Errorf("any-region: %v", err)
		}
	})
	t.Run("signature compared case-insensitively as hex", func(t *testing.T) {
		r := good()
		a := r.Header.Get("Authorization")
		i := strings.LastIndex(a, "Signature=") + len("Signature=")
		r.Header.Set("Authorization", a[:i]+strings.ToUpper(a[i:]))
		if _, err := verifier().Authenticate(r); err != nil {
			t.Errorf("upper-case hex: %v", err)
		}
	})
}

func TestPresigned(t *testing.T) {
	sign := func(method, target string, expires time.Duration, at time.Time) *http.Request {
		r := newReq(method, target, nil)
		signer.Presign(r, expires, at)
		r.RequestURI = r.URL.RequestURI()
		return r
	}
	t.Run("valid", func(t *testing.T) {
		for _, target := range []string{"/bucket/key", "/bucket/a%20b%2Bc", "/bucket/k?response-content-type=text%2Fplain", "/bucket?list-type=2&prefix=a"} {
			r := sign("GET", target, time.Hour, now)
			res, err := verifier().Authenticate(r)
			if err != nil || !res.Presigned || res.AccessKey != "alice" || res.PayloadHash != PayloadUnsigned {
				t.Errorf("%s: %+v, %v", target, res, err)
			}
		}
	})
	good := func() *http.Request { return sign("GET", "/bucket/key?v=1", time.Hour, now) }
	setQuery := func(r *http.Request, f func(q map[string][]string)) {
		q := r.URL.Query()
		f(q)
		r.URL.RawQuery = encodeValues(q)
		r.RequestURI = r.URL.RequestURI()
	}
	tests := []struct {
		name   string
		mutate func(*http.Request)
		at     time.Time
		want   error
	}{
		{"expired", nil, now.Add(time.Hour + time.Second), ErrRequestExpired},
		{"not yet valid", nil, now.Add(-16 * time.Minute), ErrRequestTimeTooSkewed},
		{"tampered path", func(r *http.Request) { r.URL.Path = "/bucket/other"; r.RequestURI = r.URL.RequestURI() }, now, ErrSignatureDoesNotMatch},
		{"tampered signed param", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["v"] = []string{"2"} })
		}, now, ErrSignatureDoesNotMatch},
		{"injected param", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["response-content-disposition"] = []string{"attachment"} })
		}, now, ErrSignatureDoesNotMatch},
		{"expires inflated", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-Expires"] = []string{"604800"} })
		}, now, ErrSignatureDoesNotMatch},
		{"wrong method", func(r *http.Request) { r.Method = "DELETE" }, now, ErrSignatureDoesNotMatch},
		{"wrong host", func(r *http.Request) { r.Host = "evil.example" }, now, ErrSignatureDoesNotMatch},
		{"missing signature", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { delete(q, "X-Amz-Signature") })
		}, now, ErrQueryParamsMalformed},
		{"missing expires", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { delete(q, "X-Amz-Expires") })
		}, now, ErrQueryParamsMalformed},
		{"expires zero", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-Expires"] = []string{"0"} })
		}, now, ErrQueryParamsMalformed},
		{"expires over a week", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-Expires"] = []string{"604801"} })
		}, now, ErrQueryParamsMalformed},
		{"expires not a number", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-Expires"] = []string{"soon"} })
		}, now, ErrQueryParamsMalformed},
		{"wrong algorithm", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-Algorithm"] = []string{"AWS4-ECDSA-P256-SHA256"} })
		}, now, ErrUnsupportedAlgorithm},
		{"security token", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-Security-Token"] = []string{"t"} })
		}, now, ErrInvalidToken},
		{"unknown key", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) {
				q["X-Amz-Credential"] = []string{strings.Replace(q["X-Amz-Credential"][0], "alice", "mallory", 1)}
			})
		}, now, ErrInvalidAccessKeyID},
		{"host not signed", func(r *http.Request) {
			setQuery(r, func(q map[string][]string) { q["X-Amz-SignedHeaders"] = []string{"x-amz-date"} })
		}, now, ErrQueryParamsMalformed},
		{"streaming payload not allowed", func(r *http.Request) {
			r.Header.Set("X-Amz-Content-Sha256", PayloadStreamingSigned)
		}, now, ErrInvalidPayloadHash},
		{"unsigned x-amz header", func(r *http.Request) { r.Header.Set("X-Amz-Acl", "public-read") }, now, ErrUnsignedHeaders},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := good()
			if tt.mutate != nil {
				tt.mutate(r)
			}
			v := verifier()
			v.Now = func() time.Time { return tt.at }
			if _, err := v.Authenticate(r); !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
		})
	}
	t.Run("valid until the last second", func(t *testing.T) {
		v := verifier()
		v.Now = func() time.Time { return now.Add(time.Hour) }
		if _, err := v.Authenticate(good()); err != nil {
			t.Errorf("at expiry: %v", err)
		}
	})
	t.Run("presigned PUT with signed content headers", func(t *testing.T) {
		r := newReq("PUT", "/bucket/up", map[string]string{"X-Amz-Meta-Tag": "v"})
		signer.Presign(r, time.Minute, now)
		r.RequestURI = r.URL.RequestURI()
		if _, err := verifier().Authenticate(r); err != nil {
			t.Errorf("presigned PUT: %v", err)
		}
	})
}

func encodeValues(q map[string][]string) string {
	var parts []string
	for k, vs := range q {
		for _, v := range vs {
			parts = append(parts, uriEncode(k, false)+"="+uriEncode(v, false))
		}
	}
	return strings.Join(parts, "&")
}

func TestChainedErrorsKeepDetail(t *testing.T) {
	v := verifier()
	v.Region = "eu-west-1"
	r := newReq("GET", "/b/k", nil)
	signer.Sign(r, emptySHA256, now)
	_, err := v.Authenticate(r)
	if !errors.Is(err, ErrAuthHeaderMalformed) || !strings.Contains(err.Error(), "eu-west-1") {
		t.Errorf("error %q should name the expected region", err)
	}
	if got := len(AllErrors()); got != 13 {
		t.Errorf("AllErrors has %d entries; update api/errors.go and this count together", got)
	}
}
