package api

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// corsRule is one rule of a bucket's CORS configuration.
type corsRule struct {
	ID             string   `json:"id,omitempty"`
	AllowedOrigins []string `json:"origins"`
	AllowedMethods []string `json:"methods"`
	AllowedHeaders []string `json:"headers,omitempty"`
	ExposeHeaders  []string `json:"expose,omitempty"`
	MaxAgeSeconds  int      `json:"maxAge,omitempty"`
}

type corsConfig struct {
	Rules []corsRule `json:"rules"`
}

const maxCORSRules = 100

var corsMethods = map[string]bool{"GET": true, "PUT": true, "POST": true, "DELETE": true, "HEAD": true}

var (
	errNoCORSConfig  = &APIError{"NoSuchCORSConfiguration", "The CORS configuration does not exist", http.StatusNotFound}
	errCORSForbidden = &APIError{"AccessForbidden", "CORSResponse: This CORS request is not allowed. This is usually because the evaluation of Origin, request method / Access-Control-Request-Method or Access-Control-Request-Headers are not whitelisted by the resource's CORS spec.", http.StatusForbidden}
)

// wildcardMatch matches s against a pattern with at most one '*'.
func wildcardMatch(pattern, s string, fold bool) bool {
	if fold {
		pattern, s = strings.ToLower(pattern), strings.ToLower(s)
	}
	i := strings.IndexByte(pattern, '*')
	if i < 0 {
		return pattern == s
	}
	pre, suf := pattern[:i], pattern[i+1:]
	return len(s) >= len(pre)+len(suf) && strings.HasPrefix(s, pre) && strings.HasSuffix(s, suf)
}

func (r *corsRule) allowsOrigin(origin string) bool {
	for _, o := range r.AllowedOrigins {
		if wildcardMatch(o, origin, false) {
			return true
		}
	}
	return false
}

func (r *corsRule) allowsMethod(m string) bool {
	for _, am := range r.AllowedMethods {
		if am == m {
			return true
		}
	}
	return false
}

// allowsHeaders reports whether every requested header is allowed.
func (r *corsRule) allowsHeaders(reqHeaders []string) bool {
	for _, h := range reqHeaders {
		ok := false
		for _, ah := range r.AllowedHeaders {
			if wildcardMatch(ah, h, true) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// match returns the first rule that admits the origin and method (and, for a
// preflight, every requested header).
func (c *corsConfig) match(origin, method string, reqHeaders []string) *corsRule {
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.allowsOrigin(origin) && r.allowsMethod(method) && r.allowsHeaders(reqHeaders) {
			return r
		}
	}
	return nil
}

// ----- XML ------------------------------------------------------------

type corsRuleXML struct {
	ID             string   `xml:"ID,omitempty"`
	AllowedHeaders []string `xml:"AllowedHeader"`
	AllowedMethods []string `xml:"AllowedMethod"`
	AllowedOrigins []string `xml:"AllowedOrigin"`
	ExposeHeaders  []string `xml:"ExposeHeader"`
	MaxAgeSeconds  *int     `xml:"MaxAgeSeconds"`
}

type corsConfigurationRequest struct {
	XMLName xml.Name      `xml:"CORSConfiguration"`
	Rules   []corsRuleXML `xml:"CORSRule"`
}

type corsConfigurationResponse struct {
	XMLName xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ CORSConfiguration"`
	Rules   []corsRuleXML `xml:"CORSRule"`
}

func invalidCORS(msg string) *APIError {
	return &APIError{"InvalidRequest", msg, http.StatusBadRequest}
}

func corsFromXML(body []byte) (*corsConfig, *APIError) {
	var req corsConfigurationRequest
	if err := xml.Unmarshal(body, &req); err != nil || len(req.Rules) == 0 {
		return nil, errMalformedXML
	}
	if len(req.Rules) > maxCORSRules {
		return nil, invalidCORS("The CORS configuration may have at most 100 rules.")
	}
	cfg := &corsConfig{}
	for _, x := range req.Rules {
		if len(x.AllowedOrigins) == 0 || len(x.AllowedMethods) == 0 {
			return nil, errMalformedXML
		}
		r := corsRule{ID: x.ID, AllowedOrigins: x.AllowedOrigins, AllowedMethods: x.AllowedMethods,
			AllowedHeaders: x.AllowedHeaders, ExposeHeaders: x.ExposeHeaders}
		for _, m := range r.AllowedMethods {
			if !corsMethods[m] {
				return nil, invalidCORS("Found unsupported HTTP method in CORS config. Unsupported method is " + m)
			}
		}
		for _, o := range r.AllowedOrigins {
			if strings.Count(o, "*") > 1 {
				return nil, invalidCORS(`AllowedOrigin "` + o + `" can not have more than one wildcard.`)
			}
		}
		for _, h := range r.AllowedHeaders {
			if strings.Count(h, "*") > 1 {
				return nil, invalidCORS(`AllowedHeader "` + h + `" can not have more than one wildcard.`)
			}
		}
		for _, h := range r.ExposeHeaders {
			if strings.Contains(h, "*") {
				return nil, invalidCORS(`ExposeHeader "` + h + `" contains a wildcard. Wildcards are not allowed in ExposeHeader.`)
			}
		}
		if x.MaxAgeSeconds != nil {
			if *x.MaxAgeSeconds < 0 {
				return nil, errMalformedXML
			}
			r.MaxAgeSeconds = *x.MaxAgeSeconds
		}
		cfg.Rules = append(cfg.Rules, r)
	}
	return cfg, nil
}

func (c *corsConfig) toXML() *corsConfigurationResponse {
	out := &corsConfigurationResponse{}
	for _, r := range c.Rules {
		x := corsRuleXML{ID: r.ID, AllowedHeaders: r.AllowedHeaders, AllowedMethods: r.AllowedMethods,
			AllowedOrigins: r.AllowedOrigins, ExposeHeaders: r.ExposeHeaders}
		if r.MaxAgeSeconds > 0 {
			n := r.MaxAgeSeconds
			x.MaxAgeSeconds = &n
		}
		out.Rules = append(out.Rules, x)
	}
	return out
}

// ----- handlers -------------------------------------------------------

func (s *Server) corsConfig(q *request, bucket string) (*corsConfig, error) {
	v, err := s.confParsed(q.r.Context(), bucket, confCORS, func(b []byte) (any, error) {
		var c corsConfig
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		return &c, nil
	})
	if err != nil || v == nil {
		return nil, err
	}
	return v.(*corsConfig), nil
}

func (s *Server) bucketCORSOp(q *request) {
	switch q.r.Method {
	case http.MethodPut:
		if !s.authorize(q, "s3:PutBucketCORS", q.bucket, "", nil) {
			return
		}
		body, err := s.readBody(q, 64<<10)
		if err != nil {
			s.fail(q, err)
			return
		}
		cfg, aerr := corsFromXML(body)
		if aerr != nil {
			s.fail(q, aerr)
			return
		}
		if !s.requireBucket(q) {
			return
		}
		data, _ := json.Marshal(cfg)
		if err := s.confPut(q.ctx(), q.bucket, confCORS, data); err != nil {
			s.fail(q, err)
			return
		}
		q.w.WriteHeader(http.StatusOK)
	case http.MethodGet:
		if !s.authorize(q, "s3:GetBucketCORS", q.bucket, "", nil) || !s.requireBucket(q) {
			return
		}
		cfg, err := s.corsConfig(q, q.bucket)
		if err != nil {
			s.fail(q, err)
			return
		}
		if cfg == nil {
			s.fail(q, errNoCORSConfig)
			return
		}
		s.writeXML(q, http.StatusOK, cfg.toXML())
	case http.MethodDelete:
		if !s.authorize(q, "s3:PutBucketCORS", q.bucket, "", nil) || !s.requireBucket(q) {
			return
		}
		s.confDrop(q.ctx(), q.bucket, confCORS)
		q.w.WriteHeader(http.StatusNoContent)
	default:
		s.fail(q, errBadMethod)
	}
}

// isPreflight reports whether r is a CORS preflight request.
func isPreflight(r *http.Request) bool {
	return r.Method == http.MethodOptions && r.Header.Get("Origin") != "" &&
		r.Header.Get("Access-Control-Request-Method") != ""
}

// preflight answers a CORS preflight. Browsers send it without credentials,
// so it is served before authentication; it reveals only whether the
// bucket's own CORS rules admit the request.
func (s *Server) preflight(q *request) {
	if q.bucket == "" {
		s.fail(q, errCORSForbidden)
		return
	}
	cfg, err := s.corsConfig(q, q.bucket)
	if err != nil {
		s.fail(q, err)
		return
	}
	origin := q.r.Header.Get("Origin")
	method := strings.ToUpper(strings.TrimSpace(q.r.Header.Get("Access-Control-Request-Method")))
	var reqHeaders []string
	for _, h := range strings.Split(q.r.Header.Get("Access-Control-Request-Headers"), ",") {
		if h = strings.TrimSpace(h); h != "" {
			reqHeaders = append(reqHeaders, h)
		}
	}
	var rule *corsRule
	if cfg != nil {
		rule = cfg.match(origin, method, reqHeaders)
	}
	if rule == nil {
		s.fail(q, errCORSForbidden)
		return
	}
	h := q.w.Header()
	setCORSOrigin(h, rule, origin)
	h.Set("Access-Control-Allow-Methods", strings.Join(rule.AllowedMethods, ", "))
	if len(reqHeaders) > 0 {
		h.Set("Access-Control-Allow-Headers", strings.Join(reqHeaders, ", "))
	}
	if rule.MaxAgeSeconds > 0 {
		h.Set("Access-Control-Max-Age", strconv.Itoa(rule.MaxAgeSeconds))
	}
	if len(rule.ExposeHeaders) > 0 {
		h.Set("Access-Control-Expose-Headers", strings.Join(rule.ExposeHeaders, ", "))
	}
	h.Add("Vary", "Origin")
	h.Add("Vary", "Access-Control-Request-Headers")
	h.Add("Vary", "Access-Control-Request-Method")
	q.w.WriteHeader(http.StatusOK)
}

// setCORSOrigin sets Allow-Origin (and Allow-Credentials for a specific
// origin) as S3 does: "*" when the rule's origin is the bare wildcard.
func setCORSOrigin(h http.Header, rule *corsRule, origin string) {
	star := false
	for _, o := range rule.AllowedOrigins {
		if o == "*" {
			star = true
		}
	}
	if star {
		h.Set("Access-Control-Allow-Origin", "*")
		return
	}
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Credentials", "true")
}

// applyCORS adds the CORS response headers to an actual (non-preflight)
// request that carries an Origin the bucket's rules admit, before any
// handler runs so error responses carry them too. Failure to read the
// configuration only means no CORS headers.
func (s *Server) applyCORS(q *request) {
	origin := q.r.Header.Get("Origin")
	if origin == "" || q.bucket == "" || q.bucket == sysBucket {
		return
	}
	cfg, err := s.corsConfig(q, q.bucket)
	if err != nil || cfg == nil {
		return
	}
	h := q.w.Header()
	h.Add("Vary", "Origin")
	rule := cfg.match(origin, q.r.Method, nil)
	if rule == nil {
		return
	}
	setCORSOrigin(h, rule, origin)
	if len(rule.ExposeHeaders) > 0 {
		exp := append([]string(nil), rule.ExposeHeaders...)
		sort.Strings(exp)
		h.Set("Access-Control-Expose-Headers", strings.Join(exp, ", "))
	}
}
