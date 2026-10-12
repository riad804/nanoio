package lifecycle

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Limits.
const (
	MaxRules   = 1000
	MaxIDLen   = 255
	MaxTags    = 10
	MaxXMLSize = 1 << 20
)

// Filter selects the objects a rule applies to. All set parts must match.
type Filter struct {
	Prefix string
	Tags   map[string]string
	// SizeGreaterThan and SizeLessThan are exclusive bounds in bytes;
	// negative means unset.
	SizeGreaterThan int64
	SizeLessThan    int64
}

// Expiration is the current-version expiration action.
type Expiration struct {
	Days int       // 0 = unset
	Date time.Time // zero = unset
	// ExpiredObjectDeleteMarker removes a delete marker that is the only
	// remaining version of its key.
	ExpiredObjectDeleteMarker bool
}

// Transition moves the current version's data to a tier.
type Transition struct {
	Days         int
	Date         time.Time
	StorageClass string // the tier name
}

// NoncurrentExpiration permanently removes noncurrent versions.
type NoncurrentExpiration struct {
	NoncurrentDays          int
	NewerNoncurrentVersions int
}

// NoncurrentTransition moves a noncurrent version's data to a tier.
type NoncurrentTransition struct {
	NoncurrentDays int
	StorageClass   string
}

// Rule is one lifecycle rule.
type Rule struct {
	ID      string
	Enabled bool
	Filter  Filter
	// LegacyPrefix is true when the rule used the top-level <Prefix>
	// element instead of <Filter>; it is rendered back the same way.
	LegacyPrefix bool

	Expiration           *Expiration
	Transitions          []Transition
	NoncurrentExpiration *NoncurrentExpiration
	NoncurrentTransition []NoncurrentTransition
	// AbortIncompleteMultipartDays is DaysAfterInitiation, 0 = unset.
	AbortIncompleteMultipartDays int
}

// Config is a parsed lifecycle configuration.
type Config struct {
	Rules []Rule
}

// Error is a configuration the server refuses; Code is the S3 error code.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

func malformed(format string, a ...any) *Error {
	return &Error{"MalformedXML", fmt.Sprintf(format, a...)}
}

func invalid(format string, a ...any) *Error {
	return &Error{"InvalidArgument", fmt.Sprintf(format, a...)}
}

// ----- XML ----------------------------------------------------------

type tagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type andXML struct {
	Prefix                *string  `xml:"Prefix"`
	Tags                  []tagXML `xml:"Tag"`
	ObjectSizeGreaterThan *int64   `xml:"ObjectSizeGreaterThan"`
	ObjectSizeLessThan    *int64   `xml:"ObjectSizeLessThan"`
}

type filterXML struct {
	Prefix                *string `xml:"Prefix"`
	Tag                   *tagXML `xml:"Tag"`
	And                   *andXML `xml:"And"`
	ObjectSizeGreaterThan *int64  `xml:"ObjectSizeGreaterThan"`
	ObjectSizeLessThan    *int64  `xml:"ObjectSizeLessThan"`
}

type expirationXML struct {
	Days                      *int    `xml:"Days"`
	Date                      *string `xml:"Date"`
	ExpiredObjectDeleteMarker *bool   `xml:"ExpiredObjectDeleteMarker"`
}

type transitionXML struct {
	Days         *int    `xml:"Days"`
	Date         *string `xml:"Date"`
	StorageClass string  `xml:"StorageClass"`
}

type noncurrentExpXML struct {
	NoncurrentDays          *int `xml:"NoncurrentDays"`
	NewerNoncurrentVersions *int `xml:"NewerNoncurrentVersions"`
}

type noncurrentTransXML struct {
	NoncurrentDays *int   `xml:"NoncurrentDays"`
	StorageClass   string `xml:"StorageClass"`
}

type abortXML struct {
	DaysAfterInitiation *int `xml:"DaysAfterInitiation"`
}

type ruleXML struct {
	ID                             string               `xml:"ID"`
	Status                         string               `xml:"Status"`
	Prefix                         *string              `xml:"Prefix"`
	Filter                         *filterXML           `xml:"Filter"`
	Expiration                     *expirationXML       `xml:"Expiration"`
	Transitions                    []transitionXML      `xml:"Transition"`
	NoncurrentVersionExpiration    *noncurrentExpXML    `xml:"NoncurrentVersionExpiration"`
	NoncurrentVersionTransitions   []noncurrentTransXML `xml:"NoncurrentVersionTransition"`
	AbortIncompleteMultipartUpload *abortXML            `xml:"AbortIncompleteMultipartUpload"`
}

type configXML struct {
	XMLName xml.Name  `xml:"LifecycleConfiguration"`
	Rules   []ruleXML `xml:"Rule"`
}

// ParseOptions supplies what validation needs from the server.
type ParseOptions struct {
	// TierExists reports whether a storage class names a configured tier.
	// Nil rejects every transition.
	TierExists func(name string) bool
}

// Parse parses and validates a LifecycleConfiguration document.
func Parse(doc []byte, opt ParseOptions) (*Config, error) {
	if len(doc) > MaxXMLSize {
		return nil, &Error{"EntityTooLarge", "The lifecycle configuration is too large"}
	}
	var in configXML
	if err := xml.Unmarshal(doc, &in); err != nil {
		return nil, malformed("The XML you provided was not well-formed or did not validate against our published schema")
	}
	if len(in.Rules) == 0 {
		return nil, malformed("The XML you provided was not well-formed or did not validate against our published schema")
	}
	if len(in.Rules) > MaxRules {
		return nil, invalid("The lifecycle configuration may have at most %d rules", MaxRules)
	}
	cfg := &Config{}
	ids := map[string]bool{}
	for i, x := range in.Rules {
		r, err := buildRule(x, opt)
		if err != nil {
			return nil, err
		}
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
			for ids[r.ID] {
				r.ID += "x"
			}
		}
		if len(r.ID) > MaxIDLen {
			return nil, invalid("The rule ID is longer than %d characters", MaxIDLen)
		}
		if ids[r.ID] {
			return nil, invalid("Rule ID must be unique. Found same ID for more than one rule: %s", r.ID)
		}
		ids[r.ID] = true
		cfg.Rules = append(cfg.Rules, r)
	}
	return cfg, nil
}

func parseDate(s string) (time.Time, *Error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(s))
	if err != nil {
		return time.Time{}, malformed("The XML you provided was not well-formed or did not validate against our published schema")
	}
	t = t.UTC()
	if t.Hour() != 0 || t.Minute() != 0 || t.Second() != 0 || t.Nanosecond() != 0 {
		return time.Time{}, invalid("'Date' must be at midnight GMT")
	}
	return t, nil
}

func buildRule(x ruleXML, opt ParseOptions) (Rule, *Error) {
	r := Rule{ID: x.ID, Filter: Filter{SizeGreaterThan: -1, SizeLessThan: -1}}
	switch x.Status {
	case "Enabled":
		r.Enabled = true
	case "Disabled":
	default:
		return r, malformed("The XML you provided was not well-formed or did not validate against our published schema")
	}
	if x.Filter != nil && x.Prefix != nil {
		return r, malformed("Filter and Prefix cannot both be specified in a rule")
	}
	switch {
	case x.Prefix != nil:
		r.Filter.Prefix, r.LegacyPrefix = *x.Prefix, true
	case x.Filter != nil:
		if err := buildFilter(&r.Filter, x.Filter); err != nil {
			return r, err
		}
	case x.Filter == nil && x.Prefix == nil:
		// A rule with neither applies to every object (S3 requires one of
		// them; an empty Filter is the way to say "all").
		return r, malformed("The XML you provided was not well-formed or did not validate against our published schema")
	}

	actions := 0
	if e := x.Expiration; e != nil {
		actions++
		exp := &Expiration{}
		set := 0
		if e.Days != nil {
			if *e.Days <= 0 {
				return r, invalid("'Days' for Expiration action must be a positive integer")
			}
			exp.Days = *e.Days
			set++
		}
		if e.Date != nil {
			d, err := parseDate(*e.Date)
			if err != nil {
				return r, err
			}
			exp.Date = d
			set++
		}
		if e.ExpiredObjectDeleteMarker != nil {
			exp.ExpiredObjectDeleteMarker = *e.ExpiredObjectDeleteMarker
			if exp.ExpiredObjectDeleteMarker {
				set++
			}
		}
		if set != 1 {
			return r, malformed("Exactly one of Days, Date or ExpiredObjectDeleteMarker (true) must be specified in Expiration")
		}
		if exp.ExpiredObjectDeleteMarker && len(r.Filter.Tags) > 0 {
			return r, invalid("Expired object delete marker cannot be specified with tags")
		}
		r.Expiration = exp
	}
	for _, t := range x.Transitions {
		actions++
		tr := Transition{StorageClass: t.StorageClass}
		set := 0
		if t.Days != nil {
			if *t.Days < 0 {
				return r, invalid("'Days' for Transition action must be a non-negative integer")
			}
			tr.Days = *t.Days
			set++
		}
		if t.Date != nil {
			d, err := parseDate(*t.Date)
			if err != nil {
				return r, err
			}
			tr.Date = d
			set++
		}
		if set != 1 {
			return r, malformed("Exactly one of Days or Date must be specified in Transition")
		}
		if tr.StorageClass == "" {
			return r, malformed("StorageClass is required in Transition")
		}
		if opt.TierExists == nil || !opt.TierExists(tr.StorageClass) {
			return r, invalid("Unknown storage class %q: no such tier is configured", tr.StorageClass)
		}
		r.Transitions = append(r.Transitions, tr)
	}
	if n := x.NoncurrentVersionExpiration; n != nil {
		actions++
		ne := &NoncurrentExpiration{}
		if n.NoncurrentDays != nil {
			if *n.NoncurrentDays < 0 {
				return r, invalid("'NoncurrentDays' must not be negative")
			}
			ne.NoncurrentDays = *n.NoncurrentDays
		}
		if n.NewerNoncurrentVersions != nil {
			if *n.NewerNoncurrentVersions < 1 || *n.NewerNoncurrentVersions > 100 {
				return r, invalid("'NewerNoncurrentVersions' must be between 1 and 100")
			}
			ne.NewerNoncurrentVersions = *n.NewerNoncurrentVersions
		}
		if n.NoncurrentDays == nil && n.NewerNoncurrentVersions == nil {
			return r, malformed("NoncurrentDays or NewerNoncurrentVersions is required in NoncurrentVersionExpiration")
		}
		if ne.NoncurrentDays == 0 && ne.NewerNoncurrentVersions == 0 {
			return r, invalid("'NoncurrentDays' must be positive")
		}
		r.NoncurrentExpiration = ne
	}
	for _, n := range x.NoncurrentVersionTransitions {
		actions++
		if n.NoncurrentDays == nil || *n.NoncurrentDays < 0 {
			return r, invalid("'NoncurrentDays' is required in NoncurrentVersionTransition and must not be negative")
		}
		if n.StorageClass == "" {
			return r, malformed("StorageClass is required in NoncurrentVersionTransition")
		}
		if opt.TierExists == nil || !opt.TierExists(n.StorageClass) {
			return r, invalid("Unknown storage class %q: no such tier is configured", n.StorageClass)
		}
		r.NoncurrentTransition = append(r.NoncurrentTransition, NoncurrentTransition{*n.NoncurrentDays, n.StorageClass})
	}
	if a := x.AbortIncompleteMultipartUpload; a != nil {
		actions++
		if a.DaysAfterInitiation == nil || *a.DaysAfterInitiation <= 0 {
			return r, invalid("'DaysAfterInitiation' must be a positive integer")
		}
		if len(r.Filter.Tags) > 0 {
			return r, invalid("AbortIncompleteMultipartUpload cannot be specified with tags")
		}
		r.AbortIncompleteMultipartDays = *a.DaysAfterInitiation
	}
	if actions == 0 {
		return r, malformed("At least one action needs to be specified in a rule")
	}
	if err := checkOrdering(&r); err != nil {
		return r, err
	}
	return r, nil
}

// checkOrdering enforces S3's rule that an object must reach a colder tier
// before it expires, and that transitions are in increasing order.
func checkOrdering(r *Rule) *Error {
	var days []int
	for _, t := range r.Transitions {
		if t.Date.IsZero() {
			days = append(days, t.Days)
		}
	}
	if !sort.IntsAreSorted(days) {
		return invalid("Transition days must be in increasing order")
	}
	if r.Expiration != nil && r.Expiration.Days > 0 {
		for _, t := range r.Transitions {
			if t.Date.IsZero() && r.Expiration.Days <= t.Days {
				return invalid("'Days' in the Expiration action for filter must be greater than 'Days' in the Transition action")
			}
		}
	}
	return nil
}

func buildFilter(f *Filter, x *filterXML) *Error {
	set := 0
	if x.Prefix != nil {
		f.Prefix = *x.Prefix
		set++
	}
	if x.Tag != nil {
		if x.Tag.Key == "" {
			return malformed("The XML you provided was not well-formed or did not validate against our published schema")
		}
		f.Tags = map[string]string{x.Tag.Key: x.Tag.Value}
		set++
	}
	if x.ObjectSizeGreaterThan != nil {
		f.SizeGreaterThan = *x.ObjectSizeGreaterThan
		set++
	}
	if x.ObjectSizeLessThan != nil {
		f.SizeLessThan = *x.ObjectSizeLessThan
		set++
	}
	if a := x.And; a != nil {
		if set > 0 {
			return malformed("Filter must have exactly one of Prefix, Tag, ObjectSize..., or And")
		}
		if a.Prefix != nil {
			f.Prefix = *a.Prefix
		}
		if len(a.Tags) > 0 {
			f.Tags = map[string]string{}
		}
		for _, t := range a.Tags {
			if t.Key == "" {
				return malformed("The XML you provided was not well-formed or did not validate against our published schema")
			}
			if _, dup := f.Tags[t.Key]; dup {
				return invalid("Duplicate tag key %q in the filter", t.Key)
			}
			f.Tags[t.Key] = t.Value
		}
		if len(f.Tags) > MaxTags {
			return invalid("A filter may name at most %d tags", MaxTags)
		}
		if a.ObjectSizeGreaterThan != nil {
			f.SizeGreaterThan = *a.ObjectSizeGreaterThan
		}
		if a.ObjectSizeLessThan != nil {
			f.SizeLessThan = *a.ObjectSizeLessThan
		}
		return checkSizes(f)
	}
	if set > 1 {
		return malformed("Filter must have exactly one of Prefix, Tag, ObjectSize..., or And; use And to combine them")
	}
	return checkSizes(f)
}

func checkSizes(f *Filter) *Error {
	if f.SizeGreaterThan >= 0 && f.SizeLessThan >= 0 && f.SizeLessThan <= f.SizeGreaterThan+1 {
		return invalid("ObjectSizeLessThan must be greater than ObjectSizeGreaterThan")
	}
	return nil
}

// ----- rendering ----------------------------------------------------

type outTag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type outAnd struct {
	Prefix                *string  `xml:"Prefix,omitempty"`
	Tags                  []outTag `xml:"Tag"`
	ObjectSizeGreaterThan *int64   `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64   `xml:"ObjectSizeLessThan,omitempty"`
}

type outFilter struct {
	Prefix                *string `xml:"Prefix,omitempty"`
	Tag                   *outTag `xml:"Tag,omitempty"`
	And                   *outAnd `xml:"And,omitempty"`
	ObjectSizeGreaterThan *int64  `xml:"ObjectSizeGreaterThan,omitempty"`
	ObjectSizeLessThan    *int64  `xml:"ObjectSizeLessThan,omitempty"`
}

type outExpiration struct {
	Days                      int    `xml:"Days,omitempty"`
	Date                      string `xml:"Date,omitempty"`
	ExpiredObjectDeleteMarker *bool  `xml:"ExpiredObjectDeleteMarker,omitempty"`
}

type outTransition struct {
	Days         *int   `xml:"Days,omitempty"`
	Date         string `xml:"Date,omitempty"`
	StorageClass string `xml:"StorageClass"`
}

type outNoncurrentExp struct {
	NoncurrentDays          *int `xml:"NoncurrentDays,omitempty"`
	NewerNoncurrentVersions *int `xml:"NewerNoncurrentVersions,omitempty"`
}

type outNoncurrentTrans struct {
	NoncurrentDays int    `xml:"NoncurrentDays"`
	StorageClass   string `xml:"StorageClass"`
}

type outRule struct {
	ID                             string               `xml:"ID"`
	Status                         string               `xml:"Status"`
	Prefix                         *string              `xml:"Prefix,omitempty"`
	Filter                         *outFilter           `xml:"Filter,omitempty"`
	Expiration                     *outExpiration       `xml:"Expiration,omitempty"`
	Transitions                    []outTransition      `xml:"Transition"`
	NoncurrentVersionExpiration    *outNoncurrentExp    `xml:"NoncurrentVersionExpiration,omitempty"`
	NoncurrentVersionTransitions   []outNoncurrentTrans `xml:"NoncurrentVersionTransition"`
	AbortIncompleteMultipartUpload *abortXML            `xml:"AbortIncompleteMultipartUpload,omitempty"`
}

// Document is the XML form of a configuration, for encoding.
type Document struct {
	XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ LifecycleConfiguration"`
	Rules   []outRule `xml:"Rule"`
}

// Render returns the document form of c.
func (c *Config) Render() *Document {
	d := &Document{}
	for _, r := range c.Rules {
		o := outRule{ID: r.ID, Status: "Disabled"}
		if r.Enabled {
			o.Status = "Enabled"
		}
		prefix := r.Filter.Prefix
		if r.LegacyPrefix {
			o.Prefix = &prefix
		} else {
			o.Filter = renderFilter(r.Filter)
		}
		if e := r.Expiration; e != nil {
			oe := &outExpiration{Days: e.Days}
			if !e.Date.IsZero() {
				oe.Date = e.Date.Format("2006-01-02T15:04:05.000Z")
			}
			if e.ExpiredObjectDeleteMarker {
				t := true
				oe.ExpiredObjectDeleteMarker = &t
			}
			o.Expiration = oe
		}
		for _, t := range r.Transitions {
			ot := outTransition{StorageClass: t.StorageClass}
			if t.Date.IsZero() {
				d := t.Days
				ot.Days = &d
			} else {
				ot.Date = t.Date.Format("2006-01-02T15:04:05.000Z")
			}
			o.Transitions = append(o.Transitions, ot)
		}
		if n := r.NoncurrentExpiration; n != nil {
			on := &outNoncurrentExp{}
			if n.NoncurrentDays > 0 {
				d := n.NoncurrentDays
				on.NoncurrentDays = &d
			}
			if n.NewerNoncurrentVersions > 0 {
				v := n.NewerNoncurrentVersions
				on.NewerNoncurrentVersions = &v
			}
			o.NoncurrentVersionExpiration = on
		}
		for _, n := range r.NoncurrentTransition {
			o.NoncurrentVersionTransitions = append(o.NoncurrentVersionTransitions, outNoncurrentTrans{n.NoncurrentDays, n.StorageClass})
		}
		if r.AbortIncompleteMultipartDays > 0 {
			d := r.AbortIncompleteMultipartDays
			o.AbortIncompleteMultipartUpload = &abortXML{DaysAfterInitiation: &d}
		}
		d.Rules = append(d.Rules, o)
	}
	return d
}

func renderFilter(f Filter) *outFilter {
	tags := make([]outTag, 0, len(f.Tags))
	keys := make([]string, 0, len(f.Tags))
	for k := range f.Tags {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		tags = append(tags, outTag{k, f.Tags[k]})
	}
	sizes := 0
	if f.SizeGreaterThan >= 0 {
		sizes++
	}
	if f.SizeLessThan >= 0 {
		sizes++
	}
	parts := sizes + len(tags)
	if f.Prefix != "" {
		parts++
	}
	ptr := func(v int64) *int64 {
		if v < 0 {
			return nil
		}
		return &v
	}
	switch {
	case parts == 0:
		empty := ""
		return &outFilter{Prefix: &empty}
	case len(tags) > 1 || parts > 1:
		a := &outAnd{Tags: tags, ObjectSizeGreaterThan: ptr(f.SizeGreaterThan), ObjectSizeLessThan: ptr(f.SizeLessThan)}
		if f.Prefix != "" {
			p := f.Prefix
			a.Prefix = &p
		}
		return &outFilter{And: a}
	case len(tags) == 1:
		return &outFilter{Tag: &tags[0]}
	case f.Prefix != "":
		p := f.Prefix
		return &outFilter{Prefix: &p}
	case f.SizeGreaterThan >= 0:
		return &outFilter{ObjectSizeGreaterThan: ptr(f.SizeGreaterThan)}
	default:
		return &outFilter{ObjectSizeLessThan: ptr(f.SizeLessThan)}
	}
}

// Marshal is the canonical stored form.
func (c *Config) Marshal() ([]byte, error) { return xml.Marshal(c.Render()) }

// UsesTransitions reports whether any rule has a transition action.
func (c *Config) UsesTransitions() bool {
	for _, r := range c.Rules {
		if len(r.Transitions) > 0 || len(r.NoncurrentTransition) > 0 {
			return true
		}
	}
	return false
}

// Tiers lists the distinct tier names the configuration refers to.
func (c *Config) Tiers() []string {
	seen := map[string]bool{}
	var out []string
	add := func(s string) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, r := range c.Rules {
		for _, t := range r.Transitions {
			add(t.StorageClass)
		}
		for _, t := range r.NoncurrentTransition {
			add(t.StorageClass)
		}
	}
	sort.Strings(out)
	return out
}
