// Package replication holds the pieces of bucket replication that do not
// need the server: the S3 ReplicationConfiguration document (rules, filters,
// priorities, matching), the remote-target record and its ARN, and the
// replication status carried in object metadata.
package replication

import (
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// Limits.
const (
	MaxRules   = 1000
	MaxXMLSize = 256 << 10
)

// Filter selects objects. Every set part must match.
type Filter struct {
	Prefix string
	Tags   map[string]string
}

// Rule is one replication rule.
type Rule struct {
	ID       string
	Enabled  bool
	Priority int
	Filter   Filter
	// LegacyPrefix is set when the rule used the top-level <Prefix>.
	LegacyPrefix bool
	// DeleteMarkers: replicate delete markers.
	DeleteMarkers bool
	// ReplicaModifications: metadata changes made to a replica are sent on.
	ReplicaModifications bool
	// Existing: objects present before the rule are replicated too.
	Existing bool
	// Destination is the remote target ARN; StorageClass optional.
	Destination  string
	StorageClass string
}

// Config is a parsed replication configuration.
type Config struct {
	Role  string
	Rules []Rule
}

// Error is a refused configuration; Code is the S3 error code.
type Error struct{ Code, Message string }

func (e *Error) Error() string { return e.Message }

func malformed() *Error {
	return &Error{"MalformedXML", "The XML you provided was not well-formed or did not validate against our published schema"}
}

func invalid(format string, a ...any) *Error {
	return &Error{"InvalidArgument", fmt.Sprintf(format, a...)}
}

// ----- XML ------------------------------------------------------------

type statusXML struct {
	Status string `xml:"Status"`
}

type tagXML struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type andXML struct {
	Prefix string   `xml:"Prefix"`
	Tags   []tagXML `xml:"Tag"`
}

type filterXML struct {
	Prefix *string `xml:"Prefix"`
	Tag    *tagXML `xml:"Tag"`
	And    *andXML `xml:"And"`
}

type destXML struct {
	Bucket       string `xml:"Bucket"`
	StorageClass string `xml:"StorageClass"`
}

type ruleXML struct {
	ID                      string     `xml:"ID"`
	Status                  string     `xml:"Status"`
	Priority                *int       `xml:"Priority"`
	Prefix                  *string    `xml:"Prefix"`
	Filter                  *filterXML `xml:"Filter"`
	DeleteMarkerReplication *statusXML `xml:"DeleteMarkerReplication"`
	DeleteReplication       *statusXML `xml:"DeleteReplication"`
	SourceSelection         *struct {
		ReplicaModifications *statusXML `xml:"ReplicaModifications"`
	} `xml:"SourceSelectionCriteria"`
	ExistingObjectReplication *statusXML `xml:"ExistingObjectReplication"`
	Destination               destXML    `xml:"Destination"`
}

type configXML struct {
	XMLName xml.Name  `xml:"ReplicationConfiguration"`
	Role    string    `xml:"Role"`
	Rules   []ruleXML `xml:"Rule"`
}

// TargetCheck resolves a destination ARN for the source bucket.
type TargetCheck func(arn string) error

// Parse validates a ReplicationConfiguration document. check reports whether
// a destination ARN is a registered, usable target.
func Parse(doc []byte, check TargetCheck) (*Config, error) {
	if len(doc) > MaxXMLSize {
		return nil, &Error{"EntityTooLarge", "The replication configuration is too large"}
	}
	var in configXML
	if err := xml.Unmarshal(doc, &in); err != nil || len(in.Rules) == 0 {
		return nil, malformed()
	}
	if len(in.Rules) > MaxRules {
		return nil, invalid("A replication configuration may have at most %d rules", MaxRules)
	}
	cfg := &Config{Role: in.Role}
	ids, prios := map[string]bool{}, map[int]bool{}
	for i, x := range in.Rules {
		r := Rule{ID: x.ID, Filter: Filter{}}
		switch x.Status {
		case "Enabled":
			r.Enabled = true
		case "Disabled":
		default:
			return nil, malformed()
		}
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if ids[r.ID] {
			return nil, invalid("Rule ID must be unique. Found same ID for more than one rule: %s", r.ID)
		}
		ids[r.ID] = true
		if x.Priority != nil {
			if *x.Priority < 0 {
				return nil, invalid("Priority must not be negative")
			}
			r.Priority = *x.Priority
			if prios[r.Priority] {
				return nil, invalid("Priority must be unique. Found same priority for more than one rule: %d", r.Priority)
			}
			prios[r.Priority] = true
		} else if len(in.Rules) > 1 {
			return nil, invalid("Priority is required when a configuration has more than one rule")
		}
		switch {
		case x.Filter != nil && x.Prefix != nil:
			return nil, malformed()
		case x.Prefix != nil:
			r.Filter.Prefix, r.LegacyPrefix = *x.Prefix, true
		case x.Filter != nil:
			if err := buildFilter(&r.Filter, x.Filter); err != nil {
				return nil, err
			}
		}
		if d := x.DeleteMarkerReplication; d != nil {
			switch d.Status {
			case "Enabled":
				r.DeleteMarkers = true
			case "Disabled":
			default:
				return nil, malformed()
			}
		}
		if d := x.DeleteReplication; d != nil && d.Status == "Enabled" {
			return nil, &Error{"NotImplemented", "Replication of permanent version deletes (DeleteReplication) is not supported"}
		}
		if x.SourceSelection != nil && x.SourceSelection.ReplicaModifications != nil {
			switch x.SourceSelection.ReplicaModifications.Status {
			case "Enabled":
				r.ReplicaModifications = true
			case "Disabled":
			default:
				return nil, malformed()
			}
		}
		if e := x.ExistingObjectReplication; e != nil {
			switch e.Status {
			case "Enabled":
				r.Existing = true
			case "Disabled":
			default:
				return nil, malformed()
			}
		}
		r.Destination = strings.TrimSpace(x.Destination.Bucket)
		r.StorageClass = x.Destination.StorageClass
		if r.Destination == "" {
			return nil, malformed()
		}
		if check != nil {
			if err := check(r.Destination); err != nil {
				return nil, invalid("%v", err)
			}
		}
		cfg.Rules = append(cfg.Rules, r)
	}
	return cfg, nil
}

func buildFilter(f *Filter, x *filterXML) *Error {
	n := 0
	if x.Prefix != nil {
		f.Prefix = *x.Prefix
		n++
	}
	if x.Tag != nil {
		if x.Tag.Key == "" {
			return malformed()
		}
		f.Tags = map[string]string{x.Tag.Key: x.Tag.Value}
		n++
	}
	if a := x.And; a != nil {
		if n > 0 {
			return malformed()
		}
		f.Prefix = a.Prefix
		if len(a.Tags) > 0 {
			f.Tags = map[string]string{}
		}
		for _, t := range a.Tags {
			if t.Key == "" {
				return malformed()
			}
			if _, dup := f.Tags[t.Key]; dup {
				return invalid("Duplicate tag key %q in the filter", t.Key)
			}
			f.Tags[t.Key] = t.Value
		}
		return nil
	}
	if n > 1 {
		return malformed()
	}
	return nil
}

// Match is one destination an event goes to and the rule that selected it.
type Match struct {
	Rule *Rule
}

// Kind is what happened to the object.
type Kind int

const (
	// KindPut: a new version was written.
	KindPut Kind = iota
	// KindMarker: a delete marker was created.
	KindMarker
	// KindMeta: tags, retention or legal hold changed.
	KindMeta
)

// Select returns, for one object, the rules that apply, one per
// destination: the highest-priority enabled rule whose filter matches,
// ordered by priority (highest first). isReplica says the object arrived by
// replication, in which case only metadata changes and only under a rule
// with ReplicaModifications go on.
func (c *Config) Select(key string, tags map[string]string, kind Kind, isReplica bool) []*Rule {
	if c == nil {
		return nil
	}
	byDest := map[string]*Rule{}
	for i := range c.Rules {
		r := &c.Rules[i]
		if !r.Enabled || !strings.HasPrefix(key, r.Filter.Prefix) {
			continue
		}
		ok := true
		for k, v := range r.Filter.Tags {
			if got, have := tags[k]; !have || got != v {
				ok = false
				break
			}
		}
		if !ok {
			continue
		}
		if kind == KindMarker && !r.DeleteMarkers {
			continue
		}
		if isReplica && !(kind == KindMeta && r.ReplicaModifications) {
			continue
		}
		if cur := byDest[r.Destination]; cur == nil || r.Priority > cur.Priority {
			byDest[r.Destination] = r
		}
	}
	out := make([]*Rule, 0, len(byDest))
	for _, r := range byDest {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// Destinations lists the distinct destination ARNs.
func (c *Config) Destinations() []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range c.Rules {
		if !seen[r.Destination] {
			seen[r.Destination] = true
			out = append(out, r.Destination)
		}
	}
	sort.Strings(out)
	return out
}

// WantsExisting reports whether any enabled rule replicates existing objects.
func (c *Config) WantsExisting() bool {
	for _, r := range c.Rules {
		if r.Enabled && r.Existing {
			return true
		}
	}
	return false
}

// ----- rendering --------------------------------------------------------

type outTag struct {
	Key   string `xml:"Key"`
	Value string `xml:"Value"`
}

type outAnd struct {
	Prefix string   `xml:"Prefix,omitempty"`
	Tags   []outTag `xml:"Tag"`
}

type outFilter struct {
	Prefix *string `xml:"Prefix,omitempty"`
	Tag    *outTag `xml:"Tag,omitempty"`
	And    *outAnd `xml:"And,omitempty"`
}

type outRule struct {
	ID                      string     `xml:"ID"`
	Status                  string     `xml:"Status"`
	Priority                int        `xml:"Priority"`
	Prefix                  *string    `xml:"Prefix,omitempty"`
	Filter                  *outFilter `xml:"Filter,omitempty"`
	DeleteMarkerReplication statusXML  `xml:"DeleteMarkerReplication"`
	DeleteReplication       statusXML  `xml:"DeleteReplication"`
	SourceSelection         *struct {
		ReplicaModifications statusXML `xml:"ReplicaModifications"`
	} `xml:"SourceSelectionCriteria,omitempty"`
	ExistingObjectReplication statusXML `xml:"ExistingObjectReplication"`
	Destination               destXML   `xml:"Destination"`
}

// Document is the XML form of a configuration.
type Document struct {
	XMLName xml.Name  `xml:"http://s3.amazonaws.com/doc/2006-03-01/ ReplicationConfiguration"`
	Role    string    `xml:"Role,omitempty"`
	Rules   []outRule `xml:"Rule"`
}

func enabled(b bool) statusXML {
	if b {
		return statusXML{"Enabled"}
	}
	return statusXML{"Disabled"}
}

// Render returns the document form of c.
func (c *Config) Render() *Document {
	d := &Document{Role: c.Role}
	for _, r := range c.Rules {
		o := outRule{ID: r.ID, Status: "Disabled", Priority: r.Priority,
			DeleteMarkerReplication: enabled(r.DeleteMarkers), DeleteReplication: statusXML{"Disabled"},
			ExistingObjectReplication: enabled(r.Existing),
			Destination:               destXML{Bucket: r.Destination, StorageClass: r.StorageClass}}
		if r.Enabled {
			o.Status = "Enabled"
		}
		if r.ReplicaModifications {
			o.SourceSelection = &struct {
				ReplicaModifications statusXML `xml:"ReplicaModifications"`
			}{enabled(true)}
		}
		prefix := r.Filter.Prefix
		switch {
		case r.LegacyPrefix:
			o.Prefix = &prefix
		case len(r.Filter.Tags) == 0:
			o.Filter = &outFilter{Prefix: &prefix}
		default:
			keys := make([]string, 0, len(r.Filter.Tags))
			for k := range r.Filter.Tags {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var tags []outTag
			for _, k := range keys {
				tags = append(tags, outTag{k, r.Filter.Tags[k]})
			}
			if len(tags) == 1 && prefix == "" {
				o.Filter = &outFilter{Tag: &tags[0]}
			} else {
				o.Filter = &outFilter{And: &outAnd{Prefix: prefix, Tags: tags}}
			}
		}
		d.Rules = append(d.Rules, o)
	}
	return d
}

// Marshal is the canonical stored form.
func (c *Config) Marshal() ([]byte, error) { return xml.Marshal(c.Render()) }
