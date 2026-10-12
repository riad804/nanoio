package event

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"sort"
	"strings"
)

// Limits of a notification configuration.
const (
	MaxRules       = 100
	MaxFilterValue = 1024
	// MaxConfigSize bounds the XML document.
	MaxConfigSize = 256 << 10
)

// Rule kinds, named after the XML element that carried the ARN.
const (
	KindTopic         = "Topic"
	KindQueue         = "Queue"
	KindCloudFunction = "CloudFunction"
)

// Rule is one entry of a bucket's notification configuration: deliver the
// events it names, for keys that pass its filters, to one target.
type Rule struct {
	ID     string
	Kind   string
	ARN    string
	Events []string
	// Prefix and Suffix filter on the object key.
	Prefix, Suffix string
	// Tags is a NanoIO extension: every listed tag must be present on the
	// object with exactly that value.
	Tags map[string]string
}

// Config is a parsed bucket notification configuration.
type Config struct {
	Rules []Rule
}

// ConfigError is a configuration the server refuses. Code is the S3 error
// code to answer with.
type ConfigError struct {
	Code    string
	Message string
}

func (e *ConfigError) Error() string { return e.Message }

func invalidArg(format string, a ...any) *ConfigError {
	return &ConfigError{Code: "InvalidArgument", Message: fmt.Sprintf(format, a...)}
}

var errMalformed = &ConfigError{Code: "MalformedXML",
	Message: "The XML you provided was not well-formed or did not validate against our published schema"}

// ----- XML ------------------------------------------------------------

type filterRuleXML struct {
	Name  string `xml:"Name"`
	Value string `xml:"Value"`
}

type filterRulesXML struct {
	Rules []filterRuleXML `xml:"FilterRule"`
}

type filterXML struct {
	S3Key *filterRulesXML `xml:"S3Key"`
	// S3Tag is the tag filter extension: each FilterRule's Name is a tag
	// key and Value its required value.
	S3Tag *filterRulesXML `xml:"S3Tag"`
}

type ruleInXML struct {
	ID            string     `xml:"Id"`
	Topic         string     `xml:"Topic"`
	Queue         string     `xml:"Queue"`
	CloudFunction string     `xml:"CloudFunction"`
	Events        []string   `xml:"Event"`
	Filter        *filterXML `xml:"Filter"`
}

type configInXML struct {
	XMLName   xml.Name    `xml:"NotificationConfiguration"`
	Topics    []ruleInXML `xml:"TopicConfiguration"`
	Queues    []ruleInXML `xml:"QueueConfiguration"`
	Functions []ruleInXML `xml:"CloudFunctionConfiguration"`
}

type topicOutXML struct {
	XMLName xml.Name   `xml:"TopicConfiguration"`
	ID      string     `xml:"Id,omitempty"`
	Topic   string     `xml:"Topic"`
	Events  []string   `xml:"Event"`
	Filter  *filterXML `xml:"Filter,omitempty"`
}

type queueOutXML struct {
	XMLName xml.Name   `xml:"QueueConfiguration"`
	ID      string     `xml:"Id,omitempty"`
	Queue   string     `xml:"Queue"`
	Events  []string   `xml:"Event"`
	Filter  *filterXML `xml:"Filter,omitempty"`
}

type functionOutXML struct {
	XMLName       xml.Name   `xml:"CloudFunctionConfiguration"`
	ID            string     `xml:"Id,omitempty"`
	CloudFunction string     `xml:"CloudFunction"`
	Events        []string   `xml:"Event"`
	Filter        *filterXML `xml:"Filter,omitempty"`
}

type configOutXML struct {
	XMLName   xml.Name         `xml:"http://s3.amazonaws.com/doc/2006-03-01/ NotificationConfiguration"`
	Topics    []topicOutXML    `xml:"TopicConfiguration"`
	Queues    []queueOutXML    `xml:"QueueConfiguration"`
	Functions []functionOutXML `xml:"CloudFunctionConfiguration"`
}

// ARNResolver maps an ARN written in a configuration to its canonical form
// and reports whether a target with that ARN exists.
type ARNResolver func(arn string) (canonical string, ok bool)

// ParseConfig parses and validates a NotificationConfiguration document.
// Every ARN must resolve. Rules without an Id are given one, so the
// canonical document returned by Render is stable.
func ParseConfig(doc []byte, resolve ARNResolver) (*Config, error) {
	if len(doc) > MaxConfigSize {
		return nil, &ConfigError{Code: "EntityTooLarge", Message: "The notification configuration is too large"}
	}
	var in configInXML
	dec := xml.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&in); err != nil {
		return nil, errMalformed
	}
	var cfg Config
	add := func(kind string, rules []ruleInXML, arn func(ruleInXML) string) error {
		for _, x := range rules {
			r, err := buildRule(kind, x, arn(x), resolve)
			if err != nil {
				return err
			}
			cfg.Rules = append(cfg.Rules, r)
		}
		return nil
	}
	if err := add(KindTopic, in.Topics, func(x ruleInXML) string { return x.Topic }); err != nil {
		return nil, err
	}
	if err := add(KindQueue, in.Queues, func(x ruleInXML) string { return x.Queue }); err != nil {
		return nil, err
	}
	if err := add(KindCloudFunction, in.Functions, func(x ruleInXML) string { return x.CloudFunction }); err != nil {
		return nil, err
	}
	if len(cfg.Rules) > MaxRules {
		return nil, invalidArg("A bucket may have at most %d notification configurations", MaxRules)
	}
	seen := map[string]bool{}
	for i := range cfg.Rules {
		r := &cfg.Rules[i]
		if r.ID == "" {
			r.ID = newRuleID()
		}
		if seen[r.ID] {
			return nil, invalidArg("Configuration id %q is used more than once", r.ID)
		}
		seen[r.ID] = true
	}
	if err := checkOverlap(cfg.Rules); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func newRuleID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func buildRule(kind string, x ruleInXML, arn string, resolve ARNResolver) (Rule, error) {
	r := Rule{ID: x.ID, Kind: kind}
	arn = strings.TrimSpace(arn)
	if arn == "" || len(x.Events) == 0 {
		return r, errMalformed
	}
	canon, ok := resolve(arn)
	if !ok {
		return r, invalidArg("Unable to validate the provided ARN %q: no such notification target", arn)
	}
	r.ARN = canon
	seenEv := map[string]bool{}
	for _, ev := range x.Events {
		ev = strings.TrimSpace(ev)
		if !ValidName(ev) {
			return r, invalidArg("The event %q is not supported", ev)
		}
		if !seenEv[ev] {
			seenEv[ev] = true
			r.Events = append(r.Events, ev)
		}
	}
	if x.Filter == nil {
		return r, nil
	}
	if x.Filter.S3Key != nil {
		var havePrefix, haveSuffix bool
		for _, fr := range x.Filter.S3Key.Rules {
			if len(fr.Value) > MaxFilterValue {
				return r, invalidArg("The filter value is longer than %d bytes", MaxFilterValue)
			}
			switch strings.ToLower(strings.TrimSpace(fr.Name)) {
			case "prefix":
				if havePrefix {
					return r, invalidArg("Cannot specify more than one prefix rule in a filter.")
				}
				havePrefix, r.Prefix = true, fr.Value
			case "suffix":
				if haveSuffix {
					return r, invalidArg("Cannot specify more than one suffix rule in a filter.")
				}
				haveSuffix, r.Suffix = true, fr.Value
			default:
				return r, invalidArg("filter rule name must be either prefix or suffix")
			}
		}
	}
	if x.Filter.S3Tag != nil {
		r.Tags = map[string]string{}
		for _, fr := range x.Filter.S3Tag.Rules {
			if fr.Name == "" || len(fr.Name) > 128 || len(fr.Value) > 256 {
				return r, invalidArg("A tag filter needs a tag key of 1 to 128 and a value of at most 256 characters")
			}
			if _, dup := r.Tags[fr.Name]; dup {
				return r, invalidArg("Cannot specify the tag %q more than once in a filter.", fr.Name)
			}
			r.Tags[fr.Name] = fr.Value
		}
		if len(r.Tags) > 10 {
			return r, invalidArg("A filter may name at most 10 tags")
		}
	}
	return r, nil
}

// checkOverlap refuses configurations that would deliver one event twice to
// the same place the way S3 does: two rules overlap when some event name,
// some key and (for tag filters) some object can satisfy both. Two rules for
// different targets may share events; S3's rule is stricter (it refuses any
// overlap on one bucket) and NanoIO follows it so existing configurations
// behave the same.
func checkOverlap(rules []Rule) error {
	for i := range rules {
		for j := i + 1; j < len(rules); j++ {
			a, b := rules[i], rules[j]
			if !eventsOverlap(a.Events, b.Events) {
				continue
			}
			if !strings.HasPrefix(a.Prefix, b.Prefix) && !strings.HasPrefix(b.Prefix, a.Prefix) {
				continue
			}
			if !strings.HasSuffix(a.Suffix, b.Suffix) && !strings.HasSuffix(b.Suffix, a.Suffix) {
				continue
			}
			if tagsDisjoint(a.Tags, b.Tags) {
				continue
			}
			return invalidArg("Configurations overlap. Configurations on the same bucket cannot share a common event type.")
		}
	}
	return nil
}

func eventsOverlap(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if namesOverlap(x, y) {
				return true
			}
		}
	}
	return false
}

// tagsDisjoint reports whether no object can carry both tag sets: some key
// is required to have different values.
func tagsDisjoint(a, b map[string]string) bool {
	for k, v := range a {
		if w, ok := b[k]; ok && w != v {
			return true
		}
	}
	return false
}

// Match returns the ARNs, in rule order and without repeats, of the targets
// that should receive an event with this name for this key. tags are the
// object's tags; a rule with tag filters never matches when they are nil.
func (c *Config) Match(name, key string, tags map[string]string) []string {
	if c == nil {
		return nil
	}
	var out []string
next:
	for _, r := range c.Rules {
		if !r.matches(name, key, tags) {
			continue
		}
		for _, a := range out {
			if a == r.ARN {
				continue next
			}
		}
		out = append(out, r.ARN)
	}
	return out
}

func (r *Rule) matches(name, key string, tags map[string]string) bool {
	ok := false
	for _, p := range r.Events {
		if NameMatches(p, name) {
			ok = true
			break
		}
	}
	if !ok || !strings.HasPrefix(key, r.Prefix) || !strings.HasSuffix(key, r.Suffix) {
		return false
	}
	for k, v := range r.Tags {
		if got, have := tags[k]; !have || got != v {
			return false
		}
	}
	return true
}

// NeedsTags reports whether any rule that could select this event name has
// a tag filter, so the producer should capture the object's tags.
func (c *Config) NeedsTags(name string) bool {
	if c == nil {
		return false
	}
	for _, r := range c.Rules {
		if len(r.Tags) == 0 {
			continue
		}
		for _, p := range r.Events {
			if NameMatches(p, name) {
				return true
			}
		}
	}
	return false
}

// Wants reports whether any rule selects this event name at all.
func (c *Config) Wants(name string) bool {
	if c == nil {
		return false
	}
	for _, r := range c.Rules {
		for _, p := range r.Events {
			if NameMatches(p, name) {
				return true
			}
		}
	}
	return false
}

// ARNs lists the distinct targets the configuration refers to.
func (c *Config) ARNs() []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range c.Rules {
		if !seen[r.ARN] {
			seen[r.ARN] = true
			out = append(out, r.ARN)
		}
	}
	sort.Strings(out)
	return out
}

func (r Rule) filterXML() *filterXML {
	var f filterXML
	if r.Prefix != "" || r.Suffix != "" {
		f.S3Key = &filterRulesXML{}
		if r.Prefix != "" {
			f.S3Key.Rules = append(f.S3Key.Rules, filterRuleXML{Name: "prefix", Value: r.Prefix})
		}
		if r.Suffix != "" {
			f.S3Key.Rules = append(f.S3Key.Rules, filterRuleXML{Name: "suffix", Value: r.Suffix})
		}
	}
	if len(r.Tags) > 0 {
		keys := make([]string, 0, len(r.Tags))
		for k := range r.Tags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		f.S3Tag = &filterRulesXML{}
		for _, k := range keys {
			f.S3Tag.Rules = append(f.S3Tag.Rules, filterRuleXML{Name: k, Value: r.Tags[k]})
		}
	}
	if f.S3Key == nil && f.S3Tag == nil {
		return nil
	}
	return &f
}

// Render is the canonical XML document for the configuration; a nil or empty
// Config renders the empty document.
func (c *Config) Render() *configOutXML {
	out := &configOutXML{}
	if c == nil {
		return out
	}
	for _, r := range c.Rules {
		switch r.Kind {
		case KindTopic:
			out.Topics = append(out.Topics, topicOutXML{ID: r.ID, Topic: r.ARN, Events: r.Events, Filter: r.filterXML()})
		case KindQueue:
			out.Queues = append(out.Queues, queueOutXML{ID: r.ID, Queue: r.ARN, Events: r.Events, Filter: r.filterXML()})
		default:
			out.Functions = append(out.Functions, functionOutXML{ID: r.ID, CloudFunction: r.ARN, Events: r.Events, Filter: r.filterXML()})
		}
	}
	return out
}

// Marshal is the canonical stored form: the Render document as XML.
func (c *Config) Marshal() ([]byte, error) {
	return xml.Marshal(c.Render())
}
