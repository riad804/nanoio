package event

import (
	"strings"
	"testing"
)

func resolveAll(arn string) (string, bool) {
	r, id, typ, ok := ParseARN(arn)
	if !ok {
		return "", false
	}
	if r == "" {
		r = "us-east-1"
	}
	return ARN(r, id, typ), id != "missing"
}

func cfgXML(rules ...string) []byte {
	return []byte(`<NotificationConfiguration>` + strings.Join(rules, "") + `</NotificationConfiguration>`)
}

func TestParseAndMatch(t *testing.T) {
	doc := cfgXML(
		`<QueueConfiguration><Id>imgs</Id><Queue>arn:minio:sqs::hook:webhook</Queue>
		   <Event>s3:ObjectCreated:*</Event>
		   <Filter><S3Key><FilterRule><Name>prefix</Name><Value>images/</Value></FilterRule>
		   <FilterRule><Name>Suffix</Name><Value>.jpg</Value></FilterRule></S3Key></Filter></QueueConfiguration>`,
		`<TopicConfiguration><Topic>arn:minio:sqs::audit:kafka</Topic>
		   <Event>s3:ObjectRemoved:Delete</Event><Event>s3:ObjectRemoved:DeleteMarkerCreated</Event></TopicConfiguration>`,
		`<CloudFunctionConfiguration><Id>tagged</Id><CloudFunction>arn:minio:sqs::db:postgresql</CloudFunction>
		   <Event>s3:ObjectAccessed:Get</Event>
		   <Filter><S3Tag><FilterRule><Name>class</Name><Value>gold</Value></FilterRule></S3Tag></Filter></CloudFunctionConfiguration>`,
	)
	c, err := ParseConfig(doc, resolveAll)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Rules) != 3 || c.Rules[1].ARN != "arn:minio:sqs:us-east-1:hook:webhook" {
		t.Fatalf("rules = %+v", c.Rules)
	}
	for _, r := range c.Rules {
		if r.ID == "" {
			t.Error("a rule without an Id must be given one")
		}
	}
	type tc struct {
		name, key string
		tags      map[string]string
		want      string
	}
	for _, x := range []tc{
		{ObjectCreatedPut, "images/cat.jpg", nil, "hook"},
		{ObjectCreatedCopy, "images/cat.jpg", nil, "hook"},
		{ObjectCreatedPut, "images/cat.png", nil, ""},
		{ObjectCreatedPut, "docs/cat.jpg", nil, ""},
		{ObjectRemovedDelete, "anything", nil, "audit"},
		{ObjectRemovedDeleteMarkerCreated, "anything", nil, "audit"},
		{ObjectAccessedGet, "k", map[string]string{"class": "gold"}, "db"},
		{ObjectAccessedGet, "k", map[string]string{"class": "tin"}, ""},
		{ObjectAccessedGet, "k", nil, ""},
		{ObjectAccessedHead, "k", map[string]string{"class": "gold"}, ""},
	} {
		got := ""
		for _, a := range c.Match(x.name, x.key, x.tags) {
			_, id, _, _ := ParseARN(a)
			got += id
		}
		if got != x.want {
			t.Errorf("Match(%s, %s, %v) = %q, want %q", x.name, x.key, x.tags, got, x.want)
		}
	}
	if !c.NeedsTags(ObjectAccessedGet) || c.NeedsTags(ObjectCreatedPut) {
		t.Error("NeedsTags is wrong")
	}

	// The canonical rendering parses back to the same configuration.
	out, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	c2, err := ParseConfig(out, resolveAll)
	if err != nil {
		t.Fatalf("canonical form does not parse: %v\n%s", err, out)
	}
	if len(c2.Rules) != 3 || c2.Rules[2].Tags["class"] != "gold" || c2.Rules[1].Suffix != ".jpg" || c2.Rules[1].ID != "imgs" ||
		c2.Rules[0].ID != c.Rules[0].ID {
		t.Errorf("round trip lost data: %+v", c2.Rules)
	}
}

func TestParseRefusals(t *testing.T) {
	q := func(arn, events, filter string) []byte {
		return cfgXML(`<QueueConfiguration><Queue>` + arn + `</Queue>` + events + filter + `</QueueConfiguration>`)
	}
	ev := `<Event>s3:ObjectCreated:*</Event>`
	rule := func(n, v string) string {
		return `<FilterRule><Name>` + n + `</Name><Value>` + v + `</Value></FilterRule>`
	}
	for name, tt := range map[string]struct {
		doc  []byte
		code string
	}{
		"not xml":           {[]byte("nope"), "MalformedXML"},
		"no event":          {q("arn:minio:sqs::a:webhook", "", ""), "MalformedXML"},
		"unknown event":     {q("arn:minio:sqs::a:webhook", `<Event>s3:Bogus:*</Event>`, ""), "InvalidArgument"},
		"unknown target":    {q("arn:minio:sqs::missing:webhook", ev, ""), "InvalidArgument"},
		"malformed arn":     {q("arn:aws:sns:us-east-1:1:t", ev, ""), "InvalidArgument"},
		"bad filter name":   {q("arn:minio:sqs::a:webhook", ev, `<Filter><S3Key>`+rule("infix", "x")+`</S3Key></Filter>`), "InvalidArgument"},
		"two prefixes":      {q("arn:minio:sqs::a:webhook", ev, `<Filter><S3Key>`+rule("prefix", "x")+rule("prefix", "y")+`</S3Key></Filter>`), "InvalidArgument"},
		"duplicate tag":     {q("arn:minio:sqs::a:webhook", ev, `<Filter><S3Tag>`+rule("t", "x")+rule("t", "y")+`</S3Tag></Filter>`), "InvalidArgument"},
		"too long a prefix": {q("arn:minio:sqs::a:webhook", ev, `<Filter><S3Key>`+rule("prefix", strings.Repeat("x", 1025))+`</S3Key></Filter>`), "InvalidArgument"},
		"overlap": {cfgXML(
			`<QueueConfiguration><Queue>arn:minio:sqs::a:webhook</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration>`,
			`<QueueConfiguration><Queue>arn:minio:sqs::b:webhook</Queue><Event>s3:ObjectCreated:Put</Event></QueueConfiguration>`), "InvalidArgument"},
		"duplicate id": {cfgXML(
			`<QueueConfiguration><Id>x</Id><Queue>arn:minio:sqs::a:webhook</Queue><Event>s3:ObjectCreated:*</Event></QueueConfiguration>`,
			`<QueueConfiguration><Id>x</Id><Queue>arn:minio:sqs::b:webhook</Queue><Event>s3:ObjectRemoved:*</Event></QueueConfiguration>`), "InvalidArgument"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := ParseConfig(tt.doc, resolveAll)
			ce, ok := err.(*ConfigError)
			if !ok || ce.Code != tt.code {
				t.Fatalf("err = %v, want code %s", err, tt.code)
			}
		})
	}
}

func TestOverlapAllowsDisjointFilters(t *testing.T) {
	doc := cfgXML(
		`<QueueConfiguration><Queue>arn:minio:sqs::a:webhook</Queue><Event>s3:ObjectCreated:*</Event>
		   <Filter><S3Key><FilterRule><Name>prefix</Name><Value>a/</Value></FilterRule></S3Key></Filter></QueueConfiguration>`,
		`<QueueConfiguration><Queue>arn:minio:sqs::b:webhook</Queue><Event>s3:ObjectCreated:*</Event>
		   <Filter><S3Key><FilterRule><Name>prefix</Name><Value>b/</Value></FilterRule></S3Key></Filter></QueueConfiguration>`,
		`<QueueConfiguration><Queue>arn:minio:sqs::c:webhook</Queue><Event>s3:ObjectCreated:*</Event>
		   <Filter><S3Tag><FilterRule><Name>t</Name><Value>1</Value></FilterRule></S3Tag>
		   <S3Key><FilterRule><Name>prefix</Name><Value>c/</Value></FilterRule></S3Key></Filter></QueueConfiguration>`,
		`<QueueConfiguration><Queue>arn:minio:sqs::d:webhook</Queue><Event>s3:ObjectCreated:*</Event>
		   <Filter><S3Tag><FilterRule><Name>t</Name><Value>2</Value></FilterRule></S3Tag>
		   <S3Key><FilterRule><Name>prefix</Name><Value>c/</Value></FilterRule></S3Key></Filter></QueueConfiguration>`,
	)
	if _, err := ParseConfig(doc, resolveAll); err != nil {
		t.Fatal(err)
	}
}

func TestNames(t *testing.T) {
	for _, n := range []string{"s3:ObjectCreated:*", "s3:ObjectCreated:Put", "s3:ObjectRestore:Completed", "s3:LifecycleExpiration:DeleteMarkerCreated"} {
		if !ValidName(n) {
			t.Errorf("%s should be valid", n)
		}
	}
	for _, n := range []string{"s3:*", "ObjectCreated:Put", "s3:ObjectCreated:Bogus", "s3:ObjectCreated:"} {
		if ValidName(n) {
			t.Errorf("%s should be invalid", n)
		}
	}
	if !NameMatches("s3:ObjectCreated:*", ObjectCreatedCopy) || NameMatches("s3:ObjectCreated:*", ObjectRemovedDelete) {
		t.Error("wildcard matching is wrong")
	}
}

func TestRecordShape(t *testing.T) {
	e := &Event{Name: ObjectCreatedPut, Bucket: "b", Key: "a b/c+d.txt", Size: 5, ETag: "abc", Principal: "AK",
		SourceIP: "10.0.0.1", Region: "us-east-1", Sequencer: "S"}
	p := NewPayload([]*Event{e})
	r := p.Records[0]
	if p.Key != "b/a b/c+d.txt" || p.EventName != "s3:ObjectCreated:Put" {
		t.Errorf("payload = %+v", p)
	}
	if r.S3.Object.Key != "a+b%2Fc%2Bd.txt" || r.S3.Bucket.ARN != "arn:aws:s3:::b" || r.UserIdentity.PrincipalID != "AK" {
		t.Errorf("record = %+v", r)
	}
}
