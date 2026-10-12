package api

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nanoio/internal/batch"
	"nanoio/internal/bucket/nslock"
)

func batchEnv(t *testing.T, clk *manualClock) *testEnv {
	t.Helper()
	return sseEnv(t, "xl", func(o *Options) {
		o.Batch = &BatchOptions{Locker: nslock.New(time.Second), Workers: 2, TaskItems: 5, Tick: 20 * time.Millisecond, Clock: clk}
	})
}

func startJob(t *testing.T, e *testEnv, doc string) string {
	t.Helper()
	resp, b := e.do("POST", "/_nanoio/admin/batch/start", strings.NewReader(doc), nil)
	if resp.StatusCode != 202 {
		t.Fatalf("start: %d %s", resp.StatusCode, b)
	}
	var out struct{ ID string }
	if err := json.Unmarshal(b, &out); err != nil || out.ID == "" {
		t.Fatalf("start response %s (%v)", b, err)
	}
	return out.ID
}

func waitJob(t *testing.T, e *testEnv, id string) batch.Status {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		resp, b := e.do("GET", "/_nanoio/admin/batch/describe?id="+id, nil, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("describe: %d %s", resp.StatusCode, b)
		}
		var st batch.Status
		if err := json.Unmarshal(b, &st); err != nil {
			t.Fatal(err)
		}
		if st.State != batch.StateRunning {
			return st
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("job did not finish")
	return batch.Status{}
}

func TestBatchExpireWithFakeClock(t *testing.T) {
	clk := &manualClock{t: time.Now()}
	e := batchEnv(t, clk)
	e.mb("expbucket")
	for i := 0; i < 23; i++ {
		e.put(fmt.Sprintf("/expbucket/tmp/o%02d", i), "x", nil)
	}
	e.put("/expbucket/keep/a", "x", nil)
	clk.Advance(10 * 24 * time.Hour)
	e.put("/expbucket/tmp/fresh", "x", nil) // created "ten days later"
	// Written with the real clock, so give it a recent mod time by
	// advancing nothing further: the job's filter looks 5 days back.
	id := startJob(t, e, "apiVersion: v1\nexpire:\n  bucket: expbucket\n  prefix: tmp/\n  filter: {olderThan: 5d}\n")
	st := waitJob(t, e, id)
	if st.State != batch.StateCompleted || st.Progress.Succeeded != 24 || st.Progress.Failed != 0 || st.Progress.Tasks != 5 {
		t.Fatalf("job = %+v", st)
	}
	_, lb := e.do("GET", "/expbucket?list-type=2", nil, nil)
	keys := strings.Count(string(lb), "<Key>")
	// keep/a stays; tmp/fresh is real-clock "now" so it is also older than
	// 5 fake days and goes: 1 object remains.
	if keys != 1 || !strings.Contains(string(lb), "keep/a") {
		t.Errorf("after the job: %s", lb)
	}
	// Listings never carry the failure samples, describe does.
	resp, b := e.do("GET", "/_nanoio/admin/batch/list", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), id) {
		t.Errorf("list = %d %s", resp.StatusCode, b)
	}
}

func TestBatchJobAdministration(t *testing.T) {
	e := batchEnv(t, &manualClock{t: time.Now()})
	e.mb("admbucket")
	resp, b := e.do("POST", "/_nanoio/admin/batch/start", strings.NewReader("expire: {bucket: admbucket, bogus: 1}"), nil)
	wantError(t, resp, b, 400, "InvalidArgument")
	resp, b = e.do("POST", "/_nanoio/admin/batch/start", strings.NewReader("expire: {bucket: admbucket}"), nil)
	if resp.StatusCode != 202 {
		t.Fatalf("start = %d %s", resp.StatusCode, b)
	}
	resp, b = e.do("GET", "/_nanoio/admin/batch/describe?id=nosuchjob", nil, nil)
	wantError(t, resp, b, 404, "NoSuchJob")
	resp, b = e.do("POST", "/_nanoio/admin/batch/cancel?id=nosuchjob", nil, nil)
	wantError(t, resp, b, 404, "NoSuchJob")
	resp, b = e.do("GET", "/_nanoio/admin/batch/template", nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(string(b), "keyrotate") {
		t.Errorf("template = %d", resp.StatusCode)
	}
	// Not for everyone.
	for _, p := range []string{"/_nanoio/admin/batch/list", "/_nanoio/admin/batch/describe?id=x", "/_nanoio/admin/batch/template"} {
		r, b := e.doAs("nobody", "GET", p, nil, nil)
		wantError(t, r, b, 403, "AccessDenied")
	}
	r, b := e.doAs("nobody", "POST", "/_nanoio/admin/batch/start", strings.NewReader("expire: {bucket: admbucket}"), nil)
	wantError(t, r, b, 403, "AccessDenied")
	if r, _ := e.doAnon("GET", "/_nanoio/admin/batch/list", nil, nil); r.StatusCode != 403 {
		t.Errorf("anonymous list = %d", r.StatusCode)
	}
}

func TestBatchReplicateToRemoteS3(t *testing.T) {
	remote := newEnv(t)
	remote.mb("backup")
	e := batchEnv(t, &manualClock{t: time.Now()})
	e.mb("srcbucket")
	plain := strings.Repeat("plain data ", 1000)
	secret := strings.Repeat("secret data ", 1000)
	e.put("/srcbucket/docs/plain.txt", plain, hdr{"Content-Type": "text/plain", "x-amz-meta-owner": "alice",
		"x-amz-tagging": "tier=gold", "Cache-Control": "max-age=60"})
	e.put("/srcbucket/docs/secret.txt", secret, hdr{"x-amz-server-side-encryption": "AES256"})
	e.put("/srcbucket/other/skip.txt", "skip", nil)

	doc := fmt.Sprintf(`
apiVersion: v1
replicate:
  source: {bucket: srcbucket, prefix: docs/}
  target:
    endpoint: %s
    bucket: backup
    prefix: mirror/
    credentials: {accessKey: %s, secretKey: %s}
`, remote.srv.URL, rootAK, rootSK)
	id := startJob(t, e, doc)
	st := waitJob(t, e, id)
	if st.State != batch.StateCompleted || st.Progress.Succeeded != 2 || st.Progress.Failed != 0 {
		t.Fatalf("job = %+v", st)
	}
	// The mirror holds the plaintext of both, with metadata and tags.
	got, resp := remote.get("/backup/mirror/docs/plain.txt")
	if got != plain || resp.Header.Get("Content-Type") != "text/plain" || resp.Header.Get("x-amz-meta-owner") != "alice" ||
		resp.Header.Get("Cache-Control") != "max-age=60" || resp.Header.Get("x-amz-tagging-count") != "1" {
		t.Errorf("plain copy: %d bytes, headers %v", len(got), resp.Header)
	}
	if got, _ := remote.get("/backup/mirror/docs/secret.txt"); got != secret {
		t.Errorf("an encrypted source was not replicated as plaintext (%d bytes)", len(got))
	}
	if r, _ := remote.do("HEAD", "/backup/mirror/other/skip.txt", nil, nil); r.StatusCode != 404 {
		t.Error("an object outside the prefix was replicated")
	}
	if resp, b := e.do("GET", "/_nanoio/admin/batch/describe?id="+id, nil, nil); strings.Contains(string(b), rootSK) {
		t.Errorf("the job's target secret key is exposed: %d %s", resp.StatusCode, b)
	}

	// Running it again copies nothing; changing one object copies that one.
	st = waitJob(t, e, startJob(t, e, doc))
	if st.Progress.Succeeded != 0 || st.Progress.Skipped != 2 {
		t.Errorf("repeat run = %+v", st.Progress)
	}
	e.put("/srcbucket/docs/plain.txt", plain+"changed", nil)
	st = waitJob(t, e, startJob(t, e, doc))
	if st.Progress.Succeeded != 1 || st.Progress.Skipped != 1 {
		t.Errorf("after one change = %+v", st.Progress)
	}
	if got, _ := remote.get("/backup/mirror/docs/plain.txt"); got != plain+"changed" {
		t.Errorf("the changed object was not re-copied")
	}

	// An unreachable target is reported per object, not as a crash.
	bad := strings.Replace(doc, remote.srv.URL, "http://127.0.0.1:1", 1) + "  retry: {attempts: 1, delay: 1ms}\n"
	st = waitJob(t, e, startJob(t, e, bad))
	if st.Progress.Failed != 2 || len(st.Progress.Failures) == 0 {
		t.Errorf("unreachable target = %+v", st.Progress)
	}
}

func TestBatchKeyRotate(t *testing.T) {
	e := batchEnv(t, &manualClock{t: time.Now()})
	e.mb("rotbucket")
	body := strings.Repeat("rotate me ", 500)
	for i := 0; i < 6; i++ {
		e.put(fmt.Sprintf("/rotbucket/k%d", i), body, hdr{
			"x-amz-server-side-encryption":                "aws:kms",
			"x-amz-server-side-encryption-aws-kms-key-id": "default"})
	}
	e.put("/rotbucket/s3obj", body, hdr{"x-amz-server-side-encryption": "AES256"})
	e.put("/rotbucket/plain", body, nil)

	r, _ := e.do("HEAD", "/rotbucket/k0", nil, nil)
	if !strings.HasSuffix(r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id"), "default") {
		t.Fatalf("before: key id %q", r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id"))
	}
	before := map[string]string{}
	for i := 0; i < 6; i++ {
		_, info := e.stored("rotbucket", fmt.Sprintf("k%d", i))
		before[fmt.Sprint(i)] = info.ETag
	}
	st := waitJob(t, e, startJob(t, e, "keyrotate:\n  bucket: rotbucket\n  encryption: {type: sse-kms, key: other}\n"))
	if st.State != batch.StateCompleted || st.Progress.Succeeded != 6 || st.Progress.Failed != 0 {
		t.Fatalf("job = %+v", st)
	}
	for i := 0; i < 6; i++ {
		key := fmt.Sprintf("/rotbucket/k%d", i)
		r, _ := e.do("HEAD", key, nil, nil)
		if got := r.Header.Get("x-amz-server-side-encryption-aws-kms-key-id"); !strings.HasSuffix(got, "other") {
			t.Errorf("%s: key id after rotation = %q", key, got)
		}
		if got, _ := e.get(key); got != body {
			t.Errorf("%s: unreadable after rotation", key)
		}
		if _, info := e.stored("rotbucket", fmt.Sprintf("k%d", i)); info.ETag != before[fmt.Sprint(i)] {
			t.Errorf("%s: the stored data changed", key)
		}
	}
	if got, _ := e.get("/rotbucket/s3obj"); got != body {
		t.Error("an SSE-S3 object was disturbed by an sse-kms rotation")
	}
	// Idempotent: a second run has nothing to do.
	st = waitJob(t, e, startJob(t, e, "keyrotate:\n  bucket: rotbucket\n  encryption: {type: sse-kms, key: other}\n"))
	if st.Progress.Succeeded != 0 {
		t.Errorf("second run rotated %d objects", st.Progress.Succeeded)
	}
}
