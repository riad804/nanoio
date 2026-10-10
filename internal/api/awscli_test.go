package api

import (
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestAWSCLI drives the real aws CLI through the commands from the Phase 2
// brief. It is skipped when `aws` is not installed.
func TestAWSCLI(t *testing.T) {
	aws, err := exec.LookPath("aws")
	if err != nil {
		t.Skip("aws CLI not installed")
	}
	e := newEnv(t)
	dir := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.Command(aws, append([]string{"--endpoint-url", e.srv.URL, "--region", "us-east-1"}, args...)...)
		cmd.Env = append(os.Environ(),
			"AWS_ACCESS_KEY_ID="+rootAK, "AWS_SECRET_ACCESS_KEY="+rootSK,
			"AWS_EC2_METADATA_DISABLED=true", "AWS_PAGER=",
			"AWS_CONFIG_FILE="+filepath.Join(dir, "config"),
			"AWS_SHARED_CREDENTIALS_FILE="+filepath.Join(dir, "creds"))
		var out, errb bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &errb
		if err := cmd.Run(); err != nil {
			t.Fatalf("aws %s: %v\n%s%s", strings.Join(args, " "), err, out.String(), errb.String())
		}
		return out.String()
	}

	small := filepath.Join(dir, "small.txt")
	os.WriteFile(small, []byte("hello from aws-cli\n"), 0o644)
	big := filepath.Join(dir, "big.bin")
	data := make([]byte, 5<<20)
	rand.New(rand.NewSource(3)).Read(data)
	os.WriteFile(big, data, 0o644)

	run("s3", "mb", "s3://clibucket")
	if out := run("s3", "ls"); !strings.Contains(out, "clibucket") {
		t.Errorf("ls: %q", out)
	}
	run("s3", "cp", small, "s3://clibucket/dir/small.txt")
	run("s3", "cp", big, "s3://clibucket/big.bin")
	if out := run("s3", "ls", "s3://clibucket/"); !strings.Contains(out, "PRE dir/") || !strings.Contains(out, "big.bin") {
		t.Errorf("ls bucket: %q", out)
	}
	if out := run("s3", "ls", "s3://clibucket/dir/"); !strings.Contains(out, "small.txt") {
		t.Errorf("ls dir: %q", out)
	}
	out := filepath.Join(dir, "out.bin")
	run("s3", "cp", "s3://clibucket/big.bin", out)
	if got, _ := os.ReadFile(out); !bytes.Equal(got, data) {
		t.Errorf("downloaded %d bytes, differs from the %d uploaded", len(got), len(data))
	}
	run("s3", "rm", "s3://clibucket/dir/small.txt")
	run("s3", "rm", "s3://clibucket", "--recursive")
	if out := run("s3", "ls", "s3://clibucket/"); strings.TrimSpace(out) != "" {
		t.Errorf("bucket not empty after recursive rm: %q", out)
	}
	run("s3", "rb", "s3://clibucket")
	if out := run("s3", "ls"); strings.Contains(out, "clibucket") {
		t.Errorf("bucket survived rb: %q", out)
	}

	// Files above the CLI's 8 MiB threshold go through multipart upload.
	run("s3", "mb", "s3://mpbucket")
	huge := filepath.Join(dir, "huge.bin")
	hugeData := make([]byte, 21<<20+12345) // 8 + 8 + 5 MiB + a little: three parts
	rand.New(rand.NewSource(5)).Read(hugeData)
	os.WriteFile(huge, hugeData, 0o644)
	run("s3", "cp", huge, "s3://mpbucket/huge.bin")
	back := filepath.Join(dir, "huge.out")
	run("s3", "cp", "s3://mpbucket/huge.bin", back)
	if got, _ := os.ReadFile(back); !bytes.Equal(got, hugeData) {
		t.Errorf("multipart round trip: %d bytes, differs from the %d uploaded", len(got), len(hugeData))
	}
	if out := run("s3api", "head-object", "--bucket", "mpbucket", "--key", "huge.bin"); !strings.Contains(out, `-3\"`) {
		t.Errorf("head-object ETag is not a 3-part multipart ETag: %s", out)
	}
	// An abandoned upload is visible and abortable, and blocks rb until aborted.
	created := run("s3api", "create-multipart-upload", "--bucket", "mpbucket", "--key", "pending.bin")
	idx := strings.Index(created, `"UploadId": "`)
	if idx < 0 {
		t.Fatalf("no UploadId in %s", created)
	}
	uploadID := created[idx+len(`"UploadId": "`):]
	uploadID = uploadID[:strings.Index(uploadID, `"`)]
	if out := run("s3api", "list-multipart-uploads", "--bucket", "mpbucket"); !strings.Contains(out, "pending.bin") {
		t.Errorf("list-multipart-uploads: %s", out)
	}
	run("s3api", "abort-multipart-upload", "--bucket", "mpbucket", "--key", "pending.bin", "--upload-id", uploadID)
	run("s3", "rm", "s3://mpbucket", "--recursive")
	run("s3", "rb", "s3://mpbucket")
}
