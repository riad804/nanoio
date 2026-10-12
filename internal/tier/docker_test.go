package tier_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	gcs "cloud.google.com/go/storage"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"google.golang.org/api/option"

	"nanoio/internal/auth"
	"nanoio/internal/tier"
)

// These tests run the real remote services in containers. They are off by
// default (they need Docker and pull images); enable with
// NANOIO_TEST_DOCKER=1.

func needDocker(t *testing.T) {
	t.Helper()
	if os.Getenv("NANOIO_TEST_DOCKER") == "" {
		t.Skip("set NANOIO_TEST_DOCKER=1 to run tests against real services in Docker")
	}
	if err := exec.Command("docker", "info").Run(); err != nil {
		t.Skipf("docker is not available: %v", err)
	}
}

// container starts image with the container port published on a free
// loopback port and returns host:port. It is removed when the test ends.
func container(t *testing.T, image string, port int, env []string, args ...string) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	host := l.Addr().(*net.TCPAddr).Port
	l.Close()
	name := fmt.Sprintf("nanoio-test-%d", time.Now().UnixNano())
	run := []string{"run", "-d", "--rm", "--name", name, "-p", fmt.Sprintf("127.0.0.1:%d:%d", host, port)}
	for _, e := range env {
		run = append(run, "-e", e)
	}
	run = append(run, image)
	run = append(run, args...)
	if out, err := exec.Command("docker", run...).CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", image, err, out)
	}
	t.Cleanup(func() { exec.Command("docker", "rm", "-f", name).Run() })
	addr := fmt.Sprintf("127.0.0.1:%d", host)
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			c.Close()
			time.Sleep(500 * time.Millisecond)
			return addr
		}
		time.Sleep(200 * time.Millisecond)
	}
	logs, _ := exec.Command("docker", "logs", name).CombinedOutput()
	t.Fatalf("%s did not start:\n%s", image, logs)
	return ""
}

// exercise runs the Backend contract against a live remote.
func exercise(t *testing.T, be tier.Backend, partThreshold int64) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := be.Check(ctx); err != nil {
		t.Fatalf("Check: %v", err)
	}
	sizes := []int64{0, 1, 4096}
	if partThreshold > 0 {
		sizes = append(sizes, partThreshold*2+12345) // forces a multipart upload
	}
	for _, size := range sizes {
		data := make([]byte, size)
		rand.Read(data)
		name := fmt.Sprintf("obj-%d-%d", size, time.Now().UnixNano())
		vid, err := be.Put(ctx, name, bytes.NewReader(data), size)
		if err != nil {
			t.Fatalf("Put %d bytes: %v", size, err)
		}
		rc, err := be.Get(ctx, name, vid, 0, -1)
		if err != nil {
			t.Fatalf("Get %d bytes: %v", size, err)
		}
		got, err := io.ReadAll(rc)
		rc.Close()
		if err != nil || !bytes.Equal(got, data) {
			t.Fatalf("%d bytes did not round trip (%d back, %v)", size, len(got), err)
		}
		if size > 100 {
			rc, err := be.Get(ctx, name, vid, 10, 50)
			if err != nil {
				t.Fatalf("range Get: %v", err)
			}
			part, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Equal(part, data[10:60]) {
				t.Errorf("range read returned the wrong bytes")
			}
			rc, err = be.Get(ctx, name, vid, size-20, -1)
			if err != nil {
				t.Fatalf("tail Get: %v", err)
			}
			tail, _ := io.ReadAll(rc)
			rc.Close()
			if !bytes.Equal(tail, data[size-20:]) {
				t.Errorf("open-ended range returned the wrong bytes")
			}
		}
		if err := be.Delete(ctx, name, vid); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := be.Delete(ctx, name, vid); err != nil {
			t.Errorf("deleting a missing object must succeed: %v", err)
		}
		if rc, err := be.Get(ctx, name, vid, 0, -1); err == nil {
			rc.Close()
			t.Errorf("a deleted object can still be read")
		}
	}
}

func TestS3BackendAgainstRealMinIO(t *testing.T) {
	needDocker(t)
	// MinIO's own image moved registries; the Bitnami build is a real MinIO
	// server and is what is commonly present. Override with
	// NANOIO_TEST_MINIO_IMAGE.
	image := os.Getenv("NANOIO_TEST_MINIO_IMAGE")
	if image == "" {
		image = "bitnamilegacy/minio:2025.4.22"
	}
	addr := container(t, image, 9000,
		[]string{"MINIO_ROOT_USER=minioadmin", "MINIO_ROOT_PASSWORD=minioadmin123"})
	// Create the bucket with a signed request.
	req, _ := http.NewRequest("PUT", "http://"+addr+"/tierbucket", nil)
	auth.Signer{AccessKey: "minioadmin", SecretKey: "minioadmin123"}.Sign(req, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", time.Now())
	var resp *http.Response
	var err error
	for i := 0; i < 30; i++ {
		resp, err = http.DefaultClient.Do(req.Clone(context.Background()))
		if err == nil && resp.StatusCode == 200 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("create bucket: %v %v", resp, err)
	}
	be, err := tier.NewS3(tier.S3Config{Endpoint: "http://" + addr, Bucket: "tierbucket", Prefix: "cold/",
		AccessKey: "minioadmin", SecretKey: "minioadmin123", PartSize: 5 << 20})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	exercise(t, be, 5<<20)
}

func TestAzureBackendAgainstAzurite(t *testing.T) {
	needDocker(t)
	addr := container(t, "mcr.microsoft.com/azure-storage/azurite:latest", 10000, nil,
		"azurite-blob", "--blobHost", "0.0.0.0", "--skipApiVersionCheck", "--loose")
	const key = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
	endpoint := "http://" + addr + "/devstoreaccount1"
	cred, _ := azblob.NewSharedKeyCredential("devstoreaccount1", key)
	cl, err := azblob.NewClientWithSharedKeyCredential(endpoint, cred, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.CreateContainer(context.Background(), "tiercontainer", nil); err != nil {
		t.Fatalf("create container: %v", err)
	}
	be, err := tier.NewAzure(tier.AzureConfig{Account: "devstoreaccount1", AccountKey: key, Container: "tiercontainer",
		Prefix: "cold/", Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	exercise(t, be, 0)
}

func TestGCSBackendAgainstFakeGCS(t *testing.T) {
	needDocker(t)
	addr := container(t, "fsouza/fake-gcs-server:latest", 4443, nil,
		"-scheme", "http", "-port", "4443", "-public-host", "127.0.0.1", "-external-url", "http://127.0.0.1:4443")
	endpoint := "http://" + addr + "/storage/v1/"
	cl, err := gcs.NewClient(context.Background(), option.WithEndpoint(endpoint), option.WithoutAuthentication())
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.Bucket("tierbucket").Create(context.Background(), "proj", nil); err != nil {
		t.Fatalf("create bucket: %v", err)
	}
	be, err := tier.NewGCS(tier.GCSConfig{Bucket: "tierbucket", Prefix: "cold/", Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	defer be.Close()
	exercise(t, be, 0)
	_ = strings.TrimSpace
}
