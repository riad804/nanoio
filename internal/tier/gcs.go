package tier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"google.golang.org/api/option"
)

type gcsBackend struct {
	cfg    GCSConfig
	client *storage.Client
}

// NewGCS returns a Google Cloud Storage tier.
func NewGCS(c GCSConfig) (Backend, error) {
	var opts []option.ClientOption
	if c.CredentialsJSON != "" {
		opts = append(opts, option.WithCredentialsJSON([]byte(c.CredentialsJSON)))
	}
	if c.Endpoint != "" {
		opts = append(opts, option.WithEndpoint(c.Endpoint), option.WithoutAuthentication())
	}
	cl, err := storage.NewClient(context.Background(), opts...)
	if err != nil {
		return nil, fmt.Errorf("gcs client: %w", err)
	}
	return &gcsBackend{cfg: c, client: cl}, nil
}

func (b *gcsBackend) obj(name string) *storage.ObjectHandle {
	return b.client.Bucket(b.cfg.Bucket).Object(strings.TrimPrefix(b.cfg.Prefix, "/") + name)
}

// Put implements Backend.
func (b *gcsBackend) Put(ctx context.Context, name string, r io.Reader, size int64) (string, error) {
	w := b.obj(name).NewWriter(ctx)
	w.ContentType = "application/octet-stream"
	if _, err := io.Copy(w, r); err != nil {
		w.Close()
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return strconv.FormatInt(w.Attrs().Generation, 10), nil
}

// Get implements Backend.
func (b *gcsBackend) Get(ctx context.Context, name, versionID string, offset, length int64) (io.ReadCloser, error) {
	o := b.obj(name)
	if versionID != "" {
		if g, err := strconv.ParseInt(versionID, 10, 64); err == nil {
			o = o.Generation(g)
		}
	}
	return o.NewRangeReader(ctx, offset, length)
}

// Delete implements Backend.
func (b *gcsBackend) Delete(ctx context.Context, name, versionID string) error {
	o := b.obj(name)
	if versionID != "" {
		if g, err := strconv.ParseInt(versionID, 10, 64); err == nil {
			o = o.Generation(g)
		}
	}
	err := o.Delete(ctx)
	if errors.Is(err, storage.ErrObjectNotExist) {
		return nil
	}
	return err
}

// Check implements Backend.
func (b *gcsBackend) Check(ctx context.Context) error {
	name := fmt.Sprintf("nanoio-tier-probe-%d", time.Now().UnixNano())
	payload := []byte("nanoio tier probe")
	vid, err := b.Put(ctx, name, bytes.NewReader(payload), int64(len(payload)))
	if err != nil {
		return err
	}
	defer b.Delete(context.Background(), name, vid)
	rc, err := b.Get(ctx, name, vid, 0, -1)
	if err != nil {
		return err
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(got, payload) {
		return errors.New("probe object did not read back intact")
	}
	return nil
}

// Close implements Backend.
func (b *gcsBackend) Close() error { return b.client.Close() }
