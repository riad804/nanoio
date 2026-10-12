package tier

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/blob"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/bloberror"
)

type azureBackend struct {
	cfg    AzureConfig
	client *azblob.Client
}

// NewAzure returns an Azure Blob Storage tier using shared-key credentials.
func NewAzure(c AzureConfig) (Backend, error) {
	cred, err := azblob.NewSharedKeyCredential(c.Account, c.AccountKey)
	if err != nil {
		return nil, fmt.Errorf("azure credentials: %w", err)
	}
	endpoint := c.Endpoint
	if endpoint == "" {
		endpoint = fmt.Sprintf("https://%s.blob.core.windows.net/", c.Account)
	}
	cl, err := azblob.NewClientWithSharedKeyCredential(endpoint, cred, &azblob.ClientOptions{
		ClientOptions: azcore.ClientOptions{Retry: retryOnce()},
	})
	if err != nil {
		return nil, err
	}
	return &azureBackend{cfg: c, client: cl}, nil
}

func (b *azureBackend) key(name string) string { return strings.TrimPrefix(b.cfg.Prefix, "/") + name }

// Put implements Backend. The SDK buffers and stages blocks itself.
func (b *azureBackend) Put(ctx context.Context, name string, r io.Reader, size int64) (string, error) {
	resp, err := b.client.UploadStream(ctx, b.cfg.Container, b.key(name), r, &azblob.UploadStreamOptions{
		BlockSize: 16 << 20, Concurrency: 2,
	})
	if err != nil {
		return "", err
	}
	if resp.VersionID != nil {
		return *resp.VersionID, nil
	}
	return "", nil
}

// Get implements Backend.
func (b *azureBackend) Get(ctx context.Context, name, versionID string, offset, length int64) (io.ReadCloser, error) {
	opts := &azblob.DownloadStreamOptions{}
	if offset > 0 || length >= 0 {
		opts.Range = blob.HTTPRange{Offset: offset}
		if length >= 0 {
			opts.Range.Count = length
		}
	}
	resp, err := b.client.DownloadStream(ctx, b.cfg.Container, b.key(name), opts)
	if err != nil {
		return nil, err
	}
	return resp.Body, nil
}

// Delete implements Backend.
func (b *azureBackend) Delete(ctx context.Context, name, versionID string) error {
	_, err := b.client.DeleteBlob(ctx, b.cfg.Container, b.key(name), nil)
	if err != nil && bloberror.HasCode(err, bloberror.BlobNotFound) {
		return nil
	}
	return err
}

// Check implements Backend.
func (b *azureBackend) Check(ctx context.Context) error {
	name := fmt.Sprintf("nanoio-tier-probe-%d", time.Now().UnixNano())
	payload := []byte("nanoio tier probe")
	if _, err := b.Put(ctx, name, bytes.NewReader(payload), int64(len(payload))); err != nil {
		return err
	}
	defer b.Delete(context.Background(), name, "")
	rc, err := b.Get(ctx, name, "", 0, -1)
	if err != nil {
		return err
	}
	defer rc.Close()
	got, err := io.ReadAll(rc)
	if err != nil || !bytes.Equal(got, payload) {
		return errors.New("probe blob did not read back intact")
	}
	return nil
}

// Close implements Backend.
func (b *azureBackend) Close() error { return nil }
