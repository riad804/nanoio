// Package oracle checks NanoIO's admin API against MinIO's own client
// library. madmin-go is AGPL-3.0, so it lives only in this separate module
// and is never linked into the server: the tests drive a nanoio binary over
// HTTP.
package oracle

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/minio/madmin-go/v3"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

const (
	rootUser = "oracleroot"
	rootPass = "oracle-root-password"
)

// startServer builds and runs nanoio over four drives.
func startServer(t *testing.T) (endpoint string) {
	t.Helper()
	dir := t.TempDir()
	bin := filepath.Join(dir, "nanoio")
	build := exec.Command("go", "build", "-o", bin, "nanoio/cmd/nanoio")
	build.Dir = "../.."
	build.Env = append(os.Environ(), "GOTOOLCHAIN=local")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := l.Addr().String()
	l.Close()
	var drives string
	for i := 1; i <= 4; i++ {
		d := filepath.Join(dir, fmt.Sprintf("d%d", i))
		os.MkdirAll(d, 0o755)
		if drives != "" {
			drives += ","
		}
		drives += d
	}
	cmd := exec.Command(bin, "--drives", drives, "--address", addr)
	cmd.Env = append(os.Environ(), "NANOIO_ROOT_USER="+rootUser, "NANOIO_ROOT_PASSWORD="+rootPass)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 100*time.Millisecond); err == nil {
			c.Close()
			time.Sleep(200 * time.Millisecond)
			return addr
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("server did not start")
	return ""
}

func randName(p string) string {
	b := make([]byte, 4)
	rand.Read(b)
	return p + hex.EncodeToString(b)
}

func TestAdminAgainstMadminClient(t *testing.T) {
	addr := startServer(t)
	ctx := context.Background()
	adm, err := madmin.NewWithOptions(addr, &madmin.Options{Creds: credentials.NewStaticV4(rootUser, rootPass, ""), Secure: false})
	if err != nil {
		t.Fatal(err)
	}

	t.Run("server info", func(t *testing.T) {
		info, err := adm.ServerInfo(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode != "online" || len(info.Servers) != 1 {
			t.Errorf("info = %+v", info)
		}
		si, err := adm.StorageInfo(ctx)
		if err != nil || len(si.Disks) != 4 {
			t.Errorf("storage info: %v, %d disks", err, len(si.Disks))
		}
	})

	t.Run("users groups policies", func(t *testing.T) {
		pol := []byte(`{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject"],"Resource":["arn:aws:s3:::*"]}]}`)
		if err := adm.AddCannedPolicy(ctx, "oracle-ro", pol); err != nil {
			t.Fatal(err)
		}
		if err := adm.AddUser(ctx, "oracle-alice", "alice-secret-123"); err != nil {
			t.Fatal(err)
		}
		if _, err := adm.AttachPolicy(ctx, madmin.PolicyAssociationReq{Policies: []string{"oracle-ro"}, User: "oracle-alice"}); err != nil {
			t.Fatal(err)
		}
		u, err := adm.GetUserInfo(ctx, "oracle-alice")
		if err != nil || u.PolicyName != "oracle-ro" || u.Status != madmin.AccountEnabled {
			t.Errorf("user info %+v %v", u, err)
		}
		if err := adm.UpdateGroupMembers(ctx, madmin.GroupAddRemove{Group: "oracle-g", Members: []string{"oracle-alice"}}); err != nil {
			t.Fatal(err)
		}
		g, err := adm.GetGroupDescription(ctx, "oracle-g")
		if err != nil || len(g.Members) != 1 {
			t.Errorf("group %+v %v", g, err)
		}
		users, err := adm.ListUsers(ctx)
		if err != nil || users["oracle-alice"].Status != madmin.AccountEnabled {
			t.Errorf("users %v %v", users, err)
		}
		// The new user can read through the policy, via an S3 client.
		mc, err := minio.New(addr, &minio.Options{Creds: credentials.NewStaticV4(rootUser, rootPass, "")})
		if err != nil {
			t.Fatal(err)
		}
		bkt := randName("oracle")
		if err := mc.MakeBucket(ctx, bkt, minio.MakeBucketOptions{}); err != nil {
			t.Fatal(err)
		}
		alice, _ := minio.New(addr, &minio.Options{Creds: credentials.NewStaticV4("oracle-alice", "alice-secret-123", "")})
		if _, err := alice.StatObject(ctx, bkt, "missing", minio.StatObjectOptions{}); err == nil {
			t.Error("stat of a missing object succeeded")
		}
		if err := adm.SetUserStatus(ctx, "oracle-alice", madmin.AccountDisabled); err != nil {
			t.Fatal(err)
		}
		if err := alice.MakeBucket(ctx, randName("x"), minio.MakeBucketOptions{}); err == nil {
			t.Error("disabled user made a bucket")
		}
	})

	t.Run("service accounts", func(t *testing.T) {
		res, err := adm.AddServiceAccount(ctx, madmin.AddServiceAccountReq{AccessKey: "oraclesvc", SecretKey: "svc-secret-12345"})
		if err != nil {
			t.Fatal(err)
		}
		if res.AccessKey != "oraclesvc" {
			t.Errorf("created %+v", res)
		}
		list, err := adm.ListServiceAccounts(ctx, "")
		if err != nil || len(list.Accounts) == 0 {
			t.Errorf("list %+v %v", list, err)
		}
		if err := adm.DeleteServiceAccount(ctx, "oraclesvc"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("config kv and heal status", func(t *testing.T) {
		if _, err := adm.HelpConfigKV(ctx, "identity_ldap", "", false); err != nil {
			t.Errorf("help: %v", err)
		}
		if _, err := adm.BackgroundHealStatus(ctx); err != nil {
			t.Errorf("background heal status: %v", err)
		}
		if _, err := adm.ListPoolsStatus(ctx); err != nil {
			t.Errorf("pools: %v", err)
		}
	})

	t.Run("an unauthenticated or unauthorised caller is refused", func(t *testing.T) {
		bad, _ := madmin.NewWithOptions(addr, &madmin.Options{Creds: credentials.NewStaticV4(rootUser, "wrong-secret-value", ""), Secure: false})
		if _, err := bad.ServerInfo(ctx); err == nil {
			t.Error("wrong secret accepted")
		}
		if err := adm.AddUser(ctx, "oracle-bob", "bob-secret-12345"); err != nil {
			t.Fatal(err)
		}
		bob, _ := madmin.NewWithOptions(addr, &madmin.Options{Creds: credentials.NewStaticV4("oracle-bob", "bob-secret-12345", ""), Secure: false})
		if _, err := bob.ServerInfo(ctx); err == nil {
			t.Error("a user with no admin policy read server info")
		}
		if err := bob.AddUser(ctx, "oracle-eve", "eve-secret-12345"); err == nil {
			t.Error("a user with no admin policy created a user")
		}
	})
}
