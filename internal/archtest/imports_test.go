// Package archtest enforces the import rules from the Phase 0 design doc.
package archtest

import (
	"os/exec"
	"strings"
	"testing"
)

const mod = "nanoio/"

func TestImportRules(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go tool not in PATH")
	}
	// forbid lists module-relative prefixes a package must not reach, even
	// transitively. "" forbids every module package (stdlib only).
	tests := []struct {
		pkg    string
		forbid []string
	}{
		{"internal/api", []string{"internal/storage/fs", "internal/storage/xl"}},
		// auth and iam are leaf packages: standard library only, so
		// credential and policy logic can never reach into storage or HTTP.
		{"internal/auth", []string{""}},
		{"internal/iam", []string{""}},
		{"internal/bucket", []string{"internal/api", "internal/auth"}},
		{"internal/storage/fs", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket", "internal/storage/xl"}},
		// xl is built on the Disk interface and knows neither the network
		// nor the cluster: remote drives and the lock manager are injected.
		{"internal/storage/xl", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket", "internal/storage/fs",
			"internal/storage/xl/disk/remote", "internal/storage/cluster", "internal/cluster"}},
		{"internal/storage/xl/disk", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket",
			"internal/storage/fs", "internal/storage/xl/disk/remote", "internal/cluster"}},
		{"internal/storage/xl/disk/remote", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket",
			"internal/storage/fs", "internal/storage/cluster"}},
		// The cluster plumbing is leaf-like: authentication and the fault
		// network are standard library only; rpc builds on rpcauth alone.
		{"internal/cluster/rpcauth", []string{""}},
		{"internal/cluster/faultnet", []string{""}},
		{"internal/cluster/rpc", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket",
			"internal/storage", "internal/cluster/dsync", "internal/cluster/faultnet"}},
		{"internal/cluster/dsync", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket",
			"internal/storage/fs", "internal/storage/xl", "internal/storage/cluster"}},
		{"internal/storage/cluster", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket",
			"internal/storage/fs", "internal/cluster/faultnet"}},
		{"internal/bucket/nslock", []string{"internal/api", "internal/auth", "internal/storage/fs", "internal/storage/xl"}},
		{"internal/config", []string{""}},
		{"internal/storage/internal/fsutil", []string{""}},
		{"internal/meta", []string{""}},
		// Encryption: kms is standard library only; sse builds on kms alone,
		// so key handling can never reach into storage, HTTP or auth.
		{"internal/kms", []string{""}},
		{"internal/sse", []string{"internal/api", "internal/auth", "internal/iam", "internal/bucket", "internal/storage", "internal/cluster"}},
		{"internal/storage", []string{""}},
	}
	for _, tt := range tests {
		t.Run(tt.pkg, func(t *testing.T) {
			deps := listDeps(t, mod+tt.pkg)
			for _, dep := range deps {
				if dep == mod+tt.pkg || !strings.HasPrefix(dep, mod) {
					continue
				}
				rel := strings.TrimPrefix(dep, mod)
				for _, f := range tt.forbid {
					if f == "" || rel == f || strings.HasPrefix(rel, f+"/") {
						t.Errorf("%s must not depend on %s", tt.pkg, dep)
					}
				}
			}
		})
	}
}

func listDeps(t *testing.T, pkg string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", pkg)
	cmd.Dir = "../.."
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}
	return strings.Fields(string(out))
}
