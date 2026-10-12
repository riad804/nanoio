package main

import (
	"context"

	"nanoio/internal/api"
	"nanoio/internal/storage"
	"nanoio/internal/storage/cluster"
	"nanoio/internal/storage/xl"
)

// maintainer adapts the erasure-coded backends to api.Maintainer, so the
// API package never links them.
type maintainer struct {
	scan         func(ctx context.Context, deep bool) (xl.ScanStats, error)
	heal         func(ctx context.Context, bucket, object string, deep bool) (xl.HealResult, error)
	hbkt         func(ctx context.Context, bucket string) ([]int, error)
	pools        func() []cluster.PoolInfo
	drain        func(ctx context.Context, pool int) (cluster.DrainStats, error)
	data, parity int
}

func xlMaintainer(x *xl.XL) api.Maintainer {
	d, p, _ := x.Layout()
	return &maintainer{scan: x.Scan, heal: x.HealObject, hbkt: x.HealBucket, data: d, parity: p}
}

func clusterMaintainer(s *cluster.Store) api.Maintainer {
	m := &maintainer{scan: s.Scan, heal: s.HealObject, hbkt: s.HealBucket, pools: s.Pools, drain: s.Drain}
	if st := s.Status(); len(st) > 0 {
		m.data, m.parity = st[0].Data, st[0].Parity
	}
	return m
}

func (m *maintainer) Scan(ctx context.Context, deep bool) (api.MaintScan, error) {
	st, err := m.scan(ctx, deep)
	return api.MaintScan{DrivesFormatted: st.DrivesFormatted, Buckets: st.Buckets, BucketsHealed: st.BucketsHealed,
		Objects: st.Objects, ShardsHealed: st.ShardsHealed, Dangling: st.Dangling, Unrecoverable: st.Unrecoverable,
		ExpiredUploads: st.ExpiredUploads, OrphanDirs: st.OrphanDirs, Staging: st.Staging}, err
}

func (m *maintainer) HealObject(ctx context.Context, bucket, object string, deep bool) (api.MaintHeal, error) {
	r, err := m.heal(ctx, bucket, object, deep)
	return api.MaintHeal{Healed: r.Healed, Dangling: r.Dangling, Skipped: r.Skipped}, err
}

func (m *maintainer) HealBucket(ctx context.Context, bucket string) ([]int, error) {
	return m.hbkt(ctx, bucket)
}

func (m *maintainer) Pools() []api.MaintPool {
	if m.pools == nil {
		return nil
	}
	var out []api.MaintPool
	for _, p := range m.pools() {
		out = append(out, api.MaintPool{Index: p.Index, Sets: p.Sets, Drives: p.Drives, Online: p.Online, Draining: p.Draining})
	}
	return out
}

func (m *maintainer) Drain(ctx context.Context, pool int) (api.MaintDrain, error) {
	if m.drain == nil {
		return api.MaintDrain{}, storage.ErrNotImplemented
	}
	d, err := m.drain(ctx, pool)
	return api.MaintDrain{Objects: d.Objects, Skipped: d.Skipped, Failed: d.Failed, Bytes: d.Bytes}, err
}

func (m *maintainer) Layout() (int, int) { return m.data, m.parity }
