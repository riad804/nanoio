package api

import (
	"net/http"
	"os"
	"runtime"
	"time"
)

var processStart = time.Now()

func init() {
	madminRegister("info", "GET", "admin:ServerInfo", (*Server).madminInfo)
	madminRegister("storageinfo", "GET", "admin:StorageInfo", (*Server).madminStorageInfo)
	madminRegister("datausageinfo", "GET", "admin:DataUsageInfo", (*Server).madminDataUsage)
}

type madminDisk struct {
	Endpoint       string `json:"endpoint,omitempty"`
	State          string `json:"state,omitempty"`
	TotalSpace     uint64 `json:"totalspace,omitempty"`
	AvailableSpace uint64 `json:"availspace,omitempty"`
	UsedSpace      uint64 `json:"usedspace,omitempty"`
	PoolIndex      int    `json:"pool_index"`
	SetIndex       int    `json:"set_index"`
	DiskIndex      int    `json:"disk_index"`
}

// backendSummary counts buckets/objects/bytes for the info responses.
func (s *Server) backendSummary(q *request) (buckets, objects, size uint64, errStr string) {
	bl, err := s.st.ListBuckets(q.ctx())
	if err != nil {
		return 0, 0, 0, err.Error()
	}
	buckets = uint64(len(bl))
	return buckets, 0, 0, ""
}

func (s *Server) madminInfo(q *request) {
	bi, err := s.st.Info(q.ctx())
	buckets, _, _, berr := s.backendSummary(q)
	host, _ := os.Hostname()
	mode := "online"
	if err != nil || !bi.Healthy {
		mode = "offline"
	}
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	backend := map[string]any{"backendType": "FS"}
	if bi.Kind == "xl" {
		parity := bi.Disks / 2
		if s.maint != nil {
			if _, p := s.maint.Layout(); p > 0 {
				parity = p
			}
		}
		backend = map[string]any{"backendType": "Erasure", "onlineDisks": bi.Disks, "offlineDisks": 0,
			"standardSCParity": parity, "rrSCParity": 1, "totalSets": []int{1}, "totalDrivesPerSet": []int{bi.Disks}}
	}
	info := map[string]any{
		"mode":         mode,
		"region":       s.region,
		"deploymentID": s.clusterID(q.ctx()),
		"buckets":      map[string]any{"count": buckets, "error": berr},
		"objects":      map[string]any{"count": 0},
		"usage":        map[string]any{"size": bi.TotalBytes - bi.FreeBytes},
		"services":     map[string]any{},
		"backend":      backend,
		"servers": []map[string]any{{
			"state":    map[bool]string{true: "online", false: "offline"}[err == nil && bi.Healthy],
			"endpoint": q.r.Host, "scheme": "http", "uptime": int64(time.Since(processStart).Seconds()),
			"version": "nanoio", "commitID": "unknown", "network": map[string]string{host: "online"},
			"drives": []madminDisk{{Endpoint: host, State: "ok", TotalSpace: bi.TotalBytes,
				AvailableSpace: bi.FreeBytes, UsedSpace: bi.TotalBytes - bi.FreeBytes}},
			"poolNumber": 1, "poolNumbers": []int{1},
			"mem_stats": map[string]uint64{"Alloc": ms.Alloc, "TotalAlloc": ms.TotalAlloc, "Mallocs": ms.Mallocs,
				"Frees": ms.Frees, "HeapAlloc": ms.HeapAlloc},
			"go_max_procs": runtime.GOMAXPROCS(0), "num_cpu": runtime.NumCPU(), "runtime_version": runtime.Version(),
			"edition": "Open Source", "is_leader": true, "ilm_expiry_in_progress": false,
		}},
	}
	s.writeJSONOK(q, info)
}

func (s *Server) madminStorageInfo(q *request) {
	bi, err := s.st.Info(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	host, _ := os.Hostname()
	kind := 1
	if bi.Kind == "xl" {
		kind = 2
	}
	disks := []madminDisk{}
	n := bi.Disks
	if n < 1 {
		n = 1
	}
	for i := 0; i < n; i++ {
		d := madminDisk{Endpoint: host, State: "ok", TotalSpace: bi.TotalBytes / uint64(n),
			AvailableSpace: bi.FreeBytes / uint64(n), DiskIndex: i}
		d.UsedSpace = d.TotalSpace - d.AvailableSpace
		disks = append(disks, d)
	}
	s.writeJSONOK(q, map[string]any{
		"Disks": disks,
		"Backend": map[string]any{"Type": kind, "OnlineDisks": map[string]int{host: n}, "OfflineDisks": map[string]int{host: 0},
			"StandardSCParity": n / 2, "RRSCParity": 1, "TotalSets": []int{1}, "DrivesPerSet": []int{n}},
	})
}

func (s *Server) madminDataUsage(q *request) {
	bl, err := s.st.ListBuckets(q.ctx())
	if err != nil {
		s.madminErr(q, err)
		return
	}
	s.writeJSONOK(q, map[string]any{"lastUpdate": time.Now().UTC(), "bucketsCount": len(bl), "objectsCount": 0,
		"versionsCount": 0, "objectsTotalSize": 0, "buckets": map[string]any{}})
}

var _ = http.StatusOK
