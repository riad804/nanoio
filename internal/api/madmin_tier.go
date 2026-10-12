package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"nanoio/internal/tier"
)

func init() {
	r := madminRegister
	r("tier", "GET PUT", "admin:SetTier", (*Server).madminTiers)
	r("tier/", "GET POST DELETE", "admin:SetTier", (*Server).madminTierOne)
	r("tier-stats", "GET", "admin:ListTier", (*Server).madminTierStats)
}

type madminTierConfig struct {
	Version string
	Type    string `json:",omitempty"`
	Name    string `json:",omitempty"`
	S3      *struct {
		Endpoint, AccessKey, SecretKey, Bucket, Prefix, Region, StorageClass string `json:",omitempty"`
	} `json:",omitempty"`
	Azure *struct {
		Endpoint, Bucket, Prefix, Region string `json:",omitempty"`
		AccountName, AccountKey          string `json:",omitempty"`
	} `json:",omitempty"`
	GCS *struct {
		Endpoint, Creds, Bucket, Prefix, Region string `json:",omitempty"`
	} `json:",omitempty"`
	MinIO *struct {
		Endpoint, AccessKey, SecretKey, Bucket, Prefix, Region string `json:",omitempty"`
	} `json:",omitempty"`
}

func (s *Server) tiersReady(q *request) bool {
	if s.tiers == nil {
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented", "tiering is not enabled on this server")
		return false
	}
	return true
}

func tierErr(s *Server, q *request, err error) {
	switch {
	case errors.Is(err, tier.ErrExists):
		s.madminFail(q, http.StatusConflict, "XMinioAdminTierAlreadyExists", err.Error())
	case errors.Is(err, tier.ErrNotFound):
		s.madminFail(q, http.StatusNotFound, "XMinioAdminNoSuchTier", "specified remote tier does not exist")
	default:
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminTierInvalidConfig", err.Error())
	}
}

func (s *Server) madminTiers(q *request) {
	if !s.tiersReady(q) {
		return
	}
	if q.r.Method == http.MethodGet {
		list, err := s.tiers.List(q.ctx())
		if err != nil {
			s.madminErr(q, err)
			return
		}
		out := []madminTierConfig{}
		for _, c := range list {
			m := madminTierConfig{Version: "v1", Type: c.Type, Name: c.Name}
			switch {
			case c.S3 != nil:
				m.S3 = &struct {
					Endpoint, AccessKey, SecretKey, Bucket, Prefix, Region, StorageClass string `json:",omitempty"`
				}{Endpoint: c.S3.Endpoint, Bucket: c.S3.Bucket, Prefix: c.S3.Prefix, Region: c.S3.Region, StorageClass: c.S3.StorageClass}
			case c.Azure != nil:
				m.Azure = &struct {
					Endpoint, Bucket, Prefix, Region string `json:",omitempty"`
					AccountName, AccountKey          string `json:",omitempty"`
				}{Endpoint: c.Azure.Endpoint, Bucket: c.Azure.Container, Prefix: c.Azure.Prefix, AccountName: c.Azure.Account}
			case c.GCS != nil:
				m.GCS = &struct {
					Endpoint, Creds, Bucket, Prefix, Region string `json:",omitempty"`
				}{Endpoint: c.GCS.Endpoint, Bucket: c.GCS.Bucket, Prefix: c.GCS.Prefix}
			}
			out = append(out, m)
		}
		s.writeJSONOK(q, out)
		return
	}
	// PUT: add a tier.
	if !s.supportsTransition() {
		s.madminFail(q, http.StatusNotImplemented, "XMinioAdminNotImplemented",
			"this storage backend cannot hold transitioned objects (use the erasure-coded or cluster backend)")
		return
	}
	pt, err := s.readEncrypted(q)
	if err != nil {
		s.madminErr(q, err)
		return
	}
	var in madminTierConfig
	if err := json.Unmarshal(pt, &in); err != nil {
		s.madminErr(q, madminBad("invalid tier configuration"))
		return
	}
	cfg := tier.Config{Name: in.Name}
	switch strings.ToLower(in.Type) {
	case "s3":
		if in.S3 == nil {
			s.madminErr(q, madminBad("missing S3 configuration"))
			return
		}
		cfg.Type = tier.TypeS3
		cfg.S3 = &tier.S3Config{Endpoint: in.S3.Endpoint, Region: in.S3.Region, Bucket: in.S3.Bucket, Prefix: in.S3.Prefix,
			AccessKey: in.S3.AccessKey, SecretKey: in.S3.SecretKey, StorageClass: in.S3.StorageClass}
	case "minio":
		if in.MinIO == nil {
			s.madminErr(q, madminBad("missing MinIO configuration"))
			return
		}
		cfg.Type = tier.TypeS3
		cfg.S3 = &tier.S3Config{Endpoint: in.MinIO.Endpoint, Region: in.MinIO.Region, Bucket: in.MinIO.Bucket, Prefix: in.MinIO.Prefix,
			AccessKey: in.MinIO.AccessKey, SecretKey: in.MinIO.SecretKey}
	case "azure":
		if in.Azure == nil {
			s.madminErr(q, madminBad("missing Azure configuration"))
			return
		}
		cfg.Type = tier.TypeAzure
		cfg.Azure = &tier.AzureConfig{Account: in.Azure.AccountName, AccountKey: in.Azure.AccountKey,
			Container: in.Azure.Bucket, Prefix: in.Azure.Prefix, Endpoint: in.Azure.Endpoint}
	case "gcs":
		if in.GCS == nil {
			s.madminErr(q, madminBad("missing GCS configuration"))
			return
		}
		cfg.Type = tier.TypeGCS
		cfg.GCS = &tier.GCSConfig{Bucket: in.GCS.Bucket, Prefix: in.GCS.Prefix, Endpoint: in.GCS.Endpoint}
		if in.GCS.Creds != "" {
			cfg.GCS.CredentialsJSON = in.GCS.Creds
		}
	default:
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminTierUnsupported", "unsupported tier type "+in.Type)
		return
	}
	// force=true (--force) skips the reachability probe, as in MinIO.
	if err := s.tiers.Add(q.ctx(), cfg, q.query.Get("force") != "true"); err != nil {
		tierErr(s, q, err)
		return
	}
	q.w.WriteHeader(http.StatusNoContent)
}

func (s *Server) madminTierOne(q *request) {
	if !s.tiersReady(q) {
		return
	}
	name := strings.TrimPrefix(strings.TrimPrefix(q.r.URL.Path, madminPrefix), "tier/")
	if name == "" || strings.Contains(name, "/") {
		s.madminFail(q, http.StatusBadRequest, "XMinioAdminTierNameEmpty", "remote tier name empty")
		return
	}
	switch q.r.Method {
	case http.MethodGet: // verify
		ctx, cancel := context.WithTimeout(q.ctx(), 30*time.Second)
		defer cancel()
		be, _, err := s.tiers.Get(ctx, name)
		if err != nil {
			tierErr(s, q, err)
			return
		}
		if err := be.Check(ctx); err != nil {
			s.madminFail(q, http.StatusBadRequest, "XMinioAdminTierUnreachable", "tier "+name+" is not usable: "+err.Error())
			return
		}
		q.w.WriteHeader(http.StatusNoContent)
	case http.MethodPost: // edit credentials
		pt, err := s.readEncrypted(q)
		if err != nil {
			s.madminErr(q, err)
			return
		}
		var cr struct {
			AccessKey string `json:"access"`
			SecretKey string `json:"secret"`
			CredsJSON []byte `json:"creds"`
		}
		if json.Unmarshal(pt, &cr) != nil {
			s.madminErr(q, madminBad("invalid credentials"))
			return
		}
		list, err := s.tiers.List(q.ctx())
		if err != nil {
			s.madminErr(q, err)
			return
		}
		var cfg *tier.Config
		for i := range list {
			if list[i].Name == name {
				cfg = &list[i]
			}
		}
		if cfg == nil {
			tierErr(s, q, tier.ErrNotFound)
			return
		}
		switch cfg.Type {
		case tier.TypeS3:
			cfg.S3.AccessKey, cfg.S3.SecretKey = cr.AccessKey, cr.SecretKey
		case tier.TypeAzure:
			cfg.Azure.Account, cfg.Azure.AccountKey = cr.AccessKey, cr.SecretKey
		case tier.TypeGCS:
			cfg.GCS.CredentialsJSON = string(cr.CredsJSON)
		}
		if err := s.tiers.Edit(q.ctx(), *cfg); err != nil {
			tierErr(s, q, err)
			return
		}
		q.w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		if q.query.Get("force") != "true" {
			if b := s.tierInUseBy(q.ctx(), name); b != "" {
				s.madminFail(q, http.StatusConflict, "XMinioAdminTierBackendInUse",
					"bucket "+b+" has a lifecycle rule that transitions to tier "+name+"; remove the rule first or use --force")
				return
			}
		}
		if err := s.tiers.Remove(q.ctx(), name); err != nil {
			tierErr(s, q, err)
			return
		}
		q.w.WriteHeader(http.StatusNoContent)
	}
}

// tierInUseBy returns a bucket whose lifecycle rules still transition to
// the tier ("" when none).
func (s *Server) tierInUseBy(ctx context.Context, name string) string {
	buckets, err := s.st.ListBuckets(ctx)
	if err != nil {
		return ""
	}
	for _, b := range buckets {
		if b.Name == sysBucket {
			continue
		}
		cfg, err := s.lifecycleConfig(ctx, b.Name)
		if err != nil || cfg == nil {
			continue
		}
		for _, t := range cfg.Tiers() {
			if t == name {
				return b.Name
			}
		}
	}
	return ""
}

func (s *Server) madminTierStats(q *request) {
	out := []map[string]any{}
	if s.tiers != nil {
		list, err := s.tiers.List(q.ctx())
		if err != nil {
			s.madminErr(q, err)
			return
		}
		out = append(out, map[string]any{"Name": "STANDARD", "Type": "internal",
			"Stats":      map[string]any{"TotalSize": 0, "NumVersions": 0, "NumObjects": 0},
			"DailyStats": map[string]any{"Bins": make([]any, 24), "UpdatedAt": time.Now().UTC()}})
		for _, c := range list {
			out = append(out, map[string]any{"Name": c.Name, "Type": c.Type,
				"Stats":      map[string]any{"TotalSize": 0, "NumVersions": 0, "NumObjects": 0},
				"DailyStats": map[string]any{"Bins": make([]any, 24), "UpdatedAt": time.Now().UTC()}})
		}
	}
	s.writeJSONOK(q, out)
}
