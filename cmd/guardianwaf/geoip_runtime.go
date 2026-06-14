package main

import (
	"context"
	"errors"
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
)

type geoIPRefreshStopper interface {
	StopWithContext(context.Context) error
}

type layerRuntimeResources struct {
	geoIPRefresh []geoIPRefreshStopper
}

func (r *layerRuntimeResources) addGeoIPRefresh(handle geoIPRefreshStopper) {
	if r == nil || handle == nil {
		return
	}
	r.geoIPRefresh = append(r.geoIPRefresh, handle)
}

func (r *layerRuntimeResources) stopGeoIPRefresh(ctx context.Context) error {
	if r == nil {
		return nil
	}
	handles := r.geoIPRefresh
	r.geoIPRefresh = nil
	var errs []error
	for _, handle := range handles {
		if handle == nil {
			continue
		}
		if err := handle.StopWithContext(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// loadGeoIP loads the GeoIP database from file or downloads it.
func loadGeoIP(cfg *config.Config, eng *engine.Engine) (*geoip.DB, func()) {
	db, handle := loadGeoIPRuntime(cfg, eng)
	if handle == nil {
		return db, func() {}
	}
	return db, handle.Stop
}

func loadGeoIPRuntime(cfg *config.Config, eng *engine.Engine) (*geoip.DB, *geoip.AutoRefreshHandle) {
	if cfg.WAF.GeoIP.DBPath != "" {
		db, err := geoip.LoadCSV(cfg.WAF.GeoIP.DBPath)
		if err == nil {
			eng.Logs.Infof("GeoIP DB loaded: %d ranges from %s", db.Count(), cfg.WAF.GeoIP.DBPath)
			if cfg.WAF.GeoIP.AutoDownload {
				handle := db.StartAutoRefreshWithContext(cfg.WAF.GeoIP.DBPath, cfg.WAF.GeoIP.DownloadURL, 7*24*time.Hour)
				eng.Logs.Info("GeoIP auto-refresh enabled (7 day interval)")
				return db, handle
			}
			return db, nil
		}
		eng.Logs.Warnf("GeoIP DB load failed: %v", err)
	}

	if cfg.WAF.GeoIP.AutoDownload {
		path := cfg.WAF.GeoIP.DBPath
		if path == "" {
			path = "/var/lib/guardianwaf/geoip.csv"
		}
		eng.Logs.Info("Downloading GeoIP database...")
		db, err := geoip.LoadOrDownload(path, cfg.WAF.GeoIP.DownloadURL, 30*24*time.Hour)
		if err != nil {
			eng.Logs.Warnf("GeoIP auto-download failed: %v", err)
			return nil, nil
		}
		eng.Logs.Infof("GeoIP DB ready: %d ranges", db.Count())
		handle := db.StartAutoRefreshWithContext(path, cfg.WAF.GeoIP.DownloadURL, 7*24*time.Hour)
		eng.Logs.Info("GeoIP auto-refresh enabled (7 day interval)")
		return db, handle
	}

	return nil, nil
}
