package main

import (
	"time"

	"github.com/guardianwaf/guardianwaf/internal/config"
	"github.com/guardianwaf/guardianwaf/internal/engine"
	"github.com/guardianwaf/guardianwaf/internal/geoip"
)

// loadGeoIP loads the GeoIP database from file or downloads it.
func loadGeoIP(cfg *config.Config, eng *engine.Engine) (*geoip.DB, func()) {
	noop := func() {}

	if cfg.WAF.GeoIP.DBPath != "" {
		db, err := geoip.LoadCSV(cfg.WAF.GeoIP.DBPath)
		if err == nil {
			eng.Logs.Infof("GeoIP DB loaded: %d ranges from %s", db.Count(), cfg.WAF.GeoIP.DBPath)
			if cfg.WAF.GeoIP.AutoDownload {
				stopFn := db.StartAutoRefresh(cfg.WAF.GeoIP.DBPath, cfg.WAF.GeoIP.DownloadURL, 7*24*time.Hour)
				eng.Logs.Info("GeoIP auto-refresh enabled (7 day interval)")
				return db, stopFn
			}
			return db, noop
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
			return nil, noop
		}
		eng.Logs.Infof("GeoIP DB ready: %d ranges", db.Count())
		stopFn := db.StartAutoRefresh(path, cfg.WAF.GeoIP.DownloadURL, 7*24*time.Hour)
		eng.Logs.Info("GeoIP auto-refresh enabled (7 day interval)")
		return db, stopFn
	}

	return nil, noop
}
