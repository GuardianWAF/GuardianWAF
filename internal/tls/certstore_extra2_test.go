package tls

import (
	"os"
	"testing"
	"time"
)

func TestStartReload_ZeroInterval(t *testing.T) {
	cs := NewCertStore()
	cs.StartReload(0)
	cs.StopReload()
}

func TestReloadIfChanged_MissingKeyFile(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "missingkey.com")
	cs := NewCertStore()
	_ = cs.LoadCert([]string{"missingkey.com"}, certFile, keyFile)
	os.Remove(keyFile)
	cs.reloadIfChanged()
}

func TestReloadIfChanged_InvalidCert(t *testing.T) {
	certFile, keyFile := generateTestCert(t, "badcert.com")
	cs := NewCertStore()
	_ = cs.LoadCert([]string{"badcert.com"}, certFile, keyFile)
	time.Sleep(10 * time.Millisecond)
	_ = os.WriteFile(certFile, []byte("not a valid cert"), 0o600)
	cs.reloadIfChanged()
}
