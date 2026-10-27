package acme

import (
	"crypto/tls"
	"crypto/x509"
	"reflect"
	"testing"
)

func TestCertDiskStoreDomainSnapshotOwnership(t *testing.T) {
	s := NewCertDiskStore(t.TempDir(), nil, nil)
	if s.CertStatus()["domains"].([][]string) != nil {
		t.Fatal("nil changed")
	}
	input := []string{"managed.example", "alt.example"}
	s.AddDomains(input)
	s.AddDomains(nil)
	s.AddDomains([]string{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() { <-release; input[0] = "caller.example"; close(done) }()
	close(release)
	<-done
	want := [][]string{{"managed.example", "alt.example"}, nil, {}}
	if got := s.CertStatus()["domains"].([][]string); !reflect.DeepEqual(got, want) {
		t.Fatalf("registered %v", got)
	}
	leaf := &x509.Certificate{DNSNames: []string{"managed.example"}}
	s.storeCert([]string{"managed.example"}, &tls.Certificate{Leaf: leaf})
	snapshot := s.CertStatus()
	groups := snapshot["domains"].([][]string)
	groups[0][0] = "snapshot.example"
	groups[1] = []string{"new.example"}
	snapshot["certs"].([]map[string]any)[0]["dns_names"].([]string)[0] = "snapshot.example"
	fresh := s.CertStatus()
	if !reflect.DeepEqual(fresh["domains"], want) || leaf.DNSNames[0] != "managed.example" {
		t.Fatal("output mutation changed store")
	}
	t.Log("FIX VERIFIED")
}
