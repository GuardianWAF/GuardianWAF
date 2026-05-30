package apisecurity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

// Hash is an alias for crypto.Hash
type Hash = crypto.Hash

// JWTConfig configures JWT validation.
type JWTConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Issuer           string   `yaml:"issuer"`
	Audience         string   `yaml:"audience"`
	Algorithms       []string `yaml:"algorithms"`
	PublicKeyFile    string   `yaml:"public_key_file"`
	JWKSURL          string   `yaml:"jwks_url"`
	ClockSkewSeconds int      `yaml:"clock_skew_seconds"`
	PublicKeyPEM     string   `yaml:"public_key_pem"`
}

// JWTValidator validates JWT tokens.
type JWTValidator struct {
	config       JWTConfig
	log          *slog.Logger
	publicKey    crypto.PublicKey
	jwksCache    *sync.Map // kid -> crypto.PublicKey (JWKS compat field)
	hmacKeys     *sync.Map // kid -> hmacKey (symmetric HMAC from JWKS)
	client       *http.Client
	stopCh       chan struct{}
	wg           sync.WaitGroup
	ssrfChecked  bool
}

// JWTClaims represents the standard JWT claims.
type JWTClaims struct {
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  any    `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	JWTID     string `json:"jti,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// --- File operation stubs ---
var (
	openFile  = func(path string) (any, error) { return nil, fmt.Errorf("file operations require runtime") }
	closeFile = func(any) {}
	readFile  = func(any, []byte) (int, error) { return 0, fmt.Errorf("file operations require runtime") }
	fileOpsMu sync.Mutex
)

func SetFileOps(openFn func(string) (any, error), closeFn func(any), readFn func(any, []byte) (int, error)) {
	fileOpsMu.Lock()
	openFile = openFn
	closeFile = closeFn
	readFile = readFn
	fileOpsMu.Unlock()
}

// --- Public key parsing ---

func parsePublicKey(pemData []byte) (crypto.PublicKey, error) {
	s := string(pemData)
	start := strings.Index(s, "-----BEGIN")
	if start == -1 {
		return nil, fmt.Errorf("no PEM data found")
	}
	end := strings.Index(s, "-----END")
	if end == -1 || end <= start {
		return nil, fmt.Errorf("invalid PEM format")
	}
	blockStart := strings.Index(s[start:], "\n") + start + 1
	blockEnd := end
	b64 := strings.ReplaceAll(s[blockStart:blockEnd], "\n", "")
	b64 = strings.ReplaceAll(b64, "\r", "")
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %bw", err)
	}
	if key := parseRSAPublicKey(der); key != nil {
		return key, nil
	}
	if key := parseECDSAPublicKey(der); key != nil {
		return key, nil
	}
	if key := parseEd25519PublicKey(der); key != nil {
		return key, nil
	}
	return nil, fmt.Errorf("could not parse public key")
}

func parseRSAPublicKey(der []byte) *rsa.PublicKey {
	if key := parseRawRSAPublicKey(der); key != nil {
		return key
	}
	if key := parsePKIXRSAPublicKey(der); key != nil {
		return key
	}
	return nil
}

func parseRawRSAPublicKey(der []byte) *rsa.PublicKey {
	if len(der) < 30 || der[0] != 0x30 {
		return nil
	}
	seq, err := parseASN1Sequence(der)
	if err != nil || len(seq) < 2 {
		return nil
	}
	modulus, err := parseASN1Integer(seq[0])
	if err != nil || modulus == nil || modulus.Sign() <= 0 {
		return nil
	}
	exponent, err := parseASN1Integer(seq[1])
	if err != nil || exponent == nil || exponent.Sign() <= 0 {
		return nil
	}
	e := int(exponent.Int64())
	if e <= 0 {
		return nil
	}
	return &rsa.PublicKey{N: modulus, E: e}
}

func parsePKIXRSAPublicKey(der []byte) *rsa.PublicKey {
	spki, err := parseASN1Sequence(der)
	if err != nil || len(spki) < 2 {
		return nil
	}
	algoSeq, err := parseASN1Sequence(spki[0])
	if err != nil || len(algoSeq) < 1 {
		return nil
	}
	if !isRSAOID(algoSeq[0]) {
		return nil
	}
	keyBits, err := parseASN1BitString(spki[1])
	if err != nil {
		return nil
	}
	rsaSeq, err := parseASN1Sequence(keyBits)
	if err != nil || len(rsaSeq) < 2 {
		return nil
	}
	modulus, err := parseASN1Integer(rsaSeq[0])
	if err != nil {
		return nil
	}
	exponent, err := parseASN1Integer(rsaSeq[1])
	if err != nil {
		return nil
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}
}

func isRSAOID(data []byte) bool {
	if len(data) < 11 {
		return false
	}
	rsaOID := []byte{0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01}
	for i := 0; i < len(rsaOID) && i < len(data); i++ {
		if data[i] != rsaOID[i] {
			return false
		}
	}
	return true
}

func parseECDSAPublicKey(der []byte) *ecdsa.PublicKey {
	spki, err := parseASN1Sequence(der)
	if err != nil || len(spki) < 2 {
		return nil
	}
	algoSeq, err := parseASN1Sequence(spki[0])
	if err != nil || len(algoSeq) < 2 {
		return nil
	}
	curveOID, err := parseASN1OID(algoSeq[1])
	if err != nil {
		return nil
	}
	var curve elliptic.Curve
	switch {
	case isP256OID(curveOID):
		curve = elliptic.P256()
	case isP384OID(curveOID):
		curve = elliptic.P384()
	case isP521OID(curveOID):
		curve = elliptic.P521()
	default:
		return nil
	}
	keyBits, err := parseASN1BitString(spki[1])
	if err != nil {
		return nil
	}
	x, y := elliptic.Unmarshal(curve, keyBits)
	if x == nil {
		return nil
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
}

func isP256OID(oid []byte) bool {
	p256OID := []byte{0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07}
	if len(oid) < len(p256OID) {
		return false
	}
	for i := 0; i < len(p256OID); i++ {
		if oid[i] != p256OID[i] {
			return false
		}
	}
	return true
}

func isP384OID(oid []byte) bool {
	p384OID := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22}
	if len(oid) < len(p384OID) {
		return false
	}
	for i := 0; i < len(p384OID); i++ {
		if oid[i] != p384OID[i] {
			return false
		}
	}
	return true
}

func isP521OID(oid []byte) bool {
	p521OID := []byte{0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23}
	if len(oid) < len(p521OID) {
		return false
	}
	for i := 0; i < len(p521OID); i++ {
		if oid[i] != p521OID[i] {
			return false
		}
	}
	return true
}

func parseEd25519PublicKey(der []byte) ed25519.PublicKey {
	if len(der) == ed25519.PublicKeySize {
		return ed25519.PublicKey(der)
	}
	return nil
}

func loadPublicKeyFromFile(path string) (crypto.PublicKey, error) {
	data := make([]byte, 4096)
	f, err := openFile(path)
	if err != nil {
		return nil, err
	}
	defer closeFile(f)
	n, err := readFile(f, data)
	if err != nil {
		return nil, err
	}
	return parsePublicKey(data[:n])
}

// --- ASN.1 Parsing Helpers ---

func parseASN1Sequence(data []byte) ([][]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("data too short")
	}
	if data[0] != 0x30 {
		return nil, fmt.Errorf("not a sequence")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("length exceeds data")
	}
	content := data[contentStart : contentStart+length]
	return parseASN1Elements(content)
}

func parseASN1Length(data []byte) (int, int, error) {
	if len(data) == 0 {
		return 0, 0, fmt.Errorf("no length bytes")
	}
	if data[0]&0x80 == 0 {
		return int(data[0]), 1, nil
	}
	numBytes := int(data[0] & 0x7F)
	if numBytes > 4 || len(data) < 1+numBytes {
		return 0, 0, fmt.Errorf("invalid length")
	}
	length := 0
	for i := 1; i <= numBytes; i++ {
		length = length<<8 | int(data[i])
	}
	return length, 1 + numBytes, nil
}

func parseASN1Elements(data []byte) ([][]byte, error) {
	var elements [][]byte
	for len(data) > 0 {
		if len(data) < 2 {
			break
		}
		_ = data[0]
		length, offset, err := parseASN1Length(data[1:])
		if err != nil {
			return nil, err
		}
		elemLen := 1 + offset + length
		if len(data) < elemLen {
			return nil, fmt.Errorf("element exceeds data")
		}
		elements = append(elements, data[:elemLen])
		data = data[elemLen:]
	}
	return elements, nil
}

func parseASN1Integer(data []byte) (*big.Int, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("integer too short")
	}
	if data[0] != 0x02 {
		return nil, fmt.Errorf("not an integer")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("integer length exceeds data")
	}
	value := data[contentStart : contentStart+length]
	if len(value) > 0 && value[0]&0x80 != 0 {
		return nil, fmt.Errorf("negative integer not supported")
	}
	return new(big.Int).SetBytes(value), nil
}

func parseASN1BitString(data []byte) ([]byte, error) {
	if len(data) < 3 {
		return nil, fmt.Errorf("bit string too short")
	}
	if data[0] != 0x03 {
		return nil, fmt.Errorf("not a bit string")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("bit string length exceeds data")
	}
	if length < 1 {
		return nil, fmt.Errorf("invalid bit string")
	}
	return data[contentStart+1 : contentStart+length], nil
}

func parseASN1OID(data []byte) ([]byte, error) {
	if len(data) < 2 {
		return nil, fmt.Errorf("OID too short")
	}
	if data[0] != 0x06 {
		return nil, fmt.Errorf("not an OID")
	}
	length, offset, err := parseASN1Length(data[1:])
	if err != nil {
		return nil, err
	}
	contentStart := 1 + offset
	if len(data) < contentStart+length {
		return nil, fmt.Errorf("OID length exceeds data")
	}
	return data[:contentStart+length], nil
}

type asn1Parser struct {
	data []byte
}

func asn1Unmarshal(data []byte, out any) error {
	p := &asn1Parser{data: data}
	return p.parseValue(out)
}

func (p *asn1Parser) parseValue(out any) error {
	if len(p.data) < 2 {
		return fmt.Errorf("too short")
	}
	tag := p.data[0]
	if tag != 0x30 {
		return fmt.Errorf("expected SEQUENCE")
	}
	p.data = p.data[1:]
	length, err := p.parseLength()
	if err != nil {
		return err
	}
	seq := p.data[:length]
	p.data = p.data[length:]
	esig := out.(*struct{ R, S *big.Int })
	if len(seq) < 2 {
		return fmt.Errorf("signature SEQUENCE too short")
	}
	seq = seq[1:]
	l1, _ := parseLengthFrom(&seq)
	if l1 > len(seq) {
		return fmt.Errorf("invalid R length")
	}
	esig.R = new(big.Int).SetBytes(stripLeadingZeros(seq[:l1]))
	seq = seq[l1:]
	if len(seq) < 2 {
		return fmt.Errorf("signature SEQUENCE too short for S")
	}
	seq = seq[1:]
	l2, _ := parseLengthFrom(&seq)
	if l2 > len(seq) {
		return fmt.Errorf("invalid S length")
	}
	esig.S = new(big.Int).SetBytes(stripLeadingZeros(seq[:l2]))
	return nil
}

func (p *asn1Parser) parseLength() (int, error) {
	if len(p.data) == 0 {
		return 0, fmt.Errorf("no length byte")
	}
	b := p.data[0]
	p.data = p.data[1:]
	if b < 0x80 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n > len(p.data) {
		return 0, fmt.Errorf("length overflow")
	}
	var length int
	for i := 0; i < n; i++ {
		length = length<<8 | int(p.data[i])
	}
	p.data = p.data[n:]
	return length, nil
}

func parseLengthFrom(data *[]byte) (int, error) {
	if len(*data) == 0 {
		return 0, fmt.Errorf("no data")
	}
	b := (*data)[0]
	*data = (*data)[1:]
	if b < 0x80 {
		return int(b), nil
	}
	n := int(b & 0x7f)
	if n > len(*data) {
		return 0, fmt.Errorf("length overflow")
	}
	var length int
	for i := 0; i < n; i++ {
		length = length<<8 | int((*data)[i])
	}
	*data = (*data)[n:]
	return length, nil
}

func stripLeadingZeros(b []byte) []byte {
	for i := 0; i < len(b); i++ {
		if b[i] != 0 {
			return b[i:]
		}
	}
	return b
}
