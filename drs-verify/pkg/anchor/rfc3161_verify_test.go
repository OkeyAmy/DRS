package anchor_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/drs-protocol/drs-verify/pkg/anchor"
)

// ── Test-local ASN.1 types ────────────────────────────────────────────────────
// These mirror the production types in rfc3161.go but are exported only to this
// test package so we can construct synthetic RFC 3161 DER without depending on
// package internals.

type tvHashAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

type tvMessageImprint struct {
	HashAlgorithm tvHashAlgorithm
	HashedMessage []byte
}

type tvTSTInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint tvMessageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
}

// tvEncapContentInfo uses asn1:"optional" on EContent (no explicit struct-tag
// transform) for the same reason as tvContentInfo: the [0] EXPLICIT wrapper
// is built by hand and stored in FullBytes so that Go's asn1 marshaler emits
// it verbatim without double-wrapping.
type tvEncapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional"`
}

type tvSignerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type tvSignedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo tvEncapContentInfo
	Certificates     asn1.RawValue  `asn1:"optional"`
	SignerInfos      []tvSignerInfo `asn1:"set"`
}

// tvContentInfo omits the explicit,tag:0 on Content because we set FullBytes
// directly to the pre-built [0]-wrapped bytes. Using explicit,tag:0 with
// FullBytes set would be a no-op — Go's asn1 uses FullBytes verbatim and
// ignores struct tags for marshaling when FullBytes is present.
type tvContentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"optional"`
}

type tvPKIStatusInfo struct {
	Status int
}

type tvTimeStampResp struct {
	Status         tvPKIStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type tvIssuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

var (
	tvSHA256OID          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	tvOIDSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	tvOIDTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	tvOIDECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	tvDummyPolicy        = asn1.ObjectIdentifier{1, 2, 3, 4}
)

// buildTestTimestampResp assembles a complete RFC 3161 TimeStampResp DER for testing.
// It generates a fresh ECDSA P-256 key pair and self-signed certificate each call.
//
//   - hashForImprint: the hash that will be embedded in TSTInfo.MessageImprint
//   - pkiStatus:      0 = granted, anything else = rejected
func buildTestTimestampResp(t *testing.T, hashForImprint []byte, pkiStatus int) []byte {
	t.Helper()

	// 1. Generate a fresh ECDSA P-256 key and a self-signed certificate.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-tsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}

	// 2. Marshal TSTInfo.
	tstInfoDER, err := asn1.Marshal(tvTSTInfo{
		Version: 1,
		Policy:  tvDummyPolicy,
		MessageImprint: tvMessageImprint{
			HashAlgorithm: tvHashAlgorithm{
				Algorithm:  tvSHA256OID,
				Parameters: asn1.NullRawValue,
			},
			HashedMessage: hashForImprint,
		},
		SerialNumber: big.NewInt(42),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("marshal TSTInfo: %v", err)
	}

	// 3. Sign SHA-256(tstInfoDER) with ECDSA.
	// verifySignerInfoSignature covers the eContent directly when SignedAttrs are absent,
	// and cert.CheckSignature(ECDSAWithSHA256, data, sig) hashes data with SHA-256 internally.
	h := sha256.Sum256(tstInfoDER)
	sig, err := ecdsa.SignASN1(rand.Reader, key, h[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}

	// 4. Build IssuerAndSerialNumber SID.
	sidDER, err := asn1.Marshal(tvIssuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	if err != nil {
		t.Fatalf("marshal IssuerAndSerial: %v", err)
	}

	// 5. Build SignerInfo (no SignedAttrs → signature covers eContent = tstInfoDER directly).
	si := tvSignerInfo{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: sidDER},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: tvSHA256OID},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: tvOIDECDSAWithSHA256},
		Signature:          sig,
	}

	// 6. Wrap the certificate in a [0] IMPLICIT context tag matching the SignedData layout.
	certTaggedDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certDER,
	})
	if err != nil {
		t.Fatalf("marshal certificate [0] IMPLICIT: %v", err)
	}

	// 7. Build SignedData.
	// EContent must be [0] EXPLICIT { OCTET STRING { tstInfoDER } }.
	// Go's asn1 marshaler ignores explicit/implicit struct tags when the
	// RawValue.Tag field (not FullBytes) is set — the [0] wrapper would be
	// silently dropped. So we build the wrapper by hand (same pattern as
	// ContentInfo.Content) and store it in FullBytes on a bare optional field.
	tstOctetDER, err := asn1.Marshal(tstInfoDER) // []byte → OCTET STRING
	if err != nil {
		t.Fatalf("marshal TSTInfo as OCTET STRING: %v", err)
	}
	eContentWrapper, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      tstOctetDER, // = 04 len tstInfoDER
	}) // = a0 { 04 len tstInfoDER }
	if err != nil {
		t.Fatalf("marshal eContent [0] EXPLICIT wrapper: %v", err)
	}
	sd := tvSignedData{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: tvSHA256OID}},
		EncapContentInfo: tvEncapContentInfo{
			EContentType: tvOIDTSTInfo,
			EContent:     asn1.RawValue{FullBytes: eContentWrapper},
		},
		Certificates: asn1.RawValue{FullBytes: certTaggedDER},
		SignerInfos:  []tvSignerInfo{si},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal SignedData: %v", err)
	}

	// 8. Build ContentInfo wrapping SignedData.
	// The Content field must be [0] EXPLICIT { sdDER }. Because FullBytes on
	// asn1.RawValue bypasses all struct-tag rewriting, we build the explicit
	// wrapper by hand and store it as FullBytes on a bare (no struct-tag) field.
	explicitWrapper, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdDER, // sdDER = full SEQUENCE DER including 0x30 tag/length
	})
	if err != nil {
		t.Fatalf("marshal [0] explicit wrapper: %v", err)
	}
	ci := tvContentInfo{
		ContentType: tvOIDSignedData,
		Content:     asn1.RawValue{FullBytes: explicitWrapper},
	}
	ciDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("marshal ContentInfo: %v", err)
	}

	// 9. Build TimeStampResp.
	resp := tvTimeStampResp{
		Status:         tvPKIStatusInfo{Status: pkiStatus},
		TimeStampToken: asn1.RawValue{FullBytes: ciDER},
	}
	respDER, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}
	return respDER
}

// ── VerifyTimestamp tests ─────────────────────────────────────────────────────

func TestVerifyTimestamp_EmptyInput(t *testing.T) {
	_, err := anchor.VerifyTimestamp([]byte{}, []byte("somehash"))
	if err == nil {
		t.Fatal("expected error for empty input, got nil")
	}
}

func TestVerifyTimestamp_TruncatedDER(t *testing.T) {
	_, err := anchor.VerifyTimestamp([]byte{0x30, 0x82, 0x01}, []byte("somehash"))
	if err == nil {
		t.Fatal("expected error for truncated DER, got nil")
	}
}

func TestVerifyTimestamp_PKIStatusNotGranted(t *testing.T) {
	// Build a response where PKIStatus == 2 (rejection).
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTestTimestampResp(t, hash, 2)

	_, err := anchor.VerifyTimestamp(der, hash)
	if err == nil {
		t.Fatal("expected error for PKIStatus=2 (rejection), got nil")
	}
	if !strings.Contains(err.Error(), "PKIStatus") {
		t.Errorf("error should mention PKIStatus, got: %v", err)
	}
}

func TestVerifyTimestamp_HashMismatch(t *testing.T) {
	// Build a token whose messageImprint carries a different hash than what we pass.
	embeddedHash := make([]byte, 32)
	_, _ = rand.Read(embeddedHash)

	differentHash := make([]byte, 32)
	_, _ = rand.Read(differentHash)
	// Ensure they differ (astronomically unlikely to collide, but make it certain).
	if len(embeddedHash) > 0 {
		differentHash[0] = embeddedHash[0] ^ 0xFF
	}

	der := buildTestTimestampResp(t, embeddedHash, 0)

	_, err := anchor.VerifyTimestamp(der, differentHash)
	if err == nil {
		t.Fatal("expected error for hash mismatch, got nil")
	}
	if !strings.Contains(err.Error(), "hash") {
		t.Errorf("error should mention hash, got: %v", err)
	}
}

func TestVerifyTimestamp_ValidToken(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTestTimestampResp(t, hash, 0)

	ts, err := anchor.VerifyTimestamp(der, hash)
	if err != nil {
		t.Fatalf("VerifyTimestamp: unexpected error: %v", err)
	}
	if ts.IsZero() {
		t.Error("VerifyTimestamp returned a zero time on success")
	}
	if time.Since(ts) > time.Minute {
		t.Errorf("returned timestamp is too old: %v", ts)
	}
}

// ── VerifyTimestampTrusted tests ───────────────────────────────────────────────

func TestVerifyTimestampTrusted_RejectsUntrustedSelfSignedToken(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTestTimestampResp(t, hash, 0)

	// Use an empty trust pool — no roots trusted
	emptyPool := x509.NewCertPool()
	_, err := anchor.VerifyTimestampTrusted(der, hash, emptyPool)
	if err == nil {
		t.Fatal("expected error for untrusted self-signed TSA token, got nil")
	}
	if !strings.Contains(err.Error(), "certificate") {
		t.Errorf("error should mention certificate validation, got: %v", err)
	}
}

func TestVerifyTimestampTrusted_RejectsMissingTimestampingEKU(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	// buildTestTimestampResp creates certs without the timestamping EKU
	der := buildTestTimestampResp(t, hash, 0)

	// Even with the self-signed cert added as a trusted root, EKU check should fail
	// However, since buildTestTimestampResp creates a cert without EKU, the
	// x509.Verify with KeyUsages=[ExtKeyUsageTimeStamping] will reject it
	emptyPool := x509.NewCertPool()
	_, err := anchor.VerifyTimestampTrusted(der, hash, emptyPool)
	if err == nil {
		t.Fatal("expected error for missing timestamping EKU, got nil")
	}
}

func TestVerifyTimestampTrusted_RejectsHashMismatch(t *testing.T) {
	embeddedHash := make([]byte, 32)
	_, _ = rand.Read(embeddedHash)
	differentHash := make([]byte, 32)
	_, _ = rand.Read(differentHash)
	differentHash[0] = embeddedHash[0] ^ 0xFF

	der := buildTestTimestampResp(t, embeddedHash, 0)
	_, err := anchor.VerifyTimestampTrusted(der, differentHash, nil)
	if err == nil {
		t.Fatal("expected error for hash mismatch, got nil")
	}
}

// ── SignedAttrs binding tests (RFC 5652 §5.4) ─────────────────────────────────

// tvContentTypeAttr / tvMessageDigestAttr OIDs (RFC 5652 §11)
var (
	tvOIDContentTypeAttr   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	tvOIDMessageDigestAttr = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
)

// tvSignerInfoWithAttrs mirrors the production signerInfo but includes
// SignedAttrs as a [0] IMPLICIT field.
type tvSignerInfoWithAttrs struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs        asn1.RawValue `asn1:"tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
}

type tvSignedDataWithAttrs struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo tvEncapContentInfo
	Certificates     asn1.RawValue           `asn1:"optional"`
	SignerInfos      []tvSignerInfoWithAttrs `asn1:"set"`
}

type tvAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue // FullBytes must be a DER-encoded SET (0x31 …).
}

// signedAttrsTamper describes how to tamper with a token's SignedAttrs binding.
type signedAttrsTamper int

const (
	tamperNone signedAttrsTamper = iota
	tamperMessageDigest
	tamperContentType
	tamperOmitMessageDigest
	tamperOmitContentType
	tamperSwapTSTInfo // sign SignedAttrs for TSTInfo_A but embed TSTInfo_B
)

// buildTimestampRespWithSignedAttrs builds a TimeStampResp DER whose SignerInfo
// carries a CMS SignedAttrs set. This is the RFC 3161 standard case that
// buildTestTimestampResp does not cover.
func buildTimestampRespWithSignedAttrs(t *testing.T, hashForImprint []byte, tamper signedAttrsTamper) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 64))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "test-tsa"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	// Build the real TSTInfo.
	tstInfoDER, err := asn1.Marshal(tvTSTInfo{
		Version: 1,
		Policy:  tvDummyPolicy,
		MessageImprint: tvMessageImprint{
			HashAlgorithm: tvHashAlgorithm{Algorithm: tvSHA256OID, Parameters: asn1.NullRawValue},
			HashedMessage: hashForImprint,
		},
		SerialNumber: big.NewInt(42),
		GenTime:      time.Now().UTC().Truncate(time.Second),
	})
	if err != nil {
		t.Fatalf("marshal TSTInfo: %v", err)
	}

	// Compute the message-digest attribute value — SHA-256 over the REAL TSTInfo.
	digestOverReal := sha256.Sum256(tstInfoDER)

	// Build content-type attribute value: SET { OID id-ct-TSTInfo }.
	ctOID := tvOIDTSTInfo
	if tamper == tamperContentType {
		ctOID = asn1.ObjectIdentifier{1, 2, 3, 999} // wrong OID
	}
	ctOIDDER, err := asn1.Marshal(ctOID)
	if err != nil {
		t.Fatalf("marshal ct OID: %v", err)
	}

	// Build message-digest attribute value: SET { OCTET STRING digest }.
	mdBytes := digestOverReal[:]
	if tamper == tamperMessageDigest {
		mdBytes = make([]byte, 32) // all zeros — definitely wrong
	}
	mdDER, err := asn1.Marshal(mdBytes) // []byte → OCTET STRING
	if err != nil {
		t.Fatalf("marshal message-digest: %v", err)
	}

	// Wrap each attribute's single value in a SET tag: 0x31 len content.
	ctSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: ctOIDDER,
	})
	if err != nil {
		t.Fatalf("wrap ct as SET: %v", err)
	}
	mdSetDER, err := asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true, Bytes: mdDER,
	})
	if err != nil {
		t.Fatalf("wrap md as SET: %v", err)
	}

	var attrs []tvAttribute
	if tamper != tamperOmitContentType {
		attrs = append(attrs, tvAttribute{
			Type:   tvOIDContentTypeAttr,
			Values: asn1.RawValue{FullBytes: ctSetDER},
		})
	}
	if tamper != tamperOmitMessageDigest {
		attrs = append(attrs, tvAttribute{
			Type:   tvOIDMessageDigestAttr,
			Values: asn1.RawValue{FullBytes: mdSetDER},
		})
	}

	// Marshal SignedAttrs as SET OF Attribute (starts with 0x31 SET tag).
	signedAttrsSetDER, err := asn1.Marshal(struct {
		Attrs []tvAttribute `asn1:"set"`
	}{Attrs: attrs})
	if err != nil {
		t.Fatalf("marshal signed attrs SET: %v", err)
	}
	// asn1.Marshal of a struct wraps in SEQUENCE (0x30). We only want the inner
	// SET OF Attribute bytes — extract them.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(signedAttrsSetDER, &outer); err != nil {
		t.Fatalf("unmarshal outer SEQUENCE: %v", err)
	}
	// outer.Bytes contains the SET OF Attribute DER (tag 0x31 …).
	setOfAttrDER := outer.Bytes

	// signedContent is the DER of the SET — this is what the signer hashes.
	signingInput := make([]byte, len(setOfAttrDER))
	copy(signingInput, setOfAttrDER)

	// Sign SHA256(signingInput) with ECDSA.
	hsi := sha256.Sum256(signingInput)
	sig, err := ecdsa.SignASN1(rand.Reader, key, hsi[:])
	if err != nil {
		t.Fatalf("ecdsa.SignASN1: %v", err)
	}

	// Build the [0] IMPLICIT tagged SignedAttrs wire form: re-tag 0x31 → 0xa0.
	implicitTagged := make([]byte, len(setOfAttrDER))
	copy(implicitTagged, setOfAttrDER)
	implicitTagged[0] = 0xa0

	sidDER, err := asn1.Marshal(tvIssuerAndSerial{
		Issuer:       asn1.RawValue{FullBytes: cert.RawIssuer},
		SerialNumber: cert.SerialNumber,
	})
	if err != nil {
		t.Fatalf("marshal IssuerAndSerial: %v", err)
	}

	si := tvSignerInfoWithAttrs{
		Version:            1,
		SID:                asn1.RawValue{FullBytes: sidDER},
		DigestAlgorithm:    pkix.AlgorithmIdentifier{Algorithm: tvSHA256OID},
		SignedAttrs:        asn1.RawValue{FullBytes: implicitTagged},
		SignatureAlgorithm: pkix.AlgorithmIdentifier{Algorithm: tvOIDECDSAWithSHA256},
		Signature:          sig,
	}

	// Optionally swap the embedded TSTInfo AFTER the signature is computed.
	// This simulates the real attack: a valid TSA signature is paired with
	// altered timestamp content. The SignedAttrs binding is what catches it.
	embeddedTSTInfo := tstInfoDER
	if tamper == tamperSwapTSTInfo {
		// Build a different TSTInfo (different serial number and imprint).
		fakeImprint := make([]byte, 32)
		_, _ = rand.Read(fakeImprint)
		fakeTSTInfo, err := asn1.Marshal(tvTSTInfo{
			Version: 1,
			Policy:  tvDummyPolicy,
			MessageImprint: tvMessageImprint{
				HashAlgorithm: tvHashAlgorithm{Algorithm: tvSHA256OID, Parameters: asn1.NullRawValue},
				HashedMessage: fakeImprint,
			},
			SerialNumber: big.NewInt(9999),
			GenTime:      time.Now().UTC().Truncate(time.Second),
		})
		if err != nil {
			t.Fatalf("marshal fake TSTInfo: %v", err)
		}
		embeddedTSTInfo = fakeTSTInfo
	}

	certTaggedDER, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      certDER,
	})
	if err != nil {
		t.Fatalf("marshal cert [0] tagged: %v", err)
	}

	tstOctetDER, err := asn1.Marshal(embeddedTSTInfo)
	if err != nil {
		t.Fatalf("marshal embedded TSTInfo: %v", err)
	}
	eContentWrapper, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      tstOctetDER,
	})
	if err != nil {
		t.Fatalf("marshal eContent [0]: %v", err)
	}

	sd := tvSignedDataWithAttrs{
		Version:          3,
		DigestAlgorithms: []pkix.AlgorithmIdentifier{{Algorithm: tvSHA256OID}},
		EncapContentInfo: tvEncapContentInfo{
			EContentType: tvOIDTSTInfo,
			EContent:     asn1.RawValue{FullBytes: eContentWrapper},
		},
		Certificates: asn1.RawValue{FullBytes: certTaggedDER},
		SignerInfos:  []tvSignerInfoWithAttrs{si},
	}
	sdDER, err := asn1.Marshal(sd)
	if err != nil {
		t.Fatalf("marshal SignedData: %v", err)
	}

	explicitWrapper, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      sdDER,
	})
	if err != nil {
		t.Fatalf("marshal [0] explicit: %v", err)
	}
	ci := tvContentInfo{
		ContentType: tvOIDSignedData,
		Content:     asn1.RawValue{FullBytes: explicitWrapper},
	}
	ciDER, err := asn1.Marshal(ci)
	if err != nil {
		t.Fatalf("marshal ContentInfo: %v", err)
	}

	resp := tvTimeStampResp{
		Status:         tvPKIStatusInfo{Status: 0},
		TimeStampToken: asn1.RawValue{FullBytes: ciDER},
	}
	respDER, err := asn1.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal TimeStampResp: %v", err)
	}
	return respDER
}

func TestVerifyTimestamp_SignedAttrs_Valid(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTimestampRespWithSignedAttrs(t, hash, tamperNone)

	ts, err := anchor.VerifyTimestamp(der, hash)
	if err != nil {
		t.Fatalf("valid SignedAttrs token must verify, got: %v", err)
	}
	if ts.IsZero() {
		t.Error("returned zero time")
	}
}

func TestVerifyTimestamp_SignedAttrs_TamperedMessageDigest(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTimestampRespWithSignedAttrs(t, hash, tamperMessageDigest)

	_, err := anchor.VerifyTimestamp(der, hash)
	if err == nil {
		t.Fatal("tampered message-digest must be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "message-digest") {
		t.Errorf("error should mention message-digest, got: %v", err)
	}
}

func TestVerifyTimestamp_SignedAttrs_TamperedContentType(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTimestampRespWithSignedAttrs(t, hash, tamperContentType)

	_, err := anchor.VerifyTimestamp(der, hash)
	if err == nil {
		t.Fatal("wrong content-type must be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "content-type") {
		t.Errorf("error should mention content-type, got: %v", err)
	}
}

func TestVerifyTimestamp_SignedAttrs_MissingMessageDigest(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTimestampRespWithSignedAttrs(t, hash, tamperOmitMessageDigest)

	_, err := anchor.VerifyTimestamp(der, hash)
	if err == nil {
		t.Fatal("missing message-digest attr must be rejected, got nil")
	}
}

func TestVerifyTimestamp_SignedAttrs_MissingContentType(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTimestampRespWithSignedAttrs(t, hash, tamperOmitContentType)

	_, err := anchor.VerifyTimestamp(der, hash)
	if err == nil {
		t.Fatal("missing content-type attr must be rejected, got nil")
	}
}

// TestVerifyTimestamp_SignedAttrs_SwappedTSTInfo is the direct proof that
// SignedAttrs binding defends against the actual attack: a valid TSA
// signature over SignedAttrs for TSTInfo_A is paired with altered
// TSTInfo_B in EncapContentInfo. Without the message-digest check, the
// signature verifies and the forgery succeeds.
func TestVerifyTimestamp_SignedAttrs_SwappedTSTInfo(t *testing.T) {
	hash := make([]byte, 32)
	_, _ = rand.Read(hash)
	der := buildTimestampRespWithSignedAttrs(t, hash, tamperSwapTSTInfo)

	_, err := anchor.VerifyTimestamp(der, hash)
	if err == nil {
		t.Fatal("swapped TSTInfo must be rejected, got nil — SignedAttrs binding is broken")
	}
}
