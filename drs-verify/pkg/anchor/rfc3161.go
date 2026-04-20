// Package anchor implements RFC 3161 trusted timestamping for DR storage.
// A Tier 3 store wraps an existing store.Store and anchors each stored DR
// with a timestamp token from a configured TSA endpoint.
package anchor

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net/http"
	"time"
)

const (
	tsaResponseContentType = "application/timestamp-reply"
	tsaRequestContentType  = "application/timestamp-query"
	tsaResponseSizeLimit   = 64 * 1024 // 64 KiB
	tsaHTTPTimeout         = 15 * time.Second
)

const pkiStatusGranted = 0

// OIDs required for RFC 3161 / CMS parsing.
var (
	sha256OID          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}

	// id-kp-timeStamping from RFC 3161 §2.3
	oidTimestampingEKU = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}

	// CMS signed-attribute OIDs per RFC 5652 §11
	oidContentTypeAttr   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigestAttr = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}

	// Digest-only OIDs (used in SignerInfo.DigestAlgorithm)
	sha384OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	sha512OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
)

// ── ASN.1 request types ───────────────────────────────────────────────────────

// hashAlgorithm encodes the AlgorithmIdentifier for SHA-256 in DER.
// parameters is an explicit NULL per RFC 3161 §2.4.1.
type hashAlgorithm struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue
}

// messageImprint encodes the MessageImprint structure per RFC 3161 §2.4.1.
type messageImprint struct {
	HashAlgorithm hashAlgorithm
	HashedMessage []byte
}

// timeStampReq is the ASN.1 TimeStampReq structure per RFC 3161 §2.4.1.
type timeStampReq struct {
	Version        int
	MessageImprint messageImprint
	CertReq        bool
}

// ── ASN.1 response types ──────────────────────────────────────────────────────

// timeStampResp is the top-level RFC 3161 response per §2.4.2.
type timeStampResp struct {
	Status         pkiStatusInfo
	TimeStampToken asn1.RawValue `asn1:"optional"`
}

type pkiStatusInfo struct {
	Status       int
	StatusString asn1.RawValue `asn1:"optional"`
	FailInfo     asn1.BitString `asn1:"optional"`
}

// contentInfo is the CMS ContentInfo wrapper per RFC 5652 §3.
type contentInfo struct {
	ContentType asn1.ObjectIdentifier
	Content     asn1.RawValue `asn1:"explicit,tag:0"`
}

// signedData is the CMS SignedData structure per RFC 5652 §5.1.
type signedData struct {
	Version          int
	DigestAlgorithms []pkix.AlgorithmIdentifier `asn1:"set"`
	EncapContentInfo encapContentInfo
	Certificates     asn1.RawValue `asn1:"optional,tag:0"`
	CRLs             asn1.RawValue `asn1:"optional,tag:1"`
	SignerInfos      []signerInfo  `asn1:"set"`
}

// encapContentInfo carries the TSTInfo payload per RFC 5652 §5.2.
type encapContentInfo struct {
	EContentType asn1.ObjectIdentifier
	EContent     asn1.RawValue `asn1:"optional,explicit,tag:0"`
}

// signerInfo is the CMS SignerInfo per RFC 5652 §5.3.
// SignedAttrs are [0] IMPLICIT — re-tag to SET (0x31) before signature verification.
type signerInfo struct {
	Version            int
	SID                asn1.RawValue
	DigestAlgorithm    pkix.AlgorithmIdentifier
	SignedAttrs         asn1.RawValue `asn1:"optional,tag:0"`
	SignatureAlgorithm pkix.AlgorithmIdentifier
	Signature          []byte
	UnsignedAttrs      asn1.RawValue `asn1:"optional,tag:1"`
}

// tstInfo carries the timestamp token content per RFC 3161 §2.4.2.
type tstInfo struct {
	Version        int
	Policy         asn1.ObjectIdentifier
	MessageImprint messageImprint
	SerialNumber   *big.Int
	GenTime        time.Time
}

// issuerAndSerial is used to match a SignerInfo SID to a certificate.
type issuerAndSerial struct {
	Issuer       asn1.RawValue
	SerialNumber *big.Int
}

// ── TSAClient ─────────────────────────────────────────────────────────────────

// TSAClient sends RFC 3161 timestamp requests to a TSA endpoint.
type TSAClient struct {
	endpoint   string
	httpClient *http.Client
}

// NewTSAClient creates a TSAClient that sends timestamp requests to the given endpoint URL.
func NewTSAClient(endpoint string) *TSAClient {
	return &TSAClient{
		endpoint:   endpoint,
		httpClient: &http.Client{Timeout: tsaHTTPTimeout},
	}
}

// Timestamp sends a hash to the TSA and returns the raw DER timestamp token.
// The token proves the hash existed at or before the time recorded in the token.
func (c *TSAClient) Timestamp(hash []byte) (token []byte, err error) {
	reqDER, err := buildTimestampRequest(hash)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: build request: %w", err)
	}

	resp, err := c.postRequest(reqDER)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("rfc3161: TSA returned HTTP %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != tsaResponseContentType {
		return nil, fmt.Errorf("rfc3161: unexpected Content-Type %q, want %q", ct, tsaResponseContentType)
	}

	tokenBytes, err := io.ReadAll(io.LimitReader(resp.Body, tsaResponseSizeLimit+1))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: read response body: %w", err)
	}
	if len(tokenBytes) > tsaResponseSizeLimit {
		return nil, fmt.Errorf("rfc3161: response body exceeds %d byte limit", tsaResponseSizeLimit)
	}

	return tokenBytes, nil
}

// VerifyTimestamp parses a raw DER TimeStampResp and verifies:
//  1. PKIStatus is granted (0)
//  2. The messageImprint SHA-256 hash matches expectedHash
//  3. The TSA certificate signature over the signed content is valid
//
// Returns the timestamp's GeneralizedTime on success.
// token is the raw DER bytes returned by Timestamp().
func VerifyTimestamp(token []byte, expectedHash []byte) (time.Time, error) {
	// 1. Parse the outer TimeStampResp
	var resp timeStampResp
	rest, err := asn1.Unmarshal(token, &resp)
	if err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse TimeStampResp: %w", err)
	}
	if len(rest) != 0 {
		return time.Time{}, fmt.Errorf("rfc3161: %d trailing bytes in TimeStampResp", len(rest))
	}
	if resp.Status.Status != pkiStatusGranted {
		return time.Time{}, fmt.Errorf("rfc3161: TSA status not granted, PKIStatus=%d", resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return time.Time{}, fmt.Errorf("rfc3161: TimeStampResp has no timeStampToken")
	}

	// 2. Parse ContentInfo
	var ci contentInfo
	if _, err := asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return time.Time{}, fmt.Errorf("rfc3161: ContentInfo type is not SignedData, got %v", ci.ContentType)
	}

	// 3. Parse SignedData
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return time.Time{}, fmt.Errorf("rfc3161: EncapContentInfo type is not id-ct-TSTInfo, got %v", sd.EncapContentInfo.EContentType)
	}

	// 4. Extract TSTInfo bytes from the eContent OCTET STRING
	var tstBytes []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstBytes); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse eContent OCTET STRING: %w", err)
	}

	// 5. Parse TSTInfo
	var tst tstInfo
	if _, err := asn1.Unmarshal(tstBytes, &tst); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse TSTInfo: %w", err)
	}

	// 6. Verify messageImprint algorithm and hash value
	if !tst.MessageImprint.HashAlgorithm.Algorithm.Equal(sha256OID) {
		return time.Time{}, fmt.Errorf("rfc3161: messageImprint uses unexpected algorithm %v", tst.MessageImprint.HashAlgorithm.Algorithm)
	}
	if subtle.ConstantTimeCompare(tst.MessageImprint.HashedMessage, expectedHash) != 1 {
		return time.Time{}, fmt.Errorf("rfc3161: messageImprint hash mismatch")
	}

	// 7. Verify the TSA signature
	if len(sd.SignerInfos) == 0 {
		return time.Time{}, fmt.Errorf("rfc3161: SignedData has no signerInfos")
	}
	si := sd.SignerInfos[0]

	cert, err := extractSignerCert(sd.Certificates, si)
	if err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: extract signer certificate: %w", err)
	}

	if err := verifySignerInfoSignature(si, tstBytes, cert); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: TSA signature invalid: %w", err)
	}

	return tst.GenTime, nil
}

// VerifyTimestampTrusted is like VerifyTimestamp but additionally validates:
//  1. The signer certificate chains to a root in trustedRoots
//  2. The signer certificate has the id-kp-timeStamping EKU
//  3. The signer certificate is currently valid (not expired, not before NotBefore)
//
// trustedRoots is a pool of root CA certificates trusted for timestamp signing.
// If trustedRoots is nil, the system roots are used.
func VerifyTimestampTrusted(token []byte, expectedHash []byte, trustedRoots *x509.CertPool) (time.Time, error) {
	var resp timeStampResp
	rest, err := asn1.Unmarshal(token, &resp)
	if err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse TimeStampResp: %w", err)
	}
	if len(rest) != 0 {
		return time.Time{}, fmt.Errorf("rfc3161: %d trailing bytes in TimeStampResp", len(rest))
	}
	if resp.Status.Status != pkiStatusGranted {
		return time.Time{}, fmt.Errorf("rfc3161: TSA status not granted, PKIStatus=%d", resp.Status.Status)
	}
	if len(resp.TimeStampToken.FullBytes) == 0 {
		return time.Time{}, fmt.Errorf("rfc3161: TimeStampResp has no timeStampToken")
	}

	var ci contentInfo
	if _, err := asn1.Unmarshal(resp.TimeStampToken.FullBytes, &ci); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse ContentInfo: %w", err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return time.Time{}, fmt.Errorf("rfc3161: ContentInfo type is not SignedData, got %v", ci.ContentType)
	}

	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse SignedData: %w", err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return time.Time{}, fmt.Errorf("rfc3161: EncapContentInfo type is not id-ct-TSTInfo")
	}

	var tstBytes []byte
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent.Bytes, &tstBytes); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse eContent OCTET STRING: %w", err)
	}

	var tst tstInfo
	if _, err := asn1.Unmarshal(tstBytes, &tst); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: parse TSTInfo: %w", err)
	}

	if !tst.MessageImprint.HashAlgorithm.Algorithm.Equal(sha256OID) {
		return time.Time{}, fmt.Errorf("rfc3161: messageImprint uses unexpected algorithm %v", tst.MessageImprint.HashAlgorithm.Algorithm)
	}
	if subtle.ConstantTimeCompare(tst.MessageImprint.HashedMessage, expectedHash) != 1 {
		return time.Time{}, fmt.Errorf("rfc3161: messageImprint hash mismatch")
	}

	if len(sd.SignerInfos) == 0 {
		return time.Time{}, fmt.Errorf("rfc3161: SignedData has no signerInfos")
	}
	si := sd.SignerInfos[0]

	cert, err := extractSignerCert(sd.Certificates, si)
	if err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: extract signer certificate: %w", err)
	}

	if err := verifySignerInfoSignature(si, tstBytes, cert); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: TSA signature invalid: %w", err)
	}

	// Trust validation: certificate chain
	intermediates := extractIntermediateCerts(sd.Certificates, cert)
	opts := x509.VerifyOptions{
		Roots:         trustedRoots,
		Intermediates: intermediates,
		CurrentTime:   tst.GenTime,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	if _, err := cert.Verify(opts); err != nil {
		return time.Time{}, fmt.Errorf("rfc3161: certificate chain validation failed: %w", err)
	}

	// Trust validation: EKU must include id-kp-timeStamping
	if !hasTimestampingEKU(cert) {
		return time.Time{}, fmt.Errorf("rfc3161: signer certificate does not have timestamping EKU (id-kp-timeStamping)")
	}

	// Trust validation: certificate validity at timestamp time
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return time.Time{}, fmt.Errorf("rfc3161: signer certificate is not currently valid (NotBefore: %v, NotAfter: %v)", cert.NotBefore, cert.NotAfter)
	}

	return tst.GenTime, nil
}

// hasTimestampingEKU returns true if cert has the id-kp-timeStamping extended key usage.
func hasTimestampingEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageTimeStamping {
			return true
		}
	}
	return false
}

// extractIntermediateCerts extracts all certificates from rawCerts except the
// leaf signer cert, returning them as an intermediate pool for chain validation.
func extractIntermediateCerts(rawCerts asn1.RawValue, leaf *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	if len(rawCerts.Bytes) == 0 {
		return pool
	}
	rest := rawCerts.Bytes
	for len(rest) > 0 {
		var certVal asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &certVal)
		if err != nil {
			break
		}
		cert, err := x509.ParseCertificate(certVal.FullBytes)
		if err != nil {
			continue
		}
		if cert.SerialNumber.Cmp(leaf.SerialNumber) != 0 {
			pool.AddCert(cert)
		}
	}
	return pool
}

// extractSignerCert finds the TSA signing certificate in SignedData.Certificates.
// For RFC 3161 tokens that embed a single certificate (the common case), it returns
// that certificate. For multi-cert tokens, it matches by serial number.
func extractSignerCert(rawCerts asn1.RawValue, si signerInfo) (*x509.Certificate, error) {
	if len(rawCerts.Bytes) == 0 {
		return nil, fmt.Errorf("no certificates embedded in SignedData")
	}

	// rawCerts.Bytes contains the SET OF Certificate content (the [0] IMPLICIT tag is stripped)
	rest := rawCerts.Bytes
	var firstCert *x509.Certificate
	for len(rest) > 0 {
		var certVal asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &certVal)
		if err != nil {
			break
		}
		cert, err := x509.ParseCertificate(certVal.FullBytes)
		if err != nil {
			continue
		}
		if firstCert == nil {
			firstCert = cert
		}
		// Match by serial number when SID is IssuerAndSerialNumber (version 1)
		if si.Version == 1 && cert.SerialNumber != nil {
			var ias issuerAndSerial
			if _, err := asn1.Unmarshal(si.SID.FullBytes, &ias); err == nil {
				if ias.SerialNumber != nil && cert.SerialNumber.Cmp(ias.SerialNumber) == 0 {
					return cert, nil
				}
			}
		}
	}
	// Fall back to the first parseable certificate (covers the single-cert common case)
	if firstCert != nil {
		return firstCert, nil
	}
	return nil, fmt.Errorf("no parseable certificate found in SignedData")
}

// cmsAttribute is the CMS Attribute structure per RFC 5652 §5.3.
// Values is a SET OF AttributeValue — we keep its raw DER bytes for per-attribute parsing.
type cmsAttribute struct {
	Type   asn1.ObjectIdentifier
	Values asn1.RawValue `asn1:"set"`
}

// verifySignerInfoSignature verifies the TSA signature in si over tstBytes using cert.
// When SignedAttrs are present (the RFC 3161 standard case), it:
//  1. Parses SignedAttrs, requires content-type == id-ct-TSTInfo
//     AND message-digest == Hash(tstBytes) using si.DigestAlgorithm
//     (without this binding, the signature over SignedAttrs says nothing
//     about the actual TSTInfo bytes carried in EncapContentInfo)
//  2. Verifies the signature over DER(SignedAttrs) re-tagged as SET (0x31)
//
// When SignedAttrs are absent, the signature covers the encapsulated content directly.
func verifySignerInfoSignature(si signerInfo, tstBytes []byte, cert *x509.Certificate) error {
	sigAlgo := mapSignatureAlgorithm(si.SignatureAlgorithm.Algorithm)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return fmt.Errorf("unsupported TSA signature algorithm: %v", si.SignatureAlgorithm.Algorithm)
	}

	if len(si.SignedAttrs.FullBytes) == 0 {
		// No SignedAttrs: signature covers the encapsulated TSTInfo bytes directly.
		return cert.CheckSignature(sigAlgo, tstBytes, si.Signature)
	}

	// SignedAttrs present: bind them to TSTInfo before trusting the signature.
	if err := verifySignedAttrsBinding(si, tstBytes); err != nil {
		return fmt.Errorf("SignedAttrs binding: %w", err)
	}

	// Re-tag [0] IMPLICIT (0xa0) to SET (0x31) per RFC 5652 §5.4 so the DER
	// matches what the signer hashed over SET OF Attribute.
	signedContent := make([]byte, len(si.SignedAttrs.FullBytes))
	copy(signedContent, si.SignedAttrs.FullBytes)
	signedContent[0] = 0x31
	return cert.CheckSignature(sigAlgo, signedContent, si.Signature)
}

// verifySignedAttrsBinding parses the SignedAttrs SET OF Attribute and enforces
// RFC 5652 §11.{1,2}: content-type attribute MUST equal id-ct-TSTInfo, and
// message-digest attribute MUST equal Hash(tstBytes) under si.DigestAlgorithm.
func verifySignedAttrsBinding(si signerInfo, tstBytes []byte) error {
	// si.SignedAttrs.FullBytes begins with [0] IMPLICIT (0xa0). Strip the outer
	// tag/length to get the SET OF Attribute content, then iterate each Attribute.
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(si.SignedAttrs.FullBytes, &outer); err != nil {
		return fmt.Errorf("parse SignedAttrs outer tag: %w", err)
	}
	attrs, err := parseAttributeSet(outer.Bytes)
	if err != nil {
		return fmt.Errorf("parse SignedAttrs: %w", err)
	}

	var ctSeen, mdSeen bool
	for _, a := range attrs {
		switch {
		case a.Type.Equal(oidContentTypeAttr):
			if ctSeen {
				return fmt.Errorf("duplicate content-type attribute")
			}
			ctSeen = true
			if err := checkContentTypeAttr(a.Values); err != nil {
				return err
			}
		case a.Type.Equal(oidMessageDigestAttr):
			if mdSeen {
				return fmt.Errorf("duplicate message-digest attribute")
			}
			mdSeen = true
			if err := checkMessageDigestAttr(a.Values, tstBytes, si.DigestAlgorithm.Algorithm); err != nil {
				return err
			}
		}
	}
	if !ctSeen {
		return fmt.Errorf("SignedAttrs missing required content-type attribute")
	}
	if !mdSeen {
		return fmt.Errorf("SignedAttrs missing required message-digest attribute")
	}
	return nil
}

// parseAttributeSet iterates the content bytes of a SET OF Attribute and
// returns each parsed Attribute. The input is the inner content of the SET
// (after tag/length), not the outer tag itself.
func parseAttributeSet(content []byte) ([]cmsAttribute, error) {
	var out []cmsAttribute
	rest := content
	for len(rest) > 0 {
		var a cmsAttribute
		var err error
		rest, err = asn1.Unmarshal(rest, &a)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, nil
}

// checkContentTypeAttr verifies the content-type attribute value is the single
// OID id-ct-TSTInfo (matching EncapContentInfo.eContentType).
func checkContentTypeAttr(values asn1.RawValue) error {
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(values.Bytes, &oid)
	if err != nil {
		return fmt.Errorf("parse content-type attribute value: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("content-type attribute has extra values")
	}
	if !oid.Equal(oidTSTInfo) {
		return fmt.Errorf("content-type is %v, want id-ct-TSTInfo", oid)
	}
	return nil
}

// checkMessageDigestAttr verifies the message-digest attribute equals
// Hash(tstBytes) under digestOID. This is the critical binding: without it,
// the signature over SignedAttrs tells us nothing about the actual TSTInfo
// bytes carried in EncapContentInfo.
func checkMessageDigestAttr(values asn1.RawValue, tstBytes []byte, digestOID asn1.ObjectIdentifier) error {
	var declared []byte
	rest, err := asn1.Unmarshal(values.Bytes, &declared)
	if err != nil {
		return fmt.Errorf("parse message-digest attribute value: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("message-digest attribute has extra values")
	}
	h, err := hasherFor(digestOID)
	if err != nil {
		return err
	}
	h.Write(tstBytes)
	computed := h.Sum(nil)
	if subtle.ConstantTimeCompare(declared, computed) != 1 {
		return fmt.Errorf("message-digest does not match Hash(TSTInfo)")
	}
	return nil
}

// hasherFor returns a fresh hash.Hash for the given digest OID.
// Supported: SHA-256, SHA-384, SHA-512.
func hasherFor(oid asn1.ObjectIdentifier) (hash.Hash, error) {
	switch {
	case oid.Equal(sha256OID):
		return sha256.New(), nil
	case oid.Equal(sha384OID):
		return sha512.New384(), nil
	case oid.Equal(sha512OID):
		return sha512.New(), nil
	}
	return nil, fmt.Errorf("unsupported digest algorithm: %v", oid)
}

// mapSignatureAlgorithm maps a signature algorithm OID to the x509 enum value.
// Only RSA and ECDSA with SHA-256/384/512 are supported — these cover all
// common TSA implementations.
func mapSignatureAlgorithm(oid asn1.ObjectIdentifier) x509.SignatureAlgorithm {
	switch {
	case oid.Equal(oidSHA256WithRSA):
		return x509.SHA256WithRSA
	case oid.Equal(oidSHA384WithRSA):
		return x509.SHA384WithRSA
	case oid.Equal(oidSHA512WithRSA):
		return x509.SHA512WithRSA
	case oid.Equal(oidECDSAWithSHA256):
		return x509.ECDSAWithSHA256
	case oid.Equal(oidECDSAWithSHA384):
		return x509.ECDSAWithSHA384
	case oid.Equal(oidECDSAWithSHA512):
		return x509.ECDSAWithSHA512
	default:
		return x509.UnknownSignatureAlgorithm
	}
}

// buildTimestampRequest encodes a DER TimeStampReq for the given hash.
func buildTimestampRequest(hash []byte) ([]byte, error) {
	req := timeStampReq{
		Version: 1,
		MessageImprint: messageImprint{
			HashAlgorithm: hashAlgorithm{
				Algorithm:  sha256OID,
				Parameters: asn1.RawValue{Tag: asn1.TagNull},
			},
			HashedMessage: hash,
		},
		CertReq: true,
	}
	der, err := asn1.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("ASN.1 marshal: %w", err)
	}
	return der, nil
}

// postRequest sends a DER timestamp query to the TSA endpoint.
func (c *TSAClient) postRequest(body []byte) (*http.Response, error) {
	req, err := http.NewRequest(http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("rfc3161: build HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", tsaRequestContentType)
	req.ContentLength = int64(len(body))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("rfc3161: HTTP request to TSA failed: %w", err)
	}
	return resp, nil
}
