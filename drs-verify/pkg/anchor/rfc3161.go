// Package anchor implements RFC 3161 trusted timestamping for DR storage.
// A Tier 3 store wraps an existing store.Store and anchors each stored DR
// with a timestamp token from a configured TSA endpoint.
package anchor

import (
	"bytes"
	"encoding/asn1"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	tsaResponseContentType = "application/timestamp-reply"
	tsaRequestContentType  = "application/timestamp-query"
	tsaResponseSizeLimit   = 64 * 1024 // 64 KiB
	tsaHTTPTimeout         = 15 * time.Second
)

// sha256OID is the ASN.1 Object Identifier for SHA-256 (id-sha256).
var sha256OID = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}

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
