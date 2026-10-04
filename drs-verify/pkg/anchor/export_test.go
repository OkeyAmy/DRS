package anchor

import "time"

// VerifyTimestampSignature exposes the shared structure/imprint/signature core
// to the external test package, so parsing and tamper tests run the exact code
// VerifyTimestampTrusted runs without needing a trusted CA for every token.
func VerifyTimestampSignature(token, expectedHash []byte) (time.Time, error) {
	ts, err := verifyTimestampSignature(token, expectedHash)
	return ts.genTime, err
}
