// Package binding enforces that an HTTP request body matches the signed
// invocation.args carried in the DRS bundle, using RFC 8785 JCS canonicalisation.
//
// Without this check, a caller can sign a policy-compliant args value and then
// send a different body that the tool server actually executes — defeating the
// purpose of signing args. Check compares the canonical form of both sides:
// if JCS(body) == JCS(args), the body is bound to what was signed.
package binding

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/gowebpki/jcs"
)

// Check returns nil if the canonical form of body equals the canonical form of args.
// Both sides are canonicalised per RFC 8785 so key order and numeric representation
// do not affect equality.
//
// An empty body matches nil args or an empty object/array. A non-empty body never
// matches nil/empty args, and vice versa.
//
// Invalid JSON in body returns an error — callers should treat this as a mismatch.
func Check(body []byte, args interface{}) error {
	bodyEmpty := len(bytes.TrimSpace(body)) == 0
	argsEmpty := IsEmptyArgs(args)

	// Trivial short-circuit: both sides literally empty.
	if bodyEmpty && argsEmpty {
		return nil
	}
	// Only one side literally empty: real mismatch. The other side has bytes
	// that will canonicalise to something non-empty, so equality can't hold.
	if bodyEmpty {
		return fmt.Errorf("body is empty but invocation.args is non-empty")
	}

	// Both sides have content. Fall through to canonicalisation and byte-equal
	// compare — the authoritative check. Do NOT early-exit on argsEmpty here:
	// a body that canonicalises to {} (or [] or null) and an args value that
	// serialises to the same canonical form must still match.
	canonicalBody, err := jcs.Transform(body)
	if err != nil {
		return fmt.Errorf("body is not valid JSON: %w", err)
	}

	argsJSON, err := json.Marshal(args)
	if err != nil {
		return fmt.Errorf("marshal args: %w", err)
	}
	canonicalArgs, err := jcs.Transform(argsJSON)
	if err != nil {
		return fmt.Errorf("canonicalise args: %w", err)
	}

	if !bytes.Equal(canonicalBody, canonicalArgs) {
		return fmt.Errorf("body does not match invocation.args")
	}
	return nil
}

// IsEmptyArgs reports whether args is nil, an empty object, or an empty array.
// Useful for deciding metric labels like "empty_match" vs "match".
func IsEmptyArgs(args interface{}) bool {
	switch v := args.(type) {
	case nil:
		return true
	case map[string]interface{}:
		return len(v) == 0
	case []interface{}:
		return len(v) == 0
	default:
		return false
	}
}
