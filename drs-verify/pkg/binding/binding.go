// Package binding enforces that an executed request matches the signed
// invocation.args carried in the DRS bundle, using RFC 8785 JCS
// canonicalisation (see CheckRaw).
//
// Without this check, a caller can sign a policy-compliant args value and then
// send a different body that the tool server actually executes — defeating the
// purpose of signing args. CheckRaw compares the canonical form of both sides:
// if JCS(body) == JCS(args), the body is bound to what was signed.
package binding

// IsEmptyArgs reports whether args is nil, an empty object, or an empty array.
// It is the decoded-value form of "no arguments" used by CheckRaw.
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
