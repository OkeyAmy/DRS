package binding

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"

	"github.com/gowebpki/jcs"
)

// Mode controls how a binding mismatch is handled by enforcement points.
type Mode string

const (
	ModeOff      Mode = "off"
	ModeLenient  Mode = "lenient"
	ModeEnforced Mode = "enforced"
)

// ParseMode converts a configuration string into a Mode. The empty string
// selects ModeEnforced. Any other unknown value is an error: a typo must
// never silently weaken enforcement.
func ParseMode(s string) (Mode, error) {
	switch Mode(s) {
	case "":
		return ModeEnforced, nil
	case ModeOff, ModeLenient, ModeEnforced:
		return Mode(s), nil
	}
	return "", fmt.Errorf("unknown binding mode %q: want off, lenient, or enforced", s)
}

// ErrNumberOutOfRange reports a number outside the I-JSON safe range
// (RFC 7493 §2.2). Such values cannot be compared reliably after JCS
// canonicalisation, which serialises numbers as IEEE-754 doubles.
var ErrNumberOutOfRange = errors.New("number outside I-JSON range (|n| > 2^53-1)")

var maxSafeNumber = new(big.Rat).SetInt64(1<<53 - 1)

// CheckRaw returns nil if body and the raw signed args are equal after RFC
// 8785 canonicalisation. Both inputs are raw JSON bytes. Empty or absent
// input is treated as "no arguments" and matches only another empty value
// ({}, [], null or nothing).
func CheckRaw(body, signedArgs []byte) error {
	bodyEmpty, err := isEmptyJSON(body)
	if err != nil {
		return fmt.Errorf("body: %w", err)
	}
	argsEmpty, err := isEmptyJSON(signedArgs)
	if err != nil {
		return fmt.Errorf("signed args: %w", err)
	}
	if bodyEmpty || argsEmpty {
		if bodyEmpty && argsEmpty {
			return nil
		}
		return errors.New("body does not match invocation.args")
	}

	canonicalBody, err := canonicalise(body)
	if err != nil {
		return fmt.Errorf("body: %w", err)
	}
	canonicalArgs, err := canonicalise(signedArgs)
	if err != nil {
		return fmt.Errorf("signed args: %w", err)
	}
	if !bytes.Equal(canonicalBody, canonicalArgs) {
		return errors.New("body does not match invocation.args")
	}
	return nil
}

func canonicalise(raw []byte) ([]byte, error) {
	if err := checkIntegerRange(raw); err != nil {
		return nil, err
	}
	out, err := jcs.Transform(raw)
	if err != nil {
		return nil, fmt.Errorf("not valid JSON: %w", err)
	}
	return out, nil
}

// isEmptyJSON reports whether raw is absent, whitespace, null, {} or [].
func isEmptyJSON(raw []byte) (bool, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return true, nil
	}
	var v interface{}
	if err := json.Unmarshal(trimmed, &v); err != nil {
		return false, fmt.Errorf("not valid JSON: %w", err)
	}
	return IsEmptyArgs(v), nil
}

// checkIntegerRange walks every number token in raw — integer, decimal or
// exponent notation — and rejects any whose magnitude exceeds 2^53-1. Beyond
// that, distinct JSON numbers can round to the same IEEE-754 double and would
// compare equal after JCS. Fractional differences below double precision
// (e.g. 0.1 vs 0.10000000000000001) still collapse and are out of scope.
func checkIntegerRange(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	for {
		tok, err := dec.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("not valid JSON: %w", err)
		}
		num, ok := tok.(json.Number)
		if !ok {
			continue
		}
		r, ok := new(big.Rat).SetString(string(num))
		if !ok {
			return fmt.Errorf("not a valid JSON number %q", num)
		}
		if r.Abs(r).Cmp(maxSafeNumber) > 0 {
			return fmt.Errorf("%w: %s", ErrNumberOutOfRange, num)
		}
	}
}
