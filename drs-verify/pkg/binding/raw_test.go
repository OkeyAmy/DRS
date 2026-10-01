package binding

import (
	"errors"
	"testing"
)

func TestCheckRawMatchesReorderedKeys(t *testing.T) {
	// blindfold: rfc — RFC 8785 sorts object keys, so key order never affects equality.
	if err := CheckRaw([]byte(`{"b":1,"a":"x"}`), []byte(`{"a":"x","b":1}`)); err != nil {
		t.Fatalf("reordered keys must match: %v", err)
	}
}

func TestCheckRawRejectsDifferentValue(t *testing.T) {
	if err := CheckRaw([]byte(`{"q":"rm -rf /"}`), []byte(`{"q":"weather"}`)); err == nil {
		t.Fatal("a different value must not bind")
	}
}

// Two distinct JSON integers that collapse to the same IEEE-754 double.
// A binding check that parses through float64 would call these equal and
// let the tool execute a value the agent never signed.
func TestCheckRawRejectsIntegersOutsideIJSONRange(t *testing.T) {
	signed := []byte(`{"amount":9007199254740992}`)
	sent := []byte(`{"amount":9007199254740993}`)
	err := CheckRaw(sent, signed)
	if err == nil {
		t.Fatal("integers beyond 2^53 must not be silently equated")
	}
	if !errors.Is(err, ErrNumberOutOfRange) {
		t.Fatalf("want ErrNumberOutOfRange, got %v", err)
	}
}

func TestCheckRawAcceptsLargestSafeInteger(t *testing.T) {
	// blindfold: rfc — RFC 7493 §2.2: integers in [-(2^53)+1, 2^53-1] are interoperable.
	v := []byte(`{"n":9007199254740991}`)
	if err := CheckRaw(v, v); err != nil {
		t.Fatalf("2^53-1 is in I-JSON range and must bind: %v", err)
	}
}

func TestCheckRawEmptyBodyMatchesEmptyArgs(t *testing.T) {
	if err := CheckRaw(nil, []byte(`{}`)); err != nil {
		t.Fatalf("empty body vs {} args: %v", err)
	}
	if err := CheckRaw(nil, nil); err != nil {
		t.Fatalf("empty body vs absent args: %v", err)
	}
}

func TestCheckRawEmptyBodyRejectsNonEmptyArgs(t *testing.T) {
	if err := CheckRaw(nil, []byte(`{"q":"x"}`)); err == nil {
		t.Fatal("empty body must not bind to non-empty args")
	}
}

func TestCheckRawRejectsInvalidJSON(t *testing.T) {
	if err := CheckRaw([]byte(`{"q":`), []byte(`{"q":"x"}`)); err == nil {
		t.Fatal("invalid body JSON must fail closed")
	}
}

func TestParseModeAcceptsKnownModes(t *testing.T) {
	for in, want := range map[string]Mode{
		"off":      ModeOff,      // blindfold: contract — documented binding modes
		"lenient":  ModeLenient,  // blindfold: contract — documented binding modes
		"enforced": ModeEnforced, // blindfold: contract — documented binding modes
		"":         ModeEnforced, // blindfold: contract — CLAUDE.md fail-closed: unset defaults to the strictest mode
	} {
		got, err := ParseMode(in)
		if err != nil || got != want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
}

func TestParseModeRejectsUnknownModes(t *testing.T) {
	// These typos previously fell through to lenient (pass-through) behaviour.
	for _, in := range []string{"enforce", "ENFORCED", "strict", " enforced"} {
		if _, err := ParseMode(in); err == nil {
			t.Errorf("ParseMode(%q) must fail closed with an error", in)
		}
	}
}

// Decimal and exponent spellings were skipped by the integer-only range check,
// so two different large decimals collapsed to one double and bound.
func TestCheckRawRejectsLargeNumbersInAnyNotation(t *testing.T) {
	for _, pair := range [][2]string{
		{`{"amount":9007199254740993.0}`, `{"amount":9007199254740992.0}`},
		{`{"amount":9.007199254740993e15}`, `{"amount":9.007199254740992e15}`},
		{`{"amount":1.0000000000000001e16}`, `{"amount":1e16}`},
	} {
		err := CheckRaw([]byte(pair[0]), []byte(pair[1]))
		if !errors.Is(err, ErrNumberOutOfRange) {
			t.Errorf("sent %s vs signed %s: want ErrNumberOutOfRange, got %v", pair[0], pair[1], err)
		}
	}
}

func TestCheckRawAcceptsOrdinaryFractions(t *testing.T) {
	if err := CheckRaw([]byte(`{"usd":0.25,"n":1e3}`), []byte(`{"n":1000,"usd":0.25}`)); err != nil {
		t.Fatalf("small fractions and exponents within range must bind: %v", err)
	}
}
