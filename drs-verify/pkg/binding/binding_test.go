package binding

import "testing"

func TestCheckMatchesIdenticalBodyAndArgs(t *testing.T) {
	body := []byte(`{"to":"amara@example.com","subject":"hi"}`)
	args := map[string]interface{}{"to": "amara@example.com", "subject": "hi"}
	if err := Check(body, args); err != nil {
		t.Errorf("identical body/args: unexpected error: %v", err)
	}
}

func TestCheckMatchesReorderedKeys(t *testing.T) {
	body := []byte(`{"subject":"hi","to":"amara@example.com"}`)
	args := map[string]interface{}{"to": "amara@example.com", "subject": "hi"}
	if err := Check(body, args); err != nil {
		t.Errorf("reordered keys should canonicalise equal: %v", err)
	}
}

func TestCheckMatchesNestedReorderedKeys(t *testing.T) {
	body := []byte(`{"outer":{"z":1,"a":2}}`)
	args := map[string]interface{}{"outer": map[string]interface{}{"a": 2, "z": 1}}
	if err := Check(body, args); err != nil {
		t.Errorf("nested reordered keys should canonicalise equal: %v", err)
	}
}

func TestCheckRejectsDifferentValue(t *testing.T) {
	body := []byte(`{"to":"attacker@example.com"}`)
	args := map[string]interface{}{"to": "amara@example.com"}
	if err := Check(body, args); err == nil {
		t.Error("different values must fail binding check")
	}
}

func TestCheckRejectsExtraFieldInBody(t *testing.T) {
	body := []byte(`{"to":"amara@example.com","cc":"attacker@example.com"}`)
	args := map[string]interface{}{"to": "amara@example.com"}
	if err := Check(body, args); err == nil {
		t.Error("extra field in body must fail binding check")
	}
}

func TestCheckRejectsMissingFieldInBody(t *testing.T) {
	body := []byte(`{"to":"amara@example.com"}`)
	args := map[string]interface{}{"to": "amara@example.com", "subject": "hi"}
	if err := Check(body, args); err == nil {
		t.Error("missing field in body must fail binding check")
	}
}

func TestCheckEmptyBodyEmptyArgs(t *testing.T) {
	if err := Check([]byte{}, nil); err != nil {
		t.Errorf("empty body + nil args should match: %v", err)
	}
	if err := Check([]byte{}, map[string]interface{}{}); err != nil {
		t.Errorf("empty body + empty-object args should match: %v", err)
	}
}

func TestCheckEmptyBodyWithArgsMismatch(t *testing.T) {
	if err := Check([]byte{}, map[string]interface{}{"x": 1}); err == nil {
		t.Error("empty body but non-empty args must fail")
	}
}

func TestCheckBodyWithEmptyArgsMismatch(t *testing.T) {
	if err := Check([]byte(`{"x":1}`), nil); err == nil {
		t.Error("non-empty body but nil args must fail")
	}
	if err := Check([]byte(`{"x":1}`), map[string]interface{}{}); err == nil {
		t.Error("non-empty body but empty args must fail")
	}
}

func TestCheckInvalidJSONBody(t *testing.T) {
	if err := Check([]byte(`not json`), map[string]interface{}{"x": 1}); err == nil {
		t.Error("invalid JSON body must fail")
	}
}

func TestCheckArrayArgs(t *testing.T) {
	body := []byte(`[1,2,3]`)
	args := []interface{}{float64(1), float64(2), float64(3)}
	if err := Check(body, args); err != nil {
		t.Errorf("array body/args should match: %v", err)
	}
}

func TestCheckArrayOrderMatters(t *testing.T) {
	body := []byte(`[3,2,1]`)
	args := []interface{}{float64(1), float64(2), float64(3)}
	if err := Check(body, args); err == nil {
		t.Error("array element order must be compared literally (RFC 8785 preserves array order)")
	}
}

func TestCheckNumberCanonicalisation(t *testing.T) {
	body := []byte(`{"n":1.0}`)
	args := map[string]interface{}{"n": float64(1)}
	if err := Check(body, args); err != nil {
		t.Errorf("1.0 and 1 should canonicalise equal: %v", err)
	}
}

func TestIsEmptyArgs(t *testing.T) {
	if !IsEmptyArgs(nil) {
		t.Error("nil should be empty")
	}
	if !IsEmptyArgs(map[string]interface{}{}) {
		t.Error("empty map should be empty")
	}
	if !IsEmptyArgs([]interface{}{}) {
		t.Error("empty slice should be empty")
	}
	if IsEmptyArgs(map[string]interface{}{"a": 1}) {
		t.Error("non-empty map should not be empty")
	}
	if IsEmptyArgs([]interface{}{1}) {
		t.Error("non-empty slice should not be empty")
	}
	if IsEmptyArgs("hi") {
		t.Error("scalar args are not treated as empty")
	}
}
