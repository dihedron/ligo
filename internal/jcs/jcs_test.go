package jcs

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"testing"
)

// TestNumbers runs the number vectors of RFC 8785 Appendix B (also checked
// against Node's Number.prototype.toString).
func TestNumbers(t *testing.T) {
	for bits, want := range map[string]string{
		"0000000000000000": "0",
		"8000000000000000": "0",
		"0000000000000001": "5e-324",
		"8000000000000001": "-5e-324",
		"7fefffffffffffff": "1.7976931348623157e+308",
		"ffefffffffffffff": "-1.7976931348623157e+308",
		"4340000000000000": "9007199254740992",
		"c340000000000000": "-9007199254740992",
		"4430000000000000": "295147905179352830000",
		"44b52d02c7e14af5": "9.999999999999997e+22",
		"44b52d02c7e14af6": "1e+23",
		"44b52d02c7e14af7": "1.0000000000000001e+23",
		"444b1ae4d6e2ef4e": "999999999999999700000",
		"444b1ae4d6e2ef4f": "999999999999999900000",
		"444b1ae4d6e2ef50": "1e+21",
		"3eb0c6f7a0b5ed8c": "9.999999999999997e-7",
		"3eb0c6f7a0b5ed8d": "0.000001",
		"41b3de4355555553": "333333333.3333332",
		"41b3de4355555554": "333333333.33333325",
		"41b3de4355555555": "333333333.3333333",
		"41b3de4355555556": "333333333.3333334",
		"41b3de4355555557": "333333333.33333343",
		"becbf647612f3696": "-0.0000033333333333333333",
		"43143ff3c1cb0959": "1424953923781206.2",
	} {
		raw, _ := hex.DecodeString(bits)
		f := math.Float64frombits(binary.BigEndian.Uint64(raw))
		got, err := formatNumber(f)
		if err != nil || got != want {
			t.Errorf("%s: (%q, %v), want %q", bits, got, err, want)
		}
	}
	for _, f := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := formatNumber(f); err == nil {
			t.Errorf("%v accepted", f)
		}
	}
}

// TestRFCExample is the canonicalization example of RFC 8785 §3.2.2.
func TestRFCExample(t *testing.T) {
	in := `{
  "numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],
  "string": "\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/",
  "literals": [null, true, false]
}`
	want := `{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`
	got, err := Transform([]byte(in))
	if err != nil || string(got) != want {
		t.Errorf("got (%s, %v)\nwant %s", got, err, want)
	}
}

// TestSorting is the key sorting example of RFC 8785 §3.2.3: by UTF-16
// code units, so the surrogate pair sorts before U+FB33.
func TestSorting(t *testing.T) {
	in := `{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}`
	want := "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u0080\":\"Control\",\"\u00f6\":\"Latin Small Letter O With Diaeresis\",\"\u20ac\":\"Euro Sign\",\"\U0001F600\":\"Emoji: Grinning Face\",\"\ufb33\":\"Hebrew Letter Dalet With Dagesh\"}"
	got, err := Transform([]byte(in))
	if err != nil || string(got) != want {
		t.Errorf("got (%s, %v)\nwant %s", got, err, want)
	}
}

func TestCanonicalize(t *testing.T) {
	v := struct {
		B  []string          `json:"b"`
		A  int               `json:"a"`
		M  map[string]string `json:"m"`
		LT string            `json:"lt"`
	}{B: []string{"x"}, A: 1, M: map[string]string{"z": "1", "a": "2"}, LT: "<&>\u2028"}
	got, err := Canonicalize(v)
	want := "{\"a\":1,\"b\":[\"x\"],\"lt\":\"<&>\u2028\",\"m\":{\"a\":\"2\",\"z\":\"1\"}}"
	if err != nil || string(got) != want {
		t.Errorf("got (%s, %v), want %s", got, err, want)
	}
}

func TestInvalid(t *testing.T) {
	for _, in := range []string{`{"a":1,"a":2}`, `{"a":1} {}`, `[1,`, "\"\xff\""} {
		if _, err := Transform([]byte(in)); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
