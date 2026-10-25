// Package jcs implements the JSON Canonicalization Scheme (RFC 8785), used
// for the governance policy hash, payload hashes, the audit hash chain and
// ETags.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// Canonicalize returns the canonical JSON of v, as encoding/json marshals it.
func Canonicalize(v any) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return Transform(data)
}

// Transform returns the canonical form of a JSON document.
func Transform(data []byte) ([]byte, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("jcs: invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var b bytes.Buffer
	if err := encode(&b, dec); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("jcs: trailing data after the JSON value")
	}
	return b.Bytes(), nil
}

// encode writes the next value of dec canonically.
func encode(b *bytes.Buffer, dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return fmt.Errorf("jcs: %w", err)
	}
	switch t := tok.(type) {
	case json.Delim:
		if t == '[' {
			return encodeArray(b, dec)
		}
		return encodeObject(b, dec)
	case string:
		writeString(b, t)
	case json.Number:
		f, err := strconv.ParseFloat(string(t), 64)
		if err != nil {
			return fmt.Errorf("jcs: number %s: %w", t, err)
		}
		s, err := formatNumber(f)
		if err != nil {
			return err
		}
		b.WriteString(s)
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case nil:
		b.WriteString("null")
	}
	return nil
}

func encodeArray(b *bytes.Buffer, dec *json.Decoder) error {
	b.WriteByte('[')
	for i := 0; dec.More(); i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		if err := encode(b, dec); err != nil {
			return err
		}
	}
	_, err := dec.Token() // ]
	b.WriteByte(']')
	return err
}

func encodeObject(b *bytes.Buffer, dec *json.Decoder) error {
	type member struct {
		key   string
		utf16 []uint16
		value []byte
	}
	var members []member
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("jcs: %w", err)
		}
		key := tok.(string)
		var v bytes.Buffer
		if err := encode(&v, dec); err != nil {
			return err
		}
		members = append(members, member{key, utf16.Encode([]rune(key)), v.Bytes()})
	}
	if _, err := dec.Token(); err != nil { // }
		return fmt.Errorf("jcs: %w", err)
	}
	slices.SortFunc(members, func(x, y member) int { return slices.Compare(x.utf16, y.utf16) })
	b.WriteByte('{')
	for i, m := range members {
		if i > 0 {
			if m.key == members[i-1].key {
				return fmt.Errorf("jcs: duplicate key %q", m.key)
			}
			b.WriteByte(',')
		}
		writeString(b, m.key)
		b.WriteByte(':')
		b.Write(m.value)
	}
	b.WriteByte('}')
	return nil
}

// writeString escapes only what RFC 8785 §3.2.2.2 requires.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// formatNumber serializes f as ECMAScript's Number.prototype.toString does
// (RFC 8785 §3.2.2.3).
func formatNumber(f float64) (string, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("jcs: %v is not a valid JSON number", f)
	}
	if f == 0 {
		return "0", nil
	}
	sign := ""
	if f < 0 {
		sign, f = "-", -f
	}
	// shortest round-trip digits and exponent: d.ddd e±x
	mantissa, exp, _ := strings.Cut(strconv.FormatFloat(f, 'e', -1, 64), "e")
	digits := strings.Replace(mantissa, ".", "", 1)
	x, _ := strconv.Atoi(exp)
	n := x + 1 // position of the decimal point, as in ECMA-262 Number::toString
	k := len(digits)
	var s string
	switch {
	case k <= n && n <= 21:
		s = digits + strings.Repeat("0", n-k)
	case 0 < n && n <= 21:
		s = digits[:n] + "." + digits[n:]
	case -6 < n && n <= 0:
		s = "0." + strings.Repeat("0", -n) + digits
	default:
		s = digits[:1]
		if k > 1 {
			s += "." + digits[1:]
		}
		if n-1 >= 0 {
			s += "e+" + strconv.Itoa(n-1)
		} else {
			s += "e-" + strconv.Itoa(1-n)
		}
	}
	return sign + s, nil
}
