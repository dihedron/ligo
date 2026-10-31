package theme

import (
	"math"
	"testing"
)

func TestContrast(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want float64
	}{
		{"#000", "#fff", 21}, {"#ffffff", "#ffffff", 1}, {"#777777", "#ffffff", 4.48}, {"#1f4e8cff", "#ffffff", 8.31},
	} {
		got, err := Contrast(c.a, c.b)
		if err != nil || math.Abs(got-c.want) > 0.01 {
			t.Errorf("Contrast(%s, %s) = %.2f %v, want %.2f", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"red", "#12", "#12345", "1f4e8c", "#ggg"} {
		if ValidColor(bad) {
			t.Errorf("%q accepted", bad)
		}
		if _, err := Contrast(bad, "#fff"); err == nil {
			t.Errorf("Contrast(%q) accepted", bad)
		}
	}
}
