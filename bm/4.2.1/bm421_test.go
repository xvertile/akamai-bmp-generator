package bmp421

import (
	"strconv"
	"strings"
	"testing"
)

func TestPortSignalUsesOneSeed(t *testing.T) {
	for i := 0; i < 32; i++ {
		parts := strings.Split(PortSignal(), ",")
		if len(parts) != 4 {
			t.Fatalf("expected four port values, got %d", len(parts))
		}
		values := make([]int, 4)
		for j, part := range parts {
			value, err := strconv.Atoi(part)
			if err != nil {
				t.Fatalf("port value %d: %v", j, err)
			}
			values[j] = value
		}
		if values[0]%7 != 0 || values[0] < 7 || values[0] > 7000 {
			t.Fatalf("invalid seed-derived first port value: %d", values[0])
		}
		seed := values[0] / 7
		if values[1] != seed*8^values[0] ||
			values[2] != seed*9^values[1] ||
			values[3] != seed*5^values[2] {
			t.Fatalf("port values do not share one XOR seed")
		}
	}
}

func TestSensorPairsEndWithPortAndAccessibility(t *testing.T) {
	pairs := BuildSensorPairs(
		DeviceProfile{ScreenWidth: 1080, ScreenHeight: 2400},
		"com.example", "1.0", 1, "https://example.com/", "", "0", 1, 1,
	)
	if len(pairs) < 3 {
		t.Fatal("sensor pairs unexpectedly short")
	}
	last := pairs[len(pairs)-3:]
	if last[0][0] != "-240" || last[1][0] != "-172" ||
		last[2][0] != "-180" || last[2][1] != "-1" {
		t.Fatalf("unexpected final pair order: %q, %q, %q",
			last[0][0], last[1][0], last[2][0])
	}
	if len(strings.Split(last[1][1], ",")) != 4 {
		t.Fatal("port pair has invalid shape")
	}
}
