package userselector

import (
	"math"
	"testing"
)

func TestMatcherIDAndRangeUnion(t *testing.T) {
	matcher, err := Compile([]string{"1,2", "'7'", "2"}, []string{"20-10", "15-25,24-30", "9223372036854775806-9223372036854775807"})
	if err != nil {
		t.Fatal(err)
	}
	for _, userID := range []int64{1, 2, 7, 10, 20, 25, 30, math.MaxInt64 - 1, math.MaxInt64} {
		if !matcher.Matches(userID) {
			t.Errorf("missing excluded ID %d", userID)
		}
	}
	for _, userID := range []int64{-1, 0, 3, 9, 31, math.MaxInt64 - 2} {
		if matcher.Matches(userID) {
			t.Errorf("unexpected excluded ID %d", userID)
		}
	}
}

func TestCompileRejectsInvalidSelectors(t *testing.T) {
	for _, token := range []string{"", "0", "-1", "x", "1,", "9223372036854775808"} {
		if _, err := Compile([]string{token}, nil); err == nil {
			t.Errorf("accepted invalid ID %q", token)
		}
	}
	for _, token := range []string{"", "0-5", "-1-5", "1-x", "1-2-3", "1-2,", "1-9223372036854775808"} {
		if _, err := Compile(nil, []string{token}); err == nil {
			t.Errorf("accepted invalid range %q", token)
		}
	}
	matcher, err := Compile(nil, nil)
	if err != nil || matcher.Matches(1) {
		t.Fatalf("empty matcher: %v, %v", matcher, err)
	}
}

func TestLegacyMatchingRemainsTolerant(t *testing.T) {
	if !MatchesIDs([]string{"bad", "1,'7'"}, 7) || MatchesIDs([]string{"-1,0"}, 0) {
		t.Fatal("legacy ID matching changed")
	}
	if !MatchesRanges([]string{"bad", "5-2,8-10"}, 2) || !MatchesRanges([]string{"5-2"}, 5) || MatchesRanges([]string{"5-2"}, 6) {
		t.Fatal("legacy range matching changed")
	}
	if _, _, ok := ParseRange(`"1"-"2"`); ok {
		t.Fatal("individually quoted bounds were previously invalid")
	}
}
