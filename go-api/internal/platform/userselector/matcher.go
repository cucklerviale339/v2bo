package userselector

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type IDRange struct {
	Start int64
	End   int64
}

type Matcher struct {
	ids    map[int64]struct{}
	ranges []IDRange
}

func parseID(token string) (int64, bool) {
	value, err := strconv.ParseInt(strings.TrimSpace(strings.Trim(token, `"'`)), 10, 64)
	return value, err == nil && value > 0
}

func ParseRange(token string) (int64, int64, bool) {
	parts := strings.Split(strings.TrimSpace(strings.Trim(token, `"'`)), "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	start, startErr := strconv.ParseInt(strings.TrimSpace(parts[0]), 10, 64)
	end, endErr := strconv.ParseInt(strings.TrimSpace(parts[1]), 10, 64)
	if startErr != nil || endErr != nil || start <= 0 || end <= 0 {
		return 0, 0, false
	}
	if end < start {
		start, end = end, start
	}
	return start, end, true
}

func MatchesIDs(tokens []string, userID int64) bool {
	if userID <= 0 {
		return false
	}
	for _, token := range tokens {
		for _, part := range strings.Split(token, ",") {
			if value, ok := parseID(part); ok && value == userID {
				return true
			}
		}
	}
	return false
}

func MatchesRanges(tokens []string, userID int64) bool {
	if userID <= 0 {
		return false
	}
	for _, token := range tokens {
		for _, part := range strings.Split(token, ",") {
			if start, end, ok := ParseRange(part); ok && userID >= start && userID <= end {
				return true
			}
		}
	}
	return false
}

func Compile(ids, ranges []string) (*Matcher, error) {
	matcher := &Matcher{ids: make(map[int64]struct{})}
	for _, token := range ids {
		for _, part := range strings.Split(token, ",") {
			value, ok := parseID(part)
			if !ok {
				return nil, fmt.Errorf("invalid user ID %q", part)
			}
			matcher.ids[value] = struct{}{}
		}
	}
	for _, token := range ranges {
		for _, part := range strings.Split(token, ",") {
			start, end, ok := ParseRange(part)
			if !ok {
				return nil, fmt.Errorf("invalid user ID range %q", part)
			}
			matcher.ranges = append(matcher.ranges, IDRange{Start: start, End: end})
		}
	}
	sort.Slice(matcher.ranges, func(left, right int) bool { return matcher.ranges[left].Start < matcher.ranges[right].Start })
	merged := matcher.ranges[:0]
	for _, span := range matcher.ranges {
		if len(merged) > 0 && span.Start <= merged[len(merged)-1].End {
			merged[len(merged)-1].End = max(merged[len(merged)-1].End, span.End)
		} else {
			merged = append(merged, span)
		}
	}
	matcher.ranges = merged
	return matcher, nil
}

func (matcher *Matcher) Matches(userID int64) bool {
	if matcher == nil || userID <= 0 {
		return false
	}
	if _, found := matcher.ids[userID]; found {
		return true
	}
	index := sort.Search(len(matcher.ranges), func(index int) bool { return matcher.ranges[index].End >= userID })
	return index < len(matcher.ranges) && matcher.ranges[index].Start <= userID
}
