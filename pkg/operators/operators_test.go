package operators

import (
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/stretchr/testify/require"
)

func TestMakeDynamicValuesCallback(t *testing.T) {
	input := map[string][]string{
		"a": {"1", "2"},
		"b": {"3"},
		"c": {},
		"d": {"A", "B", "C"},
	}

	count := 0
	MakeDynamicValuesCallback(input, true, func(data map[string]interface{}) bool {
		count++
		require.Len(t, data, 3, "could not get correct output length")
		return false
	})
	require.Equal(t, 3, count, "could not get correct result count")

	t.Run("all", func(t *testing.T) {
		input := map[string][]string{
			"a": {"1"},
			"b": {"2"},
			"c": {"3"},
		}

		count := 0
		MakeDynamicValuesCallback(input, true, func(data map[string]interface{}) bool {
			count++
			require.Len(t, data, 3, "could not get correct output length")
			return false
		})
		require.Equal(t, 1, count, "could not get correct result count")
	})

	t.Run("first", func(t *testing.T) {
		input := map[string][]string{
			"a": {"1", "2"},
			"b": {"3"},
			"c": {},
			"d": {"A", "B", "C"},
		}

		count := 0
		MakeDynamicValuesCallback(input, false, func(data map[string]interface{}) bool {
			count++
			require.Len(t, data, 3, "could not get correct output length")
			return false
		})
		require.Equal(t, 1, count, "could not get correct result count")
	})
}

func TestOperatorsCompile_InvalidMatchersCondition(t *testing.T) {
	// A misspelled matchers-condition (e.g. "andd") must be rejected at
	// compile time instead of silently falling back to OR semantics.
	operators := &Operators{
		MatchersCondition: "andd",
		Matchers: []*matchers.Matcher{{
			Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
			Words: []string{"x"},
		}},
	}
	require.Error(t, operators.Compile())

	for _, valid := range []string{"and", "or", ""} {
		operators := &Operators{
			MatchersCondition: valid,
			Matchers: []*matchers.Matcher{{
				Type:  matchers.MatcherTypeHolder{MatcherType: matchers.WordsMatcher},
				Words: []string{"x"},
			}},
		}
		require.NoError(t, operators.Compile())
	}
}
