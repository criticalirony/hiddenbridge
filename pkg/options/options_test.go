package options

import (
	"flag"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOptionSimple(t *testing.T) {
	o1 := &OptionValue{Value: 5}

	o2 := &OptionValue{}
	err := o2.Set("", 5)
	require.Nil(t, err)

	require.Equal(t, o1.Value, o2.Get("").Value)
	require.Equal(t, o1.Get("").Value, o2.Value)

	require.Equal(t, o1.Int(), o2.Get("").Int())
	require.Equal(t, o1.Get("").Int(), o2.Int())

	require.Equal(t, 5, o1.Int())
	require.Equal(t, int64(5), o1.Int64())
	require.Equal(t, "5", o1.String())
}

func TestOptionSimpleDuration(t *testing.T) {
	o1 := &OptionValue{}
	o1.Set("", 5*time.Second)
	require.Equal(t, 5*time.Second, o1.Duration())

	o2 := &OptionValue{}
	err := o2.Set("", "5s")
	require.Nil(t, err)
	require.Equal(t, 5*time.Second, o2.Duration())

	o3 := &OptionValue{}
	err = o3.Set("", 150000000000)
	require.Nil(t, err)
	require.Equal(t, 150*time.Second, o3.Duration())
}

func TestOptionSimpleList(t *testing.T) {
	o1 := &OptionValue{
		Value: []OptionValue{
			{Value: 1},
			{Value: 2},
			{Value: 3},
			{Value: 4},
			{Value: 5},
		},
	}

	expected := []int{1, 2, 3, 4, 5}
	actual := make([]int, len(o1.List()))
	for i, item := range o1.List() {
		actual[i] = item.Int()
	}

	require.Equal(t, expected, actual)

	o2 := &OptionValue{
		Value: []OptionValue{},
	}

	expected = []int{}
	actual = make([]int, len(o2.List()))
	for i, item := range o2.List() {
		actual[i] = item.Int()
	}

	require.Equal(t, expected, actual)

	o3 := &OptionValue{
		Value: 5,
	}

	expected = []int{5}
	actual = make([]int, len(o3.List()))
	for i, item := range o3.List() {
		actual[i] = item.Int()
	}

	require.Equal(t, expected, actual)

	o4 := &OptionValue{
		Value: []OptionValue{
			{Value: 1},
			{Value: 2},
			{Value: 3},
			{Value: 4},
			{Value: 5},
		},
	}

	expectedMap := map[string]int{
		"item0": 1,
		"item1": 2,
		"item2": 3,
		"item3": 4,
		"item4": 5,
	}

	actualMap := make(map[string]int, len(o4.Map()))
	for key, value := range o4.Map() {
		actualMap[key] = value.Int()
	}

	require.Equal(t, expectedMap, actualMap)
}

func TestOptionSimpleMap(t *testing.T) {
	o1 := &OptionValue{
		Value: map[string]OptionValue{
			"item0": {Value: 1},
			"item1": {Value: 2},
			"item2": {Value: 3},
			"item3": {Value: 4},
			"item4": {Value: 5},
		},
	}

	expected := map[string]int{
		"item0": 1,
		"item1": 2,
		"item2": 3,
		"item3": 4,
		"item4": 5,
	}

	actual := make(map[string]int, len(o1.Map()))
	for key, value := range o1.Map() {
		actual[key] = value.Int()
	}

	require.Equal(t, expected, actual)

	expectedList := []int{1, 2, 3, 4, 5}
	actualList := make([]int, len(o1.List()))
	for i, value := range o1.List() {
		actualList[i] = value.Int()
	}

	sort.Slice(actualList, func(i, j int) bool {
		return actualList[i] < actualList[j]
	})

	require.Equal(t, expectedList, actualList)

	o2 := &OptionValue{
		Value: map[string]OptionValue{
			"10": {Value: 10},
			"5":  {Value: 5},
			"7":  {Value: 7},
			"2":  {Value: 2},
			"3":  {Value: 3},
		},
	}

	expectedList = []int{2, 3, 5, 7, 10}
	actualList = make([]int, len(o2.List()))
	for i, value := range o2.List() {
		actualList[i] = value.Int()
	}

	require.Equal(t, expectedList, actualList)

	o3 := &OptionValue{
		Value: map[string]OptionValue{},
	}

	expected = map[string]int{}
	actual = make(map[string]int, len(o3.Map()))
	for key, value := range o3.Map() {
		actual[key] = value.Int()
	}

	require.Equal(t, expected, actual)

	o4 := &OptionValue{
		Value: 5,
	}

	expected = map[string]int{"default": 5}
	actual = make(map[string]int, len(o4.Map()))
	for key, value := range o4.Map() {
		actual[key] = value.Int()
	}

	require.Equal(t, expected, actual)
}

func TestOptionSimpleSet(t *testing.T) {
	o1 := &OptionValue{}
	err := o1.Set("top", 10)
	require.Nil(t, err)

	expected := &OptionValue{
		map[string]*OptionValue{
			"top": {10},
		},
	}

	require.Equal(t, expected, o1)

	o1 = &OptionValue{}
	err = o1.Set("root[5]", 5)
	require.Nil(t, err)

	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {
				[]OptionValue{
					{nil},
					{nil},
					{nil},
					{nil},
					{nil},
					{5},
				},
			},
		},
	}

	require.Equal(t, expected, o1)

	err = o1.Set("root[2]", 2)
	require.Nil(t, err)

	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {
				[]OptionValue{
					{nil},
					{nil},
					{2},
					{nil},
					{nil},
					{5},
				},
			},
		},
	}

	require.Equal(t, expected, o1)

	o1 = &OptionValue{}
	err = o1.Set("root.foo.bar", 5)
	require.Nil(t, err)

	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {
				map[string]*OptionValue{
					"foo": {
						map[string]*OptionValue{
							"bar": {5},
						},
					},
				},
			},
		},
	}

	require.Equal(t, expected, o1)

	o1 = &OptionValue{}
	err = o1.Set("root.foo[2].bar", 5)
	require.Nil(t, err)

	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {
				map[string]*OptionValue{
					"foo": {
						[]OptionValue{
							{nil},
							{nil},
							{
								map[string]*OptionValue{
									"bar": {5},
								},
							},
						},
					},
				},
			},
		},
	}

	require.Equal(t, expected, o1)
}

func TestSetTypeReassign(t *testing.T) {
	o1 := &OptionValue{}
	err := o1.Set("root.foo[2].bar", 5)
	require.Nil(t, err)

	err = o1.Set("root.foo.bar", "value")
	require.EqualError(t, err, "bar key type []options.OptionValue is immutable can not reassign")

	o1 = &OptionValue{}
	err = o1.Set("root.foo", 10)
	require.Nil(t, err)

	err = o1.Set("root.foo.bar", "value")
	require.EqualError(t, err, "bar key type int is immutable can not reassign")

	o1 = &OptionValue{}
	err = o1.Set("root.foo", nil)
	require.Nil(t, err)

	err = o1.Set("root.foo.bar", "value")
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("root.foo.bar", "value")
	require.Nil(t, err)

	// Try and change "bar" to a new type - should fail
	err = o1.Set("root.foo.bar.new", "new value")
	require.EqualError(t, err, "new key type string is immutable can not reassign")

	// Delete the value for "bar" so now it doesn't have any type
	err = o1.Set("root.foo.bar", nil)
	require.Nil(t, err)

	// We can now change "bar" to be a parent key to a sub key instead of a leaf key to a string
	err = o1.Set("root.foo.bar.new", "new value")
	require.Nil(t, err)

	// Leaf keys' types are mutable. Set "bar" to type string
	o1 = &OptionValue{}
	err = o1.Set("root.foo.bar", "value")
	require.Nil(t, err)

	// Without any deletion now set "bar" to type int
	err = o1.Set("root.foo.bar", 5)
	require.Nil(t, err)
}

func TestOptionSimpleGet(t *testing.T) {
	o1 := &OptionValue{}
	err := o1.Set("", "value")
	require.Nil(t, err)
	val := o1.Get("")
	require.Equal(t, &OptionValue{"value"}, val)
	require.Equal(t, "value", val.String())

	err = o1.Set("", 10)
	require.Nil(t, err)
	val = o1.Get("")
	require.Equal(t, &OptionValue{10}, val)
	require.Equal(t, 10, val.Int())

	o1 = &OptionValue{}
	err = o1.Set("root.foo.bar", "value")
	require.Nil(t, err)

	val = o1.Get("XXXXXXX.will.not.be.found")
	require.Nil(t, val)

	val = o1.Get("root.foo.bar")
	require.Equal(t, &OptionValue{"value"}, val)

	o1 = &OptionValue{}
	err = o1.Set("root.foo[2].bar", "VALUE OK")
	require.Nil(t, err)

	val = o1.Get("root.foo[2].bar")
	require.Equal(t, "VALUE OK", val.String())

	val = o1.Get("root.foo.next.bar")
	require.Nil(t, val)

	o1 = &OptionValue{}
	err = o1.Set("root.foo.bar", "VALUE OK")
	require.Nil(t, err)

	val = o1.Get("root.foo[2].bar")
	require.Nil(t, val)

	o1 = &OptionValue{}
	err = o1.Set("root.foo[2].bar", "VALUE OK")
	require.Nil(t, err)

	val = o1.Get("root.foo[10].bar")
	require.Nil(t, val)
}

func TestCommandLineArgs(t *testing.T) {
	flagSet := flag.NewFlagSet("", flag.ContinueOnError)

	o1 := &OptionValue{}

	flagSet.Func("config", "Plugin configuration YAML file", func(s string) error {
		return o1.Set("cli.config", s)
	})

	flagSet.Func("v", "Log level", func(s string) error {
		return o1.Set("cli.verbose", s)
	})

	err := flagSet.Parse([]string{"-v", "debug", "-config", "/path/to/config"})
	require.Nil(t, err)

	val := o1.Get("cli.config")
	require.Equal(t, "/path/to/config", val.String())

	val = o1.Get("cli.verbose")
	require.Equal(t, "debug", val.String())

}

func TestCommandLineArgsAppend(t *testing.T) {
	flagSet := flag.NewFlagSet("", flag.ContinueOnError)

	o1 := &OptionValue{}
	o1.Set("cli.arg", []string{})

	flagSet.Func("arg", "Will append to a list", func(s string) error {
		val := o1.Get("cli.arg")
		valList := val.Value.([]string)
		valList = append(valList, s)
		return o1.Set("cli.arg", valList)
	})

	err := flagSet.Parse([]string{"-arg", "arg1", "-arg", "arg2", "-arg", "arg3"})
	require.Nil(t, err)

	val := o1.Get("cli.arg")
	require.Equal(t, []string{"arg1", "arg2", "arg3"}, val.Value.([]string))
}
