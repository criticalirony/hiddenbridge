package options

import (
	"flag"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
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
		[]OptionValue{
			{1},
			{2},
			{3},
			{4},
			{5},
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
		map[string]*OptionValue{
			"item0": {1},
			"item1": {2},
			"item2": {3},
			"item3": {4},
			"item4": {5},
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
		Value: map[string]*OptionValue{
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
		Value: map[string]*OptionValue{},
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
	require.EqualError(t, err, "key: bar existing type: []options.OptionValue is immutable and can not be reassigned")

	o1 = &OptionValue{}
	err = o1.Set("root.foo", 10)
	require.Nil(t, err)

	err = o1.Set("root.foo.bar", "value")
	require.EqualError(t, err, "key: bar existing type: int is immutable and can not be reassigned")

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
	require.EqualError(t, err, "key: new existing type: string is immutable and can not be reassigned")

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
		valList := o1.Get("cli.arg").List()
		valList = append(valList, OptionValue{s})
		return o1.Set("cli.arg", valList)
	})

	err := flagSet.Parse([]string{"-arg", "arg1", "-arg", "arg2", "-arg", "arg3"})
	require.Nil(t, err)

	valList := o1.Get("cli.arg").List()
	require.Equal(t, []OptionValue{{"arg1"}, {"arg2"}, {"arg3"}}, valList)
}

func TestOptionParseOptionValueAsValue(t *testing.T) {
	input := &OptionValue{
		map[string]*OptionValue{
			"foo": {
				map[string]*OptionValue{
					"bar": {5},
				},
			},
		},
	}

	expected := &OptionValue{
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

	o1 := &OptionValue{}
	err := o1.Set("root", input.Value)
	require.Nil(t, err)
	require.Equal(t, expected, o1)

	input = &OptionValue{
		[]OptionValue{
			{5},
			{6},
			{7},
			{8},
		},
	}

	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {
				[]OptionValue{
					{5},
					{6},
					{7},
					{8},
				},
			},
		},
	}

	o1 = &OptionValue{}
	err = o1.Set("root", input.Value)
	require.Nil(t, err)
	require.Equal(t, expected, o1)

	// Adding a ptr OptionValue
	input = &OptionValue{5}
	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {5},
		},
	}

	o1 = &OptionValue{}
	err = o1.Set("root", input)
	require.Nil(t, err)
	require.Equal(t, expected, o1)

	// Adding a struct OptionValue
	input2 := OptionValue{5}
	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {5},
		},
	}

	o2 := &OptionValue{}
	err = o2.Set("root", input2)
	require.Nil(t, err)
	require.Equal(t, expected, o2)
}

func TestOptionParseInterfaceValue(t *testing.T) {
	// Test generic maps
	input := map[string]int{
		"key1": 5,
		"key2": 6,
		"key3": 7,
		"key4": 8,
	}

	expected := &OptionValue{
		map[string]*OptionValue{
			"root": {
				map[string]*OptionValue{
					"key1": {5},
					"key2": {6},
					"key3": {7},
					"key4": {8},
				},
			},
		},
	}

	o1 := &OptionValue{}
	err := o1.Set("root", input)
	require.Nil(t, err)
	require.Equal(t, expected, o1)

	val := o1.Get("root.key2")
	require.NotNil(t, val)
	require.Equal(t, 6, val.Int())

	val = o1.Get("root[key2]")
	require.NotNil(t, val)
	require.Equal(t, 6, val.Int())

	// Test generic lists
	input2 := []int{10, 1, 8, 3}
	expected = &OptionValue{
		map[string]*OptionValue{
			"root": {
				[]OptionValue{
					{10},
					{1},
					{8},
					{3},
				},
			},
		},
	}

	o2 := &OptionValue{}
	err = o2.Set("root", input2)
	require.Nil(t, err)
	require.Equal(t, expected, o2)

	val = o2.Get("root[2]")
	require.NotNil(t, val)
	require.Equal(t, 8, val.Int())
}

func TestOptionParseYAML(t *testing.T) {
	input := []byte(`
---
root: 5
`)

	var yamlInput interface{}
	err := yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 := &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val := o1.Get("root")
	require.NotNil(t, val)
	require.Equal(t, 5, val.Int())

	input = []byte(`
---
root:
`)

	err = yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val = o1.Get("root")
	require.NotNil(t, val)
	require.Nil(t, val.Value)

	input = []byte(`
---
root: ""
`)

	err = yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val = o1.Get("root")
	require.NotNil(t, val)
	require.Equal(t, "", val.String())

	input = []byte(`
---
root:
  - item1
  - item2
  - item3
`)

	err = yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val2 := o1.Get("root").List()
	require.NotNil(t, val2)
	require.Len(t, val2, 3)
	require.Equal(t, []OptionValue{{"item1"}, {"item2"}, {"item3"}}, val2)

	input = []byte(`
---
root:
  key1:
  key2:
  key3:
`)

	err = yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val3 := o1.Get("root").Map()
	require.NotNil(t, val3)
	require.Len(t, val3, 3)
	require.Equal(t, map[string]*OptionValue{"key1": {nil}, "key2": {nil}, "key3": {nil}}, val3)

	input = []byte(`
---
root:
  key1: "value1"
  key2: "value2"
  key3: "value3"
`)

	err = yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val3 = o1.Get("root").Map()
	require.NotNil(t, val3)
	require.Len(t, val3, 3)
	require.Equal(t, map[string]*OptionValue{"key1": {"value1"}, "key2": {"value2"}, "key3": {"value3"}}, val3)

	input = []byte(`
---
root:
  key2:
    - "listItem1"
    - "listItem2"
  key1:
    - "listItem3"
    - "listItem4"
  key3:
    key4:
      - "listItem5"
      - "listItem6"
`)

	err = yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 = &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)

	val = o1.Get("root")
	require.NotNil(t, val)
	require.Equal(t, "map[key1:[{listItem3} {listItem4}] key2:[{listItem1} {listItem2}] key3:map[key4:[{listItem5} {listItem6}]]]", val.String())
}

func TestOptionGetNilList(t *testing.T) {
	o1 := &OptionValue{}

	res := o1.Get("not.a.valid.key").List()
	require.NotNil(t, res)
	require.Equal(t, []OptionValue{}, res)
}

func TestOptionGetNilMap(t *testing.T) {
	o1 := &OptionValue{}

	res := o1.Get("not.a.valid.key").Map()
	require.NotNil(t, res)
	require.Equal(t, map[string]*OptionValue{}, res)
}

func TestOptionParseNamespaceFlatConfig(t *testing.T) {
	var yamlInput interface{}
	input := []byte(`
goproxy:
  hosts:
    - proxy.golang.org
  site.keys:
    - "keys/goproxy.key"
  site.certs:
    - "keys/goproxy.pem"
  ports.https:
    - 9000
  ports.http:
    - 9001`)

	expected := &OptionValue{
		map[string]*OptionValue{
			"goproxy": {
				map[string]*OptionValue{
					"hosts": {
						[]OptionValue{
							{"proxy.golang.org"},
						},
					},
					"site": {
						map[string]*OptionValue{
							"keys": {
								[]OptionValue{
									{"keys/goproxy.key"},
								},
							},
							"certs": {
								[]OptionValue{
									{"keys/goproxy.pem"},
								},
							},
						},
					},
					"ports": {
						map[string]*OptionValue{
							"https": {
								[]OptionValue{
									{9000},
								},
							},
							"http": {
								[]OptionValue{
									{9001},
								},
							},
						},
					},
				},
			},
		},
	}

	err := yaml.Unmarshal(input, &yamlInput)
	require.Nil(t, err)

	o1 := &OptionValue{}
	err = o1.Set("", yamlInput)
	require.Nil(t, err)
	require.Equal(t, expected, o1)
}
