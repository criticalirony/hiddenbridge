package options

import (
	"errors"
	"flag"
	"fmt"
	"hiddenbridge/pkg/utils"
	"os"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func init() {
	SetupLogging("debug")
}

func SetupLogging(level string) {
	logLevel, err := zerolog.ParseLevel(level)
	if err != nil {
		log.Panic().Err(err).Msgf("Failed to parse log level: %s", level)
	}

	noColor := !utils.IsTerminal()
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr, NoColor: noColor}).Level(logLevel).With().Timestamp().Logger().With().Caller().Logger()
}

func TestOptionSimpleSet(t *testing.T) {
	o := &OptionValue{}
	err := o.Set("", 5)
	require.Nil(t, err)

	o = &OptionValue{}
	err = o.Set("", 5, 6)
	require.Nil(t, err)

	o = &OptionValue{}
	err = o.Set("", 5, "not an int", 7)
	require.NotNil(t, err)

	err = errors.Unwrap(err)
	require.NotNil(t, err)
	require.True(t, errors.Is(err, ErrInvalidArgs))
}

func TestOptionSimpleGet(t *testing.T) {
	o := &OptionValue{Value: 5}

	o2 := o.Get("")
	require.NotNil(t, o2)
	require.Equal(t, "5", fmt.Sprintf("%v", o2.Value))

	var res int
	ok := o2.As(&res) // This is a fancy get
	require.True(t, ok)
	require.Equal(t, 5, res)

	o = &OptionValue{}
	err := o.Set("", []string{"hello", "world"})
	require.Nil(t, err)

	o2 = o.Get("0")
	require.NotNil(t, o2)
	require.Equal(t, "hello", fmt.Sprintf("%v", o2.Value))

	res2 := ""
	ok = o.GetDefault("1", nil).As(&res2)
	require.True(t, ok)
	require.Equal(t, "world", res2)
}

func TestOptionSimple(t *testing.T) {
	var res int

	o := &OptionValue{}
	o.Set("", 5)

	res, ok := o.Value.(int)
	require.True(t, ok)
	require.Equal(t, 5, res)

	res = 0

	ok = o.Get("").As(&res)
	require.True(t, ok)
	require.Equal(t, 5, res)
}

func TestOptionSimpleList(t *testing.T) {
	// Test setting an array into the option value
	var inp [2]string
	inp[0] = "hello"
	inp[1] = "world"

	o := &OptionValue{}
	err := o.Set("", inp)
	require.Nil(t, err)

	// Test setting a slice into the option value
	inp2 := []string{"goodbye", "cruel", "world"}
	o = &OptionValue{}
	err = o.Set("", inp2)
	require.Nil(t, err)

	// Test getting a list for a not found key returns an empty list
	var notFoundList []string
	ok := o.GetDefault("ips.external", nil).As(&notFoundList)
	require.True(t, ok)
	require.Equal(t, "[]", fmt.Sprintf("%v", notFoundList))
}

func TestOptionSimpleList2(t *testing.T) {
	o1 := &OptionValue{
		Value: []*OptionValue{
			{Value: 1},
			{Value: 2},
			{Value: 3},
			{Value: 4},
			{Value: 5},
		},
	}

	expected := []int{1, 2, 3, 4, 5}
	actual := []int{}
	ok := o1.As(&actual)
	require.True(t, ok)
	require.Equal(t, expected, actual)

	o2 := &OptionValue{
		Value: []*OptionValue{},
	}

	actual = []int{}
	expected = []int{}
	ok = o2.As(&actual)
	require.True(t, ok)
	require.Equal(t, expected, actual)

	o3 := &OptionValue{
		Value: 5,
	}

	actual2 := 0
	expected2 := 5
	ok = o3.As(&actual2)
	require.True(t, ok)
	require.Equal(t, expected2, actual2)
}

func TestOptionSimpleMap(t *testing.T) {
	// Test setting an array into the option value
	inp := map[string]string{}
	inp["key1"] = "hello"
	inp["key2"] = "world"

	o := &OptionValue{}
	err := o.Set("", inp)
	require.Nil(t, err)

	o2 := o.GetDefault("key2", nil)
	require.NotNil(t, o2)
	require.Equal(t, "world", fmt.Sprintf("%v", o2.Value))

	// Test map with different paths. Make sure they don't conflict with each other
	o = &OptionValue{}
	err = o.Set("path.subpath1.subpath1", 10)
	require.Nil(t, err)
	err = o.Set("path.subpath2.subpath1", 20)
	require.Nil(t, err)
	err = o.Set("path.subpath2.subpath2", 30)
	require.Nil(t, err)

	o2 = o.GetDefault("path.subpath2.subpath1", nil)
	require.NotNil(t, o2)
	require.Equal(t, "20", fmt.Sprintf("%v", o2.Value))

	o2 = o.GetDefault("path.subpath2.subpath2", nil)
	require.NotNil(t, o2)
	require.Equal(t, "30", fmt.Sprintf("%v", o2.Value))

	// Test getting a map for a not found key returns an empty list
	var notFoundVal map[string]string
	ok := o.GetDefault("ips.external", nil).As(&notFoundVal)
	require.True(t, ok)
	require.Equal(t, "map[]", fmt.Sprintf("%v", notFoundVal))
}

func TestOptionListAppend(t *testing.T) {
	// Create empty optionvalue
	o := &OptionValue{}
	var valList []string

	// Test getting an empty list
	ok := o.GetDefault("cli.host", nil).As(&valList)
	require.True(t, ok)
	require.Nil(t, valList)

	// 1. Append to a non found list - implicit creation
	// Append to list
	valList = append(valList, "some.host.org")
	err := o.Set("cli.host", valList)
	require.Nil(t, err)

	// Check list is correct
	valList = nil
	ok = o.GetDefault("cli.host", nil).As(&valList)
	require.True(t, ok)
	require.Equal(t, []string{"some.host.org"}, valList)

	// 2. Append to existing list
	valList = append(valList, "someother.host.org")
	err = o.Set("cli.host", valList)
	require.Nil(t, err)

	// Check list is still correct
	ok = o.GetDefault("cli.host", nil).As(&valList)
	require.True(t, ok)
	require.Equal(t, []string{"some.host.org", "someother.host.org"}, valList)

}

func TestOptionAdvancedSetKey(t *testing.T) {
	o := &OptionValue{}
	err := o.Set("root.subroot[7][subkey.subsubkey].leaf", 10)
	require.Nil(t, err)
	require.NotNil(t, o.Value)

	o2 := o.GetDefault("root.subroot[7][subkey.subsubkey].leaf", nil)
	require.NotNil(t, o2)
	require.Equal(t, "10", fmt.Sprintf("%v", o2.Value))
}

func TestOptionSimpleDefault(t *testing.T) {
	o := &OptionValue{}
	err := o.Set("", []int{2, 4, 6, 8})
	require.Nil(t, err)

	missingVal := o.GetDefault("100", 99)
	require.NotNil(t, missingVal)
	require.Equal(t, "99", fmt.Sprintf("%v", missingVal.Value))

	var res int
	missingVal.As(&res)
	require.Equal(t, 99, res)
}

func TestOptionAdvancedSetList(t *testing.T) {
	o := &OptionValue{}
	err := o.Set("root.subroot", []string{"value1", "value2"})
	require.Nil(t, err)
	require.NotNil(t, o.Value)

	o = &OptionValue{}
	err = o.Set("root.subroot", "value3", "value4")
	require.Nil(t, err)
	require.NotNil(t, o.Value)

	o = &OptionValue{}
	err = o.Set("root.subroot", []string{"value1", "value2"}, []string{"value3", "value4"})
	require.Nil(t, err)
	require.NotNil(t, o.Value)
	require.Equal(t, "map[root:map[subroot:[[value1 value2] [value3 value4]]]]", o.String())
}

func TestOptionAdvancedGetList(t *testing.T) {
	var value []string

	o := &OptionValue{}
	err := o.Set("", []string{"value1", "value2"})
	require.Nil(t, err)

	ok := o.As(&value)
	require.True(t, ok)
	require.Equal(t, "[value1 value2]", fmt.Sprintf("%v", value))

	var value2 []int

	o = &OptionValue{}
	err = o.Set("", []int{2, 4, 6, 8})
	require.Nil(t, err)
	err = o.Set("2", 10) // Change element at index 2 from 6 to 10
	require.Nil(t, err)
	err = o.Set("5", 20) // Add an element to the list, past the end of the list
	require.Nil(t, err)

	ok = o.As(&value2)
	require.True(t, ok)

	// Note the 0 at index 4 - highlights a dummy value filling the empty space when element value 20 was added
	// the value 0 is not really there, if you attempt to get the real value, the element won't be found
	require.Equal(t, "[2 4 10 8 0 20]", fmt.Sprintf("%v", value2))

	// Try and get the "missing value" from the list above
	missingVal := o.GetDefault("4", 99)
	// Shows the entry at index 4 doesn't exist. Internally space was allocated
	// so element at index 5 could be inserted, but element at index 4's value was never set.
	require.NotNil(t, missingVal)
	require.Equal(t, "99", fmt.Sprintf("%v", missingVal))
}

func TestOptionAdvancedSetMap(t *testing.T) {
	o := &OptionValue{}
	err := o.Set("root.subroot", map[string]int{"key1": 5, "key2": 10})
	require.Nil(t, err)
	require.NotNil(t, o.Value)

	o2 := o.GetDefault("root.subroot[key2]", nil)
	require.NotNil(t, o2)
	require.Equal(t, "10", fmt.Sprintf("%v", o2.Value))

	o2 = o.GetDefault("root.subroot.key1", nil)
	require.NotNil(t, o2)
	require.Equal(t, "5", fmt.Sprintf("%v", o2.Value))
}

func TestOptionAvancedSetMap2(t *testing.T) {
	inp := map[string]interface{}{
		"key1": []interface{}{
			1, 2, 3, 4, 5,
		},
		"key2": map[string]interface{}{
			"subkey1": []interface{}{
				"hello", "world", "goodbye", "cruel", "universe",
			},
			"subkey2": []interface{}{
				"aint", "this", "grand?",
			},
			"subkey3": map[string]interface{}{
				"subsubkey1": 2,
				"subsubkey2": 4,
				"subsubkey3": 6,
			},
		},
	}

	o := &OptionValue{}
	err := o.Set("root", inp)
	require.Nil(t, err)
	require.NotNil(t, o.Value)
	require.Equal(t, "map[root:map[key1:[1 2 3 4 5] key2:map[subkey1:[hello world goodbye cruel universe] subkey2:[aint this grand?] subkey3:map[subsubkey1:2 subsubkey2:4 subsubkey3:6]]]]", fmt.Sprintf("%v", o))
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
		valList := []string{}
		ok := o1.Get("cli.arg").As(&valList)
		require.True(t, ok)
		valList = append(valList, s)
		return o1.Set("cli.arg", valList)
	})

	err := flagSet.Parse([]string{"-arg", "arg1", "-arg", "arg2", "-arg", "arg3"})
	require.Nil(t, err)

	valList := []string{}
	ok := o1.Get("cli.arg").As(&valList)
	require.True(t, ok)
	require.Equal(t, "[arg1 arg2 arg3]", fmt.Sprintf("%v", valList))
}

// func TestOptionParseYAML(t *testing.T) {
// 	input := []byte(`
// ---
// root: 5
// `)

// 	var yamlInput interface{}
// 	err := yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 := &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val := o1.Get("root")
// 	require.NotNil(t, val)
// 	require.Equal(t, 5, val.Int())

// 	input = []byte(`
// ---
// root:
// `)

// 	err = yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 = &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val = o1.Get("root")
// 	require.NotNil(t, val)
// 	require.Nil(t, val.Value)

// 	input = []byte(`
// ---
// root: ""
// `)

// 	err = yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 = &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val = o1.Get("root")
// 	require.NotNil(t, val)
// 	require.Equal(t, "", val.String())

// 	input = []byte(`
// ---
// root:
//   - item1
//   - item2
//   - item3
// `)

// 	err = yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 = &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val2 := o1.Get("root").List()
// 	require.NotNil(t, val2)
// 	require.Len(t, val2, 3)
// 	require.Equal(t, []OptionValue{{"item1"}, {"item2"}, {"item3"}}, val2)

// 	input = []byte(`
// ---
// root:
//   key1:
//   key2:
//   key3:
// `)

// 	err = yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 = &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val3 := o1.Get("root").Map()
// 	require.NotNil(t, val3)
// 	require.Len(t, val3, 3)
// 	require.Equal(t, map[string]*OptionValue{"key1": {nil}, "key2": {nil}, "key3": {nil}}, val3)

// 	input = []byte(`
// ---
// root:
//   key1: "value1"
//   key2: "value2"
//   key3: "value3"
// `)

// 	err = yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 = &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val3 = o1.Get("root").Map()
// 	require.NotNil(t, val3)
// 	require.Len(t, val3, 3)
// 	require.Equal(t, map[string]*OptionValue{"key1": {"value1"}, "key2": {"value2"}, "key3": {"value3"}}, val3)

// 	input = []byte(`
// ---
// root:
//   key2:
//     - "listItem1"
//     - "listItem2"
//   key1:
//     - "listItem3"
//     - "listItem4"
//   key3:
//     key4:
//       - "listItem5"
//       - "listItem6"
// `)

// 	err = yaml.Unmarshal(input, &yamlInput)
// 	require.Nil(t, err)

// 	o1 = &OptionValue{}
// 	err = o1.Set("", yamlInput)
// 	require.Nil(t, err)

// 	val = o1.Get("root")
// 	require.NotNil(t, val)
// 	require.Equal(t, "map[key1:[{listItem3} {listItem4}] key2:[{listItem1} {listItem2}] key3:map[key4:[{listItem5} {listItem6}]]]", val.String())
// }

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
    - 9090
  ports.http:
    - 9001
    - 9091`)

	expected := &OptionValue{
		map[string]*OptionValue{
			"goproxy": {
				map[string]*OptionValue{
					"hosts": {
						"proxy.golang.org",
					},
					"site": {
						map[string]*OptionValue{
							"keys": {
								"keys/goproxy.key",
							},
							"certs": {
								"keys/goproxy.pem",
							},
						},
					},
					"ports": {
						map[string]*OptionValue{
							"https": {
								[]*OptionValue{
									{9000},
									{9090},
								},
							},
							"http": {
								[]*OptionValue{
									{9001},
									{9091},
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
