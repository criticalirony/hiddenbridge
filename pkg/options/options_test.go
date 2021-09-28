package options

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestOptionSimple(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err := o.CliParse([]string{"-arg1", "foo"})
	require.Nil(t, err)
	require.Len(t, o.args["arg1"], 1)
	require.Equal(t, OptionValue("foo"), o.args["arg1"][0])
}

func TestOptionAppend(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err := o.CliParse([]string{"-arg1", "foo", "-arg1", "bar"})
	require.Nil(t, err)
	require.Len(t, o.args["arg1"], 2)
	require.Equal(t, []OptionValue{"foo", "bar"}, o.args["arg1"])
}

func TestOptionGet(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err := o.CliParse([]string{"-arg1", "foo"})
	require.Nil(t, err)
	require.Len(t, o.args["arg1"], 1)

	o = NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err = o.CliParse([]string{"-arg1", "foo", "-arg1", "bar"})
	require.Nil(t, err)
	require.Len(t, o.args["arg1"], 2)

	arg := o.Get("arg1", "failed")
	require.Equal(t, "foo, bar", arg.String())

	arg = o.Get("arg2", "failed")
	require.Equal(t, "failed", arg.String())
}

func TestOptionGetAsList(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err := o.CliParse([]string{"-arg1", "foo", "-arg1", "bar"})
	require.Nil(t, err)
	require.Len(t, o.args["arg1"], 2)

	args := o.GetAsList("arg1", []string{"failed"})
	require.Equal(t, []OptionValue{"foo", "bar"}, args)

	args = o.GetAsList("arg2", []string{"failed"})
	require.Equal(t, []OptionValue{"failed"}, args)
}

func TestOptionGetAsString(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err := o.CliParse([]string{"-arg1", "foo"})
	require.Nil(t, err)

	arg := o.Get("arg1", "").String()
	require.Equal(t, "foo", arg)
}

func TestOptionGetAsDuration(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg1", "Generic arg1")

	err := o.CliParse([]string{"-arg1", "5s"})
	require.Nil(t, err)

	arg := o.Get("arg1", "").Duration()
	require.Equal(t, time.Second*5, arg)

	arg = o.Get("arg2", "3s").Duration()
	require.Equal(t, time.Second*3, arg)

	arg = o.Get("arg2", "").Duration()
	require.Equal(t, time.Duration(0), arg)
}

func TestOptionGetAsInt(t *testing.T) {
	o := NewOptions("testing")
	o.CliFlag("arg", "Generic arg1")

	err := o.CliParse([]string{"-arg", "100"})
	require.Nil(t, err)

	arg := o.Get("arg", "").Int()
	require.Equal(t, 100, arg)

	o = NewOptions("testing2")
	o.CliFlag("arg2", "Generic arg2")
	err = o.CliParse([]string{"-arg2", "705789"})
	require.Nil(t, err)

	arg2 := o.Get("arg2", "").Int64()
	require.Equal(t, int64(705789), arg2)

	arg2 = o.Get("argX", "").Int64()
	require.Equal(t, int64(0), arg2)
}
