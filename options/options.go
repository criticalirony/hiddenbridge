package options

import (
	"flag"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
)

type OptionValue string

type Options struct {
	name    string
	args    map[string][]OptionValue
	flagSet *flag.FlagSet
}

func NewOptions(name string) *Options {
	return &Options{
		name:    name,
		args:    map[string][]OptionValue{},
		flagSet: flag.NewFlagSet(name, flag.ContinueOnError),
	}
}

func FromMap(name string, args map[string]interface{}) *Options {
	o := NewOptions(name)

	for key, value := range args {
		_, ok := o.args[key]
		if ok {
			log.Panic().Msgf("key: %s already found. this should not be able to happen", key)
		}

		o.args[key] = []OptionValue{}
		oargs := o.args[key]

		var oValList []OptionValue
		switch vt := value.(type) {
		case int:
			oargs = append(oargs, OptionValue(strconv.FormatInt(int64(vt), 10)))
		case string:
			oargs = append(oargs, OptionValue(vt))
		case []interface{}:
			oValList = make([]OptionValue, len(vt))
			for i, valItem := range vt {
				switch vit := valItem.(type) {
				case int:
					oValList[i] = OptionValue(strconv.FormatInt(int64(vit), 10))
				case string:
					oValList[i] = OptionValue(vit)
				default:
					log.Warn().Msgf("unahandled option value type: %T", vit)
					continue
				}
			}
			oargs = append(oargs, oValList...)
		default:
			log.Warn().Msgf("unahandled option type: %T", vt)
			continue
		}

		o.args[key] = oargs
	}

	return o
}

func (o *Options) CliFlag(name, usage string) {
	_, ok := o.args[name]
	if ok {
		return
	}

	o.args[name] = []OptionValue{}

	o.flagSet.Func(name, usage, func(flagValue string) error {
		o.args[name] = append(o.args[name], OptionValue(flagValue))
		return nil
	})
}

func (o *Options) CliParse(args []string) error {
	return o.flagSet.Parse(args)
}

func (o *Options) Get(key, value string) OptionValue {
	args, ok := o.args[key]
	if !ok || len(args) == 0 {
		return OptionValue(value)
	}

	if len(args) > 0 {
		// Join args into comma separated list
		res := make([]string, len(args))
		for i, v := range args {
			res[i] = string(v)
		}

		return OptionValue(strings.Join(res, ", "))
	}

	return args[0]
}

func (o *Options) GetAsList(key string, value []string) []OptionValue {
	args, ok := o.args[key]
	if !ok || len(args) == 0 {
		if value == nil {
			return nil
		}

		if len(value) == 0 {
			return []OptionValue{}
		}

		res := make([]OptionValue, len(value))
		for i, v := range value {
			res[i] = OptionValue(v)
		}
		return res
	}

	return args
}

func (ov OptionValue) String() string {
	return string(ov)
}

func (ov OptionValue) Duration() time.Duration {
	v, err := time.ParseDuration(string(ov))
	if err != nil {
		return 0
	}

	return v
}

func (ov OptionValue) Int64() int64 {
	v, err := strconv.ParseInt(string(ov), 0, 64)
	if err != nil {
		return 0
	}

	return v
}

func (ov OptionValue) Int() int {
	v, err := strconv.ParseInt(string(ov), 0, strconv.IntSize)
	if err != nil {
		return 0
	}

	return int(v)
}
