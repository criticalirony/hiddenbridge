//go:build !go1.16
// +build !go1.16

package options

type funcValue func(string) error

func (f funcValue) Set(s string) error { return f(s) }

func (f funcValue) String() string { return "" }

func (o *Options) CliFlag(name, usage string) {
	_, ok := o.args[name]
	if ok {
		return
	}

	o.args[name] = []OptionValue{}

	o.flagSet.Var(funcValue(func(flagValue string) error {
		o.args[name] = append(o.args[name], OptionValue(flagValue))
		return nil
	}), name, usage)
}

func (o *Options) CliParse(args []string) error {
	return o.flagSet.Parse(args)
}
