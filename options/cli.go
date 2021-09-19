//go:build go1.16
// +build go1.16

package options

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
