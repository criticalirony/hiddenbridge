package utils

import "flag"

type FlagSet struct {
	*flag.FlagSet
}

func NewFlagSet(name string, errorHandling flag.ErrorHandling) *FlagSet {
	f := &FlagSet{
		FlagSet: flag.NewFlagSet(name, errorHandling),
	}

	return f
}
