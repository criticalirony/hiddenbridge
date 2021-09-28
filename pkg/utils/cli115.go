//go:build !go1.16
// +build !go1.16

package utils

type funcValue func(string) error

func (f funcValue) Set(s string) error { return f(s) }

func (f funcValue) String() string { return "" }
