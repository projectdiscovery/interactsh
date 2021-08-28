package stringslice

import "strings"

type StringSlice []string

func (i *StringSlice) String() string {
	return strings.Join(*i, " ")
}

func (stringSlice *StringSlice) Set(value string) error {
	*stringSlice = append(*stringSlice, value)
	return nil
}
