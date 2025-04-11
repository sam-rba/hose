package util

import (
	"fmt"
	"os"
)

func Eprintf(format string, a ...any) {
	Logf(format, a...)
	os.Exit(1)
}

func Logf(format string, a ...any) {
	msg := fmt.Sprintf(format, a...)
	fmt.Fprintf(os.Stderr, "%s\n", msg)
}
