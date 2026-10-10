package main

import (
	"fmt"
	"os"

	"github.com/cauteum-haven/cauteum-runtime/internal/app/wsinit"
)

func main() {
	if err := wsinit.Run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
