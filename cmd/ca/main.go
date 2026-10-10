package main

import (
	"fmt"
	"os"

	"perimeter/internal/ca"
)

func main() {
	c, err := ca.New("perimeter-root")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := c.Save("ca.crt", "ca.key"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Println("wrote ca.crt and ca.key")
}
