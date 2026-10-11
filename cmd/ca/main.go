package main

import (
	"os"

	"perimeter/internal/ca"
)

func main() {
	c, err := ca.New("perimeter-root")
	if err != nil {
		panic(err)
	}
	if err := c.Save("ca.crt", "ca.key"); err != nil {
		panic(err)
	}
	if _, err := os.Stdout.WriteString("wrote ca.crt and ca.key\n"); err != nil {
		panic(err)
	}
}
