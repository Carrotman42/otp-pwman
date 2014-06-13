package main

import (
	"github.com/atotto/clipboard"
)



func setClipboard(s string) error {
	return clipboard.WriteAll(s)
}


/*
func getClipboard() string {
	panic("Unused")
	//if s, err := clipboard.ReadAll(); err != nil {
		
	}
}*/




