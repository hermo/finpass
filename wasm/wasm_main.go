//go:build js && wasm
package main

import (
	"syscall/js"

	"github.com/hermo/finpass/internal"
	"github.com/hermo/finpass/internal/entropy"
)

func generatePasswordJS(this js.Value, args []js.Value) interface{} {
	wordCount := args[0].Int()
	maxLength := args[1].Int()
	delimiter := args[2].String()

	passphrase, err := internal.GeneratePassword(wordCount, uint(maxLength), delimiter, internal.Words)
	if err != nil {
		return js.ValueOf(err.Error())
	}
	return js.ValueOf(passphrase)
}

func getEntropyInfoJS(this js.Value, args []js.Value) interface{} {
	passphrase := args[0].String()
	wordCount := args[1].Int()
	maxLength := args[2].Int()

	info := entropy.DisplayEntropyInfo(passphrase, '.', wordCount, uint(maxLength), nil, true, 0, "standard", internal.Words)
	return js.ValueOf(info)
}

func main() {
	c := make(chan struct{}, 0)
	js.Global().Set("generatePassword", js.FuncOf(generatePasswordJS))
	js.Global().Set("getEntropyInfo", js.FuncOf(getEntropyInfoJS))
	<-c
}
