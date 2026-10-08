// Independent wire-compatibility vectors; no network listeners or protocol engine.
package main

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"runtime"

	"github.com/metacubex/blake3"
)

func pattern(length, step, start int) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = byte(i*step + start)
	}
	return out
}

func main() {
	type vector struct {
		ContextLength int    `json:"context_length"`
		KeyLength     int    `json:"key_length"`
		Output        string `json:"output"`
	}
	var vectors []vector
	for _, contextLength := range []int{0, 1, 16, 32, 63, 64, 65, 1023, 1024, 1025, 1120, 1216, 17005} {
		for _, keyLength := range []int{0, 32, 64, 96} {
			out := make([]byte, 32)
			blake3.DeriveKey(out, string(pattern(contextLength, 37, 255)), pattern(keyLength, 13, 7))
			vectors = append(vectors, vector{contextLength, keyLength, hex.EncodeToString(out)})
		}
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(map[string]any{
		"generator":       "github.com/metacubex/blake3@v0.1.0",
		"go_version":      runtime.Version(),
		"context_pattern": "byte(i*37 + 255)",
		"key_pattern":     "byte(i*13 + 7)",
		"vectors":         vectors,
	}); err != nil {
		panic(err)
	}
}
