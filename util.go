package nvd

import (
	"bytes"
	"compress/gzip"
	"io"
	"os"
)

func decompressGZ(rc io.ReadCloser) []byte {
	reader, _ := gzip.NewReader(rc)
	output := bytes.Buffer{}
	output.ReadFrom(reader)
	return output.Bytes()
}

// fileExists checks if a file exists and is not a directory before we
// try using it to prevent further errors.
func fileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}
