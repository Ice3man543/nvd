package nvd

import (
	"compress/gzip"
	"io"
	"io/ioutil"
	"os"
)

func decompressGZ(rc io.ReadCloser) ([]byte, error) {
	reader, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(reader)
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
