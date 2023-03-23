package nvd

import (
	"compress/gzip"
	"io"
)

func decompressGZ(rc io.ReadCloser) ([]byte, error) {
	reader, err := gzip.NewReader(rc)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}
