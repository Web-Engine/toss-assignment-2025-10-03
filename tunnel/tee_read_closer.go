package tunnel

import (
	"bytes"
	"io"
)

type TeeReadCloser struct {
	readCloser io.ReadCloser
	writer     io.Writer
}

func NewTeeReadCloser(readCloser io.ReadCloser, max uint64) (*TeeReadCloser, *bytes.Buffer) {
	buffer := &bytes.Buffer{}
	limitedWriter := NewLimitedWriter(buffer, max)

	trc := &TeeReadCloser{
		readCloser: readCloser,
		writer:     limitedWriter,
	}

	return trc, buffer
}

func (trc *TeeReadCloser) Read(buffer []byte) (int, error) {
	n, err := trc.readCloser.Read(buffer)

	if n > 0 {
		_, _ = trc.writer.Write(buffer[:n])
	}

	return n, err
}

func (trc *TeeReadCloser) Close() error {
	return trc.readCloser.Close()
}

type LimitedWriter struct {
	writer io.Writer
	max    uint64
}

func NewLimitedWriter(writer io.Writer, max uint64) *LimitedWriter {
	return &LimitedWriter{
		writer: writer,
		max:    max,
	}
}

func (lw *LimitedWriter) Write(buffer []byte) (int, error) {
	if lw.max <= 0 {
		return len(buffer), nil
	}

	if uint64(len(buffer)) > lw.max {
		buffer = buffer[:lw.max]
	}

	n, err := lw.writer.Write(buffer)
	lw.max -= uint64(n)

	return len(buffer), err
}
