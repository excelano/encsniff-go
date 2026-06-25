// Package encsniff detects common non-UTF-8 text encodings from the head of a
// file or byte slice, using only byte-perfect signatures — no heuristics.
//
// It returns one of three actions: UseAsIs (clean UTF-8/ASCII), StripBom
// (UTF-8 BOM that should be silently skipped), or Warn (a non-UTF-8 encoding
// the caller should surface to the user along with an iconv hint).
package encsniff

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
)

// Action is what the caller should do with the file.
type Action int

const (
	// UseAsIs means the input looks like UTF-8 or ASCII; proceed unchanged.
	UseAsIs Action = iota
	// StripBom means the input is UTF-8 with a leading BOM; skip BomLen bytes.
	StripBom
	// Warn means the input is a non-UTF-8 encoding the user should know about.
	Warn
)

// Encoding names the detected encoding. The zero value is empty.
type Encoding string

const (
	EncUTF8    Encoding = "UTF-8"
	EncUTF8BOM Encoding = "UTF-8 with BOM"
	EncUTF16LE Encoding = "UTF-16 little-endian"
	EncUTF16BE Encoding = "UTF-16 big-endian"
	EncUTF7    Encoding = "UTF-7"
)

// Sniff is the result of a detection pass.
type Sniff struct {
	// Action tells the caller what to do.
	Action Action
	// Encoding is the detected encoding (empty if UseAsIs and no BOM).
	Encoding Encoding
	// BomLen is the number of leading bytes to skip when Action == StripBom.
	BomLen int
	// Hint is a copy-pasteable iconv command. Set by SniffFile when Action ==
	// Warn; empty when sniffing bytes with no associated path.
	Hint string
}

// scanWindow is how far into the input we look for the UTF-7 escape marker.
// 4KB comfortably covers CSV header rows, JSON object starts, and short docs.
const scanWindow = 4096

// utf7Marker is the UTF-7 escape sequence for the double-quote character —
// the canonical user-facing tell of UTF-7 in Scoutbook and Excel exports.
var utf7Marker = []byte("+ACI-")

// SniffBytes inspects the head of b and returns the detected action. The Hint
// field is left empty; callers with a path should use SniffFile, or compose a
// hint with IconvCommand.
func SniffBytes(b []byte) Sniff {
	switch {
	case len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF:
		return Sniff{Action: StripBom, Encoding: EncUTF8BOM, BomLen: 3}
	case len(b) >= 2 && b[0] == 0xFF && b[1] == 0xFE:
		return Sniff{Action: Warn, Encoding: EncUTF16LE}
	case len(b) >= 2 && b[0] == 0xFE && b[1] == 0xFF:
		return Sniff{Action: Warn, Encoding: EncUTF16BE}
	}
	window := b
	if len(window) > scanWindow {
		window = window[:scanWindow]
	}
	if bytes.Contains(window, utf7Marker) {
		return Sniff{Action: Warn, Encoding: EncUTF7}
	}
	return Sniff{Action: UseAsIs}
}

// SniffFile opens path, sniffs the head, and returns the result with Hint set
// to a copy-pasteable iconv command when Action == Warn.
func SniffFile(path string) (Sniff, error) {
	f, err := os.Open(path)
	if err != nil {
		return Sniff{}, err
	}
	defer f.Close()
	buf := make([]byte, scanWindow)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return Sniff{}, err
	}
	s := SniffBytes(buf[:n])
	if s.Action == Warn {
		s.Hint = IconvCommand(s.Encoding, path)
	}
	return s, nil
}

// IconvCommand composes an iconv command that converts path from enc to UTF-8,
// writing to a sibling file with .utf8 inserted before the extension. It
// returns the empty string for encodings that need no conversion.
func IconvCommand(enc Encoding, path string) string {
	from := iconvFromName(enc)
	if from == "" {
		return ""
	}
	return "iconv -f " + from + " -t UTF-8 " + path + " > " + utf8SiblingPath(path)
}

func iconvFromName(enc Encoding) string {
	switch enc {
	case EncUTF7:
		return "UTF-7"
	case EncUTF16LE:
		return "UTF-16LE"
	case EncUTF16BE:
		return "UTF-16BE"
	}
	return ""
}

func utf8SiblingPath(path string) string {
	ext := filepath.Ext(path)
	if ext == "" {
		return path + ".utf8"
	}
	return path[:len(path)-len(ext)] + ".utf8" + ext
}
