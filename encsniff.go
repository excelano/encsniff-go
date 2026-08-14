// Package encsniff detects common non-UTF-8 text encodings from the head of a
// file or byte slice, using only byte-perfect signatures — no heuristics.
//
// It returns one of four actions: UseAsIs (clean UTF-8/ASCII), StripBom
// (UTF-8 BOM that should be silently skipped), Warn (a named non-UTF-8
// encoding the caller should surface along with an iconv hint), or WarnUnknown
// (bytes that are provably not UTF-8, encoding unnameable).
package encsniff

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"unicode/utf8"
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
	// WarnUnknown means the input is provably not UTF-8, but which encoding it
	// is could not be determined. Encoding is empty — nothing was proven about
	// the identity, only about what it is not.
	//
	// Naming a single-byte encoding would be a guess, and this package does not
	// guess. Saying the bytes are not UTF-8 is not a guess: UTF-8 is a decidable
	// grammar, and this decides it exactly.
	WarnUnknown
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
	// Hint is a copy-pasteable iconv command. Set by SniffFile on either warning
	// action; empty when sniffing bytes with no associated path.
	Hint string
}

// IsWarning reports whether this result is something the user should be told
// about.
//
// Prefer this to comparing against Warn: every consumer in the fleet wrote
// `s.Action != encsniff.Warn` to mean "nothing to report", and in Go a new
// constant does not break that — it is silently ignored, which is worse than a
// compile error. A predicate absorbs the next verdict too.
func (s Sniff) IsWarning() bool {
	return s.Action == Warn || s.Action == WarnUnknown
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
	if hasInvalidUTF8(window) {
		return Sniff{Action: WarnUnknown}
	}
	return Sniff{Action: UseAsIs}
}

// hasInvalidUTF8 reports whether b contains a genuinely invalid UTF-8 byte, as
// opposed to a multi-byte rune cut in half by the end of the scan window.
//
// The distinction is the whole difficulty. scanWindow is a fixed 4KB, so a rune
// straddling byte 4096 arrives here truncated, and a file that is perfectly good
// UTF-8 would be reported as broken. utf8.Valid cannot tell the two apart —
// it reports false for both — so this walks the input and decides at the point
// of failure. Rust's std::str::from_utf8 exposes the same distinction directly
// as Utf8Error::error_len; Go has no equivalent, so it is reconstructed here.
func hasInvalidUTF8(b []byte) bool {
	for i := 0; i < len(b); {
		if b[i] < utf8.RuneSelf {
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		// A correctly encoded U+FFFD decodes as RuneError with size 3, so only
		// the size-1 form marks a byte that could not be decoded at all.
		if r != utf8.RuneError || size != 1 {
			i += size
			continue
		}
		return !isTruncatedRune(b[i:])
	}
	return false
}

// isTruncatedRune reports whether b is the beginning of a multi-byte rune that
// simply ran out of input: a legal lead byte, only continuation bytes after it,
// and fewer bytes present than the lead byte promised.
func isTruncatedRune(b []byte) bool {
	var want int
	switch {
	case b[0]&0xE0 == 0xC0:
		want = 2
	case b[0]&0xF0 == 0xE0:
		want = 3
	case b[0]&0xF8 == 0xF0:
		want = 4
	default:
		// Not a lead byte at all — 0xFF, or a stray continuation byte. Nothing
		// could have completed it, so truncation is not an explanation.
		return false
	}
	if len(b) >= want {
		// Enough bytes were present and it still failed to decode, so the
		// failure is in the bytes rather than in where the window stopped:
		// a bad continuation byte, an overlong form, or a surrogate.
		return false
	}
	for _, c := range b[1:] {
		if c&0xC0 != 0x80 {
			return false
		}
	}
	return true
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
	switch s.Action {
	case Warn:
		s.Hint = IconvCommand(s.Encoding, path)
	case WarnUnknown:
		s.Hint = IconvGuessCommand(path)
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

// IconvGuessCommand composes a suggested conversion for a file that is provably
// not UTF-8 but whose encoding could not be named.
//
// Deliberately worded as something to try rather than as a claim. Every other
// hint this package produces follows a byte-perfect signature and can assert
// what the file is; this one follows only the absence of valid UTF-8, and the
// two candidates it names are the common cases, not a detection.
func IconvGuessCommand(path string) string {
	return "if this is a legacy export, try: iconv -f WINDOWS-1252 -t UTF-8 " +
		path + " > " + utf8SiblingPath(path) + " (or -f LATIN1)"
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
