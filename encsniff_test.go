package encsniff

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSniffBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantAct Action
		wantEnc Encoding
		wantBom int
	}{
		{
			name:    "empty",
			input:   nil,
			wantAct: UseAsIs,
		},
		{
			name:    "clean ASCII",
			input:   []byte("memberid,prefix,firstname\n101,Mr,David\n"),
			wantAct: UseAsIs,
		},
		{
			name:    "clean UTF-8 with non-ASCII",
			input:   []byte("name,city\nDavid,München\n"),
			wantAct: UseAsIs,
		},
		{
			name:    "UTF-8 BOM",
			input:   append([]byte{0xEF, 0xBB, 0xBF}, []byte("memberid,prefix\n")...),
			wantAct: StripBom,
			wantEnc: EncUTF8BOM,
			wantBom: 3,
		},
		{
			name:    "UTF-16 little-endian BOM",
			input:   []byte{0xFF, 0xFE, 'a', 0x00, 'b', 0x00},
			wantAct: Warn,
			wantEnc: EncUTF16LE,
		},
		{
			name:    "UTF-16 big-endian BOM",
			input:   []byte{0xFE, 0xFF, 0x00, 'a', 0x00, 'b'},
			wantAct: Warn,
			wantEnc: EncUTF16BE,
		},
		{
			name:    "UTF-7 with +ACI- marker",
			input:   []byte("+ACI-memberid+ACI-,+ACI-prefix+ACI-\n"),
			wantAct: Warn,
			wantEnc: EncUTF7,
		},
		{
			name:    "UTF-7 marker deep in window",
			input:   append(bytes.Repeat([]byte("a"), 3000), []byte("+ACI-x+ACI-")...),
			wantAct: Warn,
			wantEnc: EncUTF7,
		},
		{
			name:    "UTF-7 marker past window — not detected (acceptable)",
			input:   append(bytes.Repeat([]byte("a"), scanWindow), []byte("+ACI-x+ACI-")...),
			wantAct: UseAsIs,
		},
		{
			name:    "short ASCII fragment that could be a BOM prefix",
			input:   []byte{0xEF},
			wantAct: UseAsIs,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SniffBytes(tt.input)
			if got.Action != tt.wantAct {
				t.Errorf("Action = %v, want %v", got.Action, tt.wantAct)
			}
			if got.Encoding != tt.wantEnc {
				t.Errorf("Encoding = %q, want %q", got.Encoding, tt.wantEnc)
			}
			if got.BomLen != tt.wantBom {
				t.Errorf("BomLen = %d, want %d", got.BomLen, tt.wantBom)
			}
			if got.Hint != "" {
				t.Errorf("SniffBytes set Hint = %q, want empty", got.Hint)
			}
		})
	}
}

func TestSniffFile(t *testing.T) {
	dir := t.TempDir()

	writeFixture := func(name string, b []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	t.Run("UTF-7 CSV — hint matches user-facing wording", func(t *testing.T) {
		p := writeFixture("Roster_Report.csv",
			[]byte("+ACI-memberid+ACI-,+ACI-prefix+ACI-\n101,Mr\n"))
		s, err := SniffFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if s.Action != Warn || s.Encoding != EncUTF7 {
			t.Fatalf("got %+v, want Warn UTF-7", s)
		}
		want := "iconv -f UTF-7 -t UTF-8 " + p + " > " +
			filepath.Join(dir, "Roster_Report.utf8.csv")
		if s.Hint != want {
			t.Errorf("Hint = %q\nwant   %q", s.Hint, want)
		}
	})

	t.Run("UTF-8 BOM — strip, no hint", func(t *testing.T) {
		p := writeFixture("excel.csv",
			append([]byte{0xEF, 0xBB, 0xBF}, []byte("a,b\n1,2\n")...))
		s, err := SniffFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if s.Action != StripBom || s.BomLen != 3 {
			t.Fatalf("got %+v, want StripBom BomLen=3", s)
		}
		if s.Hint != "" {
			t.Errorf("Hint = %q, want empty for StripBom", s.Hint)
		}
	})

	t.Run("UTF-16-LE — hint suggests UTF-16LE", func(t *testing.T) {
		p := writeFixture("wide.csv", []byte{0xFF, 0xFE, 'a', 0x00})
		s, err := SniffFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if s.Action != Warn || s.Encoding != EncUTF16LE {
			t.Fatalf("got %+v, want Warn UTF-16LE", s)
		}
		if !strings.Contains(s.Hint, "UTF-16LE") {
			t.Errorf("Hint missing UTF-16LE: %q", s.Hint)
		}
	})

	t.Run("clean UTF-8 — no action, no hint", func(t *testing.T) {
		p := writeFixture("clean.csv", []byte("a,b\n1,2\n"))
		s, err := SniffFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if s.Action != UseAsIs {
			t.Fatalf("got %+v, want UseAsIs", s)
		}
	})

	t.Run("missing file returns error", func(t *testing.T) {
		_, err := SniffFile(filepath.Join(dir, "nope.csv"))
		if err == nil {
			t.Fatal("want error for missing file")
		}
	})

	t.Run("file shorter than scan window still works", func(t *testing.T) {
		p := writeFixture("tiny.csv", []byte("a"))
		s, err := SniffFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if s.Action != UseAsIs {
			t.Fatalf("got %+v, want UseAsIs", s)
		}
	})
}

func TestUtf8SiblingPath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"Roster.csv", "Roster.utf8.csv"},
		{"/tmp/data.txt", "/tmp/data.utf8.txt"},
		{"noext", "noext.utf8"},
		{"a.b.csv", "a.b.utf8.csv"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			if got := utf8SiblingPath(tt.in); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSniffBytesLatin1IsNotUseAsIs(t *testing.T) {
	// "café" in Latin-1: 0xE9 sits in front of a newline, which cannot be a
	// continuation byte, so the bytes are decidably not UTF-8.
	got := SniffBytes([]byte("name,city\nDavid,caf\xE9\n"))
	if got.Action != WarnUnknown {
		t.Errorf("a CP1252/Latin-1 export must not assert it is usable as-is; got %v", got.Action)
	}
	if got.Encoding != "" {
		t.Errorf("nothing was proven about which encoding it is; got %q", got.Encoding)
	}
}

func TestSniffBytesFlagsInvalidByteAtVeryEnd(t *testing.T) {
	// 0xFF can never appear in UTF-8 at all, so no truncation story excuses it.
	if got := SniffBytes([]byte("ok,\xFF")); got.Action != WarnUnknown {
		t.Errorf("got %v, want WarnUnknown", got.Action)
	}
}

func TestSniffBytesDoesNotFlagRuneCutByScanWindow(t *testing.T) {
	// The trap the whole check has to survive: a 3-byte rune starting at 4094
	// leaves two of its bytes inside the window and one outside. The file is
	// perfectly good UTF-8; only our view of it is truncated.
	input := append(bytes.Repeat([]byte("a"), scanWindow-2), []byte("€")...)
	if len(input) != scanWindow+1 {
		t.Fatalf("test setup: input is %d bytes, want %d", len(input), scanWindow+1)
	}
	if got := SniffBytes(input); got.Action != UseAsIs {
		t.Errorf("a rune straddling the window boundary is not a broken file; got %v", got.Action)
	}
}

func TestSniffBytesDoesNotFlagTruncatedRuneAtEndOfInput(t *testing.T) {
	euro := []byte("€")
	if got := SniffBytes(euro[:2]); got.Action != UseAsIs {
		t.Errorf("got %v, want UseAsIs", got.Action)
	}
}

func TestSniffBytesDoesNotFlagLoneHighByteAtEndOfInput(t *testing.T) {
	// Looks like a bug and is not. 0xE9 is a legal lead byte for a 3-byte rune,
	// so as the final byte it is indistinguishable from a rune the window cut in
	// half, and truncation is never flagged. Real Latin-1 files are unaffected:
	// 4KB of legacy text puts high bytes in front of ASCII repeatedly, and each
	// of those is a genuine error. Only a file ending exactly on one is quiet,
	// which is the price of never crying wolf on a good file.
	if got := SniffBytes([]byte("caf\xE9")); got.Action != UseAsIs {
		t.Errorf("lone trailing lead byte: got %v, want UseAsIs", got.Action)
	}
	if got := SniffBytes([]byte("caf\xE9\n")); got.Action != WarnUnknown {
		t.Errorf("lead byte followed by a non-continuation: got %v, want WarnUnknown", got.Action)
	}
}

func TestSniffBytesFlagsOverlongAndSurrogate(t *testing.T) {
	// Well-formed in shape, illegal in UTF-8. Enough bytes are present in each
	// case, so truncation cannot be the explanation.
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"overlong NUL", []byte("a\xC0\x80b")},
		{"surrogate half", []byte("a\xED\xA0\x80b")},
		{"bad continuation", []byte("a\xE2\x28\xA1b")},
	} {
		if got := SniffBytes(tc.in); got.Action != WarnUnknown {
			t.Errorf("%s: got %v, want WarnUnknown", tc.name, got.Action)
		}
	}
}

func TestIsWarning(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
		want bool
	}{
		{"latin-1", []byte("caf\xE9\n"), true},
		{"utf-16le bom", []byte{0xFF, 0xFE}, true},
		{"plain ascii", []byte("plain ascii"), false},
		{"utf-8 bom", []byte{0xEF, 0xBB, 0xBF}, false},
	} {
		if got := SniffBytes(tc.in).IsWarning(); got != tc.want {
			t.Errorf("%s: IsWarning() = %v, want %v", tc.name, got, tc.want)
		}
	}
}

func TestSniffFileHintsAtConversionForUnnameableEncoding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "l1.csv")
	if err := os.WriteFile(path, []byte("name\ncaf\xE9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := SniffFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.Action != WarnUnknown {
		t.Fatalf("got %v, want WarnUnknown", got.Action)
	}
	if got.Encoding != "" {
		t.Errorf("encoding should stay empty; got %q", got.Encoding)
	}
	for _, want := range []string{"WINDOWS-1252", "LATIN1", "l1.utf8.csv"} {
		if !strings.Contains(got.Hint, want) {
			t.Errorf("hint %q does not mention %q", got.Hint, want)
		}
	}
	// Worded as a suggestion, because unlike every other hint here it does not
	// follow from a signature.
	if !strings.HasPrefix(got.Hint, "if this is") {
		t.Errorf("hint should read as a suggestion, not a claim; got %q", got.Hint)
	}
}
