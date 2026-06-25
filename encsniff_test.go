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
		name     string
		input    []byte
		wantAct  Action
		wantEnc  Encoding
		wantBom  int
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
