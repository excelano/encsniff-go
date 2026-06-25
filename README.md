# encsniff-go

A small Go library for sniffing common non-UTF-8 text encodings at the head of a file or byte slice. It detects only patterns with byte-perfect signatures — no heuristics. It returns an action (use as is, strip BOM, or warn) and a copy-pasteable `iconv` hint when conversion is needed.

Companion to [`encsniff`](https://github.com/excelano/encsniff) (Rust).

## Install

```
go get github.com/excelano/encsniff-go
```

## Usage

```go
import "github.com/excelano/encsniff-go"

s, err := encsniff.SniffFile("Roster_Report.csv")
if err != nil { /* ... */ }

switch s.Action {
case encsniff.UseAsIs:
    // proceed
case encsniff.StripBom:
    // skip s.BomLen bytes silently
case encsniff.Warn:
    fmt.Fprintf(os.Stderr, "warning: file appears to be %s encoded.\n", s.Encoding)
    fmt.Fprintf(os.Stderr, "hint: %s\n", s.Hint)
}
```

`SniffBytes(b []byte) Sniff` is the in-memory version.

## What it detects

| Pattern | Action | Why |
| --- | --- | --- |
| `EF BB BF` at offset 0 | StripBom | UTF-8 BOM from "Save as CSV UTF-8". Skip the 3 bytes; the file is otherwise clean. |
| `FF FE` at offset 0 | Warn | UTF-16 little-endian. Hint suggests `iconv -f UTF-16LE -t UTF-8`. |
| `FE FF` at offset 0 | Warn | UTF-16 big-endian. Hint suggests `iconv -f UTF-16BE -t UTF-8`. |
| `+ACI-` in first 4KB | Warn | UTF-7 escape for `"` (common in Scoutbook and some Microsoft exports). Hint suggests `iconv -f UTF-7 -t UTF-8`. |
| Anything else | UseAsIs | Assume UTF-8/ASCII; no guessing. |

## What it does not do

No heuristic encoding detection. CP1252 vs Latin-1, language-based detection, byte-frequency analysis are all out of scope. If you need that, reach for `uchardet`.

## License

MIT. Author: David M. Anderson. Built with AI assistance (Claude, Anthropic).
