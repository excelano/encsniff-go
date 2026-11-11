# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately, using the **Report a vulnerability** button on the Security tab of the repository concerned. If that button is not there, or you would rather not go through GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest release receives security fixes. Older versions are not supported. A fix ships in a new release; update the dependency to take it.

## What encsniff-go can access

encsniff-go is a library, not a service. `SniffBytes` inspects a byte slice you pass it and never touches the filesystem or network. `SniffFile` opens the path you give it, reads only the head of the file to check for a known signature and to test whether those bytes are valid UTF-8, and closes it. It does no writes, makes no network calls, runs no subprocesses, and stores nothing. It detects only byte-perfect signatures (UTF-8 BOM, UTF-16 LE/BE, the UTF-7 escape) and UTF-8 validity — there is no heuristic parsing of file contents and no execution of anything the file contains.

`IconvCommand` and `IconvGuessCommand` compose an `iconv` command as a string for the caller to display. Neither is ever run, and nothing in this package executes a shell.

## What encsniff-go stores

Nothing. No telemetry, no analytics, no caching, no remote logging. The only output is the returned `Sniff` value and, for `SniffFile`, a single read against the path you supplied.
