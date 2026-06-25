# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities privately through GitHub Security Advisories at https://github.com/excelano/encsniff-go/security/advisories/new. If you would rather not use GitHub, email david.anderson@excelano.com instead. I aim to respond within seven days.

Please do not open public issues for security problems.

## Supported versions

The latest v0.x release receives security fixes. Older versions are not supported.

## What encsniff-go can access

encsniff-go is a library, not a service. `SniffBytes` inspects a byte slice you pass it and never touches the filesystem or network. `SniffFile` opens the path you give it, reads only the first few bytes to check for a known signature, and closes it. It does no writes, makes no network calls, runs no subprocesses, and stores nothing. It detects only byte-perfect signatures (UTF-8 BOM, UTF-16 LE/BE) — there is no heuristic parsing of file contents and no execution of anything the file contains.

## What encsniff-go stores

Nothing. No telemetry, no analytics, no caching, no remote logging. The only output is the returned `Sniff` value and, for `SniffFile`, a single read against the path you supplied.
