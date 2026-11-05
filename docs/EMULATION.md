# Speakeasy emulation notes

Measured coverage on local benign software is documented in
`docs/EMULATION_COVERAGE.md`.

GlassBox PE runs Windows binaries only in user-mode emulation (Speakeasy on
Linux). It never executes a sample natively. The emulation path is best for
turning static capabilities into `attempted` behaviour and for discovering
sleep-free, anti-analysis traps a static scan cannot see.

## What is captured

- API calls with DLL, PC offset, arguments, return value
- categories: `process`, `file`, `network`, `registry`, `pe`, `signature`, and `other`
- behaviour findings such as process injection, persistence, network and file writes
- dynamically generated code segments
- dropped files written by the sample
- in-memory strings reported by Speakeasy
- a compact resource summary (`file` / `network` / `registry`) in the case artifact
- emulation status and resource limits for failures

## Argument resolution

Speakeasy often logs a raw pointer instead of a readable string. For pointer
arguments that point into the sample's image, GlassBox maps the address back to
a file offset and decodes the null-terminated ANSI or UTF-16LE string there.
Events include both the raw arguments and `resolved_args`.

This recovers useful values such as:

- `CreateFileW C:\Windows\system32\t64.exe`
- registry paths like `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`
- URL destinations passed to network APIs
- library/module names passed to loaders

It does **not** resolve:

- stack- or heap-resident pointers
- encrypted or packed strings
- pointers produced dynamically by the sample
- strings that have not been materialised yet
- managed IL arguments (the PE/.NET metadata path is separate)

Unresolved pointers are left as raw hex values. They are not silently guessed.

## Safety and limits

- Windows x86 and x86-64 PE only; ARM64 is rejected with a clear message.
- Emulation runs in a subprocess with CPU, address-space, and file-descriptor limits on Linux.
- Dropping files is supported, and files are retained as artifacts. They are not executed.
- Child processes are not emulated by default.
- Network is simulated; it does not contact real hosts.
- Anti-analysis samples may hide or terminate early; GlassBox reports an empty API trace explicitly.

## Example result

Emulation may report:

- attempted file access with the resolved path;
- attempted registry writes with the key string;
- attempted network activity with the resolved destination;
- dynamic code generation or a packed image signature.

A `GB-EMU-000` finding says nothing reached an API. That can mean packing,
anti-emulation, an unsupported path, or an invalid sample; it is not proof of
innocence or malice.

## Current limitations

- No native Windows process execution; Windows APIs are emulated.
- Emulated registry and network operations are modelled, not physically performed.
- Network/registry behaviour validation on representative benign software is still thin.
- ARM64 support is unavailable in Speakeasy.
- Heap/stack pointers are unresolved; this is narrowing, not complete analysis.
- Emulation is not proof of installation. Everything detected is `attempted`, not `observed`.
