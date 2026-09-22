# Code Scanning Review

This document records the results of the first full CodeQL analysis run
against this repository (Go, Python, and JavaScript/TypeScript), why each
finding was resolved the way it was, and the one real bug it caught.

GitHub's automatic "Default setup" for code scanning couldn't actually
analyze the Go portions of this repo out of the box — this repo has three
independent Go modules (each its own `go.mod`), and one of them is
platform-gated with no Linux build target at all, which Default setup's
autobuild has no way to handle. `.github/workflows/codeql.yml` in this
repository switches to CodeQL's "Advanced setup" with an explicit build
step for Go, so all three languages are now genuinely analyzed on every
push.

That first full run produced 13 findings. Twelve are false positives,
each backed by a real, existing mitigation that CodeQL's static analysis
isn't able to see. One was a genuine bug, now fixed. Both are documented
below.

## Findings

| # | Rule | Location | Severity | Result |
|---|------|----------|----------|--------|
| 1 | Uncontrolled data used in path expression | `src/engine/migrate_archive.py:63` | High | False positive |
| 2 | Uncontrolled data used in path expression | `src/api/server.py:335` | High | False positive |
| 3 | Uncontrolled data used in path expression | `src/api/server.py:1337` | High | False positive |
| 4 | Uncontrolled data used in path expression | `src/api/server.py:1337` | High | False positive |
| 5 | Binding a socket to all network interfaces | `src/pollers/dhcp_sniffer.py:164` | Medium | **Real bug — fixed** |
| 6 | Binding a socket to all network interfaces | `src/pollers/hostname_discovery.py:65` | Medium | False positive |
| 7 | Binding a socket to all network interfaces | `src/pollers/hostname_discovery.py:67` | Medium | False positive |
| 8 | Binding a socket to all network interfaces | `src/engine/smart_switch_pipeline.py:174` | Medium | False positive |
| 9 | Information exposure through an exception | `src/api/server.py:1177` | Medium | False positive |
| 10 | Inclusion of functionality from an untrusted source | `src/ui/links.html:11` | Medium | False positive |
| 11 | Client-side URL redirect | `src/ui/index.html:983` | Medium | False positive |
| 12 | DOM text reinterpreted as HTML | `src/ui/alerting.html:724` | High | False positive |
| 13 | Client-side cross-site scripting | `src/ui/index.html:983` | High | False positive |

## Why the false positives are false positives

### #13 and #11 — `index.html:983`, `frame.src = targetPage`

`targetPage` is read from the page's own `?page=` URL parameter, but
before it's ever used it's checked against a strict allowlist regex:
`^[a-zA-Z0-9_-]+\.html(\?[a-zA-Z0-9_=&.%-]*)?$`. That character set
contains no `:`, `"`, `<`, `>`, or `/`, so the value can never become an
absolute URL and can never break out of the context it's placed in.
CodeQL's taint tracker doesn't recognize a hand-written regex like this
as a sanitizer, so it flags the assignment regardless of the value being
provably constrained.

### #12 — `alerting.html:724`, `link.href = deepLink`

`deepLink` is built from a template literal with a hardcoded, literal
`ntfy://` prefix. Whatever ends up in the interpolated parts, the result
can never start with anything other than `ntfy://` — it cannot become a
`javascript:` URI. The input feeding it is also the user's own webhook
URL setting from their own configuration, not attacker-supplied data.

### #10 — `links.html:11`

This is a pinned, version-locked CDN script include
(`cytoscape.min.js@3.23.0`). CodeQL's "untrusted source" query flags any
third-party script tag by default as a general supply-chain awareness
signal — it isn't identifying a specific defect here, just standard
practice for any web app using a CDN-hosted library.

### #9 — `server.py:1177`

The surrounding function only has `except ValueError: pass` blocks —
nothing about the exception, including its existence, is ever returned
to the client. Every other error handler in this codebase follows the
same convention used throughout the file: log the exception server-side,
return a generic `{"error": "An internal error occurred..."}` message,
never `str(e)`. No exception detail is exposed here.

### #1 through #4 — path traversal, `server.py` and `migrate_archive.py`

`get_db_connection()` calls `os.path.basename(archive_file)` before ever
joining the value into a filesystem path — `basename()` strips all
directory components, so a traversal attempt like `../../etc/passwd`
collapses to just `passwd`. The archive-delete endpoint separately
validates the filename against a strict regex
(`^network_\d{8}_\d{6}\.db$`) *and* confirms the resolved path stays
inside the archive directory via `os.path.commonpath()`. Both are real,
working sanitizers. `migrate_archive.py`'s finding is the same value
downstream of that same `basename()` call — CodeQL's dataflow analysis
doesn't track the value across the function boundary, so it re-flags an
already-sanitized value as if it were still raw.

### #6, #7, #8 — socket binds all interfaces

Each of these call sites invokes `bind_socket_to_scan_interface()`
immediately before the socket bind — a helper that applies
`SO_BINDTODEVICE`, a separate socket option that pins the socket to one
physical network interface at the kernel level, independent of the bind
address itself. CodeQL's query only looks at the literal address passed
to `bind()` (`"0.0.0.0"` or `""`), which genuinely is a wildcard on its
own — it has no visibility into `SO_BINDTODEVICE` restricting it
afterward. Binding to the wildcard address and then scoping via this
option is deliberate: broadcast and multicast discovery require it.

## The real bug: #5

`dhcp_sniffer.py` was the one file in that same "binds all interfaces"
group that was missing the `bind_socket_to_scan_interface()` call before
its own `sock.bind(("", 67))`. It's a newer file than the others —
added when the DHCP-sniffing poller was rewritten to drop a scapy
dependency for licensing reasons — and it didn't get the same
interface-scoping treatment the rest of the discovery pollers already
had.

The practical effect: on a deployment configured to stay scoped to one
network interface (`SCAN_INTERFACE_OVERRIDE`), DHCP broadcast capture
was running on every interface anyway, regardless of that setting.

Fixed with the same call already used everywhere else in the discovery
pipeline, applied the same way:

```python
from engine.auto_discovery import bind_socket_to_scan_interface

# ...

sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
bind_socket_to_scan_interface(sock)
sock.bind(("", 67))
```
