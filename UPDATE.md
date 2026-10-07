## 2026-10-07 09:30:00
version 2.2.1
fix: a client that connects and hangs up before sending an address made the TCP handler skip its exit on io.EOF and then call String() on the nil address — recovered, but every such probe logged a full stack instead of closing quietly
fix: the user-list endpoint and the shutdown path iterated the user table without its lock while the 5-minute panel sync rewrote it; concurrent map access is an unrecoverable Go runtime fatal error, so the whole node process died, not just the connection
fix: an empty node secret made an unauthenticated request (`"" == ""`) pass the push-API check on a port bound to all interfaces; the node now refuses to start the push server, and refuses a reload, instead of running unauthenticated
fix: node startup no longer logs the node secret and user passwords (the `%+v` node-info dump and the push-request body were both written at info level)
fix: `vnet --version` now exists (cobra only had a version template, no version), and the deploy script asks for it at the real install path `/usr/bin/vnet/vnet` — the "already on the latest version" branch had never actually compared anything
fix: the ReportTask goroutine re-read the manager's context field each tick, so after a reload it was watching the *new* context and never saw its own cancel — one leaking reporter per reload
fix: the panel user list's ETag was a plain global read and written by both the reporter goroutine and the reload handler
fix: a pushed user row with a missing port used to bind a random port and a missing password used to open the account; both are rejected now
security: the panel WebAPI no longer skips TLS certificate verification — a middleman could previously impersonate the panel and push a user table or a node config
update: every traffic report batch carries a `report_id` (same across the rows of one batch, unchanged on resend) so the panel can dedupe the one window where a report is charged twice: the panel accepted it but the response was lost
update: the counters for per-connection traffic moved to the head of the decorate struct — on the published 32-bit targets (386/arm/mips/mipsle) Go does not pad an int64 field to 8 bytes, so any 4-byte field inserted before them would make `sync/atomic` panic at run time; verified with a compile-time offset assertion
update: UDP receive buffer 2 KiB -> 64 KiB; a datagram plus IV, obfs and AEAD overhead used to be cut off at the socket
docs: `TestCommittedCapabilitiesMatchesTheRegistry` compares content, not line endings — a Windows checkout with `core.autocrlf=true` was always red there

## 2026-10-06 14:00:00
version 2.2.0
fix: api_host was read into the app but never used, so every WebAPI request went to a host-less URL and the process exited at startup
fix: a failed traffic/online report dropped that round for good; un-sent increments are requeued now, and the 50 KiB per-minute floor is gone
update: user add/edit applies the pushed state by uid — enable=0 removes the account, an identical row is a no-op, so pushes and retries are idempotent
update: the full user list is re-synced every 5 minutes with If-None-Match, and a node reload keeps the running services when the panel is unreachable
fix: an algorithm name this backend doesn't implement now returns an error instead of calling a nil factory in every connection
update: startup no longer depends on api.ip.sb — the public address is recorded by the panel from the heartbeat's source IP instead
update: every direct Go dependency is now at its latest release tag
update: chacha20 tracks the 2023 release of yawning's implementation, which gates its SSSE3 assembly on the SSSE3 feature bit instead of SSE3 — the keystream is unchanged, pinned by golden vectors
fix: the packet-mode stream decorator decrypted with an encrypter, so anything past the first 16 bytes came out shifted — that helper is only reachable from `CipherPacketDecorate`, which no server path calls (the shipped UDP path goes through `Encryptor.DecryptAll`, which already asked for a decrypter), so live datagrams were never garbled by this

## 2020-12-13 03:38:56
version 2.1.0
Open-source!

## 2019-11-12 18:09:00
version 2.0.4
fix: AEAD package Integrity

## 2019-10-29 00:09:15
version 2.0.3
fix: bug of Limit the number of client logins
update: obfs log
fix: traffic limit of node

## 2019-10-21 23:55:16
version: 2.0.2
update: Limit the number of client logins

## 2019-10-17 00:09:21
version: 2.0.1
update: user limit prefer