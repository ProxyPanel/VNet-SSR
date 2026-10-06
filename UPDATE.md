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
fix: UDP datagrams over aes-128/192/256-cfb came out garbled beyond the first 16 bytes — the packet path asked for an encrypter where the TCP path asks for a decrypter

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