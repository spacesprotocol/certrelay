# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
## [0.2.9](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.8...fabric-v0.2.9)
 - 2026-08-19

### Bug Fixes

- *(fabric-js)* Surface VeritasError detail instead of enum name

## [0.2.8](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.7...fabric-v0.2.8)
 - 2026-08-17

### Bug Fixes

- Report the newest anchor as the tip, not the oldest
- Preserve a root cert's ZK receipt on a receipt-less re-send

### Chore

- Bump libveritas to 0.4.2 across Rust and all client bindings

### Documentation

- *(examples)* Add resolve_with_certs example in all languages

### Features

- *(fabric)* Populate SEED_SEMI_TRUSTED with production relay keys
- *(fabric)* ResolveWithCerts in Go, Python, Kotlin, Swift
- *(fabric-js)* Pinned semi-trusted relay pool with quorum
- *(fabric)* Pinned semi-trusted relay pool with quorum
- *(relay)* Sign anchor root + expose version
- *(fabric)* Resolve_with_certs — one-pass resolve + export + parent commitments
- Version-aware /query and /hints caching + per-call noCache client opt

### Style

- Cargo fmt --all

## [0.2.7](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.6...fabric-v0.2.7)
 - 2026-08-01

### Bug Fixes

- Stop trusting source_ip from propagated peer lists

## [0.2.6](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.5...fabric-v0.2.6)
 - 2026-07-28

### Chore

- Bump libveritas to 0.3.3

## [0.2.5](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.4...fabric-v0.2.5)
 - 2026-07-26

### Bug Fixes

- *(js)* Restore "*" workspace dep so publish CI can pin it

## [0.2.4](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.3...fabric-v0.2.4)
 - 2026-07-26

### Chore

- Bump libveritas to 0.3.1, spaces crates to 0.2.1
- *(js)* Bump libveritas to 0.3 and tighten dependency pins
- Bump libveritas to 0.3, spaces crates to 0.2

### Features

- Replace push gossip with pull-based sync + pokes

## [0.2.3](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.2...fabric-v0.2.3)
 - 2026-04-26

### Bug Fixes

- Sort merged anchors by descending height, fix non-Rust client builds

## [0.2.2](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.1...fabric-v0.2.2)
 - 2026-04-26

### Bug Fixes

- Use sliding windows for anchor sets so trust_ids stay resolvable

## [0.2.1](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.2.0...fabric-v0.2.1)
 - 2026-04-25

### Refactor

- Remove rootId from VerifiedMessageHandle

## [0.2.0](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.1.4...fabric-v0.2.0)
 - 2026-04-24

### Features

- [**breaking**] Return Zone directly from resolve, drop Resolved/ResolvedBatch
- Badge fix, ResolvedBatch.get(), and state persistence

## [0.1.4](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.1.3...fabric-v0.1.4)
 - 2026-04-21

### Bug Fixes

- Export() skips epoch hints to always include receipt in .spacecert

### Chore

- Bump libveritas to 0.1.4 across all clients

### Style

- Fix formatting for resolve_flat signature

## [0.1.3](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.1.2...fabric-v0.1.3)
 - 2026-04-20

### Bug Fixes

- Resolve() should return null/nil across all clients when handle not found

## [0.1.2](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.1.1...fabric-v0.1.2)
 - 2026-04-20

### Bug Fixes

- *(js)* Handle libveritas default export

### Refactor

- Move Cargo.toml to fabric/ root

## [0.1.1](https://github.com/spacesprotocol/certrelay/compare/fabric-v0.1.0...fabric-v0.1.1)
 - 2026-04-20

### Features

- Add release-plz, CI, and publish fabric-rs to crates.io
