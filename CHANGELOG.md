# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
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
