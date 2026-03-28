# signet-wallet

ERC-4337 smart wallet using FROST threshold Schnorr signatures on secp256k1 as the root authentication scheme, built on [Kernel v3](https://github.com/zerodevapp/kernel) with [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) modular account architecture.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full architecture and rationale.

---

## Overview

The wallet uses Kernel v3 as the smart account implementation. Authentication is provided by two custom ERC-7579 modules:

**FROSTValidator** — a type-1 validator module. Stores the FROST group public key per account and verifies 96-byte FROST Schnorr signatures `(rx, ry, z)` against the [RFC 9591](https://www.rfc-editor.org/rfc/rfc9591) challenge hash using the `ecrecover` precompile. Installed as the Kernel root (sudo) validator; key rotation happens via `changeRootValidator` in a root-mode UserOp.

**TokenWhitelistHook** *(planned)* — a type-4 hook module. Runs in `preCheck` on every UserOp regardless of which validator authorized it. Enforces per-account token allowlists and per-period spend limits on ERC-20 `transfer` and `transferFrom` calls.

### Signature verification

On-chain FROST/Schnorr verification is implemented in `FROSTVerifier.sol`, borrowed from [`oleary-labs/signet-research`](https://github.com/oleary-labs/signet-research). It reformulates the Schnorr equation `z·G = R + c·Y` to use `ecrecover`, costing ~6,000 gas.

The FROST ciphersuite is `FROST-secp256k1-SHA256-v1` per RFC 9591 — challenge hash uses SHA-256 via `expand_message_xmd`, not keccak256.

---

## Contracts

```
src/
  FROSTVerifier.sol          — FROST Schnorr verifier library (ecrecover-based)
  FROSTValidator.sol         — ERC-7579 validator module wrapping FROSTVerifier
  SignetAccount.sol          — minimal ERC-4337 account (reference implementation)
  interfaces/
    IAccount.sol             — PackedUserOperation, IAccount (ERC-4337 v0.7)
    IERC7579Modules.sol      — IModule, IValidator, module type constants
```

---

## Development

Requires [Foundry](https://book.getfoundry.sh/).

```bash
forge build          # compile
forge test           # run all tests
forge test -vv       # with logs (gas reports, etc.)
```

The integration test in `FROSTVerifier.t.sol` reads `test/testdata/frost_vector.json`. Generate it with `go run ./cmd/testvector/` from the `signet-research` repo, then copy the file here.

---

## Dependencies

| Library | Purpose |
|---|---|
| `forge-std` | Foundry test utilities |
| `openzeppelin-contracts-upgradeable` | OZ v5 (included for future hook/executor modules) |

---

## License

MIT
