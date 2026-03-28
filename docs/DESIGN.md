# EVM Smart Wallet Design — FROST + Kernel v3

**Status:** Draft  
**Date:** March 2026

---

## 1. Overview

This document describes the architecture for a programmable smart wallet built on ERC-4337 account abstraction. The design uses Kernel v3 as the smart account implementation, with FROST threshold Schnorr signatures on secp256k1 as the primary authentication scheme, layered with configurable transaction policies enforced via ERC-7579 hook modules.

The two primary requirements driving the design are:

- Multiple authentication methods with different signing schemes, including a FROST threshold group as the root authority
- Dynamic transaction rules — whitelisting specific ERC-20 tokens for transfer, capping spend, restricting target contracts — enforced on-chain without requiring validator replacement

---

## 2. Standards and protocol context

### ERC-4337 — Account Abstraction

ERC-4337 enables smart contract wallets without protocol-level changes. Instead of EOA-signed transactions, users submit `UserOperation` objects to an off-chain mempool. Bundlers collect these, submit them to the singleton `EntryPoint` contract, which calls `validateUserOp` on the smart account and then executes the operation.

Key consequence: the smart account's `validateUserOp` is programmable — it can implement any signature scheme, not just ECDSA.

### ERC-7579 — Modular Smart Accounts

ERC-7579 defines a minimal, interoperable module interface for smart accounts. Modules are typed:

| Type | ID | Purpose |
|------|----|---------|
| Validator | 1 | Controls who can authorize a UserOp |
| Executor | 2 | Can trigger transactions on behalf of the account |
| Fallback | 3 | Extends the account interface |
| Hook | 4 | Pre/post execution logic — transaction policy lives here |

Kernel v3 is natively ERC-7579 compliant. Modules built to this standard are portable across Kernel, Biconomy Nexus, Safe + adapter, and other compliant accounts.

### EIP-7702 — EOA Delegation

Introduced in Ethereum's Pectra upgrade (May 2025). Allows an existing EOA to temporarily delegate to smart account code for a single transaction. Complementary to ERC-4337 but not a replacement; both can share the same bundler and paymaster infrastructure. Not a primary concern for this design but worth noting for future EOA upgrade paths.

---

## 3. Account implementation: Kernel v3

Kernel v3 (by ZeroDev) is the chosen smart account implementation. It is ERC-7579 native, co-authored the standard, and is currently the most widely deployed modular smart account (~133k v3 accounts, ~771k v2 accounts in the past six months).

### Nonce-based validation routing

The most important architectural detail of Kernel v3 is that the `userOp.nonce` encodes which validator to invoke — not the signature field as in v2:

```
nonce[0:2]  = ValidationMode  (root vs. regular)
nonce[2:22] = ValidationId    (type byte + 20-byte validator address)
nonce[22:32]= sequential nonce
```

`VALIDATION_TYPE_ROOT` (0x00) invokes the sudo validator unconditionally. `VALIDATION_TYPE_VALIDATOR` (0x01) invokes a regular (non-root) validator, subject to an `allowedSelectors` check — the validator must have been granted access to the specific function selector being called.

### Validation storage

Each `ValidationId` maps to a `ValidationConfig` struct containing:

- The hook address attached to this validator
- `validAfter` / `validUntil` timestamps
- The `allowedSelectors` bitmap

### `changeRootValidator` (v3.1+)

Added in Kernel v3.1. Allows the current sudo validator to replace itself atomically. This is the mechanism for FROST group key rotation. Only callable via a root-mode UserOp — regular validators cannot invoke it.

---

## 4. Signing scheme: FROST on secp256k1

### What FROST is

FROST (Flexible Round-Optimized Schnorr Threshold Signatures) is a threshold signature scheme. A root secret key is split into `n` shares distributed to participants; any `t` of them can cooperate to produce a signature verifiable against the root public key. The final signature is indistinguishable from a single-party Schnorr signature — no on-chain observer can determine the threshold or number of participants.

The specific ciphersuite used is FROST(secp256k1, SHA-256) from RFC-9591, which means:

- Root key and group public key are standard secp256k1 key pairs
- Challenge hash uses SHA-256 per the FROST spec (not keccak256)
- Two-round signing protocol: participants commit to nonces (round 1), then produce partial signatures (round 2); a coordinator aggregates into the final `(R, z)` pair

### On-chain verification: the ecrecover trick

The EVM has no native Schnorr precompile. FROST/Schnorr verification (`z·G = R + c·P`) is reformulated to use the existing `ecrecover` precompile, reducing gas cost to approximately 5,600 gas — comparable to ECDSA. The signature passes the full uncompressed group public key coordinates `(px, py)` alongside the nonce commitment `(rx, ry)` and response scalar `z`.

This verification approach is implemented in the `FROST.sol` library from `oleary-labs/signet-research`.

### Signature format

A FROST UserOp signature is 160 bytes:

```
bytes[0:32]   px   — group public key x-coordinate
bytes[32:64]  py   — group public key y-coordinate
bytes[64:96]  rx   — nonce commitment R x-coordinate
bytes[96:128] ry   — nonce commitment R y-coordinate
bytes[128:160] z   — response scalar
```

In the validator module design below, `(px, py)` are stored at install time, reducing the per-UserOp signature to 96 bytes `(rx, ry, z)`.

### Signing roles

| Role | Responsibilities |
|------|-----------------|
| Dealer | Splits the root key into shares; distributes shares to signers; only active at key generation |
| Signer | Holds one key share; participates in both signing rounds |
| Coordinator | Collects nonce commitments; builds signing package; aggregates partial signatures |

The dealer role is optional if distributed key generation (DKG) is used instead of trusted dealer setup.

---

## 5. Architecture

### Component overview

```
┌─────────────────────────────────────────────────────────────┐
│  Kernel v3 account (ERC-1967 proxy)                         │
│                                                             │
│  Root validator                Regular validators           │
│  ┌──────────────────┐         ┌────────────────────────┐    │
│  │ FROSTValidator   │         │ ECDSAValidator          │    │
│  │ stores (px, py)  │         │ day-to-day ops key      │    │
│  │ per account      │         ├────────────────────────┤    │
│  └──────────────────┘         │ SmartSessions           │    │
│                               │ session keys + policies │    │
│                               ├────────────────────────┤    │
│                               │ RecoveryValidator       │    │
│                               │ guardian multisig       │    │
│                               │ scoped to               │    │
│                               │ changeRootValidator only│    │
│                               └────────────────────────┘    │
│                                                             │
│  Global hook                                                │
│  ┌─────────────────────────────────────────────────────┐    │
│  │ TokenWhitelistHook / HookMultiplexer                │    │
│  │ preCheck: inspect calldata, enforce policy          │    │
│  └─────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────┘
```

### Module roles

**FROSTValidator** (custom — to build): The sudo validator. Wraps `FROST.sol`. Stores `(px, py)` per account address in a `mapping(address => PublicKey)` on `onInstall`. `validateUserOp` calls `FROST.verify(userOpHash, px, py, rx, ry, z)` and compares the recovered address to the stored group key address.

**ECDSAValidator** (existing — ZeroDev): Installed as a regular validator for routine operations. Scoped to `execute` and `executeBatch` selectors only; cannot call `installValidation`, `changeRootValidator`, or other privileged functions.

**SmartSessions** (existing — Rhinestone × Biconomy): Session key validator with composable policies. Enables sub-key delegation for automated or application-scoped access with fine-grained calldata rules.

**RecoveryValidator** (existing — Rhinestone Social Recovery, or custom): A regular validator holding a guardian set. Scoped exclusively to the `changeRootValidator` selector. Guardians cannot transact freely — they can only rotate the root key.

**TokenWhitelistHook** (custom — to build): An ERC-7579 Hook module. `preCheck` inspects `callData`, rejects ERC-20 `transfer` and `transferFrom` calls targeting non-whitelisted token contract addresses, and enforces any per-token spend limits. Configured per-account via `onInstall`. The `ColdStorage Hook` from Rhinestone is a structural reference for this pattern.

**HookMultiplexer** (existing — Rhinestone): Chains multiple hooks since Kernel normally only supports one hook per validator. Required if more than one hook policy needs to be active simultaneously.

---

## 6. Deployment sequence

### Phase 1: deploy shared singletons (once)

```solidity
FROSTValidator    frostValidator    = new FROSTValidator();
TokenWhitelistHook whitelistHook   = new TokenWhitelistHook();
// ECDSAValidator, SmartSessions, RecoveryValidator — already deployed
```

Validators and hooks hold no account-specific state of their own. All per-account data lives in mappings keyed by `msg.sender` (the account address), consistent with ERC-4337's storage access rules.

### Phase 2: deploy account

Account address is deterministic via `KernelFactory` + CREATE2 before any deployment gas is spent.

```solidity
bytes memory initData = abi.encodeCall(
    Kernel.initialize,
    (
        toValidationId(address(frostValidator)),  // root validator
        IHook(address(whitelistHook)),            // root hook (or address(0))
        abi.encode(px, py),                       // FROSTValidator.onInstall data
        abi.encode(whitelistConfig)               // hook.onInstall data
    )
);
address kernel = factory.createAccount(kernelImpl, initData, salt);
```

`initialize` sets `_validationStorage().rootValidator`, calls `frostValidator.onInstall(abi.encode(px, py))`, and stores `(px, py)` in `frostValidator.groupKeys[kernel]`.

### Phase 3: install regular validators

Each install is a root-mode UserOp signed by the FROST group:

```
userOp.nonce = 0x0000 <frostValidatorAddress> <sequentialNonce>
userOp.callData = kernel.installValidation(
    toValidationId(address(ecdsaValidator)),
    IHook(address(0)),
    abi.encode(ownerAddress),
    ""
)
userOp.signature = abi.encode(rx, ry, z)   // FROST sig
```

The recovery validator is installed similarly, then restricted to the `changeRootValidator` selector only:

```solidity
kernel.allowSelector(
    toValidationId(address(recoveryValidator)),
    Kernel.changeRootValidator.selector
);
```

---

## 7. UserOp validation flow

```
UserOp submitted to bundler
        │
        ▼
EntryPoint.handleOps → kernel.validateUserOp
        │
        ▼
Decode nonce: mode = nonce[0:2], validatorAddr = nonce[2:22]
        │
   ┌────┴────┐
   │         │
mode=0x00  mode=0x01
(root)    (regular)
   │         │
   ▼         ▼
FROSTValidator    any installed validator
FROST.verify()    + allowedSelectors check
   │         │
   └────┬────┘
        │
        ▼
Hook.preCheck(callData)   ← token whitelist enforced here
        │
        ▼
execute
        │
        ▼
Hook.postCheck
```

---

## 8. Transaction policy design

Policies are enforced by the `TokenWhitelistHook` in `preCheck`. The hook runs before execution regardless of which validator authorized the UserOp.

### Per-account policy storage

```solidity
struct Policy {
    mapping(address token => bool) allowedTokens;
    mapping(address token => uint256) spendLimit;     // per-period cap
    mapping(address token => uint256) spentThisPeriod;
    uint256 periodStart;
    uint256 periodDuration;
}
mapping(address account => Policy) policies;
```

### preCheck logic (pseudocode)

```
function preCheck(address, uint256, bytes calldata callData):
    selector = bytes4(callData[0:4])
    
    if selector == EXECUTE_SELECTOR:
        (target, value, data) = decode(callData)
        checkCall(target, data)
    
    else if selector == EXECUTE_BATCH_SELECTOR:
        calls[] = decode(callData)
        for each call: checkCall(call.target, call.data)

function checkCall(address target, bytes data):
    if bytes4(data) in [ERC20_TRANSFER, ERC20_TRANSFER_FROM]:
        require policies[msg.sender].allowedTokens[target],
            "token not whitelisted"
        amount = decode transfer amount from data
        require spendWithinLimit(target, amount)
```

### Policy updates

Policy configuration is updated via a dedicated function callable only via root-mode UserOp (FROST-signed) or, for delegated policy management, via SmartSessions with a `UniversalActionPolicy` scoped to the `updatePolicy` selector.

---

## 9. FROST group key rotation

The FROST group key is replaced by calling `changeRootValidator` in a root-mode UserOp signed by the current group:

```solidity
kernel.changeRootValidator(
    toValidationId(address(frostValidator)),  // same contract
    IHook(address(whitelistHook)),
    abi.encode(px2, py2)                      // new group public key
)
```

`frostValidator.onInstall(abi.encode(px2, py2))` is called, updating `groupKeys[kernel]` to the new key. The old group cannot sign further root-mode UserOps.

### Recovery path

If the FROST group is lost or compromised and no valid shares remain:

1. The guardian set calls `changeRootValidator` via the `RecoveryValidator`
2. This is valid because the recovery validator has `allowedSelectors[changeRootValidator.selector] = true`
3. A new FROST group (with new key split) is installed as the root
4. Normal operation resumes

Guardians have no other privileged access — they cannot transact, install modules, or read account state beyond what is public on-chain.

---

## 10. Available modules (ecosystem inventory)

### ZeroDev kernel-7579-plugins

| Module | Type | Purpose |
|--------|------|---------|
| ECDSAValidator | Validator | Single-owner secp256k1 |
| Weighted ECDSA Validator | Validator | M-of-N ECDSA multisig |
| WebAuthn Validator | Validator | Passkey / FIDO (secp256r1 / P-256) |
| ECDSA Signer | Signer | For use inside permission system |
| WebAuthn Signer | Signer | Passkey within permission system |
| Call Policy | Policy | Whitelist contracts, selectors, arguments |
| Gas Policy | Policy | Cap gas per session |
| Rate Limit Policy | Policy | Max N calls per time window |
| Signature Policy | Policy | Signature format rules |
| Sudo Policy | Policy | Full unrestricted access (permissive baseline) |
| Timestamp Policy | Policy | Session valid-after / valid-until |
| Only EntryPoint Hook | Hook | Reject any non-EntryPoint caller |
| Recovery Action | Executor | Implements `changeRootValidator` for recovery flows |

### Rhinestone core modules (ERC-7579 ecosystem)

| Module | Type | Purpose |
|--------|------|---------|
| Ownable Validator | Validator | Multi-owner ECDSA, configurable threshold |
| WebAuthn Validator | Validator | Passkey (independent Rhinestone implementation) |
| Social Recovery Validator | Validator | Guardian-based root key recovery |
| Deadman Switch Validator | Validator | Access after inactivity period |
| Multi-Factor Validator | Validator | Require multiple validators to co-sign |
| ZK Email Recovery | Executor | Email-based recovery via DKIM ZK proofs |
| Ownable Executor | Executor | Parent account controls child account |
| Scheduled Transfers | Executor | Recurring token transfers on a schedule |
| Scheduled Orders | Executor | Recurring Uniswap swaps (DCA) |
| Auto Savings | Executor | Sweep % of inbound tokens to vault |
| Flashloan Callback | Executor | Account acts as flashloan receiver |
| Cold Storage Hook | Hook | Timelock + single-address withdrawal restriction |
| Hook Multiplexer | Hook | Chain multiple hooks on one validator |
| Registry Hook | Hook | Enforce Rhinestone module attestation before install |
| SmartSessions | Validator + Policies | Session keys with composable spend/call/time policies |

---

## 11. Custom modules to build

Two modules are required that do not exist in the current ecosystem:

### FROSTValidator

- **Type:** Validator (ERC-7579 type 1)
- **Interface:** `IValidator` from `kernel/interfaces/IERC7579Modules.sol`
- **Core dependency:** `FROST.sol` from `oleary-labs/signet-research`
- **Storage:** `mapping(address account => PublicKey) groupKeys` where `PublicKey = { uint256 x; uint256 y; }`
- **`onInstall`:** Decode `(px, py)` from `data`; validate point is on curve and not identity; store in `groupKeys[msg.sender]`
- **`validateUserOp`:** Decode `(rx, ry, z)` from `userOp.signature` (96 bytes); call `FROST.verify(userOpHash, pk.x, pk.y, rx, ry, z)`; compare recovered address to `keccak256(abi.encodePacked(pk.x, pk.y))[12:]`
- **`isValidSignatureWithSender`:** ERC-1271 support for off-chain signature verification
- **`onUninstall`:** Delete `groupKeys[msg.sender]`
- **Gas estimate:** ~8,000–12,000 gas per validation (FROST verify ~5,600 + storage reads + calldata)

### TokenWhitelistHook

- **Type:** Hook (ERC-7579 type 4)
- **Interface:** `IHook` with `preCheck` and `postCheck`
- **Storage:** `mapping(address account => Policy)` where Policy includes token allowlist, per-token spend caps, and period tracking
- **`preCheck`:** Inspect `callData`; if an ERC-20 `transfer`/`transferFrom` is being called, verify target token is in allowlist and amount is within spend limit; revert if not
- **`postCheck`:** Update `spentThisPeriod` after execution
- **Configuration:** Policy updates callable only via root-mode UserOp or a SmartSessions session scoped to the policy update selector
- **Reference implementation:** Rhinestone `ColdStorage Hook` for structural pattern; Rhinestone `ModuleKit` for testing scaffold

---

## 12. Tooling and infrastructure

### Development

| Tool | Purpose |
|------|---------|
| Foundry | Contract development, testing, local fork simulation |
| Rhinestone ModuleKit | Integration test scaffold for ERC-7579 modules across Kernel, Nexus, Safe |
| Rhinestone ModuleSDK / `@rhinestone/sdk` | TypeScript SDK for module installation and interaction |
| ZeroDev SDK (`@zerodev/sdk`) | Kernel account client, UserOp construction and signing |
| permissionless.js | Lower-level ERC-4337 primitives; bundler and paymaster integration |
| viem | Ethereum client; used by both ZeroDev and Rhinestone SDKs |

### FROST signing infrastructure

| Tool | Purpose |
|------|---------|
| `oleary-labs/signet-research` | FROST.sol on-chain verifier; Rust CLI for key generation and signing rounds |
| `safe-research/safe-frost` | Reference implementation and end-to-end test patterns; FROST(secp256k1, SHA-256) ERC-4337 integration |

### Runtime infrastructure

| Component | Options |
|-----------|---------|
| Bundler | Pimlico Alto, ZeroDev UltraRelay, Alchemy Rundler |
| Paymaster | Pimlico verifying paymaster, ZeroDev paymaster |
| RPC | Alchemy, Infura, QuickNode |
| Explorer | JiffyScan (UserOp-level); Blockscout / Etherscan (bundle-level) |
| Debugger | ZeroDev UserOp Debugger (`debug.zerodev.app`); Tenderly for hook revert traces |

### Module registry

Rhinestone's Module Registry (ERC-7484) stores on-chain attestations from security auditors. Once the custom modules are audited, registering them enables the `Registry Hook` to act as an installation gatekeeper — blocking unattested modules from being installed on the account.

---

## 13. Security considerations

**Sudo validator loss:** If all FROST shares are destroyed and no recovery validator is installed, the account is permanently inaccessible. A recovery validator with guardian set must be installed before the account holds significant value.

**Guardian collusion:** The recovery validator's guardian threshold should reflect the trust model. For institutional use, guardians should be geographically and organizationally separate. The recovery validator is scoped only to `changeRootValidator` — collusion cannot drain funds directly.

**Hook denial of service:** A malicious or buggy hook that always reverts in `preCheck` will permanently block all transactions. The policy update path (via root-mode FROST UserOp) must remain usable even when the hook is blocking regular transactions. Hook updates (reinstall/reconfigure) bypass `preCheck` since they are not execution-phase operations — they are account configuration operations.

**Module installation gating:** Without the `Registry Hook`, any validator the current sudo installs immediately gains access. Consider enabling the Registry Hook and pointing it at a controlled attester list to prevent accidental installation of unaudited modules.

**ecrecover edge case:** The FROST verifier uses `ecrecover` with the public key x-coordinate as the `r` parameter. Keys whose x-coordinate falls in the range `[secp256k1.n, secp256k1.p)` cannot be used — the CLI should reject such keys at generation time (probability ≈ 2⁻¹²⁸).

**Signature malleability:** Schnorr signatures are not malleable (unlike ECDSA), so the replay protection concerns specific to ECDSA do not apply. Standard ERC-4337 nonce management handles replay protection.

**ERC-4337 storage access rules:** Validators are called with `CALL` (not `DELEGATECALL`) during the validation phase. Storage access is restricted by bundler simulation rules — only associated storage (slots keyed on `userOp.sender`) is permitted. The `groupKeys[msg.sender]` mapping pattern is compliant.

---

## 14. Open questions

- **FROST ciphersuite compatibility:** Confirm whether `oleary-labs/signet-research` uses the same challenge hash construction as `safe-research/safe-frost` (RFC-9591 compliant SHA-256, not keccak256). If different, the off-chain signing tooling and on-chain verifier must match exactly.
- **Signature format:** Confirm whether the on-chain verifier accepts `(rx, ry, z)` as three separate 32-byte values, or a different encoding. This determines the exact `userOp.signature` layout.
- **Multi-group accounts:** If multiple independent FROST groups should each have root access (e.g. a 2-of-2 between two groups), the design needs a `MultiFactorValidator` wrapping two `FROSTValidator` instances, rather than a single root validator.
- **Cross-chain deployment:** If the same account address is needed across chains (same `(px, py)` and salt), confirm that `KernelFactory` is deployed at the same address on all target chains and that the FROST verifier contract addresses are consistent.
- **Session key integration with FROST:** SmartSessions session keys are authorized by the session key validator, not the root FROST group — but they still pass through the `TokenWhitelistHook`. Confirm whether session key spend should be tracked against the same limits as root-key spend, or tracked separately.
