# send-userop

Builds, signs, and submits an ERC-4337 v0.7 `PackedUserOperation` for a
**SignetAccount** smart wallet.

The command takes a raw secp256k1 private key and uses the FROST
(RFC 9591, FROST-secp256k1-SHA256-v1) Go library directly to produce a
single-party (1-of-1) Schnorr signature — no signet node required.

Signet account factory is deployed on ETH Sepolia at `0xDd2ce0290596Ebd1897FB58cfF8eF4012C87E4F6`

---

## Build

```bash
cd cmd/send-userop
go build -o send-userop .
```

---

## Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--rpc` | `http://localhost:8545` | Ethereum JSON-RPC URL |
| `--bundler` | *(required)* | ERC-4337 bundler JSON-RPC URL |
| `--entry-point` | `0x0000000071727De22E5E9d8BAf0edAc6f37da032` | EntryPoint v0.7 address |
| `--factory` | — | `SignetAccountFactory` address; derives sender and builds `initCode` automatically |
| `--salt` | `0` | CREATE2 salt passed to the factory (decimal or `0x` hex) |
| `--sender` | *(required unless `--factory` set)* | `SignetAccount` address |
| `--key` | *(required)* | secp256k1 private key hex |
| `--to` | *(required)* | Target address for the inner `execute()` call |
| `--value` | `0` | Wei value forwarded to the target |
| `--calldata` | `0x` | ABI-encoded calldata for the target (hex) |
| `--verification-gas-limit` | `500000` | `verificationGasLimit` |
| `--call-gas-limit` | `100000` | `callGasLimit` |
| `--pre-verification-gas` | `50000` | `preVerificationGas` |
| `--max-fee-per-gas` | 120% of `eth_gasPrice` | `maxFeePerGas` in wei |
| `--max-priority-fee-per-gas` | `1000000000` (1 gwei) | `maxPriorityFeePerGas` in wei |
| `--timeout` | `2m0s` | Overall operation timeout |

---

## Usage

### Sending to an existing account

```bash
send-userop \
  --rpc      http://localhost:8545 \
  --bundler  http://localhost:4337 \
  --sender   0xYourSignetAccount \
  --key      0xYourPrivateKeyHex \
  --to       0xTargetAddress \
  --value    0 \
  --calldata 0x
```

### First deployment via factory

When `--factory` is provided the counterfactual sender address is derived
by calling `factory.getAddress` on-chain.  If the account is not yet deployed,
`initCode` is populated automatically so the EntryPoint deploys it on the first
UserOp.

```bash
./send-userop \
  --rpc      http://localhost:8545 \
  --bundler  http://localhost:4337 \
  --factory  0xYourSignetAccountFactory \
  --key      0xYourPrivateKeyHex \
  --to       0xTargetAddress \
  --value    0
```

---

## Generating calldata with `cast`

Use Foundry's `cast calldata` to ABI-encode any function call:

```bash
cast calldata "transfer(address,uint256)" 0xRecipient 1000000000000000000
```

Pipe it directly into the command:

```bash
send-userop \
  --factory  0xYourFactory \
  --key      0xYourPrivateKeyHex \
  --to       0xTokenContract \
  --calldata $(cast calldata "transfer(address,uint256)" 0xRecipient 1000000000000000000)
```

`cast calldata` handles all ABI types — dynamic arrays, tuples, strings, etc.

```bash
# ERC-721 safeTransferFrom
cast calldata "safeTransferFrom(address,address,uint256)" 0xFrom 0xTo 42

# Arbitrary tuple
cast calldata "foo((address,uint256))" "(0xabc...,100)"
```

---

## How signing works

The private key is treated as a 1-of-1 FROST key share.  The group
verification key is the corresponding compressed secp256k1 public key
(`privKey × G`), which must match the key stored in the `SignetAccount`.

The resulting 65-byte signature has the layout expected by the on-chain
`FROSTVerifier`:

```
R.x (32 bytes) || z (32 bytes) || v (1 byte, R.y parity)
```

The derived group public key is printed at startup so you can verify it
matches what is registered in the account.
