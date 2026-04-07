// send-userop builds, signs, and submits an ERC-4337 v0.7 PackedUserOperation
// targeting a deployed (or not yet deployed) SignetAccount.
//
// It takes a secp256k1 private key directly and uses the FROST (RFC 9591)
// implementation to produce a single-party (1-of-1) Schnorr signature
// compatible with the on-chain FROSTVerifier.
//
// Usage (existing account):
//
//	send-userop \
//	  --rpc        http://localhost:8545 \
//	  --bundler    http://localhost:4337 \
//	  --entry-point 0x0000000071727De22E5E9d8BAf0edAc6f37da032 \
//	  --sender     0xYourSignetAccount \
//	  --key        0xYourPrivateKeyHex \
//	  --to         0xTargetAddress \
//	  --value      0 \
//	  --calldata   0x
//
// Usage (first deployment via factory):
//
//	send-userop \
//	  --rpc        http://localhost:8545 \
//	  --bundler    http://localhost:4337 \
//	  --factory    0xYourSignetAccountFactory \
//	  --key        0xYourPrivateKeyHex \
//	  --to         0xTargetAddress \
//	  --value      0 \
//	  --calldata   0x
//
// When --factory is provided the counterfactual sender address is derived
// on-chain via factory.getAddress.  If the account is not yet deployed,
// initCode is populated automatically so the EntryPoint deploys it on the
// first UserOp.  --sender is inferred from the factory; supply it explicitly
// only if you want the tool to verify it matches.
//
// The derived group public key is printed so you can verify it matches the one
// installed in the SignetAccount's FROSTValidator (or the account's groupPublicKey).
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/bytemare/frost"
	"github.com/bytemare/secret-sharing/keys"
	"golang.org/x/crypto/sha3"
)

// packedUserOp is an ERC-4337 v0.7 PackedUserOperation.
type packedUserOp struct {
	Sender             [20]byte
	Nonce              *big.Int
	InitCode           []byte
	CallData           []byte
	AccountGasLimits   [32]byte // verificationGasLimit (hi 128 bits) || callGasLimit (lo 128 bits)
	PreVerificationGas *big.Int
	GasFees            [32]byte // maxPriorityFeePerGas (hi 128 bits) || maxFeePerGas (lo 128 bits)
	PaymasterAndData   []byte
	Signature          []byte
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "send-userop: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		rpcURL             = flag.String("rpc", "http://localhost:8545", "Ethereum JSON-RPC URL")
		bundlerURL         = flag.String("bundler", "", "ERC-4337 bundler JSON-RPC URL (required)")
		entryPointStr      = flag.String("entry-point", "0x0000000071727De22E5E9d8BAf0edAc6f37da032", "EntryPoint v0.7 address")
		factoryStr         = flag.String("factory", "", "SignetAccountFactory address; when set, initCode is built automatically")
		saltStr            = flag.String("salt", "0", "CREATE2 salt passed to the factory (decimal or 0x hex)")
		senderStr          = flag.String("sender", "", "SignetAccount address (required unless --factory is set)")
		privKeyHex         = flag.String("key", "", "secp256k1 private key hex (required)")
		toStr              = flag.String("to", "", "Call target address for execute() (required)")
		valueStr           = flag.String("value", "0", "Value forwarded to the target: wei integer (e.g. 1000000000000000000), decimal ETH (e.g. 0.01eth or 0.01), or 0x-prefixed hex wei")
		calldataHex        = flag.String("calldata", "0x", "Inner call data forwarded to the target (hex)")
		verificationGasLim = flag.Uint64("verification-gas-limit", 80000, "verificationGasLimit")
		callGasLim         = flag.Uint64("call-gas-limit", 100000, "callGasLimit")
		preVerifGas        = flag.Uint64("pre-verification-gas", 50000, "preVerificationGas")
		maxFeeStr          = flag.String("max-fee-per-gas", "", "maxFeePerGas in wei (default: 2*baseFee + maxPriorityFeePerGas)")
		maxPrioStr         = flag.String("max-priority-fee-per-gas", "1000000000", "maxPriorityFeePerGas in wei (default: 1 gwei)")
		timeout            = flag.Duration("timeout", 120*time.Second, "operation timeout")
		vectorOut          = flag.String("vector-out", "", "Write a frost_vector.json test vector to this path (for forge test)")
		noEstimateGas      = flag.Bool("no-estimate-gas", false, "Skip eth_estimateUserOperationGas and use flag values directly")
	)
	flag.Parse()

	var missing []string
	if *bundlerURL == "" {
		missing = append(missing, "--bundler")
	}
	if *factoryStr == "" && *senderStr == "" {
		missing = append(missing, "--sender (or --factory to derive it)")
	}
	if *privKeyHex == "" {
		missing = append(missing, "--key")
	}
	if *toStr == "" {
		missing = append(missing, "--to")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flags: %s", strings.Join(missing, ", "))
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	entryPoint, err := parseAddress(*entryPointStr)
	if err != nil {
		return fmt.Errorf("invalid --entry-point: %w", err)
	}
	to, err := parseAddress(*toStr)
	if err != nil {
		return fmt.Errorf("invalid --to: %w", err)
	}

	value, err := parseValue(*valueStr)
	if err != nil {
		return fmt.Errorf("invalid --value %q: %w", *valueStr, err)
	}

	maxPrioFee, ok := new(big.Int).SetString(*maxPrioStr, 0)
	if !ok {
		return fmt.Errorf("invalid --max-priority-fee-per-gas %q", *maxPrioStr)
	}

	// Derive the FROST group public key from the private key and print it.
	groupPubKey, err := derivePublicKey(*privKeyHex)
	if err != nil {
		return fmt.Errorf("derive public key: %w", err)
	}
	fmt.Printf("group pubkey:  0x%s\n", hex.EncodeToString(groupPubKey))

	// Print the Ethereum signer address derived from the public key.
	// This must match what the factory stores in the account's signer field.
	expectedSigner, err := pubKeyToAddress(groupPubKey)
	if err != nil {
		return fmt.Errorf("derive signer address: %w", err)
	}
	fmt.Printf("expected signer: 0x%s\n", hex.EncodeToString(expectedSigner[:]))

	chainID, err := fetchChainID(ctx, *rpcURL)
	if err != nil {
		return fmt.Errorf("fetch chain id: %w", err)
	}
	fmt.Printf("chain id:      %s\n", chainID)

	var maxFeePerGas *big.Int
	if *maxFeeStr == "" {
		// EIP-1559: maxFeePerGas = 2 * baseFee + maxPriorityFeePerGas.
		// Doubling the baseFee means the tx stays valid through a full epoch of base-fee growth.
		baseFee, err := fetchBaseFee(ctx, *rpcURL)
		if err != nil {
			return fmt.Errorf("fetch base fee: %w", err)
		}
		maxFeePerGas = new(big.Int).Mul(baseFee, big.NewInt(2))
		maxFeePerGas.Add(maxFeePerGas, maxPrioFee)
	} else {
		maxFeePerGas, ok = new(big.Int).SetString(*maxFeeStr, 0)
		if !ok {
			return fmt.Errorf("invalid --max-fee-per-gas %q", *maxFeeStr)
		}
	}

	// Resolve sender and optional initCode.
	var (
		sender   [20]byte
		initCode []byte
	)

	if *factoryStr != "" {
		factory, err := parseAddress(*factoryStr)
		if err != nil {
			return fmt.Errorf("invalid --factory: %w", err)
		}
		salt, saltOK := new(big.Int).SetString(*saltStr, 0)
		if !saltOK {
			return fmt.Errorf("invalid --salt %q", *saltStr)
		}

		// Call factory.getAddress to derive the counterfactual address.
		counterfactual, err := fetchGetAddress(ctx, *rpcURL, factory, entryPoint, groupPubKey, salt)
		if err != nil {
			return fmt.Errorf("factory.getAddress: %w", err)
		}
		fmt.Printf("counterfactual: 0x%s\n", hex.EncodeToString(counterfactual[:]))

		// If --sender was also supplied, verify it matches.
		if *senderStr != "" {
			explicit, err := parseAddress(*senderStr)
			if err != nil {
				return fmt.Errorf("invalid --sender: %w", err)
			}
			if explicit != counterfactual {
				return fmt.Errorf("--sender 0x%s does not match factory.getAddress 0x%s",
					hex.EncodeToString(explicit[:]), hex.EncodeToString(counterfactual[:]))
			}
		}
		sender = counterfactual

		// Check whether the account is already deployed.
		deployed, err := isDeployed(ctx, *rpcURL, sender)
		if err != nil {
			return fmt.Errorf("check deployment: %w", err)
		}
		if deployed {
			fmt.Println("account:        already deployed")
			// Read the signer stored in the deployed account and compare to expected.
			onChainSigner, err := fetchAccountSigner(ctx, *rpcURL, sender)
			if err != nil {
				fmt.Printf("account signer: (read failed: %v)\n", err)
			} else {
				match := onChainSigner == expectedSigner
				fmt.Printf("account signer: 0x%s (match=%v)\n", hex.EncodeToString(onChainSigner[:]), match)
			}
		} else {
			fmt.Println("account:        not yet deployed — including initCode")
			initCode = buildInitCode(factory, entryPoint, groupPubKey, salt)
		}
	} else {
		sender, err = parseAddress(*senderStr)
		if err != nil {
			return fmt.Errorf("invalid --sender: %w", err)
		}
	}

	nonce, err := fetchNonce(ctx, *rpcURL, entryPoint, sender)
	if err != nil {
		return fmt.Errorf("fetch nonce: %w", err)
	}
	fmt.Printf("account nonce: %s\n", nonce)

	innerData, err := decodeHex(*calldataHex)
	if err != nil {
		return fmt.Errorf("decode --calldata: %w", err)
	}

	op := &packedUserOp{
		Sender:             sender,
		Nonce:              nonce,
		InitCode:           initCode,
		CallData:           buildExecuteCalldata(to, value, innerData),
		AccountGasLimits:   packUint128s(*verificationGasLim, *callGasLim),
		PreVerificationGas: new(big.Int).SetUint64(*preVerifGas),
		GasFees:            packBigInts(maxPrioFee, maxFeePerGas),
	}

	// Estimate gas via the bundler before computing the hash (gas limits are part of the hash).
	if !*noEstimateGas {
		est, err := fetchGasEstimate(ctx, *bundlerURL, op, entryPoint)
		if err != nil {
			fmt.Printf("gas estimate: failed (%v) — using flag values\n", err)
		} else {
			op.PreVerificationGas = est.PreVerificationGas
			// Use the estimated callGasLimit but keep verificationGasLimit from the flag.
			// Alchemy's estimation over-pads verificationGasLimit to ~5.8× actual, which
			// violates its own 2.5× (0.4 efficiency) check on submission.
			callGasEst := est.CallGasLimit
			op.AccountGasLimits = packBigInts(new(big.Int).SetUint64(*verificationGasLim), callGasEst)
			fmt.Printf("gas estimate:  preVerif=%s verif=%s(flag) call=%s\n",
				est.PreVerificationGas, new(big.Int).SetUint64(*verificationGasLim), callGasEst)
		}
	}

	opHash := computeUserOpHash(op, chainID, entryPoint)
	fmt.Printf("userOpHash:    0x%s\n", hex.EncodeToString(opHash[:]))

	sig, err := frostSign(*privKeyHex, opHash[:])
	if err != nil {
		return fmt.Errorf("frost sign: %w", err)
	}

	fmt.Printf("signature:     0x%s\n", hex.EncodeToString(sig))
	op.Signature = sig

	// Optionally write a test vector for forge test FROSTIntegrationTest.
	if *vectorOut != "" {
		if err := writeVector(*vectorOut, groupPubKey, opHash[:], expectedSigner, sig); err != nil {
			fmt.Printf("vector-out: %v\n", err)
		} else {
			fmt.Printf("vector written: %s\n", *vectorOut)
		}
	}

	fmt.Printf("submitting to  %s...\n", *bundlerURL)
	resultHash, err := submitToBundler(ctx, *bundlerURL, op, entryPoint)
	if err != nil {
		return fmt.Errorf("submit: %w", err)
	}

	fmt.Printf("submitted:     %s\n", resultHash)
	return nil
}

// frostSign produces a FROST (RFC 9591, FROST-secp256k1-SHA256-v1) signature
// using a single-party (1-of-1) setup from the given secp256k1 private key.
//
// The private key is treated as the sole key share; the group verification key
// equals the signer's public key. The result is a 65-byte Ethereum-compatible
// signature: R.x(32) || z(32) || v(1) where v is the parity of R.y.
func frostSign(privKeyHex string, message []byte) ([]byte, error) {
	privKeyBytes, err := decodeHex(privKeyHex)
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("private key must be 32 bytes, got %d", len(privKeyBytes))
	}

	// Compute public key = privKey * G.
	g := frost.Secp256k1.Group()
	scalar := g.NewScalar()
	if err := scalar.Decode(privKeyBytes); err != nil {
		return nil, fmt.Errorf("decode scalar: %w", err)
	}
	pubKeyPoint := g.Base().Multiply(scalar)
	pubKeyBytes := pubKeyPoint.Encode() // 33-byte compressed secp256k1

	// Build a 1-of-1 FROST key share: the secret share equals the private key,
	// and the group verification key equals the signer's public key.
	keyShare, err := frost.NewKeyShare(frost.Secp256k1, 1, privKeyBytes, pubKeyBytes, pubKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("create key share: %w", err)
	}

	publicKeyShares := make([]*keys.PublicKeyShare, 1)
	publicKeyShares[0] = keyShare.Public()

	cfg := &frost.Configuration{
		Ciphersuite:           frost.Secp256k1,
		Threshold:             1,
		MaxSigners:            1,
		VerificationKey:       pubKeyPoint,
		SignerPublicKeyShares: publicKeyShares,
	}
	if err := cfg.Init(); err != nil {
		return nil, fmt.Errorf("init frost config: %w", err)
	}

	signer, err := cfg.Signer(keyShare)
	if err != nil {
		return nil, fmt.Errorf("create signer: %w", err)
	}

	// Round 1: produce a nonce commitment.
	commitment := signer.Commit()
	commitmentList := frost.CommitmentList{commitment}
	commitmentList.Sort()

	// Round 2: produce the signature share.
	sigShare, err := signer.Sign(message, commitmentList)
	if err != nil {
		return nil, fmt.Errorf("sign: %w", err)
	}

	// Aggregate into a final FROST signature (1-of-1 aggregation).
	frostSig, err := cfg.AggregateSignatures(message, []*frost.SignatureShare{sigShare}, commitmentList, true)
	if err != nil {
		return nil, fmt.Errorf("aggregate signature: %w", err)
	}

	// Encode as 65 bytes: R.x(32) || z(32) || v(1) where v = R.y parity.
	// This matches the format expected by the on-chain FROSTVerifier.
	rEnc := frostSig.R.Encode() // 33 bytes: 0x02/0x03 prefix + R.x
	zEnc := frostSig.Z.Encode() // 32 bytes
	if len(rEnc) != 33 || len(zEnc) != 32 {
		return nil, fmt.Errorf("unexpected signature encoding lengths: R=%d Z=%d", len(rEnc), len(zEnc))
	}
	out := make([]byte, 65)
	copy(out[0:32], rEnc[1:33]) // R.x (skip the 0x02/0x03 prefix byte)
	copy(out[32:64], zEnc)      // z
	if rEnc[0] == 0x03 {
		out[64] = 1 // v = 1 when R.y is odd
	}

	// Local verification: independently compute the FROST challenge and check
	// z·G = R + c·PK.  This distinguishes a challenge mismatch from a signing bug.
	ok := verifyFrostSig(out, message, pubKeyBytes)
	fmt.Printf("local sig valid: %v\n", ok)

	return out, nil
}

// verifyFrostSig locally verifies a FROST signature (65 bytes: R.x||z||v) over
// message against the 33-byte compressed pubKeyBytes.
//
// It independently implements the RFC 9591 challenge hash (expand_message_xmd
// with SHA-256, DST="FROST-secp256k1-SHA256-v1chal", 48 bytes) and checks
// z·G = R + c·PK using secp256k1 group operations.
func verifyFrostSig(sig, message, pubKeyBytes []byte) bool {
	if len(sig) != 65 || len(pubKeyBytes) != 33 {
		return false
	}

	v := sig[64]

	// Reconstruct 33-byte compressed R from R.x and v parity.
	rCompressed := make([]byte, 33)
	if v == 0 {
		rCompressed[0] = 0x02
	} else {
		rCompressed[0] = 0x03
	}
	copy(rCompressed[1:], sig[0:32])

	// Compute challenge c = H2(R_compressed || pubKey || message).
	inputBuf := make([]byte, 0, len(rCompressed)+len(pubKeyBytes)+len(message))
	inputBuf = append(inputBuf, rCompressed...)
	inputBuf = append(inputBuf, pubKeyBytes...)
	inputBuf = append(inputBuf, message...)
	c := frostChallengeGo(inputBuf)
	fmt.Printf("local challenge: 0x%s\n", hex.EncodeToString(c.Bytes()))

	g := frost.Secp256k1.Group()

	// Decode z.
	zScalar := g.NewScalar()
	if err := zScalar.Decode(sig[32:64]); err != nil {
		fmt.Printf("local verify: z decode: %v\n", err)
		return false
	}

	// z·G
	zG := g.Base().Multiply(zScalar)

	// Decode R.
	rPoint := g.NewElement()
	if err := rPoint.Decode(rCompressed); err != nil {
		fmt.Printf("local verify: R decode: %v\n", err)
		return false
	}

	// Decode PK.
	pkPoint := g.NewElement()
	if err := pkPoint.Decode(pubKeyBytes); err != nil {
		fmt.Printf("local verify: PK decode: %v\n", err)
		return false
	}

	// c as 32-byte scalar (c is already reduced mod N).
	cBytes := padLeft32(c.Bytes())
	cScalar := g.NewScalar()
	if err := cScalar.Decode(cBytes); err != nil {
		fmt.Printf("local verify: c scalar decode: %v\n", err)
		return false
	}

	// R + c·PK
	// Multiply a fresh copy of PK by c, then add R.
	cPK := g.NewElement()
	if err := cPK.Decode(pubKeyBytes); err != nil {
		return false
	}
	cPK.Multiply(cScalar)
	rPoint.Add(cPK) // rPoint is now R + c·PK

	return zG.Equal(rPoint)
}

// frostChallengeGo computes the FROST RFC 9591 challenge:
//
//	c = int(expand_message_xmd(SHA-256, input, DST, 48)) mod N
//
// where DST = "FROST-secp256k1-SHA256-v1chal" and input = R_compressed || PK || message.
// This matches the on-chain FROSTVerifier._frostChallenge exactly.
func frostChallengeGo(input []byte) *big.Int {
	dst := []byte("FROST-secp256k1-SHA256-v1chal")
	dstPrime := append(dst, byte(len(dst))) // DST || I2OSP(len(DST),1)

	uniform := expandMessageXMD(input, dstPrime, 48)

	N, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	c := new(big.Int).SetBytes(uniform)
	c.Mod(c, N)
	return c
}

// expandMessageXMD implements RFC 9380 expand_message_xmd with SHA-256.
// s_in_bytes (block size) = 64, b_in_bytes (output size) = 32.
func expandMessageXMD(msg, dstPrime []byte, outLen int) []byte {
	ell := (outLen + 31) / 32

	zPad := make([]byte, 64)
	lStr := []byte{byte(outLen >> 8), byte(outLen)} // I2OSP(outLen, 2)

	// b0 = SHA256(Z_pad || msg || I2OSP(outLen,2) || 0x00 || DST_prime)
	h := sha256.New()
	h.Write(zPad)
	h.Write(msg)
	h.Write(lStr)
	h.Write([]byte{0x00})
	h.Write(dstPrime)
	b0 := h.Sum(nil)

	// b1 = SHA256(b0 || 0x01 || DST_prime)
	h = sha256.New()
	h.Write(b0)
	h.Write([]byte{0x01})
	h.Write(dstPrime)
	b1 := h.Sum(nil)

	bs := [][]byte{b1}
	for i := 2; i <= ell; i++ {
		prev := bs[len(bs)-1]
		xorPrev := make([]byte, 32)
		for j := 0; j < 32; j++ {
			xorPrev[j] = prev[j] ^ b0[j]
		}
		h = sha256.New()
		h.Write(xorPrev)
		h.Write([]byte{byte(i)})
		h.Write(dstPrime)
		bs = append(bs, h.Sum(nil))
	}

	var uniform []byte
	for _, b := range bs {
		uniform = append(uniform, b...)
	}
	return uniform[:outLen]
}

// derivePublicKey returns the 33-byte compressed secp256k1 public key for the
// given private key, so callers can verify it matches the SignetAccount's stored key.
func derivePublicKey(privKeyHex string) ([]byte, error) {
	privKeyBytes, err := decodeHex(privKeyHex)
	if err != nil {
		return nil, err
	}
	g := frost.Secp256k1.Group()
	s := g.NewScalar()
	if err := s.Decode(privKeyBytes); err != nil {
		return nil, fmt.Errorf("decode scalar: %w", err)
	}
	return g.Base().Multiply(s).Encode(), nil
}

// computeUserOpHash computes the ERC-4337 v0.7 userOpHash:
//
//	keccak256(abi.encode(
//	    keccak256(abi.encode(
//	        sender, nonce,
//	        keccak256(initCode), keccak256(callData),
//	        accountGasLimits, preVerificationGas,
//	        gasFees, keccak256(paymasterAndData)
//	    )),
//	    chainId, entryPoint
//	))
//
// All dynamic fields are pre-hashed so both encodes contain only static
// 32-byte values — no offsets needed.
func computeUserOpHash(op *packedUserOp, chainID *big.Int, entryPoint [20]byte) [32]byte {
	inner := make([]byte, 256) // 8 × 32 bytes

	copy(inner[12:32], op.Sender[:])
	copy(inner[32:64], padLeft32(op.Nonce.Bytes()))
	copy(inner[64:96], keccak256(op.InitCode))
	copy(inner[96:128], keccak256(op.CallData))
	copy(inner[128:160], op.AccountGasLimits[:])
	copy(inner[160:192], padLeft32(op.PreVerificationGas.Bytes()))
	copy(inner[192:224], op.GasFees[:])
	copy(inner[224:256], keccak256(op.PaymasterAndData))

	var innerHash [32]byte
	copy(innerHash[:], keccak256(inner))

	// Outer: abi.encode(innerHash, address(entryPoint), chainId)
	// EntryPoint v0.7: keccak256(abi.encode(userOp.hash(), address(this), block.chainid))
	outer := make([]byte, 96)
	copy(outer[0:32], innerHash[:])
	copy(outer[44:64], entryPoint[:]) // address left-padded: [32:44] zeros, [44:64] address
	copy(outer[64:96], padLeft32(chainID.Bytes()))

	var h [32]byte
	copy(h[:], keccak256(outer))
	return h
}

// buildExecuteCalldata ABI-encodes SignetAccount.execute(address,uint256,bytes).
//
// Layout (after the 4-byte selector):
//
//	[0:32]   to address (left-padded)
//	[32:64]  value (uint256)
//	[64:96]  offset to bytes data = 96 (0x60)
//	[96:128] bytes data length
//	[128+]   bytes data (zero-padded to 32-byte boundary)
func buildExecuteCalldata(to [20]byte, value *big.Int, data []byte) []byte {
	selector := keccak256([]byte("execute(address,uint256,bytes)"))[:4]

	dataPaddedLen := ((len(data) + 31) / 32) * 32
	buf := make([]byte, 4+32+32+32+32+dataPaddedLen)

	copy(buf[0:4], selector)
	copy(buf[4+12:4+32], to[:])                                              // to, left-padded
	copy(buf[4+32:4+64], padLeft32(value.Bytes()))                           // value
	buf[4+64+31] = 0x60                                                      // offset = 96
	copy(buf[4+96:4+128], padLeft32(big.NewInt(int64(len(data))).Bytes()))   // data length
	copy(buf[4+128:], data)                                                  // data, zero-padded by make

	return buf
}

// fetchChainID calls eth_chainId and returns the result as a *big.Int.
func fetchChainID(ctx context.Context, rpcURL string) (*big.Int, error) {
	result, err := rpc(ctx, rpcURL, "eth_chainId", nil)
	if err != nil {
		return nil, err
	}
	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return nil, fmt.Errorf("decode chainId: %w", err)
	}
	return hexToBigInt(hexStr)
}

// fetchBaseFee fetches the baseFeePerGas from the latest block.
func fetchBaseFee(ctx context.Context, rpcURL string) (*big.Int, error) {
	result, err := rpc(ctx, rpcURL, "eth_getBlockByNumber", []any{"latest", false})
	if err != nil {
		return nil, err
	}
	var block struct {
		BaseFeePerGas string `json:"baseFeePerGas"`
	}
	if err := json.Unmarshal(result, &block); err != nil {
		return nil, fmt.Errorf("decode block: %w", err)
	}
	if block.BaseFeePerGas == "" {
		return nil, fmt.Errorf("baseFeePerGas not present (pre-London block?)")
	}
	return hexToBigInt(block.BaseFeePerGas)
}

// buildInitCode builds the ERC-4337 initCode field for first-time deployment:
//
//	factory (20 bytes) || createAccount.selector (4 bytes) || abi.encode(entryPoint, groupPublicKey, salt)
func buildInitCode(factory, entryPoint [20]byte, groupPubKey []byte, salt *big.Int) []byte {
	sel := keccak256([]byte("createAccount(address,bytes,uint256)"))[:4]
	args := abiEncodeFactoryArgs(entryPoint, groupPubKey, salt)
	out := make([]byte, 20+4+len(args))
	copy(out[0:20], factory[:])
	copy(out[20:24], sel)
	copy(out[24:], args)
	return out
}

// fetchGetAddress calls factory.getAddress(entryPoint, groupPublicKey, salt)
// via eth_call and returns the resulting address.
func fetchGetAddress(ctx context.Context, rpcURL string, factory, entryPoint [20]byte, groupPubKey []byte, salt *big.Int) ([20]byte, error) {
	sel := keccak256([]byte("getAddress(address,bytes,uint256)"))[:4]
	args := abiEncodeFactoryArgs(entryPoint, groupPubKey, salt)

	calldata := make([]byte, 4+len(args))
	copy(calldata[:4], sel)
	copy(calldata[4:], args)

	params := []any{
		map[string]string{
			"to":   "0x" + hex.EncodeToString(factory[:]),
			"data": "0x" + hex.EncodeToString(calldata),
		},
		"latest",
	}
	result, err := rpc(ctx, rpcURL, "eth_call", params)
	if err != nil {
		return [20]byte{}, err
	}
	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return [20]byte{}, fmt.Errorf("decode getAddress result: %w", err)
	}
	b, err := decodeHex(hexStr)
	if err != nil {
		return [20]byte{}, fmt.Errorf("decode getAddress hex: %w", err)
	}
	// The ABI-encoded address is right-aligned in a 32-byte word.
	if len(b) < 20 {
		return [20]byte{}, fmt.Errorf("getAddress returned %d bytes, want ≥20", len(b))
	}
	var addr [20]byte
	copy(addr[:], b[len(b)-20:])
	return addr, nil
}

// isDeployed returns true if the address has non-empty code on-chain.
func isDeployed(ctx context.Context, rpcURL string, addr [20]byte) (bool, error) {
	params := []any{"0x" + hex.EncodeToString(addr[:]), "latest"}
	result, err := rpc(ctx, rpcURL, "eth_getCode", params)
	if err != nil {
		return false, err
	}
	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return false, fmt.Errorf("decode eth_getCode result: %w", err)
	}
	b, err := decodeHex(hexStr)
	if err != nil {
		return false, fmt.Errorf("decode eth_getCode hex: %w", err)
	}
	return len(b) > 0, nil
}

// abiEncodeFactoryArgs ABI-encodes (address entryPoint, bytes groupPublicKey, uint256 salt).
// This is the tail of the calldata for both createAccount and getAddress.
//
// ABI layout (all slots are 32 bytes):
//
//	[0]  entryPoint address (left-padded)
//	[1]  offset to bytes data = 3*32 = 96
//	[2]  salt (uint256)
//	[3]  bytes length
//	[4+] bytes data (zero-padded to 32-byte boundary)
func abiEncodeFactoryArgs(entryPoint [20]byte, groupPubKey []byte, salt *big.Int) []byte {
	dataPaddedLen := ((len(groupPubKey) + 31) / 32) * 32
	buf := make([]byte, 4*32+dataPaddedLen)

	copy(buf[12:32], entryPoint[:])                         // address, left-padded
	buf[32+31] = 0x60                                        // offset = 96
	copy(buf[64:96], padLeft32(salt.Bytes()))               // salt
	copy(buf[96:128], padLeft32(big.NewInt(int64(len(groupPubKey))).Bytes())) // bytes length
	copy(buf[128:], groupPubKey)                            // bytes data

	return buf
}

// fetchNonce calls EntryPoint.getNonce(sender, 0) via eth_call.
func fetchNonce(ctx context.Context, rpcURL string, entryPoint, sender [20]byte) (*big.Int, error) {
	// Selector: keccak256("getNonce(address,uint192)")[:4]
	sel := keccak256([]byte("getNonce(address,uint192)"))[:4]

	calldata := make([]byte, 4+32+32) // sel + address(32) + uint192 key=0(32)
	copy(calldata[0:4], sel)
	copy(calldata[4+12:4+32], sender[:]) // address, left-padded; key remains zero

	params := []any{
		map[string]string{
			"to":   "0x" + hex.EncodeToString(entryPoint[:]),
			"data": "0x" + hex.EncodeToString(calldata),
		},
		"latest",
	}
	result, err := rpc(ctx, rpcURL, "eth_call", params)
	if err != nil {
		return nil, err
	}

	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return nil, fmt.Errorf("decode nonce: %w", err)
	}
	b, err := decodeHex(hexStr)
	if err != nil {
		return nil, fmt.Errorf("decode nonce hex: %w", err)
	}
	if len(b) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(b):], b)
		b = padded
	}
	return new(big.Int).SetBytes(b[:32]), nil
}

type gasEstimate struct {
	PreVerificationGas   *big.Int
	VerificationGasLimit *big.Int
	CallGasLimit         *big.Int
}

// fetchGasEstimate calls eth_estimateUserOperationGas on the bundler.
// It sends the op with an empty dummy signature (65 zero bytes) so the bundler
// can simulate without requiring a valid FROST signature.
func fetchGasEstimate(ctx context.Context, bundlerURL string, op *packedUserOp, entryPoint [20]byte) (*gasEstimate, error) {
	maxPriorityFeePerGas := new(big.Int).SetBytes(op.GasFees[0:16])
	maxFeePerGas := new(big.Int).SetBytes(op.GasFees[16:32])

	// Use high gas caps for the estimation request so factory deployment doesn't OOG
	// during simulation.  The bundler returns the actual amounts needed.
	userOpJSON := map[string]any{
		"sender":               "0x" + hex.EncodeToString(op.Sender[:]),
		"nonce":                bigToHex(op.Nonce),
		"callData":             bytesToHex(op.CallData),
		"verificationGasLimit": "0x" + fmt.Sprintf("%x", 5_000_000),
		"callGasLimit":         "0x" + fmt.Sprintf("%x", 1_000_000),
		"preVerificationGas":   "0x" + fmt.Sprintf("%x", 100_000),
		"maxPriorityFeePerGas": bigToHex(maxPriorityFeePerGas),
		"maxFeePerGas":         bigToHex(maxFeePerGas),
		"signature":            "0x" + strings.Repeat("00", 65),
	}
	if len(op.InitCode) >= 20 {
		userOpJSON["factory"] = "0x" + hex.EncodeToString(op.InitCode[:20])
		userOpJSON["factoryData"] = bytesToHex(op.InitCode[20:])
	}

	params := []any{userOpJSON, "0x" + hex.EncodeToString(entryPoint[:])}
	result, err := rpc(ctx, bundlerURL, "eth_estimateUserOperationGas", params)
	if err != nil {
		return nil, err
	}

	var resp struct {
		PreVerificationGas   string `json:"preVerificationGas"`
		VerificationGasLimit string `json:"verificationGasLimit"`
		CallGasLimit         string `json:"callGasLimit"`
	}
	if err := json.Unmarshal(result, &resp); err != nil {
		return nil, fmt.Errorf("decode gas estimate response: %w", err)
	}

	pvg, err := parseBigHex(resp.PreVerificationGas)
	if err != nil {
		return nil, fmt.Errorf("parse preVerificationGas: %w", err)
	}
	vgl, err := parseBigHex(resp.VerificationGasLimit)
	if err != nil {
		return nil, fmt.Errorf("parse verificationGasLimit: %w", err)
	}
	cgl, err := parseBigHex(resp.CallGasLimit)
	if err != nil {
		return nil, fmt.Errorf("parse callGasLimit: %w", err)
	}

	return &gasEstimate{
		PreVerificationGas:   pvg,
		VerificationGasLimit: vgl,
		CallGasLimit:         cgl,
	}, nil
}

// parseBigHex parses a 0x-prefixed hex string into a *big.Int.
// parseValue parses a value flag into wei. Accepted formats:
//   - "0.01" or "0.01eth" — decimal ETH, multiplied by 1e18
//   - "1000000000000000000" — decimal wei integer
//   - "0x..." — hex wei integer
func parseValue(s string) (*big.Int, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimSuffix(strings.ToLower(s), "eth")
	s = strings.TrimSpace(s)

	// Hex.
	if strings.HasPrefix(s, "0x") {
		n, ok := new(big.Int).SetString(strings.TrimPrefix(s, "0x"), 16)
		if !ok {
			return nil, fmt.Errorf("invalid hex integer")
		}
		return n, nil
	}

	// If there's a decimal point, treat as ETH and convert to wei.
	if strings.Contains(s, ".") {
		parts := strings.SplitN(s, ".", 2)
		whole, ok1 := new(big.Int).SetString(parts[0], 10)
		if !ok1 {
			return nil, fmt.Errorf("invalid decimal")
		}
		// Scale whole part to wei.
		wei := new(big.Int).Mul(whole, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))

		// Fractional part: pad or trim to 18 digits then parse.
		frac := parts[1]
		if len(frac) > 18 {
			frac = frac[:18]
		} else {
			frac += strings.Repeat("0", 18-len(frac))
		}
		fracWei, ok2 := new(big.Int).SetString(frac, 10)
		if !ok2 {
			return nil, fmt.Errorf("invalid decimal fraction")
		}
		return wei.Add(wei, fracWei), nil
	}

	// Plain decimal integer (wei).
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		return nil, fmt.Errorf("expected decimal wei, decimal ETH (e.g. 0.01 or 0.01eth), or 0x-prefixed hex")
	}
	return n, nil
}

func parseBigHex(s string) (*big.Int, error) {
	s = strings.TrimPrefix(s, "0x")
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex integer: %q", s)
	}
	return n, nil
}

// submitToBundler sends eth_sendUserOperation to the bundler using the
// ERC-4337 v0.7 JSON-RPC format.
//
// The on-chain PackedUserOperation packs several fields for gas efficiency,
// but the bundler RPC API expects them split out:
//
//	accountGasLimits → verificationGasLimit (hi 128) + callGasLimit (lo 128)
//	gasFees          → maxPriorityFeePerGas (hi 128) + maxFeePerGas (lo 128)
//	initCode         → factory (20 bytes) + factoryData (remainder)
func submitToBundler(ctx context.Context, bundlerURL string, op *packedUserOp, entryPoint [20]byte) (string, error) {
	verificationGasLimit := new(big.Int).SetBytes(op.AccountGasLimits[0:16])
	callGasLimit := new(big.Int).SetBytes(op.AccountGasLimits[16:32])
	maxPriorityFeePerGas := new(big.Int).SetBytes(op.GasFees[0:16])
	maxFeePerGas := new(big.Int).SetBytes(op.GasFees[16:32])

	userOpJSON := map[string]any{
		"sender":               "0x" + hex.EncodeToString(op.Sender[:]),
		"nonce":                bigToHex(op.Nonce),
		"callData":             bytesToHex(op.CallData),
		"verificationGasLimit": bigToHex(verificationGasLimit),
		"callGasLimit":         bigToHex(callGasLimit),
		"preVerificationGas":   bigToHex(op.PreVerificationGas),
		"maxPriorityFeePerGas": bigToHex(maxPriorityFeePerGas),
		"maxFeePerGas":         bigToHex(maxFeePerGas),
		"signature":            bytesToHex(op.Signature),
	}

	// initCode (if present) is split into factory address + factoryData.
	if len(op.InitCode) >= 20 {
		userOpJSON["factory"] = "0x" + hex.EncodeToString(op.InitCode[:20])
		userOpJSON["factoryData"] = bytesToHex(op.InitCode[20:])
	}

	params := []any{userOpJSON, "0x" + hex.EncodeToString(entryPoint[:])}
	result, err := rpc(ctx, bundlerURL, "eth_sendUserOperation", params)
	if err != nil {
		return "", err
	}
	var hashStr string
	if err := json.Unmarshal(result, &hashStr); err != nil {
		return "", fmt.Errorf("decode bundler result: %w", err)
	}
	return hashStr, nil
}

// rpc makes a JSON-RPC call and returns the raw result field, or an error if
// the server returned a JSON-RPC error object.
func rpc(ctx context.Context, url, method string, params []any) (json.RawMessage, error) {
	if params == nil {
		params = []any{}
	}
	reqBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  method,
		"params":  params,
	})
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", method, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", method, err)
	}

	var envelope struct {
		Result json.RawMessage `json:"result"`
		Error  json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("decode %s response: %w", method, err)
	}
	if len(envelope.Error) > 0 && string(envelope.Error) != "null" {
		return nil, fmt.Errorf("%s error: %s", method, string(envelope.Error))
	}
	return envelope.Result, nil
}

// packUint128s packs two uint64 values into a bytes32 as uint128 hi || uint128 lo.
// Used for accountGasLimits: verificationGasLimit (hi) || callGasLimit (lo).
func packUint128s(hi, lo uint64) [32]byte {
	var b [32]byte
	binary.BigEndian.PutUint64(b[8:16], hi)  // hi in upper half, right-aligned
	binary.BigEndian.PutUint64(b[24:32], lo) // lo in lower half, right-aligned
	return b
}

// packBigInts packs two *big.Int values into a bytes32 as uint128 hi || uint128 lo.
// Used for gasFees: maxPriorityFeePerGas (hi) || maxFeePerGas (lo).
func packBigInts(hi, lo *big.Int) [32]byte {
	var b [32]byte
	into128 := func(dst []byte, v *big.Int) {
		if v == nil {
			return
		}
		vb := v.Bytes()
		if len(vb) > 16 {
			vb = vb[len(vb)-16:]
		}
		copy(dst[16-len(vb):16], vb) // right-align within the 16-byte half
	}
	into128(b[0:16], hi)
	into128(b[16:32], lo)
	return b
}

// keccak256 computes the Ethereum keccak256 hash of the concatenation of inputs.
func keccak256(data ...[]byte) []byte {
	h := sha3.NewLegacyKeccak256()
	for _, d := range data {
		h.Write(d)
	}
	return h.Sum(nil)
}

// parseAddress decodes a 0x-prefixed 20-byte Ethereum address.
func parseAddress(s string) ([20]byte, error) {
	b, err := decodeHex(s)
	if err != nil {
		return [20]byte{}, err
	}
	if len(b) != 20 {
		return [20]byte{}, fmt.Errorf("expected 20 bytes, got %d", len(b))
	}
	var addr [20]byte
	copy(addr[:], b)
	return addr, nil
}

// decodeHex decodes a 0x-prefixed hex string to bytes.
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(s, "0x")
	if s == "" {
		return nil, nil
	}
	return hex.DecodeString(s)
}

// bytesToHex encodes bytes as a 0x-prefixed hex string; nil/empty → "0x".
func bytesToHex(b []byte) string {
	if len(b) == 0 {
		return "0x"
	}
	return "0x" + hex.EncodeToString(b)
}

// bigToHex encodes a *big.Int as a 0x-prefixed minimal hex string.
func bigToHex(n *big.Int) string {
	if n == nil || n.Sign() == 0 {
		return "0x0"
	}
	return "0x" + n.Text(16)
}

// hexToBigInt decodes a 0x-prefixed hex string to a *big.Int.
func hexToBigInt(s string) (*big.Int, error) {
	s = strings.TrimPrefix(s, "0x")
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		return nil, fmt.Errorf("invalid hex integer: %q", s)
	}
	return n, nil
}

// writeVector writes a frost_vector.json test vector file compatible with
// the FROSTIntegrationTest in test/FROSTVerifier.t.sol.
//
// Fields:
//
//	groupPubKey : 33-byte compressed secp256k1 public key (hex)
//	msgHash     : 32-byte message that was signed (the userOpHash)
//	signer      : Ethereum address derived from the public key
//	sigRx       : sig[0:32] — R.x
//	sigZ        : sig[32:64] — z scalar
//	sigV        : sig[64]   — R.y parity (0=even, 1=odd)
func writeVector(path string, groupPubKey, message []byte, signer [20]byte, sig []byte) error {
	v := map[string]any{
		"groupPubKey": "0x" + hex.EncodeToString(groupPubKey),
		"msgHash":     "0x" + hex.EncodeToString(message),
		"signer":      "0x" + hex.EncodeToString(signer[:]),
		"sigRx":       "0x" + hex.EncodeToString(sig[0:32]),
		"sigZ":        "0x" + hex.EncodeToString(sig[32:64]),
		"sigV":        int(sig[64]),
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(pathDir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

// pathDir returns the directory component of a file path.
func pathDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == '\\' {
			return p[:i]
		}
	}
	return "."
}

// fetchAccountSigner calls account.signer() via eth_call and returns the address.
func fetchAccountSigner(ctx context.Context, rpcURL string, account [20]byte) ([20]byte, error) {
	// keccak256("signer()") = 0x238ac933...
	sel := keccak256([]byte("signer()"))[:4]
	params := []any{
		map[string]string{
			"to":   "0x" + hex.EncodeToString(account[:]),
			"data": "0x" + hex.EncodeToString(sel),
		},
		"latest",
	}
	result, err := rpc(ctx, rpcURL, "eth_call", params)
	if err != nil {
		return [20]byte{}, err
	}
	var hexStr string
	if err := json.Unmarshal(result, &hexStr); err != nil {
		return [20]byte{}, fmt.Errorf("decode signer result: %w", err)
	}
	b, err := decodeHex(hexStr)
	if err != nil {
		return [20]byte{}, err
	}
	if len(b) < 20 {
		return [20]byte{}, fmt.Errorf("signer() returned %d bytes", len(b))
	}
	var addr [20]byte
	copy(addr[:], b[len(b)-20:])
	return addr, nil
}

// pubKeyToAddress derives the Ethereum signer address from a 33-byte compressed
// secp256k1 public key: keccak256(uncompressed_x || uncompressed_y)[12:].
//
// This matches the SignetAccountFactory._signerAddress logic exactly.
func pubKeyToAddress(pubKey []byte) ([20]byte, error) {
	if len(pubKey) != 33 {
		return [20]byte{}, fmt.Errorf("pubKeyToAddress: need 33 bytes, got %d", len(pubKey))
	}
	prefix := pubKey[0]
	if prefix != 0x02 && prefix != 0x03 {
		return [20]byte{}, fmt.Errorf("pubKeyToAddress: invalid prefix 0x%02x", prefix)
	}
	// secp256k1 field prime P.
	P, _ := new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	x := new(big.Int).SetBytes(pubKey[1:33])

	// y² = x³ + 7 mod P
	y2 := new(big.Int).Mul(x, x)
	y2.Mod(y2, P)
	y2.Mul(y2, x)
	y2.Mod(y2, P)
	y2.Add(y2, big.NewInt(7))
	y2.Mod(y2, P)

	// y = y²^((P+1)/4) mod P  (valid since P ≡ 3 mod 4)
	exp := new(big.Int).Add(P, big.NewInt(1))
	exp.Rsh(exp, 2)
	y := new(big.Int).Exp(y2, exp, P)

	// Select the root whose parity matches the prefix.
	if (y.Bit(0) == 1) != (prefix == 0x03) {
		y.Sub(P, y)
	}

	// keccak256(x_32 || y_32)[12:]
	hash := keccak256(padLeft32(x.Bytes()), padLeft32(y.Bytes()))
	var addr [20]byte
	copy(addr[:], hash[12:])
	return addr, nil
}

// padLeft32 left-pads b with zeros to exactly 32 bytes.
func padLeft32(b []byte) []byte {
	if len(b) >= 32 {
		return b
	}
	out := make([]byte, 32)
	copy(out[32-len(b):], b)
	return out
}
