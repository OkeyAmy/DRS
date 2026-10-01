// Package testkit issues real, Ed25519-signed DRS delegation chains for tests,
// in the spirit of net/http/httptest. Nothing here is mocked: bundles produced
// by an Issuer verify under the production verifier.
//
// testkit must never be imported by production code.
package testkit

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/OkeyAmy/DRS/drs-verify/pkg/types"
)

// Key is an Ed25519 identity with its did:key.
type Key struct {
	Private ed25519.PrivateKey
	DID     string
}

// NewKey generates a fresh Ed25519 identity.
func NewKey() (Key, error) {
	pub, prv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("generate key: %w", err)
	}
	return Key{Private: prv, DID: "did:key:z" + base58(append([]byte{0xed, 0x01}, pub...))}, nil
}

// Issuer holds a one-hop chain (human root → agent) and signs invocations.
type Issuer struct {
	ToolServer string
	root       Key
	agent      Key
	rootJWT    string
}

// NewIssuer signs a root delegation for cmd under policy, valid for one hour.
func NewIssuer(toolServer, cmd string, policy types.Policy) (*Issuer, error) {
	root, err := NewKey()
	if err != nil {
		return nil, err
	}
	agent, err := NewKey()
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	exp := now + 3600
	jti, err := randomID("dr")
	if err != nil {
		return nil, err
	}
	rootJWT, err := sign(root.Private, types.DelegationReceipt{
		Iss: root.DID, Sub: root.DID, Aud: agent.DID,
		DrsV: "4.0", DrsType: "delegation-receipt",
		Cmd: cmd, Policy: policy,
		Nbf: now - 60, Exp: &exp, Iat: now, Jti: jti,
	})
	if err != nil {
		return nil, err
	}
	return &Issuer{ToolServer: toolServer, root: root, agent: agent, rootJWT: rootJWT}, nil
}

// Bundle signs a fresh invocation (unique jti) of cmd with argsJSON as the
// exact signed args, and returns the chain bundle.
func (i *Issuer) Bundle(cmd string, argsJSON []byte) (types.ChainBundle, error) {
	jti, err := randomID("inv")
	if err != nil {
		return types.ChainBundle{}, err
	}
	digest := sha256.Sum256([]byte(i.rootJWT))
	payload := map[string]interface{}{
		"iss": i.agent.DID, "sub": i.root.DID,
		"drs_v": "4.0", "drs_type": "invocation-receipt",
		"cmd": cmd, "args": json.RawMessage(argsJSON),
		"dr_chain":    []string{"sha256:" + hex.EncodeToString(digest[:])},
		"tool_server": i.ToolServer,
		"iat":         time.Now().Unix(), "jti": jti,
	}
	invJWT, err := sign(i.agent.Private, payload)
	if err != nil {
		return types.ChainBundle{}, err
	}
	return types.ChainBundle{BundleVersion: "4.0", Receipts: []string{i.rootJWT}, Invocation: invJWT}, nil
}

// Header returns Bundle encoded for the X-DRS-Bundle header (base64url JSON).
func (i *Issuer) Header(cmd string, argsJSON []byte) (string, error) {
	b, err := i.Bundle(cmd, argsJSON)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(b)
	if err != nil {
		return "", fmt.Errorf("marshal bundle: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func sign(key ed25519.PrivateKey, payload interface{}) (string, error) {
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "typ": "JWT"})
	if err != nil {
		return "", fmt.Errorf("marshal header: %w", err)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal payload: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(body)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, []byte(input))), nil
}

func randomID(prefix string) (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return prefix + ":" + hex.EncodeToString(b), nil
}

func base58(b []byte) string {
	const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
	digits := []int{0}
	for _, by := range b {
		carry := int(by)
		for j := len(digits) - 1; j >= 0; j-- {
			carry += 256 * digits[j]
			digits[j] = carry % 58
			carry /= 58
		}
		for carry > 0 {
			digits = append([]int{carry % 58}, digits...)
			carry /= 58
		}
	}
	out := []byte{}
	for _, by := range b {
		if by != 0 {
			break
		}
		out = append(out, '1')
	}
	for _, d := range digits {
		out = append(out, alphabet[d])
	}
	return string(out)
}
