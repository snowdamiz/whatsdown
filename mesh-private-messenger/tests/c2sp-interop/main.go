// This test server delegates all witness behavior to transparency-dev/witness.
// The deterministic keys below are public test fixtures, never deployment keys.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	formatnote "github.com/transparency-dev/formats/note"
	"github.com/transparency-dev/witness/persistence/inmemory"
	"github.com/transparency-dev/witness/witness"
	"golang.org/x/mod/sumdb/note"
)

func run() error {
	const origin = "morseapp.io/log/main/v2"
	const witnessName = "witness.example/morse-development"
	logPublic := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, 32)).Public().(ed25519.PublicKey)
	logVKey, err := note.NewEd25519VerifierKey(origin, logPublic)
	if err != nil {
		return err
	}
	logVerifier, err := note.NewVerifier(logVKey)
	if err != nil {
		return err
	}
	secret, public, err := note.GenerateKey(bytes.NewReader(bytes.Repeat([]byte{0x62}, 64)), witnessName)
	if err != nil {
		return err
	}
	signer, err := formatnote.NewSignerForCosignatureV1(secret)
	if err != nil {
		return err
	}
	public, err = formatnote.VKeyToCosignatureV1(public)
	if err != nil {
		return err
	}
	publicMaterial, err := base64.StdEncoding.DecodeString(strings.SplitN(public, "+", 3)[2])
	if err != nil {
		return err
	}
	w, err := witness.New(context.Background(), witness.Opts{
		Persistence: inmemory.New(), Signers: []note.Signer{signer},
		VerifierForLog: func(_ context.Context, name string) (note.Verifier, bool, error) {
			return logVerifier, name == origin, nil
		},
	})
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /add-checkpoint", witness.NewHTTPHandler(w).AddCheckpoint)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := json.NewEncoder(os.Stdout).Encode(map[string]string{
		"url": "http://" + listener.Addr().String(), "name": witnessName,
		"public_key": hex.EncodeToString(publicMaterial[1:]), "verifier": public,
	}); err != nil {
		return err
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return server.Serve(listener)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
