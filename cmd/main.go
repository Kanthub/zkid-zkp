package main

import (
	"log"

	setup_keys "github.com/kanthub/zkid-zkp/keys"
	proof_age "github.com/kanthub/zkid-zkp/proof"
	verify_age "github.com/kanthub/zkid-zkp/verifier_mock"
)

func main() {
	// 1) Generate zk-SNARK key pair (ProvingKey + VerifyingKey), save pk to a local file, then generate a Solidity contract using vk
	_, vk := setup_keys.GenerateKeys()

	// 2) Generate a zk-SNARK proof, and save the proof to a local file
	did := proof_age.ComputeLocalDID("Alice", "Wonderland", "123 Fantasy Rd", 28, 123456789, []byte{1, 2, 3, 4})
	log.Printf("======Computed DID: %s ======", did.String())

	C := proof_age.ComputeCommitment(
		1, 1, // policyID, version
		"Alice", "Wonderland", "123 Fantasy Rd",
		28, 123456789,
		[]byte{1, 2, 3, 4},
		did,
	)
	log.Printf("======Computed Commitment C: %s ======", C.String())

	publicInputs, publicInputsStr, err := proof_age.GenerateProof(
		1, 1, 18,
		"Alice", "Wonderland", "123 Fantasy Rd",
		28, 123456789,
		[]byte{1, 2, 3, 4},
		did, C,
	)
	if err != nil {
		log.Fatalf("Proof generation failed: %v", err)
	}
	log.Printf("======Public inputs for verification: %v ======", publicInputs)
	log.Printf("======Public inputs (string) for verification: %v ======", publicInputsStr)

	// 3) Simulate the on-chain verification process: the user provides (1) public inputs and (2) the proof
	verify_age.VerifyProof(
		1, 1, 18,
		"Alice", "Wonderland", "123 Fantasy Rd",
		28, 123456789,
		[]byte{1, 2, 3, 4},
		did, C, vk,
	)
}
