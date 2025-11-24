package main

import (
	"log"

	setup_keys "github.com/kanthub/zkid-zkp/keys"
	proof_age "github.com/kanthub/zkid-zkp/proof"
	verify_age "github.com/kanthub/zkid-zkp/verifier_mock"
)

func main() {
	// 1) 生成 zk-SNARK 密钥对（ProvingKey + VerifyingKey），并保存pk到本地文件，然后用vk生成Solidity合约
	_, vk := setup_keys.GenerateKeys()

	// 2) 生成 zk-SNARK 证明，并保存 proof 到本地文件
	did := proof_age.ComputeLocalDID("Alice", "Wonderland", "123 Fantasy Rd", 28, 123456789, []byte{1, 2, 3, 4})
	log.Println("Computed DID:", did.String())

	C := proof_age.ComputeCommitment(
		1, 1, // policyID, version
		"Alice", "Wonderland", "123 Fantasy Rd",
		28, 123456789,
		[]byte{1, 2, 3, 4},
		did,
	)
	log.Println("Computed Commitment C:", C.String())

	proof_age.GenerateProof(
		1, 1, 18,
		"Alice", "Wonderland", "123 Fantasy Rd",
		28, 123456789,
		[]byte{1, 2, 3, 4},
		did, C,
	)

	// 3) 模拟链上验证过程：用户提供 1. 公共输入 和 2. proof
	verify_age.VerifyProof(
		1, 1, 18,
		"Alice", "Wonderland", "123 Fantasy Rd",
		28, 123456789,
		[]byte{1, 2, 3, 4},
		did, C, vk,
	)
}
