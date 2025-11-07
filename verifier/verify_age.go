// 模拟用户链上验证过程：用户提供 1. 公共输入 和 2. proof
// 链上合约使用 hardcode 的 vk 进行验证
package main

import (
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"

	"github.com/kanthub/zkid-zkp/circuits"
)

func main() {
	verify()
}

func verify() {
	log.Println("🔍 验证 proof_age.bin")

	// 1️⃣ 编译电路（仅结构）
	// var circuit circuits.Circuit
	field := fr.Modulus()
	// cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	// if err != nil {
	// 	log.Fatalf("❌ 电路编译失败: %v", err)
	// }

	// 2️⃣ 加载 vk
	fvk, err := os.Open("../cmd/age_vk.bin")
	if err != nil {
		log.Fatalf("❌ 打开 vk 失败: %v", err)
	}
	defer fvk.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(fvk); err != nil {
		log.Fatalf("❌ 读取 vk 失败: %v", err)
	}

	// 3️⃣ 加载 proof
	fproof, err := os.Open("proof_age.bin")
	if err != nil {
		log.Fatalf("❌ 打开 proof 文件失败: %v", err)
	}
	defer fproof.Close()

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(fproof); err != nil {
		log.Fatalf("❌ 读取 proof 失败: %v", err)
	}

	// 4️⃣ 公共输入 witness（与电路一致）
	publicWitness := circuits.Circuit{
		PolicyID:  big.NewInt(1),
		Version:   big.NewInt(1),
		C:         big.NewInt(0x12345),
		Threshold: big.NewInt(18),
	}
	pubWit, err := frontend.NewWitness(&publicWitness, field, frontend.PublicOnly())
	if err != nil {
		log.Fatalf("❌ 构造公开 witness 失败: %v", err)
	}

	// 5️⃣ 验证, 模拟用户链上验证过程：只提供 公共输入 和 proof
	// 注意：这里的 vk 是从文件加载的，实际链上会 hardcode 进合约
	if err := groth16.Verify(proof, vk, pubWit); err != nil {
		log.Fatalf("❌ 验证失败: %v", err)
	}
	log.Println("✅ Proof 验证通过！")
}
