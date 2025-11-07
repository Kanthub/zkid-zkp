// 根据电路生成 Groth16 的 ProvingKey 和 VerifyingKey
package main

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/kanthub/zkid-zkp/circuits"
)

func generateKeys() {
	log.Println("🧩 Step 1: 编译电路...")

	var circuit circuits.Circuit
	field := fr.Modulus()                                         // 返回 *big.Int 类型的模数, 曲线的域
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit) // ConstraintSystem
	if err != nil {
		log.Fatalf("❌ 电路编译失败: %v", err)
	}
	log.Println("✅ 电路编译成功")

	log.Println("⚙️ Step 2: 生成 groth16.ProvingKey / groth16.VerifyingKey...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatalf("❌ Setup 失败: %v", err)
	}
	log.Println("✅ Setup 完成")

	// 保存 pk
	pkFile, err := os.Create("age_pk.bin")
	if err != nil {
		log.Fatalf("❌ 创建 pk 文件失败: %v", err)
	}
	defer pkFile.Close()
	if _, err := pk.WriteTo(pkFile); err != nil {
		log.Fatalf("❌ 写入 pk 文件失败: %v", err)
	}
	log.Println("💾 保存 age_pk.bin 成功")

	// 保存 vk
	vkFile, err := os.Create("age_vk.bin")
	if err != nil {
		log.Fatalf("❌ 创建 vk 文件失败: %v", err)
	}
	defer vkFile.Close()
	if _, err := vk.WriteTo(vkFile); err != nil {
		log.Fatalf("❌ 写入 vk 文件失败: %v", err)
	}
	log.Println("💾 保存 age_vk.bin 成功")

	log.Println("🎉 Setup 完成！")
}
