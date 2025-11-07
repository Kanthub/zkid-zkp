// 根据 VerifyingKey导出 Solidity verifier 合约
// 生成合约只需要 VerifyingKey
package main

import (
	"log"
	"os"

	"github.com/consensys/gnark/backend/groth16"
)

func exportVerifier() {
	log.Println("📖 读取 vk 文件...")
	fvk, err := os.Open("age_vk.bin")
	if err != nil {
		log.Fatalf("❌ 打开 age_vk.bin 失败: %v", err)
	}
	defer fvk.Close()

	var vk groth16.VerifyingKey
	if _, err := vk.ReadFrom(fvk); err != nil {
		log.Fatalf("❌ 读取 vk 失败: %v", err)
	}
	log.Println("✅ 成功读取 vk")

	out, err := os.Create("AgeVerifier.sol")
	if err != nil {
		log.Fatalf("❌ 创建 AgeVerifier.sol 失败: %v", err)
	}
	defer out.Close()

	if err := vk.ExportSolidity(out); err != nil {
		log.Fatalf("❌ 导出 Solidity verifier 失败: %v", err)
	}

	log.Println("🎉 成功生成 Solidity Verifier: AgeVerifier.sol")
}
