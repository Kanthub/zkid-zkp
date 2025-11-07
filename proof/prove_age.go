// 终端 CLI：给用户本地生成 proof， 用户私下持有 proof_age.bin 文件
// 用户拿着 proof_age.bin 去链上验证

// 用户生成proof需要 1. 私密输入 + 公共输入  2. 电路的 ProvingKey 3. 电路结构cs（编译电路）
package main

import (
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/sha3"

	"github.com/kanthub/zkid-zkp/circuits"
)

// func main() {
// 	generateProof()
// }

// AssignmentCircuit 是用户端 witness 构造函数。
// 它负责把所有字段（string / 数字 / bytes）转成域内 big.Int。
func NewAssignmentCircuit(
	policyID, version, threshold int64,
	name, nation, address string,
	age, identityID int64,
	attrValue []byte, // 指纹特征（bytes）
	did *big.Int,
) (*circuits.Circuit, error) {

	// 1️⃣ 辅助函数：Keccak256(bytes) → *big.Int
	toBigInt := func(data []byte) *big.Int {
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		sum := h.Sum(nil)
		return new(big.Int).SetBytes(sum)
	}

	// 2️⃣ 对字符串字段哈希
	nameInt := toBigInt([]byte(name))
	nationInt := toBigInt([]byte(nation))
	addressInt := toBigInt([]byte(address))

	// 3️⃣ 对数字字段哈希
	ageBytes := big.NewInt(age).Bytes()
	ageInt := toBigInt(ageBytes)

	idBytes := big.NewInt(identityID).Bytes()
	identityInt := toBigInt(idBytes)

	// 4️⃣ AttrValue（指纹）bytes 直接哈希
	attrInt := toBigInt(attrValue)

	// 5️⃣ DID：用原始字段拼接后哈希
	//    Keccak256(name + nation + address + age + identityID + attrValue)
	didHasher := sha3.NewLegacyKeccak256()
	didHasher.Write([]byte(name))
	didHasher.Write([]byte(nation))
	didHasher.Write([]byte(address))
	didHasher.Write(ageBytes)
	didHasher.Write(idBytes)
	didHasher.Write(attrValue)
	didSum := didHasher.Sum(nil)
	didInt := new(big.Int).SetBytes(didSum)

	if did != didInt {
		log.Fatalf("❌ did not match")
	}

	// 6️⃣ 构造 assignment
	assign := &circuits.Circuit{
		PolicyID:  big.NewInt(policyID),
		Version:   big.NewInt(version),
		Threshold: big.NewInt(threshold),

		Name:       nameInt,
		Age:        ageInt,
		Nation:     nationInt,
		Address:    addressInt,
		IdentityID: identityInt,
		AttrValue:  attrInt,
		DID:        didInt,
	}

	return assign, nil
}

func generateProof(
	policyID, version, threshold int64,
	name, nation, address string,
	age, identityID int64,
	attrValue []byte, // 指纹特征（bytes）
	did *big.Int,
) {
	log.Println("🧩 生成证明")

	// 1️⃣ 编译电路
	var circuit circuits.Circuit
	field := fr.Modulus()                                         // 返回 *big.Int 类型的模数, 曲线的域
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit) // ConstraintSystem
	if err != nil {
		log.Fatalf("❌ 电路编译失败: %v", err)
	}

	// 2️⃣ 构造 witness（用户私密输入 + 公共输入）
	assignment, err := NewAssignmentCircuit(policyID, version, threshold, name, nation, address, age, identityID, attrValue, did)
	if err != nil {
		log.Fatalf("❌ assignment 构造失败: %v", err)
	}
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("❌ witness 构造失败: %v", err)
	}

	// 3️⃣ 加载 pk
	fpk, err := os.Open("../cmd/age_pk.bin")
	if err != nil {
		log.Fatalf("❌ 打开 pk 文件失败: %v", err)
	}
	defer fpk.Close()

	var pk groth16.ProvingKey
	if _, err := pk.ReadFrom(fpk); err != nil {
		log.Fatalf("❌ 读取 pk 失败: %v", err)
	}

	// 4️⃣ 生成 proof
	proof, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		log.Fatalf("❌ 生成 proof 失败: %v", err)
	}

	file, err := os.Create("proof_age.bin")
	if err != nil {
		log.Fatalf("❌ 创建 proof 文件失败: %v", err)
	}
	defer file.Close()
	if _, err := proof.WriteTo(file); err != nil {
		log.Fatalf("❌ 写入 proof 失败: %v", err)
	}
	log.Println("🎉 成功生成 proof_age.bin")
}
