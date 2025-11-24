// 模拟用户链上验证过程：用户提供 1. 公共输入 和 2. proof
// 链上合约使用 hardcode 的 vk 进行验证
package verify_age

import (
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"golang.org/x/crypto/sha3"

	"github.com/kanthub/zkid-zkp/circuits"
)

func VerifyProof(
	policyID, version, threshold int64,
	name, nation, address string,
	age, identityID int64,
	attrValue []byte,
	did *big.Int,
	C *big.Int, // commitment
	vk groth16.VerifyingKey,
) {
	log.Println("Running off-chain verification...")

	// 1) Compile the circuit (same as proving)
	// var circuit circuits.Circuit
	field := fr.Modulus()
	// cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	// if err != nil {
	// 	log.Fatalf("compile failed: %v", err)
	// }
	// _, vk, err := groth16.Setup(cs)
	// if err != nil {
	// 	log.Fatalf("Setup failed: %v", err)
	// }
	// 不可以重新Setup生成 vk，因为会不一样

	// 2) Recompute witness (same as proving）
	assignment, err := NewAssignmentCircuit(
		policyID, version, threshold,
		name, nation, address,
		age, identityID,
		attrValue, did, C,
	)
	if err != nil {
		log.Fatalf("assignment error: %v", err)
	}

	// Public input C
	assignment.C = C

	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		log.Fatalf("make witness failed: %v", err)
	}

	// 4) Load proof
	fproof, err := os.Open("proof_age.bin")
	if err != nil {
		log.Fatalf("proof open failed: %v", err)
	}
	defer fproof.Close()

	proof := groth16.NewProof(ecc.BN254)
	if _, err := proof.ReadFrom(fproof); err != nil {
		log.Fatalf("proof parse failed: %v", err)
	}

	// 5) Extract public witness
	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatalf("public input failed: %v", err)
	}
	// 这里 publicWitness 的顺序必须和电路中定义的 public inputs 顺序一致
	fmt.Println("Public inputs for verification:")
	vec := publicWitness.Vector().(fr.Vector)
	for i, v := range vec {
		fmt.Printf("  Public input %d: %s\n", i, v.String())
	}

	// 6) Run Groth16 verification
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		log.Fatalf("Verification FAILED: %v", err)
	}

	log.Println("Verification SUCCESS (off-chain) ✅")
}

// AssignmentCircuit is the witness constructor used on the user side.
// It is responsible for converting all fields (string / number / bytes)
// into field elements (big.Int) inside the circuit.
func NewAssignmentCircuit(
	policyID, version, threshold int64,
	name, nation, address string,
	age, identityID int64,
	attrValue []byte, // fingerprint features (bytes)
	did, C *big.Int,
) (*circuits.Circuit, error) {

	// 1. Helper: Keccak256(bytes) → *big.Int
	toBigInt := func(data []byte) *big.Int {
		h := sha3.NewLegacyKeccak256()
		h.Write(data)
		sum := h.Sum(nil)
		return new(big.Int).SetBytes(sum)
	}

	// 2. Hash string fields
	nameInt := toBigInt([]byte(name))
	nationInt := toBigInt([]byte(nation))
	addressInt := toBigInt([]byte(address))

	// 3. Process numeric fields
	ageBytes := big.NewInt(age).Bytes()
	ageInt := big.NewInt(age) // Do NOT hash for age; it's a raw value used for comparison

	idBytes := big.NewInt(identityID).Bytes()
	identityInt := toBigInt(idBytes)

	// 4. AttrValue (fingerprint) raw bytes → hash
	attrInt := toBigInt(attrValue)

	// 5. DID: hash the concatenation of original fields
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
	log.Printf("Constructed DID (decimal): %s\n", didInt.String())

	if did.Cmp(didInt) != 0 {
		log.Fatalf("did not match")
	}

	// 6. Construct the assignment
	assign := &circuits.Circuit{
		PolicyID:  big.NewInt(policyID),
		Version:   big.NewInt(version),
		C:         C,
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
