// Terminal CLI: locally generate proof for the user.
// The user privately holds the file proof_age.bin.
// The user then brings proof_age.bin to the blockchain for verification.

// To generate a proof, the user needs:
//  1. Private inputs + public inputs
//  2. The circuit's ProvingKey
//  3. The compiled circuit constraint system (cs)
package proof_age

import (
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16_bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"golang.org/x/crypto/sha3"

	frhashmimc "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/kanthub/zkid-zkp/circuits"
)

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

// ComputeLocalDID computes the DID locally using the exact same
// hashing scheme used in the witness constructor.
// The returned *big.Int can be compared with the DID provided by the Oracle.
func ComputeLocalDID(
	name, nation, address string,
	age, identityID int64,
	attrValue []byte, // fingerprint bytes
) *big.Int {

	// Convert integers to bytes
	ageBytes := big.NewInt(age).Bytes()
	idBytes := big.NewInt(identityID).Bytes()

	// Keccak256(name + nation + address + age + identityID + attrValue)
	hasher := sha3.NewLegacyKeccak256()
	hasher.Write([]byte(name))
	hasher.Write([]byte(nation))
	hasher.Write([]byte(address))
	hasher.Write(ageBytes)
	hasher.Write(idBytes)
	hasher.Write(attrValue)

	sum := hasher.Sum(nil)

	didInt := new(big.Int).SetBytes(sum)
	log.Printf("Locally computed DID (decimal): %s\n", didInt.String())
	return didInt
}

// ComputeCommitment computes the public commitment C that the circuit enforces:
//
//	C = MiMC(
//	    PolicyID,
//	    Version,
//	    NameHash,
//	    Age,
//	    NationHash,
//	    AddressHash,
//	    IdentityIDHash,
//	    AttrValueHash,
//	    DID,
//	)
//
// The hashing / preprocessing must be exactly the same as in NewAssignmentCircuit
// and in your Circuit.Define() MiMC.Write(...) order.
func ComputeCommitment(
	policyID, version int64,
	name, nation, address string,
	age, identityID int64,
	attrValue []byte,
	did *big.Int,
) *big.Int {

	// 为了避免和电路不一致，这里直接复用 NewAssignmentCircuit 的逻辑，
	// 保证 Name/Nation/Address/IdentityID/AttrValue/DID 的 Keccak 预处理完全一致。
	assignment, err := NewAssignmentCircuit(
		policyID, version /* threshold = */, 0, // 阈值不参与哈希，随便给个 0
		name, nation, address,
		age, identityID,
		attrValue,
		did, big.NewInt(0), // C 不参与哈希，随便给个 0 值
	)
	if err != nil {
		log.Fatalf("ComputeCommitment: failed to build assignment: %v", err)
	}

	// 从 assignment 里把各字段按电路里的顺序取出来
	//（在 NewAssignmentCircuit 中，这些字段都被赋值为 *big.Int）
	getBig := func(v interface{}) *big.Int {
		if v == nil {
			log.Fatalf("ComputeCommitment: got nil field in assignment")
		}
		bi, ok := v.(*big.Int)
		if !ok {
			log.Fatalf("ComputeCommitment: expected *big.Int, got %T", v)
		}
		return bi
	}

	inputs := []*big.Int{
		getBig(assignment.PolicyID),
		getBig(assignment.Version),
		getBig(assignment.Name),
		getBig(assignment.Age),
		getBig(assignment.Nation),
		getBig(assignment.Address),
		getBig(assignment.IdentityID),
		getBig(assignment.AttrValue),
		getBig(assignment.DID),
	}

	// 使用 gnark-crypto 的 MiMC（bn254/fr）做哈希，
	// 这和 gnark/std/hash/mimc gadget 底层是一套参数。
	h := frhashmimc.NewMiMC()

	// 把每个 field element 规范化成 fr.Element 再写入
	for _, x := range inputs {
		var fe fr.Element
		fe.SetBigInt(x)       // big.Int -> F_r 元素
		h.Write(fe.Marshal()) // 以标准字节编码写入
	}

	sum := h.Sum(nil)

	// 输出也是一个 F_r 元素（字段内的 hash 值）
	var out fr.Element

	sumBigInt := new(big.Int).SetBytes(sum)
	sumBigInt.Mod(sumBigInt, fr.Modulus()) // reduce into field
	out.SetBigInt(sumBigInt)

	C := out.BigInt(new(big.Int))
	log.Printf("Locally computed Commitment C (decimal): %s\n", C.String())
	return C
}

func GenerateProof(
	policyID, version, threshold int64,
	name, nation, address string,
	age, identityID int64,
	attrValue []byte, // fingerprint features (bytes)
	did, C *big.Int,
) ([]*big.Int, []string, error) {
	log.Println("Generating proof...")

	// 1. Compile the circuit
	var circuit circuits.Circuit
	field := fr.Modulus()                                         // Returns the modulus (*big.Int), field of the curve
	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit) // Build the ConstraintSystem
	if err != nil {
		return nil, nil, fmt.Errorf("circuit compilation failed: %w", err)
	}

	// 2. Construct witness (private input + public input)
	assignment, err := NewAssignmentCircuit(
		policyID, version, threshold,
		name, nation, address,
		age, identityID,
		attrValue, did, C,
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to build assignment: %w", err)
	}
	witness, err := frontend.NewWitness(assignment, field)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to construct witness: %w", err)
	}

	// 3. Load pk
	fpk, err := os.Open("./age_pk.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open pk file: %w", err)
	}
	defer fpk.Close()

	// var pk groth16.ProvingKey
	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(fpk); err != nil {
		return nil, nil, fmt.Errorf("failed to read pk: %w", err)
	}

	// 4. Generate proof
	pIface, err := groth16.Prove(cs, pk, witness)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate proof: %w", err)
	}

	pStruct, ok := pIface.(*groth16_bn254.Proof)
	if !ok {
		return nil, nil, fmt.Errorf("failed to cast proof to bn254.Proof")
	}
	ExportProofForSol(*pStruct)

	file, err := os.Create("proof_age.bin")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create proof file: %w", err)
	}
	defer file.Close()

	if _, err := pIface.WriteTo(file); err != nil {
		return nil, nil, fmt.Errorf("failed to write proof: %w", err)
	}
	log.Println("Successfully generated proof_age.bin")

	// 5. Prepare public inputs for user's verification
	publicInputs := []*big.Int{
		big.NewInt(policyID),
		big.NewInt(version),
		C,
		big.NewInt(threshold),
	}
	pubInputsStr := ExportPublicInputs(witness)
	return publicInputs, pubInputsStr, nil
}

func ExportProofForSol(proof groth16_bn254.Proof) {
	// A point
	a := [2]string{
		proof.Ar.X.String(),
		proof.Ar.Y.String(),
	}

	// B point (G2)
	b := [2][2]string{
		{proof.Bs.X.A0.String(), proof.Bs.X.A1.String()},
		{proof.Bs.Y.A0.String(), proof.Bs.Y.A1.String()},
	}

	// C point
	c := [2]string{
		proof.Krs.X.String(),
		proof.Krs.Y.String(),
	}

	log.Println("======ExportProofForSolidity: =======")
	fmt.Println("a:", a)
	fmt.Println("b:", b)
	fmt.Println("c:", c)
}

func ExportPublicInputs(w witness.Witness) []string {
	public, _ := w.Public()

	elems := public.Vector().(fr.Vector)
	result := []string{}

	for _, e := range elems {
		bi := e.BigInt(new(big.Int)) // fr.Element → *big.Int
		result = append(result, bi.String())
	}

	return result
}
