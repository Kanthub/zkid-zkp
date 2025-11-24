// circuits/age_ge/circuit.go
// Circuit design: for example, proving "age ≥ 18" without revealing the actual age
package circuits

import (
	"github.com/consensys/gnark/frontend"
	mimc "github.com/consensys/gnark/std/hash/mimc"
)

// More general circuit definition, allowing zkID to support multiple attribute validations
type Circuit struct {

	// Public inputs (ordering is important! gnark processes public inputs in the declared order)
	PolicyID  frontend.Variable `gnark:",public"`
	Version   frontend.Variable `gnark:",public"`
	C         frontend.Variable `gnark:",public"` // Commitment of the attribute
	Threshold frontend.Variable `gnark:",public"`

	// Private inputs (order is flexible)
	Name       frontend.Variable // User name
	Age        frontend.Variable // User age
	Nation     frontend.Variable // Nationality
	Address    frontend.Variable // Address
	IdentityID frontend.Variable // Identity number
	AttrValue  frontend.Variable // Attribute value (e.g., face/fingerprint biometric)
	DID        frontend.Variable
}

// Define defines the circuit constraints

// The API is not a runtime executor. It encodes all arithmetic operations and
// comparisons into algebraic constraints, which form the zk circuit and can be
// proven in zero-knowledge.

func (c *Circuit) Define(api frontend.API) error {
	// -------------------------------------------------
	// 1. Poseidon hash: h = Poseidon(policy_id, version, did, m, r)
	// -------------------------------------------------
	// hasher, err := poseidon2.NewMerkleDamgardHasher(api)
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	// Write fields to hash
	hasher.Write(
		c.PolicyID,
		c.Version,
		c.Name,
		c.Age,
		c.Nation,
		c.Address,
		c.IdentityID,
		c.AttrValue,
		c.DID,
	)

	// Compute the hash output (as a field element)
	h := hasher.Sum()

	api.Println("Poseidon hash result:", h)

	api.AssertIsEqual(h, c.C) // Assert the hash result matches the public commitment

	// -------------------------------------------------
	// 2. HashToCurve placeholder logic (for future use)
	// -------------------------------------------------

	// -------------------------------------------------
	// 3. Age ≥ threshold constraint
	// -------------------------------------------------
	api.AssertIsLessOrEqual(c.Threshold, c.AttrValue)

	return nil
}
