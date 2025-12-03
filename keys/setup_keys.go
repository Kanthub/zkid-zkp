// Generate Groth16 ProvingKey and VerifyingKey based on the circuit
package setup_keys

import (
	"log"
	"os"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"

	"github.com/kanthub/zkid-zkp/circuits"
)

func GenerateKeys() (groth16.ProvingKey, groth16.VerifyingKey) {
	log.Println("Step 1: Compiling circuit...")

	var circuit circuits.Circuit
	field := fr.Modulus()

	cs, err := frontend.Compile(field, r1cs.NewBuilder, &circuit)
	if err != nil {
		log.Fatalf("Circuit compilation failed: %v", err)
	}
	log.Println("Circuit compiled successfully")

	log.Println("Step 2: Running Groth16 Setup...")
	pk, vk, err := groth16.Setup(cs)
	if err != nil {
		log.Fatalf("Setup failed: %v", err)
	}
	log.Println("Setup completed")

	// ----------------------------------------------------------------------
	// 1) Save the ProvingKey (this is allowed)
	// ----------------------------------------------------------------------
	pkFile, err := os.Create("age_pk.bin")
	if err != nil {
		log.Fatalf("Failed to create pk file: %v", err)
	}
	defer pkFile.Close()

	if _, err := pk.WriteTo(pkFile); err != nil {
		log.Fatalf("Failed to write pk file: %v", err)
	}
	log.Println("Successfully saved age_pk.bin")

	// ----------------------------------------------------------------------
	// 2) Cannot serialize the VerifyingKey anymore!
	//    The official library has removed VK's WriteTo / ReadFrom / encoding capability
	//    The VerifyingKey must be used directly to generate the Solidity verifier
	// ----------------------------------------------------------------------

	// vkFile, err := os.Create("age_vk.bin")
	// if err != nil {
	// 	log.Fatalf("Failed to create vk file: %v", err)
	// }
	// defer vkFile.Close()

	// if _, err := vk.WriteTo(vkFile); err != nil {
	// 	log.Fatalf("Failed to write vk file: %v", err)
	// }
	// log.Println("Successfully saved age_vk.bin")
	log.Println("⚠ Skipped saving age_vk.bin (unsupported by modern gnark)")

	// ----------------------------------------------------------------------
	// 3) Export the Solidity verifier contract directly
	// ----------------------------------------------------------------------
	verifierFile, err := os.Create("AgeVerifier.sol")
	if err != nil {
		log.Fatalf("Failed to create AgeVerifier.sol: %v", err)
	}
	defer verifierFile.Close()

	if err := vk.ExportSolidity(verifierFile); err != nil {
		log.Fatalf("Failed to export solidity verifier: %v", err)
	}

	log.Println("Successfully exported AgeVerifier.sol")
	log.Println("🔵 Groth16 Key Generation Finished")

	return pk, vk
}
