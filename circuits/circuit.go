// circuits/age_ge/circuit.go
// 设计电路：比如在不暴露年龄的前提下，证明年龄 >= 18
package circuits

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/poseidon2"
)

// 更通用的电路定义，让 zkID 支持多种属性验证
type Circuit struct {

	// 公开输入（顺序很重要！因为 gnark 按照声明顺序处理公开输入）
	PolicyID  frontend.Variable `gnark:",public"`
	Version   frontend.Variable `gnark:",public"`
	C         frontend.Variable `gnark:",public"` // 属性的承诺值
	Threshold frontend.Variable `gnark:",public"`

	// 私有输入(顺序可随意)
	Name       frontend.Variable // 用户名
	Age        frontend.Variable // 用户年龄
	Nation     frontend.Variable // 国籍
	Address    frontend.Variable // 地址
	IdentityID frontend.Variable // 身份证号
	AttrValue  frontend.Variable // 属性值（比如用户面部 / 指纹）
	DID        frontend.Variable
}

// Define 定义电路约束
func (c *Circuit) Define(api frontend.API) error {
	// -------------------------------------------------
	// 1. Poseidon 哈希：h = Poseidon(policy_id, version, did, m, r)
	// -------------------------------------------------
	hasher, err := poseidon2.NewMerkleDamgardHasher(api)
	if err != nil {
		return err
	}

	// 写入要哈希的字段
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
	// 求和（得到 field 元素）
	h := hasher.Sum()

	api.Println("Poseidon hash result:", h)

	api.AssertIsEqual(h, c.C) // 断言哈希结果与公开承诺值一致

	// -------------------------------------------------
	// 2. HashToCurve 占位逻辑
	// -------------------------------------------------

	// -------------------------------------------------
	// 3. 年龄 >= 阈值 约束
	// -------------------------------------------------
	api.AssertIsLessOrEqual(c.Threshold, c.AttrValue)

	return nil
}
