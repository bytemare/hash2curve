// SPDX-License-Identifier: MIT
//
// Copyright (C) 2021-2023-2023 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package hash2curve

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/bytemare/hash2curve/internal/field"
)

const (
	secp256k1FieldOrder = "115792089237316195423570985008687907853269984665640564039457584007908834671663"
)

var (
	initOnceSecp256k1 sync.Once
	secp256k1Field    field.Field
)

func setString(s string, base int) *big.Int {
	i := new(big.Int)
	if _, ok := i.SetString(s, base); !ok {
		panic(fmt.Sprintf("setting int in base %d failed: %v", base, s))
	}

	return i
}

func initSecp256k1() {
	secp256k1Field = field.NewField(setString(secp256k1FieldOrder, 10))
}

var (
	_k10 = setString("0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7", 0)
	_k11 = setString("0x07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581", 0)
	_k12 = setString("0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262", 0)
	_k13 = setString("0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c", 0)
	_k20 = setString("0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b", 0)
	_k21 = setString("0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14", 0)
	_k30 = setString("0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c", 0)
	_k31 = setString("0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3", 0)
	_k32 = setString("0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931", 0)
	_k33 = setString("0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84", 0)
	_k40 = setString("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b", 0)
	_k41 = setString("0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573", 0)
	_k42 = setString("0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f", 0)
)

// IsogenySecp256k13iso is a 3-degree isogeny from Secp256k1 3-ISO to the Secp256k1 elliptic curve.
func IsogenySecp256k13iso(x, y *big.Int) (px, py *big.Int, isIdentity bool) {
	initOnceSecp256k1.Do(initSecp256k1)

	fp := secp256k1Field
	var x2, x3, k11, k12, k13, k21, k31, k32, k33, k41, k42 big.Int
	fp.Mul(&x2, x, x)
	fp.Mul(&x3, &x2, x)

	// x_num, x_den
	var xNum big.Int
	fp.Mul(&k13, _k13, &x3) // _k(1,3) * x'^3
	fp.Mul(&k12, _k12, &x2) // _k(1,2) * x'^2
	fp.Mul(&k11, _k11, x)   // _k(1,1) * x'
	fp.Add(&xNum, &k13, &k12)
	fp.Add(&xNum, &xNum, &k11)
	fp.Add(&xNum, &xNum, _k10)

	var xDen big.Int
	fp.Mul(&k21, _k21, x) // _k(2,1) * x'
	fp.Add(&xDen, &x2, &k21)
	fp.Add(&xDen, &xDen, _k20)

	// y_num, y_den
	var yNum big.Int
	fp.Mul(&k33, _k33, &x3) // _k(3,3) * x'^3
	fp.Mul(&k32, _k32, &x2) // _k(3,2) * x'^2
	fp.Mul(&k31, _k31, x)   // _k(3,1) * x'
	fp.Add(&yNum, &k33, &k32)
	fp.Add(&yNum, &yNum, &k31)
	fp.Add(&yNum, &yNum, _k30)

	var yDen big.Int
	fp.Mul(&k42, _k42, &x2) // _k(4,2) * x'^2
	fp.Mul(&k41, _k41, x)   // _k(4,1) * x'
	fp.Add(&yDen, &x3, &k42)
	fp.Add(&yDen, &yDen, &k41)
	fp.Add(&yDen, &yDen, _k40)

	// final x, y
	px, py = new(big.Int), new(big.Int)

	fp.Inv(px, &xDen)
	isIdentity = fp.IsZero(px)
	fp.Mul(px, px, &xNum)

	fp.Inv(py, &yDen)
	isIdentity = isIdentity || fp.IsZero(py)
	fp.Mul(py, py, &yNum)
	fp.Mul(py, py, y)

	return px, py, isIdentity
}
