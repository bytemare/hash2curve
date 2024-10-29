// SPDX-License-Identifier: MIT
//
// Copyright (C) 2020-2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package secp256k1 implements RFC9380 for the secp256k1 group.
package secp256k1

import (
	"crypto"
	"math"
	"math/big"

	"github.com/bytemare/hash2curve"
	"github.com/bytemare/hash2curve/internal"
	"github.com/bytemare/hash2curve/internal/field"
)

const (
	// H2C represents the hash-to-curve string identifier for secp256k1.
	H2C = "secp256k1_XMD:SHA-256_SSWU_RO_"

	// E2C represents the encode-to-curve string identifier for secp256k1.
	E2C = "secp256k1_XMD:SHA-256_SSWU_NU_"

	scalarLength = 32
	secLength    = 48
)

type disallowEqual [0]func()

// Point represents a point on the secp256k1 curve, internally represented in affine coordinates. Standard projective
// coordinates are not necessary here since we only do simple operations that work well enough in the affine system.
type Point struct {
	_    disallowEqual
	X, Y big.Int
}

// Bytes returns the compressed 33-byte representation of the point on the secp256k1 curve.
func (p *Point) Bytes() []byte {
	var output [33]byte

	nonZero := byte(math.Abs(float64(p.X.Sign()))) & byte(math.Abs(float64(p.Y.Sign())))
	sign := byte(2 | p.Y.Bit(0)&1)
	output[0] = (nonZero * sign) & 3 // if nonZero == 0, result is 0, and sign otherwise.
	p.X.FillBytes(output[1:])

	return output[:]
}

// HashToCurve implements hash-to-curve mapping to secp256k1 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToCurve(input, dst []byte) *Point {
	u := hash2curve.HashToFieldXMD(crypto.SHA256, input, dst, 2, 1, secLength, fp.Order())
	q0 := map2IsoCurve(u[0])
	q1 := map2IsoCurve(u[1])
	q0.add(q1)

	return isogeny3iso(q0)
}

// EncodeToCurve implements encode-to-curve mapping to secp256k1 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToCurve(input, dst []byte) *Point {
	u := hash2curve.HashToFieldXMD(crypto.SHA256, input, dst, 1, 1, secLength, fp.Order())
	q0 := map2IsoCurve(u[0])

	return isogeny3iso(q0)
}

// HashToScalar returns a safe mapping of the arbitrary input to a scalar for the prime-order group of secp256k1.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *big.Int {
	s := hash2curve.HashToFieldXMD(crypto.SHA256, input, dst, 1, 1, secLength, fn.Order())[0]

	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	bytes := s.Bytes()

	length := scalarLength
	if l := length - len(bytes); l > 0 {
		buf := make([]byte, l, length)
		buf = append(buf, bytes...)
		bytes = buf
	}

	return new(big.Int).SetBytes(bytes)
}

// add uses an affine add because the others are tailored for a = 0 and b = 7.
func (p *Point) add(element *Point) *Point {
	var t0, t1, ll, x, y big.Int
	x1, y1 := &p.X, &p.Y
	x2, y2 := &element.X, &element.Y

	fp.Sub(&t0, y2, y1)   // (y2-y1)
	fp.Sub(&t1, x2, x1)   // (x2-x1)
	fp.Inv(&t1, &t1)      // 1/(x2-x1)
	fp.Mul(&ll, &t0, &t1) // l = (y2-y1)/(x2-x1).

	fp.Square(&t0, &ll)  // l^2
	fp.Sub(&t0, &t0, x1) // l^2-x1
	fp.Sub(&x, &t0, x2)  // X' = l^2-x1-x2

	fp.Sub(&t0, x1, &x)   // x1-x3
	fp.Mul(&t0, &t0, &ll) // l(x1-x3)
	fp.Sub(&y, &t0, y1)   // y3 = l(x1-x3)-y1.

	p.X.Set(&x)
	p.Y.Set(&y)

	return p
}

var (
	// field order: 2^256 - 2^32 - 977
	// = 115792089237316195423570985008687907853269984665640564039457584007908834671663
	// = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f.
	fp = field.NewField(new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
	}))

	// group order: 2^256 - 432420386565659656852420866394968145599
	// = 115792089237316195423570985008687907852837564279074904382605163141518161494337
	// = xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141.
	fn = field.NewField(new(big.Int).SetBytes([]byte{
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254,
		186, 174, 220, 230, 175, 72, 160, 59, 191, 210, 94, 140, 208, 54, 65, 65,
	}))

	mapZ = new(big.Int).Mod(big.NewInt(-11), fp.Order())

	// 0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533.
	secp256k13ISOA = new(big.Int).SetBytes([]byte{
		63, 135, 49, 171, 221, 102, 26, 220, 160, 138, 85, 88, 240, 245, 210, 114,
		233, 83, 211, 99, 203, 111, 14, 93, 64, 84, 71, 192, 26, 68, 69, 51,
	})
	secp256k13ISOB = new(big.Int).SetBytes([]byte{6, 235}) // 1771.
)

func newPoint(x, y *big.Int) *Point {
	return &Point{
		X: *new(big.Int).Set(x),
		Y: *new(big.Int).Set(y),
	}
}

func map2IsoCurve(fe *big.Int) *Point {
	x, y := internal.MapToCurveSSWU(&fp, secp256k13ISOA, secp256k13ISOB, mapZ, fe)
	return newPoint(x, y)
}

func isogeny3iso(e *Point) *Point {
	x, y, isIdentity := isogenySecp256k13iso(&e.X, &e.Y)

	if isIdentity {
		return newPoint(new(big.Int), new(big.Int))
	}

	// We can save cofactor clearing because it is 1.
	return newPoint(x, y)
}

func stringToInt(s string) *big.Int {
	i, _ := new(big.Int).SetString(s, 0)
	return i
}

var (
	_k10 = stringToInt("0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa8c7")
	_k11 = stringToInt("0x07d3d4c80bc321d5b9f315cea7fd44c5d595d2fc0bf63b92dfff1044f17c6581")
	_k12 = stringToInt("0x534c328d23f234e6e2a413deca25caece4506144037c40314ecbd0b53d9dd262")
	_k13 = stringToInt("0x8e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38e38daaaaa88c")
	_k20 = stringToInt("0xd35771193d94918a9ca34ccbb7b640dd86cd409542f8487d9fe6b745781eb49b")
	_k21 = stringToInt("0xedadc6f64383dc1df7c4b2d51b54225406d36b641f5e41bbc52a56612a8c6d14")
	_k30 = stringToInt("0x4bda12f684bda12f684bda12f684bda12f684bda12f684bda12f684b8e38e23c")
	_k31 = stringToInt("0xc75e0c32d5cb7c0fa9d0a54b12a0a6d5647ab046d686da6fdffc90fc201d71a3")
	_k32 = stringToInt("0x29a6194691f91a73715209ef6512e576722830a201be2018a765e85a9ecee931")
	_k33 = stringToInt("0x2f684bda12f684bda12f684bda12f684bda12f684bda12f684bda12f38e38d84")
	_k40 = stringToInt("0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffff93b")
	_k41 = stringToInt("0x7a06534bb8bdb49fd5e9e6632722c2989467c1bfc8e8d978dfb425d2685c2573")
	_k42 = stringToInt("0x6484aa716545ca2cf3a70c3fa8fe337e0a3d21162f0d6299a7bf8192bfd2a76f")
)

// isogenySecp256k13iso is a 3-degree isogeny from secp256k1 3-ISO to the secp256k1 elliptic curve.
func isogenySecp256k13iso(x, y *big.Int) (px, py *big.Int, isIdentity bool) {
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
