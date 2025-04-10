// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package edwards25519 implements RFC9380 for the edwards25519 group, and returns points and scalars in
// filippo.io/edwards25519.
package edwards25519

import (
	"crypto"
	"math/big"

	"filippo.io/edwards25519"
	"filippo.io/edwards25519/field"

	"github.com/bytemare/hash2curve"
)

const (
	// H2C represents the hash-to-curve string identifier.
	H2C = "edwards25519_XMD:SHA-512_ELL2_RO_"

	// E2C represents the encode-to-curve string identifier.
	E2C = "edwards25519_XMD:SHA-512_ELL2_NU_"

	canonicalEncodingLength = 32
)

// HashToCurve implements hash-to-curve mapping to Edwards25519 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToCurve(input, dst []byte) *edwards25519.Point {
	u := hash2curve.HashToFieldXMD(crypto.SHA512, input, dst, 2, 1, 48, fieldPrime())
	q0 := element(adjust(u[0].Bytes()))
	q1 := element(adjust(u[1].Bytes()))
	p0 := Elligator2Edwards(q0)
	p1 := Elligator2Edwards(q1)
	p0.Add(p0, p1)
	p0.MultByCofactor(p0)

	return p0
}

// EncodeToCurve implements encode-to-curve mapping to Edwards25519 of input with dst.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func EncodeToCurve(input, dst []byte) *edwards25519.Point {
	q := hash2curve.HashToFieldXMD(crypto.SHA512, input, dst, 1, 1, 48, fieldPrime())
	b := adjust(q[0].Bytes())
	p0 := Elligator2Edwards(element(b))
	p0.MultByCofactor(p0)

	return p0
}

// HashToScalar returns a safe mapping of the arbitrary input to a scalar for the Edwards25519 group.
// The DST must not be empty or nil, and is recommended to be longer than 16 bytes.
func HashToScalar(input, dst []byte) *edwards25519.Scalar {
	orderBytes := []byte{
		237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 16,
	}
	order := new(big.Int).SetBytes(orderBytes)

	sc := hash2curve.HashToFieldXMD(crypto.SHA512, input, dst, 1, 1, 48, order)
	b := adjust(sc[0].Bytes())

	s, err := edwards25519.NewScalar().SetCanonicalBytes(b)
	if err != nil {
		panic(err)
	}

	return s
}

// fieldPrime returns the prime 2^255 - 19 for the field of elements.
func fieldPrime() *big.Int {
	// p25519 is the prime 2^255 - 19 for the field.
	// = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed.
	// = 57896044618658097711785492504343953926634992332820282019728792003956564819949.
	p25519 := []byte{
		127, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
		255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 237,
	}

	return new(big.Int).SetBytes(p25519)
}

func fe() *field.Element {
	return new(field.Element)
}

func element(input []byte) *field.Element {
	e, err := new(field.Element).SetBytes(input)
	if err != nil {
		panic(err)
	}

	return e
}

func adjust(in []byte) []byte {
	// If necessary, build a buffer of right size, so it gets correctly interpreted.
	if l := canonicalEncodingLength - len(in); l > 0 {
		buf := make([]byte, l, canonicalEncodingLength)
		buf = append(buf, in...)
		in = buf
	}

	// Reverse, because filippo.io/edwards25519 works in little-endian
	return reverse(in)
}

func reverse(b []byte) []byte {
	l := len(b) - 1
	for i := range len(b) / 2 {
		b[i], b[l-i] = b[l-i], b[i]
	}

	return b
}

// Elligator2Edwards maps the field element to a point on Edwards25519.
func Elligator2Edwards(e *field.Element) *edwards25519.Point {
	u, v := Elligator2Montgomery(e)
	x, y := MontgomeryToEdwards(u, v)

	return AffineToEdwards(x, y)
}

// Elligator2Montgomery implements the Elligator2 mapping to Curve25519.
func Elligator2Montgomery(e *field.Element) (x, y *field.Element) {
	one := fe().One()
	a := element([]byte{
		6, 109, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	})

	two := fe().Add(one, one)
	minA := fe().Negate(a)
	minOne := fe().Negate(one)

	t1 := fe().Square(e)     // u^2
	t1.Multiply(t1, two)     // t1 = 2u^2
	e1 := t1.Equal(minOne)   //
	t1.Swap(fe().Zero(), e1) // if 2u^2 == -1, t1 = 0

	x1 := fe().Add(t1, one) // t1 + 1
	x1.Invert(x1)           // 1 / (t1 + 1)
	x1.Multiply(x1, minA)   // x1 = -A / (t1 + 1).

	gx1 := fe().Add(x1, a) // x1 + A
	gx1.Multiply(gx1, x1)  // x1 * (x1 + A)
	gx1.Add(gx1, one)      // x1 * (x1 + A) + 1
	gx1.Multiply(gx1, x1)  // x1 * (x1 * (x1 + A) + 1)

	x2 := fe().Negate(x1) // -x1
	x2.Subtract(x2, a)    // -x2 - A

	gx2 := fe().Multiply(t1, gx1) // t1 * gx1

	root1, _isSquare := fe().SqrtRatio(gx1, one) // root1 = (+) sqrt(gx1)
	negRoot1 := fe().Negate(root1)               // negRoot1 = (-) sqrt(gx1)
	root2, _ := fe().SqrtRatio(gx2, one)         // root2 = (+) sqrt(gx2)

	// if gx1 is square, set the point to (x1, -root1)
	// if not, set the point to (x2, +root2)
	if _isSquare == 1 {
		x = x1
		y = negRoot1 // set sgn0(y) == 1, i.e. negative
	} else {
		x = x2
		y = root2 // set sgn0(y) == 0, i.e. positive
	}

	return x, y
}

// AffineToEdwards takes the affine coordinates of an Edwards25519 and returns a pointer to Point, represented in
// extended projective coordinates.
func AffineToEdwards(x, y *field.Element) *edwards25519.Point {
	t := fe().Multiply(x, y)

	p, err := new(edwards25519.Point).SetExtendedCoordinates(x, y, fe().One(), t)
	if err != nil {
		panic(err)
	}

	return p
}

// MontgomeryToEdwards lifts a Curve25519 point to its Edwards25519 equivalent.
func MontgomeryToEdwards(u, v *field.Element) (x, y *field.Element) {
	invsqrtD := element([]byte{
		6, 126, 69, 255, 170, 4, 110, 204, 130, 26, 125, 75, 209, 211, 161, 197,
		126, 79, 252, 3, 220, 8, 123, 210, 187, 6, 160, 96, 244, 237, 38, 15,
	})

	x = fe().Invert(v)
	x.Multiply(x, u)
	x.Multiply(x, invsqrtD)

	y = MontgomeryUToEdwardsY(u)

	return x, y
}

// MontgomeryUToEdwardsY transforms a Curve25519 x (or u) coordinate to an Edwards25519 y coordinate.
func MontgomeryUToEdwardsY(u *field.Element) *field.Element {
	one := fe().One()
	u1 := fe().Subtract(u, one)
	u2 := fe().Add(u, one)

	return u1.Multiply(u1, u2.Invert(u2))
}
