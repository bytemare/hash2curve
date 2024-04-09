// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

// Package field provides modular operations over very high integers.
package field

import (
	"math/big"
)

var one = big.NewInt(1)

// Field represents a Galois Field.
type Field struct {
	order       *big.Int
	pMinus1div2 *big.Int // used in IsSquare
	pMinus2     *big.Int // used for Field big.Int inversion
	exp         *big.Int
}

// NewField returns a newly instantiated field for the given prime order.
func NewField(prime *big.Int) Field {
	// pMinus1div2 is used to determine whether a big Int is a quadratic square.
	pMinus1div2 := big.NewInt(1)
	pMinus1div2.Sub(prime, pMinus1div2)
	pMinus1div2.Rsh(pMinus1div2, 1)

	// pMinus2 is used for modular inversion.
	pMinus2 := big.NewInt(2)
	pMinus2.Sub(prime, pMinus2)

	// precompute e = (p + 1) / 4
	exp := big.NewInt(1)
	exp.Add(prime, exp)
	exp.Rsh(exp, 2)

	return Field{
		order:       prime,
		pMinus1div2: pMinus1div2,
		pMinus2:     pMinus2,
		exp:         exp,
	}
}

// One returns one big.Int of the finite Field.
func (f Field) One() *big.Int {
	return one
}

// Order returns the size of the Field.
func (f Field) Order() *big.Int {
	return f.order
}

// AreEqual returns whether both elements are equal.
func (f Field) AreEqual(f1, f2 *big.Int) bool {
	return f.IsZero(f.Sub(&big.Int{}, f1, f2))
}

// IsZero returns whether the big.Int is equivalent to zero.
func (f Field) IsZero(e *big.Int) bool {
	return e.Sign() == 0
}

// Inv sets res to the modular inverse of x mod field order.
func (f Field) Inv(res, x *big.Int) {
	f.Exponent(res, x, f.pMinus2)
}

// LegendreSymbol applies the Legendre symbole on (a/p) and returns either {-1, 0, 1} mod field order.
func (f Field) LegendreSymbol(a *big.Int) *big.Int {
	var res big.Int
	return f.Exponent(&res, a, f.pMinus1div2)
}

// Exponent returns x^n mod field order.
func (f Field) Exponent(res, x, n *big.Int) *big.Int {
	return res.Exp(x, n, f.order)
}

// IsSquare returns whether e is a quadratic square.
func (f Field) IsSquare(e *big.Int) bool {
	return f.AreEqual(f.LegendreSymbol(e), f.One())
}

// Mod reduces x modulo the field order.
func (f Field) Mod(x *big.Int) *big.Int {
	return x.Mod(x, f.order)
}

// Neg sets res to the -x modulo the field order.
func (f Field) Neg(res, x *big.Int) *big.Int {
	return f.Mod(res.Neg(x))
}

// Add sets res to x + y modulo the field order.
func (f Field) Add(res, x, y *big.Int) {
	f.Mod(res.Add(x, y))
}

// Sub sets res to x - y modulo the field order.
func (f Field) Sub(res, x, y *big.Int) *big.Int {
	return f.Mod(res.Sub(x, y))
}

// Mul sets res to the multiplication of x and y modulo the field order.
func (f Field) Mul(res, x, y *big.Int) {
	f.Mod(res.Mul(x, y))
}

// Square sets res to the square of x modulo the field order.
func (f Field) Square(res, x *big.Int) {
	f.Mod(res.Mul(x, x))
}

// CondMov sets res to y if b true, and to x otherwise.
func (f Field) CondMov(res, x, y *big.Int, b bool) {
	if b {
		res.Set(y)
	} else {
		res.Set(x)
	}
}

// Sgn0 returns the first bit in the big-endian representation.
func (f Field) Sgn0(x *big.Int) int {
	return int(x.Bit(0))
}

func (f Field) sqrt3mod4(res, e *big.Int) *big.Int {
	return f.Exponent(res, e, f.exp)
}

// SquareRoot sets res to a square root of e mod the field's order, if such a square root exists.
func (f Field) SquareRoot(res, e *big.Int) *big.Int {
	return f.sqrt3mod4(res, e)
}

// SqrtRatio res result to the square root of (e/v), and indicates whether (e/v) is a square.
func (f Field) SqrtRatio(res, zMapConstant, e, v *big.Int) bool {
	f.Inv(res, v)
	f.Mul(res, res, e)

	square := f.IsSquare(res)
	if !square {
		f.Mul(res, res, zMapConstant)
	}

	f.SquareRoot(res, res)

	return square
}
