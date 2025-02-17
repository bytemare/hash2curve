// SPDX-License-Identifier: MIT
//
// Copyright (C) 2024 Daniel Bourdrez. All Rights Reserved.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree or at
// https://spdx.org/licenses/MIT.html

package internal

import (
	"math/big"

	"github.com/bytemare/hash2curve/nist/internal/field"
)

// MapToCurveSSWU implements the Simplified SWU method for Weierstrass curves for any base field.
func MapToCurveSSWU(fp *field.Field, a, b, z, fe *big.Int) (x, y *big.Int) {
	var tv1, tv2, tv3, tv4, tv5, tv6, _y1 big.Int
	x, y = new(big.Int), new(big.Int)

	fp.Square(&tv1, fe)          //    1.  tv1 = u^2
	fp.Mul(&tv1, z, &tv1)        //    2.  tv1 = Z * tv1
	fp.Square(&tv2, &tv1)        //    3.  tv2 = tv1^2
	fp.Add(&tv2, &tv2, &tv1)     //    4.  tv2 = tv2 + tv1
	fp.Add(&tv3, &tv2, fp.One()) //    5.  tv3 = tv2 + 1
	fp.Mul(&tv3, b, &tv3)        //    6.  tv3 = B * tv3
	fp.CondMov(&tv4, z,
		fp.Neg(&big.Int{}, &tv2),
		!fp.IsZero(&tv2)) //    7.  tv4 = CMOV(Z, -tv2, tv2 != 0)
	fp.Mul(&tv4, a, &tv4)                            //    8.  tv4 = A * tv4
	fp.Square(&tv2, &tv3)                            //    9.  tv2 = tv3^2
	fp.Square(&tv6, &tv4)                            //    10. tv6 = tv4^2
	fp.Mul(&tv5, a, &tv6)                            //    11. tv5 = A * tv6
	fp.Add(&tv2, &tv2, &tv5)                         //    12. tv2 = tv2 + tv5
	fp.Mul(&tv2, &tv2, &tv3)                         //    13. tv2 = tv2 * tv3
	fp.Mul(&tv6, &tv6, &tv4)                         //    14. tv6 = tv6 * tv4
	fp.Mul(&tv5, b, &tv6)                            //    15. tv5 = B * tv6
	fp.Add(&tv2, &tv2, &tv5)                         //    16. tv2 = tv2 + tv5
	fp.Mul(x, &tv1, &tv3)                            //    17.   x = tv1 * tv3
	isGx1Square := fp.SqrtRatio(&_y1, z, &tv2, &tv6) //    18. isGx1Square, y1 = sqrt_ratio(tv2, tv6)
	fp.Mul(y, &tv1, fe)                              //    19.   y = tv1 * u
	fp.Mul(y, y, &_y1)                               //    20.   y = y * y1
	fp.CondMov(x, x, &tv3, isGx1Square)              //    21.   x = CMOV(x, tv3, isGx1Square)
	fp.CondMov(y, y, &_y1, isGx1Square)              //    22.   y = CMOV(y, y1, isGx1Square)
	e1 := fp.Sgn0(fe) == fp.Sgn0(y)                  //    23.  e1 = sgn0(u) == sgn0(y)
	fp.CondMov(y, fp.Neg(&big.Int{}, y), y, e1)      //    24.   y = CMOV(-y, y, e1)
	fp.Inv(&tv4, &tv4)                               //    25.   1 / tv4
	fp.Mul(x, x, &tv4)                               //	 26.   x = x / tv4

	return x, y
}
