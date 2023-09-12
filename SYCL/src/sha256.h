/* Modifications Copyright (C) 2023 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2, as published
 * by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

/*
 * BitCracker: BitLocker password cracking tool, CUDA version.
 * Copyright (C) 2013-2017  Elena Ago <elena dot ago at gmail dot com>
 *							Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 * 
 * This file is part of the BitCracker project: https://github.com/e-ago/bitcracker
 * 
 * BitCracker is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * 
 * BitCracker is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with BitCracker. If not, see <http://www.gnu.org/licenses/>.
 */

#include <sycl/sycl.hpp>

#define ROR07(x) (((x) << 25) | ((x) >> 7))
#define ROR18(x) (((x) << 14) | ((x) >> 18))

#define ROR17(x) (((x) << 15) | ((x) >> 17))
#define ROR19(x) (((x) << 13) | ((x) >> 19))

// #define SWAP_UINT32(x) (((x) >> 24) | (((x) & 0x00FF0000) >> 8) | (((x) & 0x0000FF00) << 8) | ((x) << 24))
#define __dpcpp_inline__ __inline__ __attribute__((always_inline))

static __dpcpp_inline__ uint32_t LOP3LUT_XOR(uint32_t a, uint32_t b, uint32_t c) {
    return a^b^c;
}

static __dpcpp_inline__ uint32_t LOP3LUT_XORAND(uint32_t g, uint32_t e, uint32_t f) {
    return (g ^ (e & (f ^ g)));
}

static __dpcpp_inline__ uint32_t LOP3LUT_ANDOR(uint32_t a, uint32_t b, uint32_t c) {
    return  ((a & (b | c)) | (b & c));
}

#define SCHEDULE00()  \
		schedule00 = schedule16 + schedule25 \
			+ LOP3LUT_XOR(ROR07(schedule17) , ROR18(schedule17) , (schedule17 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule30) , ROR19(schedule30) , (schedule30 >> 10));

#define SCHEDULE01()  \
		schedule01 = schedule17 + schedule26 \
			+ LOP3LUT_XOR(ROR07(schedule18) , ROR18(schedule18) , (schedule18 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule31) , ROR19(schedule31) , (schedule31 >> 10));

#define SCHEDULE02()  \
		schedule02 = schedule18 + schedule27 \
			+ LOP3LUT_XOR(ROR07(schedule19) , ROR18(schedule19) , (schedule19 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule00) , ROR19(schedule00) , (schedule00 >> 10));

#define SCHEDULE03()  \
		schedule03 = schedule19 + schedule28 \
			+ LOP3LUT_XOR(ROR07(schedule20) , ROR18(schedule20) , (schedule20 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule01) , ROR19(schedule01) , (schedule01 >> 10));

#define SCHEDULE04()  \
		schedule04 = schedule20 + schedule29 \
			+ LOP3LUT_XOR(ROR07(schedule21) , ROR18(schedule21) , (schedule21 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule02) , ROR19(schedule02) , (schedule02 >> 10));

#define SCHEDULE05()  \
		schedule05 = schedule21 + schedule30 \
			+ LOP3LUT_XOR(ROR07(schedule22) , ROR18(schedule22) , (schedule22 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule03) , ROR19(schedule03) , (schedule03 >> 10));

#define SCHEDULE06()  \
		schedule06 = schedule22 + schedule31 \
			+ LOP3LUT_XOR(ROR07(schedule23) , ROR18(schedule23) , (schedule23 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule04) , ROR19(schedule04) , (schedule04 >> 10));

#define SCHEDULE07()  \
		schedule07 = schedule23 + schedule00 \
			+ LOP3LUT_XOR(ROR07(schedule24) , ROR18(schedule24) , (schedule24 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule05) , ROR19(schedule05) , (schedule05 >> 10));

#define SCHEDULE08()  \
		schedule08 = schedule24 + schedule01 \
			+ LOP3LUT_XOR(ROR07(schedule25) , ROR18(schedule25) , (schedule25 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule06) , ROR19(schedule06) , (schedule06 >> 10));

#define SCHEDULE09()  \
		schedule09 = schedule25 + schedule02 \
			+ LOP3LUT_XOR(ROR07(schedule26) , ROR18(schedule26) , (schedule26 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule07) , ROR19(schedule07) , (schedule07 >> 10));

#define SCHEDULE10()  \
		schedule10 = schedule26 + schedule03 \
			+ LOP3LUT_XOR(ROR07(schedule27) , ROR18(schedule27) , (schedule27 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule08) , ROR19(schedule08) , (schedule08 >> 10));

#define SCHEDULE11()  \
		schedule11 = schedule27 + schedule04 \
			+ LOP3LUT_XOR(ROR07(schedule28) , ROR18(schedule28) , (schedule28 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule09) , ROR19(schedule09) , (schedule09 >> 10));

#define SCHEDULE12()  \
		schedule12 = schedule28 + schedule05 \
			+ LOP3LUT_XOR(ROR07(schedule29) , ROR18(schedule29) , (schedule29 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule10) , ROR19(schedule10) , (schedule10 >> 10));

#define SCHEDULE13()  \
		schedule13 = schedule29 + schedule06 \
			+ LOP3LUT_XOR(ROR07(schedule30) , ROR18(schedule30) , (schedule30 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule11) , ROR19(schedule11) , (schedule11 >> 10));

#define SCHEDULE14()  \
		schedule14 = schedule30 + schedule07 \
			+ LOP3LUT_XOR(ROR07(schedule31) , ROR18(schedule31) , (schedule31 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule12) , ROR19(schedule12) , (schedule12 >> 10));

#define SCHEDULE15()  \
		schedule15 = schedule31 + schedule08 \
			+ LOP3LUT_XOR(ROR07(schedule00) , ROR18(schedule00) , (schedule00 >> 3)) \
			+ LOP3LUT_XOR(ROR17(schedule13) , ROR19(schedule13) , (schedule13 >> 10));

#define SCHEDULE16()  \
		schedule16 = schedule00 + schedule09  \
			+ LOP3LUT_XOR( ROR07(schedule01), ROR18(schedule01), (schedule01 >> 3))  \
			+ LOP3LUT_XOR( ROR17(schedule14), ROR19(schedule14), (schedule14 >> 10));

#define SCHEDULE17()  \
		schedule17 = schedule01 + schedule10  \
			+ LOP3LUT_XOR(ROR07(schedule02) , ROR18(schedule02) , (schedule02 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule15) , ROR19(schedule15) , (schedule15 >> 10));

#define SCHEDULE18()  \
		schedule18 = schedule02 + schedule11  \
			+ LOP3LUT_XOR(ROR07(schedule03) ,ROR18(schedule03) ,(schedule03 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule16), ROR19(schedule16), (schedule16 >> 10));
#define SCHEDULE19()  \
		schedule19 = schedule03 + schedule12  \
			+ LOP3LUT_XOR(ROR07(schedule04) , ROR18(schedule04) , (schedule04 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule17) , ROR19(schedule17) , (schedule17 >> 10));

#define SCHEDULE20()  \
		schedule20 = schedule04 + schedule13  \
			+ LOP3LUT_XOR(ROR07(schedule05) , ROR18(schedule05) , (schedule05 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule18) , ROR19(schedule18) , (schedule18 >> 10));

#define SCHEDULE21()  \
		schedule21 = schedule05 + schedule14  \
			+ LOP3LUT_XOR(ROR07(schedule06) , ROR18(schedule06) , (schedule06 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule19) , ROR19(schedule19) , (schedule19 >> 10));

#define SCHEDULE22()  \
		schedule22 = schedule06 + schedule15  \
			+ LOP3LUT_XOR(ROR07(schedule07) , ROR18(schedule07) , (schedule07 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule20) , ROR19(schedule20) , (schedule20 >> 10));

#define SCHEDULE23()  \
		schedule23 = schedule07 + schedule16  \
			+ LOP3LUT_XOR(ROR07(schedule08) , ROR18(schedule08) , (schedule08 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule21) , ROR19(schedule21) , (schedule21 >> 10));

#define SCHEDULE24()  \
		schedule24 = schedule08 + schedule17  \
			+ LOP3LUT_XOR(ROR07(schedule09) , ROR18(schedule09) , (schedule09 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule22) , ROR19(schedule22) , (schedule22 >> 10));

#define SCHEDULE25()  \
		schedule25 = schedule09 + schedule18  \
			+ LOP3LUT_XOR(ROR07(schedule10) , ROR18(schedule10) , (schedule10 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule23) , ROR19(schedule23) , (schedule23 >> 10));

#define SCHEDULE26()  \
		schedule26 = schedule10 + schedule19  \
			+ LOP3LUT_XOR(ROR07(schedule11) , ROR18(schedule11) , (schedule11 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule24) , ROR19(schedule24) , (schedule24 >> 10));

#define SCHEDULE27()  \
		schedule27 = schedule11 + schedule20  \
			+ LOP3LUT_XOR(ROR07(schedule12) , ROR18(schedule12) , (schedule12 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule25) , ROR19(schedule25) , (schedule25 >> 10));

#define SCHEDULE28()  \
		schedule28 = schedule12 + schedule21  \
			+ LOP3LUT_XOR(ROR07(schedule13) , ROR18(schedule13) , (schedule13 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule26) , ROR19(schedule26) , (schedule26 >> 10));

#define SCHEDULE29()  \
		schedule29 = schedule13 + schedule22  \
			+ LOP3LUT_XOR(ROR07(schedule14) , ROR18(schedule14) , (schedule14 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule27) , ROR19(schedule27) , (schedule27 >> 10));

#define SCHEDULE30()  \
		schedule30 = schedule14 + schedule23  \
			+ LOP3LUT_XOR(ROR07(schedule15) , ROR18(schedule15) , (schedule15 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule28) , ROR19(schedule28) , (schedule28 >> 10));

#define SCHEDULE31()  \
		schedule31 = schedule15 + schedule24  \
			+ LOP3LUT_XOR(ROR07(schedule16) , ROR18(schedule16) , (schedule16 >> 3))  \
			+ LOP3LUT_XOR(ROR17(schedule29) , ROR19(schedule29) , (schedule29 >> 10));

#define ROR06(x) (((x) << 26) | ((x) >> 6))
#define ROR11(x) (((x) << 21) | ((x) >> 11))
#define ROR25(x) (((x) << 7) | ((x) >> 25))

#define ROR02(x) (((x) << 30) | ((x) >> 2))
#define ROR13(x) (((x) << 19) | ((x) >> 13))
#define ROR22(x) (((x) << 10) | ((x) >> 22))

#define ROUND(a, b, c, d, e, f, g, h, W, k) \
		h += LOP3LUT_XOR(ROR06(e), ROR11(e), ROR25(e)) + LOP3LUT_XORAND(g,e,f) + k + W; \
		d += h;  \
		h += LOP3LUT_XOR(ROR02(a), ROR13(a), ROR22(a)) + LOP3LUT_ANDOR(a,b,c);

#define ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, i, k, indexW) \
		h += LOP3LUT_XOR(ROR06(e), ROR11(e), ROR25(e)) + LOP3LUT_XORAND(g,e,f) + k + w_words_uint32[(indexW + i)]; \
		d += h;  \
		h += LOP3LUT_XOR(ROR02(a), ROR13(a), ROR22(a)) + LOP3LUT_ANDOR(a,b,c);

#define ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h, i, k, w) \
		h += LOP3LUT_XOR(ROR06(e), ROR11(e), ROR25(e)) + LOP3LUT_XORAND(g,e,f) + k +  w; \
		d += h;  \
		h += LOP3LUT_XOR(ROR02(a), ROR13(a), ROR22(a)) + LOP3LUT_ANDOR(a,b,c);

#define ALL_SCHEDULE_LAST16() \
		SCHEDULE16() \
		SCHEDULE17() \
		SCHEDULE18() \
		SCHEDULE19() \
		SCHEDULE20() \
		SCHEDULE21() \
		SCHEDULE22() \
		SCHEDULE23() \
		SCHEDULE24() \
		SCHEDULE25() \
		SCHEDULE26() \
		SCHEDULE27() \
		SCHEDULE28() \
		SCHEDULE29() \
		SCHEDULE30() \
		SCHEDULE31() 

#define ALL_SCHEDULE32() \
		SCHEDULE00() \
		SCHEDULE01() \
		SCHEDULE02() \
		SCHEDULE03() \
		SCHEDULE04() \
		SCHEDULE05() \
		SCHEDULE06() \
		SCHEDULE07() \
		SCHEDULE08() \
		SCHEDULE09() \
		SCHEDULE10() \
		SCHEDULE11() \
		SCHEDULE12() \
		SCHEDULE13() \
		SCHEDULE14() \
		SCHEDULE15() \
		SCHEDULE16() \
		SCHEDULE17() \
		SCHEDULE18() \
		SCHEDULE19() \
		SCHEDULE20() \
		SCHEDULE21() \
		SCHEDULE22() \
		SCHEDULE23() \
		SCHEDULE24() \
		SCHEDULE25() \
		SCHEDULE26() \
		SCHEDULE27() \
		SCHEDULE28() \
		SCHEDULE29() \
		SCHEDULE30() \
		SCHEDULE31() 

#define ALL_ROUND_B1_1() \
		ROUND(a, b, c, d, e, f, g, h, schedule00, 0x428A2F98) \
		ROUND(h, a, b, c, d, e, f, g, schedule01, 0x71374491) \
		ROUND(g, h, a, b, c, d, e, f, schedule02, 0xB5C0FBCF) \
		ROUND(f, g, h, a, b, c, d, e, schedule03, 0xE9B5DBA5) \
		ROUND(e, f, g, h, a, b, c, d, schedule04, 0x3956C25B) \
		ROUND(d, e, f, g, h, a, b, c, schedule05, 0x59F111F1) \
		ROUND(c, d, e, f, g, h, a, b, schedule06, 0x923F82A4) \
		ROUND(b, c, d, e, f, g, h, a, schedule07, 0xAB1C5ED5) \
		ROUND(a, b, c, d, e, f, g, h, schedule08, 0xD807AA98) \
		ROUND(h, a, b, c, d, e, f, g, schedule09, 0x12835B01) \
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE) \
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3) \
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74) \
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE) \
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7) \
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174) \
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1) \
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786) \
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6) \
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC) \
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F) \
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA) \
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC) \
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA) \
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152) \
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D) \
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8) \
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7) \
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3) \
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147) \
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351) \
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967) 

#define ALL_ROUND_B1_2() \
        ROUND(a, b, c, d, e, f, g, h, schedule00, 0x27B70A85) \
        ROUND(h, a, b, c, d, e, f, g, schedule01, 0x2E1B2138) \
        ROUND(g, h, a, b, c, d, e, f, schedule02, 0x4D2C6DFC) \
        ROUND(f, g, h, a, b, c, d, e, schedule03, 0x53380D13) \
        ROUND(e, f, g, h, a, b, c, d, schedule04, 0x650A7354) \
        ROUND(d, e, f, g, h, a, b, c, schedule05, 0x766A0ABB) \
        ROUND(c, d, e, f, g, h, a, b, schedule06, 0x81C2C92E) \
        ROUND(b, c, d, e, f, g, h, a, schedule07, 0x92722C85) \
        ROUND(a, b, c, d, e, f, g, h, schedule08, 0xA2BFE8A1) \
        ROUND(h, a, b, c, d, e, f, g, schedule09, 0xA81A664B) \
        ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70) \
        ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3) \
        ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819) \
        ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624) \
        ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585) \
        ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070) \
        ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116) \
        ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08) \
        ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C) \
        ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5) \
        ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3) \
        ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A) \
        ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F) \
        ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3) \
        ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE) \
        ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F) \
        ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814) \
        ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208) \
        ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA) \
        ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB) \
        ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7) \
        ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2) 
