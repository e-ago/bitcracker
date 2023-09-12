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
 *			    Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
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
#include "bitcracker.h"
#include "aes.h"

#define TIMER_START_() time_start_ = std::chrono::steady_clock::now();
#define TIMER_END_()                                                                         \
    time_end_ = std::chrono::steady_clock::now();                                            \
    time_total_  += std::chrono::duration<double, std::milli>(time_end_ - time_start_).count();
#define TIMER_PRINT_(name) std::cout << name <<": " << time_total_ / 1e3 << " s\n";

void encrypt(
	uint32_t k0,
	uint32_t k1,
	uint32_t k2,
	uint32_t k3,
	uint32_t k4,
	uint32_t k5,
	uint32_t k6,
	uint32_t k7,
	uint32_t m0,
	uint32_t m1,
	uint32_t m2,
	uint32_t m3,
	uint32_t * output0,
	uint32_t * output1,
	uint32_t * output2,
	uint32_t * output3,
	unsigned int *TS0,
	unsigned int *TS1,
	unsigned int *TS2,
	unsigned int *TS3)
{
	uint32_t enc_schedule0, enc_schedule1, enc_schedule2, enc_schedule3, enc_schedule4, enc_schedule5, enc_schedule6, enc_schedule7;
	uint32_t local_key0, local_key1, local_key2, local_key3, local_key4, local_key5, local_key6, local_key7;

	local_key0 = k0;
	local_key1 = k1;
	local_key2 = k2;
	local_key3 = k3;
	local_key4 = k4;
	local_key5 = k5;
	local_key6 = k6;
	local_key7 = k7;

    /*
    DPCT1004:55: Compatible DPC++ code could not be generated.
    enc_schedule0 = __byte_perm(m0, 0, 0x0123) ^ local_key0;
    */
    enc_schedule0 = __builtin_bswap32(m0) ^ local_key0;

    /*
    DPCT1004:56: Compatible DPC++ code could not be generated.
    enc_schedule1 = __byte_perm(m1, 0, 0x0123) ^ local_key1;
    */
    enc_schedule1 = __builtin_bswap32(m1) ^ local_key1;

    /*
    DPCT1004:57: Compatible DPC++ code could not be generated.
    enc_schedule2 = __byte_perm(m2, 0, 0x0123) ^ local_key2;
    */
    enc_schedule2 = __builtin_bswap32(m2) ^ local_key2;
    
    /*
    DPCT1004:58: Compatible DPC++ code could not be generated.
    enc_schedule3 = __byte_perm(m3, 0, 0x0123) ^ local_key3;
    */
    enc_schedule3 = __builtin_bswap32(m3) ^ local_key3;

    enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x01000000; //RCON[0];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x02000000; //RCON[1];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x04000000; //RCON[2];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x08000000; //RCON[3];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x10000000; //RCON[4];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x20000000; //RCON[5];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)       ] & 0xFF000000) ^
                  (TS0[(local_key3 >> 16) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key3 >>  8) & 0xFF] & 0x0000FF00) ^
                  (TS2[(local_key3      ) & 0xFF] & 0x000000FF);
	local_key5 ^= local_key4;
	local_key6 ^= local_key5;
	local_key7 ^= local_key6;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= (TS2[(local_key7 >> 24)       ] & 0x000000FF) ^
                  (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000) ^
                  (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000) ^
                  (TS1[(local_key7      ) & 0xFF] & 0x0000FF00) ^ 0x40000000; //RCON[6];
	local_key1 ^= local_key0;
	local_key2 ^= local_key1;
	local_key3 ^= local_key2;

	enc_schedule0 = (TS2[(enc_schedule4 >> 24)       ] & 0xFF000000) ^
		 (TS3[(enc_schedule5 >> 16) & 0xFF] & 0x00FF0000) ^
		 (TS0[(enc_schedule6 >>  8) & 0xFF] & 0x0000FF00) ^
		 (TS1[(enc_schedule7      ) & 0xFF] & 0x000000FF) ^ local_key0;

	enc_schedule1 = (TS2[(enc_schedule5 >> 24)       ] & 0xFF000000) ^
		 (TS3[(enc_schedule6 >> 16) & 0xFF] & 0x00FF0000) ^
		 (TS0[(enc_schedule7 >>  8) & 0xFF] & 0x0000FF00) ^
		 (TS1[(enc_schedule4      ) & 0xFF] & 0x000000FF) ^ local_key1;

	enc_schedule2 = (TS2[(enc_schedule6 >> 24)       ] & 0xFF000000) ^
		 (TS3[(enc_schedule7 >> 16) & 0xFF] & 0x00FF0000) ^
		 (TS0[(enc_schedule4 >>  8) & 0xFF] & 0x0000FF00) ^
		 (TS1[(enc_schedule5      ) & 0xFF] & 0x000000FF) ^ local_key2;

	enc_schedule3 = (TS2[(enc_schedule7 >> 24)       ] & 0xFF000000) ^
		 (TS3[(enc_schedule4 >> 16) & 0xFF] & 0x00FF0000) ^
		 (TS0[(enc_schedule5 >>  8) & 0xFF] & 0x0000FF00) ^
		 (TS1[(enc_schedule6      ) & 0xFF] & 0x000000FF) ^ local_key3;

    /*
    DPCT1004:59: Compatible DPC++ code could not be generated.
    output0[0] = __byte_perm(enc_schedule0, 0, 0x0123);
    */
    output0[0] = __builtin_bswap32(enc_schedule0);

    /*
    DPCT1004:60: Compatible DPC++ code could not be generated.
    output1[0] = __byte_perm(enc_schedule1, 0, 0x0123);
    */
    output1[0] = __builtin_bswap32(enc_schedule1);

    /*
    DPCT1004:61: Compatible DPC++ code could not be generated.
    output2[0] = __byte_perm(enc_schedule2, 0, 0x0123);
    */
    output2[0] = __builtin_bswap32(enc_schedule2);

    /*
    DPCT1004:62: Compatible DPC++ code could not be generated.
    output3[0] = __byte_perm(enc_schedule3, 0, 0x0123);
    */
    output3[0] = __builtin_bswap32(enc_schedule3);
}

void decrypt_vmk_with_mac(
    uint32_t num_pswd_per_kernel_launch,
    int *found,
    unsigned char * vmkKey,
    unsigned char * vmkIV,
    unsigned char * mac,
    unsigned char * macIV,
    unsigned char * computedMacIV,
    int v0,
    int v1,
    int v2,
    int v3,
    uint32_t s0,
    uint32_t s1,
    uint32_t s2,
    uint32_t s3,
    uint32_t *pswd_uint32,
    uint32_t *w_words_uint32,
    unsigned int *TS0,
    unsigned int *TS1,
    unsigned int *TS2,
    unsigned int *TS3 ,
    sycl::nd_item<1> item //, sycl::stream out
    )
{
   	uint32_t schedule00, schedule01, schedule02, schedule03, schedule04, schedule05, schedule06, schedule07, schedule08, schedule09;
	uint32_t schedule10, schedule11, schedule12, schedule13, schedule14, schedule15, schedule16, schedule17, schedule18, schedule19;
	uint32_t schedule20, schedule21, schedule22, schedule23, schedule24, schedule25, schedule26, schedule27, schedule28, schedule29;
	uint32_t schedule30, schedule31;
	uint32_t first_hash0, first_hash1, first_hash2, first_hash3, first_hash4, first_hash5, first_hash6, first_hash7;
	uint32_t hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	uint32_t a, b, c, d, e, f, g, h;

    unsigned int tid = item.get_global_id(0);
    if (tid >= num_pswd_per_kernel_launch) return;
    int index_generic;  // goes from 0-0x100000
	int indexW;         // first index into pswd_uint32 and then index into w_words_uint32
	int8_t redo = 0;

	// while(tid < num_pswd_per_kernel_launch)
	{
		first_hash0 = UINT32_C(0x6A09E667);
		first_hash1 = UINT32_C(0xBB67AE85);
		first_hash2 = UINT32_C(0x3C6EF372);
		first_hash3 = UINT32_C(0xA54FF53A);
		first_hash4 = UINT32_C(0x510E527F);
		first_hash5 = UINT32_C(0x9B05688C);
		first_hash6 = UINT32_C(0x1F83D9AB);
		first_hash7 = UINT32_C(0x5BE0CD19);

		a = UINT32_C(0x6A09E667);
		b = UINT32_C(0xBB67AE85);
		c = UINT32_C(0x3C6EF372);
		d = UINT32_C(0xA54FF53A);
		e = UINT32_C(0x510E527F);
		f = UINT32_C(0x9B05688C);
		g = UINT32_C(0x1F83D9AB);
		h = UINT32_C(0x5BE0CD19);

    /**********************************************************************
    ***************************** FIRST HASH ******************************
    **********************************************************************/
		indexW = tid * PSWD_NUM_UINT32; // indexing into pswd_uint32 with block size of 32
		redo = 0;

        schedule00 = (uint32_t)(pswd_uint32[indexW +  0]);
        schedule01 = (uint32_t)(pswd_uint32[indexW +  1]);
        schedule02 = (uint32_t)(pswd_uint32[indexW +  2]);
        schedule03 = (uint32_t)(pswd_uint32[indexW +  3]);
        schedule04 = (uint32_t)(pswd_uint32[indexW +  4]);
        schedule05 = (uint32_t)(pswd_uint32[indexW +  5]);
        schedule06 = (uint32_t)(pswd_uint32[indexW +  6]);
        schedule07 = (uint32_t)(pswd_uint32[indexW +  7]);
        schedule08 = (uint32_t)(pswd_uint32[indexW +  8]);
        schedule09 = (uint32_t)(pswd_uint32[indexW +  9]);
        schedule10 = (uint32_t)(pswd_uint32[indexW + 10]);
        schedule11 = (uint32_t)(pswd_uint32[indexW + 11]);
        schedule12 = (uint32_t)(pswd_uint32[indexW + 12]);
        schedule13 = (uint32_t)(pswd_uint32[indexW + 13]);
        schedule14 = (uint32_t)(pswd_uint32[indexW + 14]);
		//Input password is shorter than FIRST_LENGHT
	    if(schedule14 == 0xFFFFFFFF) {
            schedule14 = 0;
        } else {
            redo = 1;
        }
        schedule15 = (uint32_t)(pswd_uint32[indexW + 15]);

        ALL_SCHEDULE_LAST16()
        ALL_ROUND_B1_1()
        ALL_SCHEDULE32()
        ALL_ROUND_B1_2()

        first_hash0 += a;
        first_hash1 += b;
        first_hash2 += c;
        first_hash3 += d;
        first_hash4 += e;
        first_hash5 += f;
        first_hash6 += g;
        first_hash7 += h;

        if(redo == 1)
        {
            schedule00 = (uint32_t)(pswd_uint32[indexW + 16]);
            schedule01 = (uint32_t)(pswd_uint32[indexW + 17]);
            schedule02 = (uint32_t)(pswd_uint32[indexW + 18]);
            schedule03 = (uint32_t)(pswd_uint32[indexW + 19]);
            schedule04 = (uint32_t)(pswd_uint32[indexW + 20]);
            schedule05 = (uint32_t)(pswd_uint32[indexW + 21]);
            schedule06 = (uint32_t)(pswd_uint32[indexW + 22]);
            schedule07 = (uint32_t)(pswd_uint32[indexW + 23]);
            schedule08 = (uint32_t)(pswd_uint32[indexW + 24]);
            schedule09 = (uint32_t)(pswd_uint32[indexW + 25]);
            schedule10 = (uint32_t)(pswd_uint32[indexW + 26]);
            schedule11 = (uint32_t)(pswd_uint32[indexW + 27]);
            schedule12 = (uint32_t)(pswd_uint32[indexW + 28]);
            schedule13 = (uint32_t)(pswd_uint32[indexW + 29]);
            schedule14 = (uint32_t)(pswd_uint32[indexW + 30]);
            schedule15 = (uint32_t)(pswd_uint32[indexW + 31]);

            a = first_hash0;
            b = first_hash1;
            c = first_hash2;
            d = first_hash3;
            e = first_hash4;
            f = first_hash5;
            g = first_hash6;
            h = first_hash7;

            ALL_SCHEDULE_LAST16()
            ALL_ROUND_B1_1()
            ALL_SCHEDULE32()
            ALL_ROUND_B1_2()
        
            first_hash0 += a;
            first_hash1 += b;
            first_hash2 += c;
            first_hash3 += d;
            first_hash4 += e;
            first_hash5 += f;
            first_hash6 += g;
            first_hash7 += h;
        }

    /**********************************************************************
    ***************************** SECOND HASH *****************************
    **********************************************************************/
        schedule00 = first_hash0;
        schedule01 = first_hash1;
        schedule02 = first_hash2;
        schedule03 = first_hash3;
        schedule04 = first_hash4;
        schedule05 = first_hash5;
        schedule06 = first_hash6;
        schedule07 = first_hash7;
        schedule08 = 0x80000000;
        schedule09 = 0;
        schedule10 = 0;
        schedule11 = 0;
        schedule12 = 0;
        schedule13 = 0;
        schedule14 = 0;
        schedule15 = 0x100;

        first_hash0 = UINT32_C(0x6A09E667);
        first_hash1 = UINT32_C(0xBB67AE85);
        first_hash2 = UINT32_C(0x3C6EF372);
        first_hash3 = UINT32_C(0xA54FF53A);
        first_hash4 = UINT32_C(0x510E527F);
        first_hash5 = UINT32_C(0x9B05688C);
        first_hash6 = UINT32_C(0x1F83D9AB);
        first_hash7 = UINT32_C(0x5BE0CD19);

        a = first_hash0;
        b = first_hash1;
        c = first_hash2;
        d = first_hash3;
        e = first_hash4;
        f = first_hash5;
        g = first_hash6;
        h = first_hash7;

        ALL_SCHEDULE_LAST16()

        // execute first 32 rounds
        ALL_ROUND_B1_1()

        // compute second 32 W rounds
        ALL_SCHEDULE32()

        // execute second 32 rounds
        ALL_ROUND_B1_2()
        
        first_hash0 += a;
        first_hash1 += b;
        first_hash2 += c;
        first_hash3 += d;
        first_hash4 += e;
        first_hash5 += f;
        first_hash6 += g;
        first_hash7 += h;

    /**********************************************************************
    ***************************** LOOP HASH *******************************
    **********************************************************************/

		hash0 = 0;
		hash1 = 0;
		hash2 = 0;
		hash3 = 0;
		hash4 = 0;
		hash5 = 0;
		hash6 = 0;
		hash7 = 0;

		indexW = 0; // reusing variable to index into w_words_uint32

		for(index_generic = 0; index_generic < NUM_HASH_BLOCKS; index_generic++)
		{
            // set start value
			a = UINT32_C(0x6A09E667);
			b = UINT32_C(0xBB67AE85);
			c = UINT32_C(0x3C6EF372);
			d = UINT32_C(0xA54FF53A);
			e = UINT32_C(0x510E527F);
			f = UINT32_C(0x9B05688C);
			g = UINT32_C(0x1F83D9AB);
			h = UINT32_C(0x5BE0CD19);

            // compute first 32 W words
			schedule00 = hash0;
			schedule01 = hash1;
			schedule02 = hash2;
			schedule03 = hash3;
			schedule04 = hash4;
			schedule05 = hash5;
			schedule06 = hash6;
			schedule07 = hash7;
			schedule08 = first_hash0;
			schedule09 = first_hash1;
			schedule10 = first_hash2;
			schedule11 = first_hash3;
			schedule12 = first_hash4;
			schedule13 = first_hash5;
			schedule14 = first_hash6;
			schedule15 = first_hash7;

			ALL_SCHEDULE_LAST16()

            // execute first 32 rounds
			ALL_ROUND_B1_1()

            // compute second 32 W words
			ALL_SCHEDULE32()

            // executer second 32 rounds
			ALL_ROUND_B1_2()

            // update hash value
			hash0 = UINT32_C(0x6A09E667) + a;
			hash1 = UINT32_C(0xBB67AE85) + b;
			hash2 = UINT32_C(0x3C6EF372) + c;
			hash3 = UINT32_C(0xA54FF53A) + d;
			hash4 = UINT32_C(0x510E527F) + e;
			hash5 = UINT32_C(0x9B05688C) + f;
			hash6 = UINT32_C(0x1F83D9AB) + g;
			hash7 = UINT32_C(0x5BE0CD19) + h;
			
			a = hash0;
			b = hash1;
			c = hash2;
			d = hash3;
			e = hash4;
			f = hash5;
			g = hash6;
			h = hash7;

			// execute 64 rounds, reading W blocks from w_words_uint32
			ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h,  0, 0x428A2F98, v0)
			ROUND_SECOND_BLOCK_CONST(h, a, b, c, d, e, f, g,  1, 0x71374491, v1)
			ROUND_SECOND_BLOCK_CONST(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, v2)
			ROUND_SECOND_BLOCK_CONST(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, v3)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d,  4, 0x3956C25B, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c,  5, 0x59F111F1, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b,  6, 0x923F82A4, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a,  7, 0xAB1C5ED5, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  8, 0xD807AA98, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  9, 0x12835B01, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 10, 0x243185BE, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 11, 0x550C7DC3, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 12, 0x72BE5D74, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 13, 0x80DEB1FE, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 14, 0x9BDC06A7, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 15, 0xC19BF174, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 16, 0xE49B69C1, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 17, 0xEFBE4786, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 18, 0x0FC19DC6, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 19, 0x240CA1CC, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 20, 0x2DE92C6F, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 21, 0x4A7484AA, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 22, 0x5CB0A9DC, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 23, 0x76F988DA, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 24, 0x983E5152, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 25, 0xA831C66D, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 26, 0xB00327C8, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 27, 0xBF597FC7, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 28, 0xC6E00BF3, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 29, 0xD5A79147, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 30, 0x06CA6351, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 31, 0x14292967, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 32, 0x27B70A85, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 33, 0x2E1B2138, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 34, 0x4D2C6DFC, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 35, 0x53380D13, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 36, 0x650A7354, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 37, 0x766A0ABB, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 38, 0x81C2C92E, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 39, 0x92722C85, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 40, 0xA2BFE8A1, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 41, 0xA81A664B, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 42, 0xC24B8B70, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 43, 0xC76C51A3, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 44, 0xD192E819, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 45, 0xD6990624, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 46, 0xF40E3585, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 47, 0x106AA070, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 48, 0x19A4C116, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 49, 0x1E376C08, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 50, 0x2748774C, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 51, 0x34B0BCB5, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 52, 0x391C0CB3, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 53, 0x4ED8AA4A, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 54, 0x5B9CCA4F, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 55, 0x682E6FF3, indexW)
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 56, 0x748F82EE, indexW)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 57, 0x78A5636F, indexW)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 58, 0x84C87814, indexW)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 59, 0x8CC70208, indexW)
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 60, 0x90BEFFFA, indexW)
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 61, 0xA4506CEB, indexW)
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 62, 0xBEF9A3F7, indexW)
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 63, 0xC67178F2, indexW)

            // update hash value
			hash0 += a;
			hash1 += b;
			hash2 += c;
			hash3 += d;
			hash4 += e;
			hash5 += f;
			hash6 += g;
			hash7 += h;

			indexW += HASH_BLOCK_NUM_UINT32;
		}

    /**********************************************************************
    *************************** MAC COMPARISON ****************************
    **********************************************************************/

		a = ((uint32_t *)(vmkIV     ))[0];
		b = ((uint32_t *)(vmkIV +  4))[0];
		c = ((uint32_t *)(vmkIV +  8))[0];
		d = ((uint32_t *)(vmkIV + 12))[0];

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            a, b, c, d,
            &(schedule00), &(schedule01), &(schedule02), &(schedule03),
            TS0, TS1, TS2, TS3
        );

        schedule00 =
			(((uint32_t)(vmkKey[3] ^ ((uint8_t) (schedule00 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[2] ^ ((uint8_t) (schedule00 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[1] ^ ((uint8_t) (schedule00 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[0] ^ ((uint8_t) (schedule00)))) << 0);

		schedule01 =
			(((uint32_t)(vmkKey[7] ^ ((uint8_t) (schedule01 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[6] ^ ((uint8_t) (schedule01 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[5] ^ ((uint8_t) (schedule01 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[4] ^ ((uint8_t) (schedule01)))) << 0);

		schedule02 =
			(((uint32_t)(vmkKey[11] ^ ((uint8_t) (schedule02 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[10] ^ ((uint8_t) (schedule02 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[9]  ^ ((uint8_t) (schedule02 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[8]  ^ ((uint8_t) (schedule02)))) << 0);

		schedule03 =
			(((uint32_t)(vmkKey[15] ^ ((uint8_t) (schedule03 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[14] ^ ((uint8_t) (schedule03 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[13] ^ ((uint8_t) (schedule03 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[12] ^ ((uint8_t) (schedule03)))) << 0);

		d += 0x01000000;

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            a, b, c, d,
            &(schedule04), &(schedule05), &(schedule06), &(schedule07),
            TS0, TS1, TS2, TS3
        );

        schedule04 =
			(((uint32_t)(vmkKey[19] ^ ((uint8_t) (schedule04 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[18] ^ ((uint8_t) (schedule04 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[17] ^ ((uint8_t) (schedule04 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[16] ^ ((uint8_t) (schedule04)))) << 0);

		schedule05 =
			(((uint32_t)(vmkKey[23] ^ ((uint8_t) (schedule05 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[22] ^ ((uint8_t) (schedule05 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[21] ^ ((uint8_t) (schedule05 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[20] ^ ((uint8_t) (schedule05)))) << 0);

		schedule06 =
			(((uint32_t)(vmkKey[27] ^ ((uint8_t) (schedule06 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[26] ^ ((uint8_t) (schedule06 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[25] ^ ((uint8_t) (schedule06 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[24] ^ ((uint8_t) (schedule06)))) << 0);

		schedule07 =
			(((uint32_t)(vmkKey[31] ^ ((uint8_t) (schedule07 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[30] ^ ((uint8_t) (schedule07 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[29] ^ ((uint8_t) (schedule07 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[28] ^ ((uint8_t) (schedule07)))) << 0);

		d += 0x01000000;

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            a, b, c, d,
            &(schedule08), &(schedule09), &(schedule10), &(schedule11),
            TS0, TS1, TS2, TS3
        );

        schedule08 =
			(((uint32_t)(vmkKey[35] ^ ((uint8_t) (schedule08 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[34] ^ ((uint8_t) (schedule08 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[33] ^ ((uint8_t) (schedule08 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[32] ^ ((uint8_t) (schedule08)))) << 0);

		schedule09 =
			(((uint32_t)(vmkKey[39] ^ ((uint8_t) (schedule09 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[38] ^ ((uint8_t) (schedule09 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[37] ^ ((uint8_t) (schedule09 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[36] ^ ((uint8_t) (schedule09)))) << 0);

		schedule10 =
			(((uint32_t)(vmkKey[43] ^ ((uint8_t) (schedule10 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[42] ^ ((uint8_t) (schedule10 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[41] ^ ((uint8_t) (schedule10 >>  8) ))) <<  8) | 
			(((uint32_t)(vmkKey[40] ^ ((uint8_t) (schedule10)))) << 0);

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            ((uint32_t *)(macIV     ))[0],
            ((uint32_t *)(macIV +  4))[0],
            ((uint32_t *)(macIV +  8))[0],
            ((uint32_t *)(macIV + 12))[0],
            &(schedule16), &(schedule17), &(schedule18), &(schedule19),
            TS0, TS1, TS2, TS3
        );

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            ((uint32_t *)(computedMacIV     ))[0],
            ((uint32_t *)(computedMacIV +  4))[0],
            ((uint32_t *)(computedMacIV +  8))[0],
            ((uint32_t *)(computedMacIV + 12))[0],
            &(schedule12), &(schedule13), &(schedule14), &(schedule15),
            TS0, TS1, TS2, TS3
        );

        schedule28 = schedule00 ^ schedule12;
		schedule29 = schedule01 ^ schedule13;
		schedule30 = schedule02 ^ schedule14;
		schedule31 = schedule03 ^ schedule15;

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            schedule28, schedule29, schedule30, schedule31,
            &(schedule12), &(schedule13), &(schedule14), &(schedule15),
            TS0, TS1, TS2, TS3
        );

        schedule28 = schedule04 ^ schedule12;
		schedule29 = schedule05 ^ schedule13;
		schedule30 = schedule06 ^ schedule14;
		schedule31 = schedule07 ^ schedule15;

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            schedule28, schedule29, schedule30, schedule31,
            &(schedule12), &(schedule13), &(schedule14), &(schedule15),
            TS0, TS1, TS2, TS3
        );

        schedule28 = schedule08 ^ schedule12;
		schedule29 = schedule09 ^ schedule13;
		schedule30 = schedule10 ^ schedule14;
		schedule31 = schedule15;

        encrypt(
            hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
            schedule28, schedule29, schedule30, schedule31,
            &(schedule12), &(schedule13), &(schedule14), &(schedule15),
            TS0, TS1, TS2, TS3
        );

        auto condition = (
				schedule12 == ( (uint32_t)
						(((uint32_t)(mac[3] ^ ((uint8_t) (schedule16 >> 24) ))) << 24) | 
						(((uint32_t)(mac[2] ^ ((uint8_t) (schedule16 >> 16) ))) << 16) | 
						(((uint32_t)(mac[1] ^ ((uint8_t) (schedule16 >>  8) ))) <<  8) | 
						(((uint32_t)(mac[0] ^ ((uint8_t) (schedule16)))) << 0) )
			)
			&&
			(
				schedule13 == ( (uint32_t)
						(((uint32_t)(mac[7] ^ ((uint8_t) (schedule17 >> 24) ))) << 24) | 
						(((uint32_t)(mac[6] ^ ((uint8_t) (schedule17 >> 16) ))) << 16) | 
						(((uint32_t)(mac[5] ^ ((uint8_t) (schedule17 >>  8) ))) <<  8) | 
						(((uint32_t)(mac[4] ^ ((uint8_t) (schedule17)))) << 0) )
			)
			&&
			(
				schedule14 == ( (uint32_t)
						(((uint32_t)(mac[11] ^ ((uint8_t) (schedule18 >> 24) ))) << 24) | 
						(((uint32_t)(mac[10] ^ ((uint8_t) (schedule18 >> 16) ))) << 16) | 
						(((uint32_t)(mac[9]  ^ ((uint8_t) (schedule18 >>  8) ))) <<  8) | 
						(((uint32_t)(mac[8]  ^ ((uint8_t) (schedule18)))) << 0) )
			)
			&&
			(
				schedule15 == ( (uint32_t)
						(((uint32_t)(mac[15] ^ ((uint8_t) (schedule19 >> 24) ))) << 24) | 
						(((uint32_t)(mac[14] ^ ((uint8_t) (schedule19 >> 16) ))) << 16) | 
						(((uint32_t)(mac[13] ^ ((uint8_t) (schedule19 >>  8) ))) <<  8) | 
						(((uint32_t)(mac[12] ^ ((uint8_t) (schedule19)))) << 0) )
			);

		if (condition) {
			// *found = tid;
			*found += 1;
			// break;
		}

        // tid += (item.get_local_range().get(0) * item.get_group_range(0));
    }

	return;
}

int 	*h_found;
char	*h_pswd_char;       // used only for printing purpose, never moved to device
int     pswd_per_thread = 1;               // only for printing
char	printed_pswd[PSWD_NUM_CHAR + 1];   // only for printing

static int check_match() {
    int	out_pswd_ind;
	if (*h_found >= 0){
		out_pswd_ind = *h_found;
		snprintf((char*)printed_pswd, PSWD_NUM_CHAR, "%s", (char *)(h_pswd_char + out_pswd_ind * PSWD_NUM_CHAR));
		for (int i = 0; i < PSWD_NUM_CHAR; i++) {
			if (printed_pswd[i] == (char)0x80 || printed_pswd[i] == (char)0xffffff80) {
                printed_pswd[i] = '\0';
            }
        }
		return 1;
	}
	return 0;
}

double attack(
    char *dname,
    uint32_t* d_w_words_uint32,
    unsigned char* encryptedVMK,
    unsigned char* nonce,
    unsigned char* encryptedMAC,
    int gridBlocks,
    double& duration,
    sycl::queue qbc)
{
    try {
    std::chrono::steady_clock::time_point time_start_;
    std::chrono::steady_clock::time_point time_end_;
    double time_total_ = 0.0;

    FILE			*fp;
	// int				done = 0;
	int				match = 0;
	int				h_w_words_uint32[4];
	uint32_t		num_read_pswd;
	// int				cudaThreads = CUDA_THREADS_NO_MAC;
	long long		tot_num_read_pswd = 0;
	uint8_t			vmkIV[IV_SIZE], *d_vmkIV, *d_vmk;
	uint8_t			macIV[IV_SIZE], *d_macIV, *d_mac;
	uint8_t			computedMacIV[IV_SIZE];
	uint8_t			*d_computedMacIV;

    int*			d_found;
    uint32_t*		h_pswd_uint32;     // uint32 representation of passwords in host
    uint32_t* 		d_pswd_uint32;     // uint32 representation of passwords in device

    unsigned int*   d_TS0;
    unsigned int*   d_TS1;
    unsigned int*   d_TS2;
    unsigned int*   d_TS3;

	if(dname == NULL || d_w_words_uint32 == NULL || encryptedVMK == NULL)
	{
		fprintf(stderr, "Attack input error\n");
		return 0.0;
	}

	if(max_num_pswd_per_read <= 0)
	{
		fprintf(stderr, "Attack tot passwords error: %d\n", max_num_pswd_per_read);
		return 0.0;
	}
	
	//-------- vmkIV setup ------
	memset(vmkIV, 0, IV_SIZE);
	vmkIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
	memcpy(vmkIV + 1, nonce, NONCE_SIZE);
	if(IV_SIZE - 1 - NONCE_SIZE - 1 < 0)
	{
		fprintf(stderr, "Attack nonce error\n");
		return 0.0;
	}
	vmkIV[IV_SIZE - 1] = 1; 
	// -----------------------

    // cudaThreads = THREADS_PER_BLOCK;

    //-------- macIV setup ------
    memset(macIV, 0, IV_SIZE);
    macIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
    memcpy(macIV + 1, nonce, NONCE_SIZE);
    if(IV_SIZE - 1 - NONCE_SIZE - 1 < 0)
    {
        fprintf(stderr, "Attack nonce error\n");
        return 0.0;
    }
    macIV[IV_SIZE - 1] = 0; 
    // -----------------------

    //-------- computedMacIV setup ------
    memset(computedMacIV, 0, IV_SIZE);
    computedMacIV[0] = 0x3a;
    memcpy(computedMacIV + 1, nonce, NONCE_SIZE);
    if(IV_SIZE - 1 - NONCE_SIZE - 1 < 0)
    {
        fprintf(stderr, "Attack nonce error\n");
        return 0.0;
    }
    computedMacIV[IV_SIZE - 1] = 0x2c;

	// ---- Open File Dictionary ----
	if (!memcmp(dname, "-\0", 2)) {
		fp = stdin;
	} else {
		fp = fopen(dname, "r");
		if (!fp) {
			fprintf(stderr, "Can't open dictionary file %s.\n", dname);
			return 0.0;
		}
	}
	// -------------------------------

    // ---- HOST VARS ----
    h_found        = sycl::malloc_host<int>(     1,                                        qbc);
    h_pswd_char    = sycl::malloc_host<char>(    max_num_pswd_per_read * PSWD_NUM_CHAR,    qbc);
    h_pswd_uint32  = sycl::malloc_host<uint32_t>(max_num_pswd_per_read * PSWD_NUM_UINT32,  qbc);
    *h_found = -1;
    // h_pswd_char is later populated in read_password(). It is never copied over to device.
    // h_pswd_uint32 is populated in read_password() and copied over to device.
    // d_w_words_uint32 was allocated and populated in evaluate_w_block()/kernel_w_block()

#ifdef DEBUG_TIME
    auto time11 = std::chrono::steady_clock::now();
#endif

    qbc.memcpy(h_w_words_uint32, d_w_words_uint32, 4 * sizeof(int));
    // ------------------------

    // ---- DEVICE VARS are d_vmk, d_vmkIV, d_mac, d_macIV, d_computedMacIV, d_found, d_w_words_uint32, d_pswd_uint32 ----
    d_vmk           = sycl::malloc_device<uint8_t>( VMK_FULL_SIZE, qbc);
    d_vmkIV         = sycl::malloc_device<uint8_t>( IV_SIZE,       qbc);
    d_mac           = sycl::malloc_device<uint8_t>( MAC_SIZE,      qbc);
    d_macIV         = sycl::malloc_device<uint8_t>( IV_SIZE,       qbc);
    d_computedMacIV = sycl::malloc_device<uint8_t>( IV_SIZE,       qbc);
    d_found         = sycl::malloc_device<int>(     1,             qbc);

    d_pswd_uint32   = sycl::malloc_device<uint32_t>(max_num_pswd_per_read * PSWD_NUM_UINT32,   qbc);
    // d_w_words_uint32 was allocated and populated in evaluate_w_block()/kernel_w_block()

    d_TS0 = sycl::malloc_device<unsigned int>(256, qbc);
    d_TS1 = sycl::malloc_device<unsigned int>(256, qbc);
    d_TS2 = sycl::malloc_device<unsigned int>(256, qbc);
    d_TS3 = sycl::malloc_device<unsigned int>(256, qbc);

    qbc.memcpy(d_vmk,             encryptedVMK,   VMK_FULL_SIZE   * sizeof(uint8_t));
    qbc.memcpy(d_vmkIV,           vmkIV,          IV_SIZE         * sizeof(uint8_t));
    qbc.memcpy(d_mac,             encryptedMAC,   MAC_SIZE        * sizeof(uint8_t));
    qbc.memcpy(d_macIV,           macIV,          IV_SIZE         * sizeof(uint8_t));
    qbc.memcpy(d_computedMacIV,   computedMacIV,  IV_SIZE         * sizeof(uint8_t));
    qbc.memcpy(d_found,           h_found,                          sizeof(uint32_t));
    // d_pswd_uint32 is allocated above but copied from h_pswd_uint32 in while loop below
    // d_w_words_uint32 was allocated and populated in evaluate_w_block()/kernel_w_block()

    qbc.memcpy(d_TS0, h_TS0, 256 * sizeof(unsigned int));
    qbc.memcpy(d_TS1, h_TS1, 256 * sizeof(unsigned int));
    qbc.memcpy(d_TS2, h_TS2, 256 * sizeof(unsigned int));
    qbc.memcpy(d_TS3, h_TS3, 256 * sizeof(unsigned int));

    qbc.wait();

#ifdef DEBUG_TIME
    auto time12 = std::chrono::steady_clock::now();
    auto duration1 = std::chrono::duration<double, std::micro>(time12 - time11).count();
    duration += duration1;
    std::cout << "attack() - alloc + memcpy, duration1: " << duration1 << " us\n\n";
#endif

    printf("Type of attack: %s\n", "User Password");
	// printf("CUDA threads per block: %d\n", cudaThreads);
	// printf("CUDA Blocks: %d\n", gridBlocks);
	printf("Psw per thread: %d\n", pswd_per_thread);
	printf("max_num_pswd_per_read: %d\n", max_num_pswd_per_read);
	printf("Dictionary: %s\n", (fp == stdin) ? "standard input" : dname);
	printf("MAC Comparison (-m): %s\n", "Yes");
	printf("\n");

    auto v0 = h_w_words_uint32[0];
    auto v1 = h_w_words_uint32[1];
    auto v2 = h_w_words_uint32[2];
    auto v3 = h_w_words_uint32[3];

	uint32_t s0 =  ((uint32_t)salt[ 0]) << 24 | ((uint32_t)salt[ 1]) << 16 | ((uint32_t)salt[ 2]) <<  8 | ((uint32_t)salt[ 3]); 
	uint32_t s1 =  ((uint32_t)salt[ 4]) << 24 | ((uint32_t)salt[ 5]) << 16 | ((uint32_t)salt[ 6]) <<  8 | ((uint32_t)salt[ 7]); 
	uint32_t s2 =  ((uint32_t)salt[ 8]) << 24 | ((uint32_t)salt[ 9]) << 16 | ((uint32_t)salt[10]) <<  8 | ((uint32_t)salt[11]);
	uint32_t s3 =  ((uint32_t)salt[12]) << 24 | ((uint32_t)salt[13]) << 16 | ((uint32_t)salt[14]) <<  8 | ((uint32_t)salt[15]);

    int iter = 0;
	while(true) {
        iter++;

        TIMER_START_()
        // populate h_pswd_uint32 and h_pswd_char
        num_read_pswd = read_password(&h_pswd_uint32, &h_pswd_char, max_num_pswd_per_read, fp);
        if(num_read_pswd <= 0) {
            break;
        }
        std::cout <<"\nIter: " << iter<< ", num passwords read: " << num_read_pswd << std::endl;
        TIMER_END_()

#ifdef DEBUG_TIME
        auto time_iter11 = std::chrono::steady_clock::now();
        // auto time21 = std::chrono::steady_clock::now();
#endif

        // copy h_pswd_uint32 over to d_pswd_uint32
        auto e1 = qbc.memcpy(d_pswd_uint32, h_pswd_uint32, num_read_pswd * PSWD_NUM_UINT32 * sizeof(uint32_t));

        // auto time22 = std::chrono::steady_clock::now();
        // auto duration2 = std::chrono::duration<double, std::micro>(time22 - time21).count();
        // duration += duration2;
        // std::cout << "attack() - memcpy H2D: " << duration2 << " us\n\n";

        // auto time31 = std::chrono::steady_clock::now();

        // launch kernel
        unsigned int wg_size  = 256; // wg_size tuned to 256
        unsigned int in_range = ((num_read_pswd + wg_size -1) / wg_size) * wg_size;
        auto e2 = qbc.submit([&](sycl::handler &cgh) {
            cgh.depends_on(e1);
            cgh.parallel_for(
                sycl::nd_range<1>(in_range, wg_size),
                [=](sycl::nd_item<1> item) [[intel::reqd_sub_group_size(16)]] {
                    decrypt_vmk_with_mac(
                        num_read_pswd,
                        d_found,
                        d_vmk,
                        d_vmkIV,
                        d_mac,
                        d_macIV,
                        d_computedMacIV,
                        v0,
                        v1,
                        v2,
                        v3,
                        s0,
                        s1,
                        s2,
                        s3,
                        d_pswd_uint32,
                        d_w_words_uint32,
                        d_TS0,
                        d_TS1,
                        d_TS2,
                        d_TS3,
                        item
                    );
                }
            );
        });

        // auto time32 = std::chrono::steady_clock::now();
        // auto duration3 = std::chrono::duration<double, std::micro>(time32 - time31).count();
        // duration += duration3;
        // std::cout << "attack() - decrypt_vmk_with_mac(): " << duration3 << " us\n\n";

        // auto time41 = std::chrono::steady_clock::now();

        // copy d_found from device to h_found in host
        qbc.memcpy(h_found, d_found, sizeof(unsigned int), std::move(e2));
        qbc.wait();

        // auto time42 = std::chrono::steady_clock::now();
        // auto duration4 = std::chrono::duration<double, std::micro>(time42 - time41).count();
        // duration += duration4;
        // std::cout << "attack() - memcpy D2H: " << duration4 << " us\n\n";

#ifdef DEBUG_TIME
        auto time_iter12 = std::chrono::steady_clock::now();
        auto duration_iter = std::chrono::duration<double, std::micro>(time_iter12 - time_iter11).count();
        duration += duration_iter;
        std::cout << "H2D + decrypt_vmk_with_mac() + D2H: " << duration_iter << " us\n\n";
#endif

        printf("Kernel execution:\n"
                "\tEffective passwords: %d\n"
                "\tPasswords Range:\n"
                "\t\t%s\n"
                "\t\t.....\n"
                "\t\t%s\n",
                num_read_pswd,
                (char *)(h_pswd_char),                                          // first password in batch
                (char *)(h_pswd_char + ((num_read_pswd - 1) * PSWD_NUM_CHAR)));  // last password in batch
        std::cout << "--------------------\n";

        tot_num_read_pswd += num_read_pswd;
        match = check_match();  // uses h_found
        if(match || feof(fp)) {
            break;
        }
	}

    std::cout << "================================================\n"
              << "Bitcracker attack completed\n"
              << "Total passwords evaluated: " << tot_num_read_pswd << std::endl;
    if (match == 1) std::cout << "Password found: " << printed_pswd << std::endl;
    else std::cout << "Password not found!\n";
    std::cout << "================================================\n";

    // close file
	if (fp != stdin)
		fclose(fp);

    // free host allocated variables
    sycl::free(h_found,         qbc);
    sycl::free(h_pswd_char,     qbc);
    sycl::free(h_pswd_uint32,   qbc);
    // free device allocated variables
    sycl::free(d_vmk,           qbc);
    sycl::free(d_vmkIV,         qbc);
    sycl::free(d_mac,           qbc);
    sycl::free(d_macIV,         qbc);
    sycl::free(d_computedMacIV, qbc);
    sycl::free(d_found,         qbc);
    sycl::free(d_pswd_uint32,   qbc);
    sycl::free(d_TS0,           qbc);
    sycl::free(d_TS1,           qbc);
    sycl::free(d_TS2,           qbc);
    sycl::free(d_TS3,           qbc);

    TIMER_PRINT_("time to subtract from total")
	return time_total_;
    }
    catch (sycl::exception const &exc) {
        std::cerr << exc.what() << "Exception caught at file:" << __FILE__ << ", line:" << __LINE__ << std::endl;
        std::exit(1);
    }
}
