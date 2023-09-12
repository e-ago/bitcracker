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
#include "bitcracker.h"
#include <iostream>
#include <chrono>

#define ROR(x, i) (((x) << (32 - (i))) | ((x) >> (i)))

#define LOADSCHEDULE_WPRE(j, i)  \
		d_w_words_uint32[j] =                         \
			  (uint32_t)block[i * 4 + 0] << 24  \
			| (uint32_t)block[i * 4 + 1] << 16  \
			| (uint32_t)block[i * 4 + 2] <<  8  \
			| (uint32_t)block[i * 4 + 3];

#define CALCSCHEDULE_WPRE(j)  \
		d_w_words_uint32[j] = d_w_words_uint32[j - 16] + d_w_words_uint32[j - 7]  \
			+ (ROR(d_w_words_uint32[j - 15],  7) ^ ROR(d_w_words_uint32[j - 15], 18) ^ (d_w_words_uint32[j - 15] >>  3))  \
			+ (ROR(d_w_words_uint32[j -  2], 17) ^ ROR(d_w_words_uint32[j -  2], 19) ^ (d_w_words_uint32[j -  2] >> 10));

void kernel_w_block(
    unsigned char salt[SALT_SIZE],
    unsigned char padding[40],
    uint32_t * d_w_words_uint32,
    sycl::nd_item<1> item) //, sycl::stream out)
{
    uint64_t tid = item.get_global_id(0);
    if (tid >= NUM_HASH_BLOCKS) return;

    uint64_t texBlockId;
    unsigned char block[HASH_BLOCK_NUM_UINT32];
	
	int i;
    // index 0-15
	for(i = 0; i < SALT_SIZE; i++){
		block[i] = salt[i];
    }
    // index 24-63
	for(i = 0; i < PADDING_SIZE; i++){
		block[i + 24] = padding[i];
	}
	
	// while(tid < NUM_HASH_BLOCKS)
	{
        // index 16-23
		block[16] = (unsigned char) (tid >> (0 * 8));
		block[17] = (unsigned char) (tid >> (1 * 8));
		block[18] = (unsigned char) (tid >> (2 * 8));
		block[19] = (unsigned char) (tid >> (3 * 8));
		block[20] = (unsigned char) (tid >> (4 * 8));
		block[21] = (unsigned char) (tid >> (5 * 8));
		block[22] = (unsigned char) (tid >> (6 * 8));
		block[23] = (unsigned char) (tid >> (7 * 8));

        texBlockId = HASH_BLOCK_NUM_UINT32 * tid;
		LOADSCHEDULE_WPRE(texBlockId +  0,  0)
		LOADSCHEDULE_WPRE(texBlockId +  1,  1)
		LOADSCHEDULE_WPRE(texBlockId +  2,  2)
		LOADSCHEDULE_WPRE(texBlockId +  3,  3)
		LOADSCHEDULE_WPRE(texBlockId +  4,  4)
		LOADSCHEDULE_WPRE(texBlockId +  5,  5)
		LOADSCHEDULE_WPRE(texBlockId +  6,  6)
		LOADSCHEDULE_WPRE(texBlockId +  7,  7)
		LOADSCHEDULE_WPRE(texBlockId +  8,  8)
		LOADSCHEDULE_WPRE(texBlockId +  9,  9)
		LOADSCHEDULE_WPRE(texBlockId + 10, 10)
		LOADSCHEDULE_WPRE(texBlockId + 11, 11)
		LOADSCHEDULE_WPRE(texBlockId + 12, 12)
		LOADSCHEDULE_WPRE(texBlockId + 13, 13)
		LOADSCHEDULE_WPRE(texBlockId + 14, 14)
		LOADSCHEDULE_WPRE(texBlockId + 15, 15)
		CALCSCHEDULE_WPRE(texBlockId + 16)
		CALCSCHEDULE_WPRE(texBlockId + 17)
		CALCSCHEDULE_WPRE(texBlockId + 18)
		CALCSCHEDULE_WPRE(texBlockId + 19)
		CALCSCHEDULE_WPRE(texBlockId + 20)
		CALCSCHEDULE_WPRE(texBlockId + 21)
		CALCSCHEDULE_WPRE(texBlockId + 22)
		CALCSCHEDULE_WPRE(texBlockId + 23)
		CALCSCHEDULE_WPRE(texBlockId + 24)
		CALCSCHEDULE_WPRE(texBlockId + 25)
		CALCSCHEDULE_WPRE(texBlockId + 26)
		CALCSCHEDULE_WPRE(texBlockId + 27)
		CALCSCHEDULE_WPRE(texBlockId + 28)
		CALCSCHEDULE_WPRE(texBlockId + 29)
		CALCSCHEDULE_WPRE(texBlockId + 30)
		CALCSCHEDULE_WPRE(texBlockId + 31)
		CALCSCHEDULE_WPRE(texBlockId + 32)
		CALCSCHEDULE_WPRE(texBlockId + 33)
		CALCSCHEDULE_WPRE(texBlockId + 34)
		CALCSCHEDULE_WPRE(texBlockId + 35)
		CALCSCHEDULE_WPRE(texBlockId + 36)
		CALCSCHEDULE_WPRE(texBlockId + 37)
		CALCSCHEDULE_WPRE(texBlockId + 38)
		CALCSCHEDULE_WPRE(texBlockId + 39)
		CALCSCHEDULE_WPRE(texBlockId + 40)
		CALCSCHEDULE_WPRE(texBlockId + 41)
		CALCSCHEDULE_WPRE(texBlockId + 42)
		CALCSCHEDULE_WPRE(texBlockId + 43)
		CALCSCHEDULE_WPRE(texBlockId + 44)
		CALCSCHEDULE_WPRE(texBlockId + 45)
		CALCSCHEDULE_WPRE(texBlockId + 46)
		CALCSCHEDULE_WPRE(texBlockId + 47)
		CALCSCHEDULE_WPRE(texBlockId + 48)
		CALCSCHEDULE_WPRE(texBlockId + 49)
		CALCSCHEDULE_WPRE(texBlockId + 50)
		CALCSCHEDULE_WPRE(texBlockId + 51)
		CALCSCHEDULE_WPRE(texBlockId + 52)
		CALCSCHEDULE_WPRE(texBlockId + 53)
		CALCSCHEDULE_WPRE(texBlockId + 54)
		CALCSCHEDULE_WPRE(texBlockId + 55)
		CALCSCHEDULE_WPRE(texBlockId + 56)
		CALCSCHEDULE_WPRE(texBlockId + 57)
		CALCSCHEDULE_WPRE(texBlockId + 58)
		CALCSCHEDULE_WPRE(texBlockId + 59)
		CALCSCHEDULE_WPRE(texBlockId + 60)
		CALCSCHEDULE_WPRE(texBlockId + 61)
		CALCSCHEDULE_WPRE(texBlockId + 62)
		CALCSCHEDULE_WPRE(texBlockId + 63)

        // if (texBlockId == (64*10)) { 
        //     out <<"hello from kernel_w_block\n\n";
        //     out << "NUM_HASH_BLOCKS: " << NUM_HASH_BLOCKS << "\n";
        //     out << "texBlockId: ";
        //     out << texBlockId << "\n";
        //     for (int j = 0; j < 64; j++) {
        //         out << "d_w_words_uint32[" << sycl::setw(2) << j << "] = " << d_w_words_uint32[texBlockId + j] << "\n";
        //     }
        //     out << "\n";
        // }

        // tid += (item.get_local_range().get(0) * item.get_group_range(0));
    }
}

int evaluate_w_block(
    unsigned char * salt,
    uint32_t * d_w_words_uint32,
    double& duration,
    sycl::queue qbc)
{
	unsigned char * salt_d;
	unsigned char * padding;
    unsigned char * padding_d;
	uint64_t msgLen;

	if(salt == NULL || d_w_words_uint32 == NULL)
		return BIT_FAILURE;

	padding = (unsigned char *) Calloc(PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding + 1, 0, 31);
	msgLen = (FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (int i = 0; i < 8; i++) {
		padding[PADDING_SIZE - 1 - i] = (uint8_t)(msgLen >> (i * 8));
    }

#ifdef DEBUG_TIME
    auto time11 = std::chrono::steady_clock::now();
#endif

    // allocate device memory
    salt_d    = (unsigned char *)sycl::malloc_device(SALT_SIZE    * sizeof(unsigned char), qbc);
    padding_d = (unsigned char *)sycl::malloc_device(PADDING_SIZE * sizeof(unsigned char), qbc);

    // copy to device memory
    auto e1 = qbc.memcpy(salt_d,    salt,    SALT_SIZE    * sizeof(unsigned char));
    auto e2 = qbc.memcpy(padding_d, padding, PADDING_SIZE * sizeof(unsigned char));

    // auto time12 = std::chrono::steady_clock::now();
    // auto duration1 = std::chrono::duration<double, std::micro>(time12 - time11).count();
    // duration += duration1;
    // std::cout << "evaluate_w_block() - alloc and memcpy, duration1: " << duration1 << " us\n\n";

    // auto time21 = std::chrono::steady_clock::now();

    // launch kernel
    qbc.parallel_for(
        sycl::nd_range<1>(NUM_HASH_BLOCKS, 32), {std::move(e1), std::move(e2)},
        [=](sycl::nd_item<1> item) {
            kernel_w_block(salt_d, padding_d, d_w_words_uint32, item);
        }
    );
    qbc.wait();

#ifdef DEBUG_TIME
    auto time22 = std::chrono::steady_clock::now();
    auto duration2 = std::chrono::duration<double, std::micro>(time22 - time11).count();
    duration += duration2;
    std::cout << "evaluate_w_block -> malloc + H2D + kernel_w_block, duration2: " << duration2 << " us\n\n";
#endif

    free(padding);

    sycl::free(salt_d,    qbc);
    sycl::free(padding_d, qbc);

	return BIT_SUCCESS;
}
