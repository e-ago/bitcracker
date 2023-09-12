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
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

#define MIN(a,b) (((a)<(b))?(a):(b))
#define AUTHENTICATOR_LENGTH 16
#define AES_CTX_LENGTH 256
#define FALSE 0
#define TRUE 1
#define SALT_SIZE 16
#define MAC_SIZE 16
#define NONCE_SIZE 12
#define IV_SIZE 16
#define VMK_SIZE 60
#define VMK_HEADER_SIZE 12
#define VMK_BODY_SIZE 32
#define VMK_FULL_SIZE 44


#define DICT_BUFSIZE	(50*1024*1024)
#define MAX_PLEN 32

#define RECOVERY_KEY_SIZE_CHAR 56
#define RECOVERY_PASS_BLOCKS 8
#define MODE_RECV_PASS	2

#define HASH_TAG "$bitlocker$"
#define HASH_TAG_LEN (sizeof(HASH_TAG) - 1)
#define INPUT_HASH_SIZE	245
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

#define HASH_SIZE 8
#define ROUND_SHA_NUM 64
#define SINGLE_BLOCK_W_SIZE 64
#define HASH_BLOCK_NUM_UINT32 64
#define PADDING_SIZE 40
#define NUM_HASH_BLOCKS 0x100000
#define WORD_SIZE 4
#define INPUT_SIZE 2048
#define FIXED_PART_INPUT_CHAIN_HASH 88
#define MIN_INPUT_PASSWORD_LEN 8
#define MAX_INPUT_PASSWORD_LEN 27

#define PSWD_NUM_CHAR 64
#define PSWD_NUM_UINT32 32

#define FIRST_LENGHT 27
#define SECOND_LENGHT 55

#define BLOCK_UNIT 32
#define HASH_SIZE_STRING 32

#define CUDA_THREADS_NO_MAC 1024
#define THREADS_PER_BLOCK 256

#define BIT_SUCCESS 0
#define BIT_FAILURE 1

extern uint32_t max_num_pswd_per_read;
extern unsigned char * salt;

int evaluate_w_block(unsigned char * salt, uint32_t * d_w_words_uint32, double& duration, sycl::queue qbc);
uint32_t read_password(uint32_t ** buf_i, char ** buf_c, uint32_t max_num_pswd_per_read, FILE *fp);
int parse_data(char *input_hash, unsigned char ** salt, unsigned char ** nonce,	unsigned char ** vmk, unsigned char ** mac);
char * strtokm(char *s1, const char *delims);
double attack(char *dname, uint32_t * d_w_words_uint32, unsigned char * encryptedVMK, unsigned char * nonce, unsigned char * encryptedMAC, int gridBlocks, double& duration, sycl::queue qbc);
void * Calloc(size_t len, size_t size);
