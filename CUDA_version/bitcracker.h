/*
 * BitCracker: BitLocker password cracking tool, CUDA version.
 * Copyright (C) 2013-2017  Elena Ago <elena dot ago at gmail dot com>
 *							Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
 * 
 * This file is part of BitCracker.
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

#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <cuda.h>
#include <cuda_runtime.h>
#include "sha256_header.h"
#include "aes_header.h"

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
#define VMK_DECRYPT_SIZE 16
#define DICT_BUFSIZE	(50*1024*1024)
#define MAX_PLEN 32

#define HASH_TAG              "$bitlocker$"
#define HASH_TAG_LEN          (sizeof(HASH_TAG) - 1)
#define INPUT_HASH_SIZE			210
#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

#define HASH_SIZE 8 //32
#define ROUND_SHA_NUM 64
#define SINGLE_BLOCK_SHA_SIZE 64
#define SINGLE_BLOCK_W_SIZE 64
#define PADDING_SIZE 40
#define ITERATION_NUMBER 0x100000
#define WORD_SIZE 4
#define INPUT_SIZE 2048
#define FIXED_PART_INPUT_CHAIN_HASH 88
#define MAX_INPUT_PASSWORD_LEN 27
#define FIXED_PASSWORD_BUFFER 32

#define BLOCK_UNIT 32
#define HASH_SIZE_STRING 32

#define ATTACK_DEFAULT_THREADS 1024

#define BIT_SUCCESS 0
#define BIT_FAILURE 1

#define BITCRACKER_CUDA_CHECK( call) {                                    \
	    cudaError err = call;                                                    \
	    if( cudaSuccess != err) {                                                \
		            fprintf(stderr, "Cuda error in file '%s' in line %i : %s.\n",        \
					                    __FILE__, __LINE__, cudaGetErrorString( err) );              \
		            exit(EXIT_FAILURE);                                                  \
		        } }

#define BITCRACKER_CUDA_CHECK_LAST_ERROR() {                                    \
	    if( cudaSuccess != cudaGetLastError()) {                                                \
		            fprintf(stderr, "Cuda error in file '%s' in line %i : %s.\n",        \
					                    __FILE__, __LINE__, cudaGetErrorString( cudaGetLastError() ) );              \
		            exit(EXIT_FAILURE);                                                  \
		        } }

extern int gpu_id;
extern int psw_x_thread;
extern int tot_psw;
extern size_t size_psw;
extern int strict_check;

/* ++++++++++++++++++++++++++++++++++++++ DEVICE FUNCTIONS ++++++++++++++++++++++++++++++++++++++ */
__global__ void w_block_evaluate(unsigned char salt[SALT_SIZE], int totNumIteration, unsigned char padding[PADDING_SIZE], uint32_t * w_blocks);
__global__ __launch_bounds__(1024,1) void decrypt_vmk(int numStream, int numPassword, int *found, unsigned char * vmkKey, unsigned char * IV, int check);

/* ++++++++++++++++++++++++++++++++++++++ HOST FUNCTIONS ++++++++++++++++++++++++++++++++++++++ */
int w_block_precomputed(unsigned char * salt, uint32_t * w_blocks_d);
int readFilePassword(char ** buf, int maxNumPsw, FILE *fp);
int parse_data(char *input_hash, unsigned char ** salt, unsigned char ** nonce,	unsigned char ** vmk);
char *strtokm(char *s1, const char *delims);
char *cuda_attack(char *dname, uint32_t * w_blocks_d, unsigned char * encryptedVMK, unsigned char * nonce,  int gridBlocks);
void setBufferPasswordSize(size_t avail, size_t * passwordBufferSize, int * numPassword);

void * Calloc(size_t len, size_t size);
void print_hex(unsigned char hash[], int size);

