/*
 * BitCracker: BitLocker password cracking tool, OpenCL version.
 * Copyright (C) 2013-2017  Elena Ago <elena dot ago at gmail dot com>
 *                          Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
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

#define MIN(a,b) (((a)<(b))?(a):(b))
#define AUTHENTICATOR_LENGTH 16
#define AES_CTX_LENGTH 256
#define FALSE 0
#define TRUE 1
#define SALT_SIZE 16
#define MAC_SIZE 16
#define NONCE_SIZE 12
#define IV_SIZE 16
#define VMK_SIZE 44
#define VMK_DECRYPT_SIZE 16
#define DICT_BUFSIZE	(50*1024*1024)
#define MAX_PLEN 32
#define UINT32_C(c) c ## UL

#define HASH_SIZE 8 //32
#define ROUND_SHA_NUM 64
#define SINGLE_BLOCK_SHA_SIZE 64
#define SINGLE_BLOCK_W_SIZE 64
#define PADDING_SIZE 40
#define ITERATION_NUMBER 0x100000
#define WORD_SIZE 4
#define INPUT_SIZE 512
#define FIXED_PART_INPUT_CHAIN_HASH 88
#define MAX_INPUT_PASSWORD_LEN 16
#define BLOCK_UNIT 32
#define HASH_SIZE_STRING 32

#define CUDA_GRID_THREAD_X 32 /* 32 - 16*/
#define CUDA_GRID_THREAD_Y 32
#define MAX_SOURCE_SIZE (0x100000)  

#define ROR(x, i) (((x) << (32 - (i))) | ((x) >> (i)))

#define LOADSCHEDULE_WPRE(i, j)  \
                w_blocks_d[j] =                           \
                          (unsigned int)block[i * 4 + 0] << 24  \
                        | (unsigned int)block[i * 4 + 1] << 16  \
                        | (unsigned int)block[i * 4 + 2] <<  8  \
                        | (unsigned int)block[i * 4 + 3];
        
#define SCHEDULE_WPRE(i)  \
                w_blocks_d[i] = w_blocks_d[i - 16] + w_blocks_d[i - 7]  \
                        + (ROR(w_blocks_d[i - 15], 7) ^ ROR(w_blocks_d[i - 15], 18) ^ (w_blocks_d[i - 15] >> 3))  \
                        + (ROR(w_blocks_d[i - 2], 17) ^ ROR(w_blocks_d[i - 2], 19) ^ (w_blocks_d[i - 2] >> 10));


__kernel void opencl_bitcracker_wblocks(int totNumIteration, __global unsigned char * salt_d, __global unsigned char * padding_d, __global unsigned int * w_blocks_d) 
{ 
	unsigned long loop = get_global_id(0);
	unsigned char block[SINGLE_BLOCK_W_SIZE];
	
	int i, j;

	for(i=0; i<SALT_SIZE; i++)
		block[i] = salt_d[i];
	
	i+=8;
	
	for(j=0; j<40; i++, j++)
		block[i] = padding_d[j];
	
	while(loop < ITERATION_NUMBER)
	{
		block[16] = (unsigned char) (loop >> (0*8));
		block[17] = (unsigned char) (loop >> (1*8));
		block[18] = (unsigned char) (loop >> (2*8));
		block[19] = (unsigned char) (loop >> (3*8));
		block[20] = (unsigned char) (loop >> (4*8));
		block[21] = (unsigned char) (loop >> (5*8));
		block[22] = (unsigned char) (loop >> (6*8));
		block[23] = (unsigned char) (loop >> (7*8));

		LOADSCHEDULE_WPRE( 0, (SINGLE_BLOCK_W_SIZE*loop)+0)
		LOADSCHEDULE_WPRE( 1, (SINGLE_BLOCK_W_SIZE*loop)+1)
		LOADSCHEDULE_WPRE( 2, (SINGLE_BLOCK_W_SIZE*loop)+2)
		LOADSCHEDULE_WPRE( 3, (SINGLE_BLOCK_W_SIZE*loop)+3)
		LOADSCHEDULE_WPRE( 4, (SINGLE_BLOCK_W_SIZE*loop)+4)
		LOADSCHEDULE_WPRE( 5, (SINGLE_BLOCK_W_SIZE*loop)+5)
		LOADSCHEDULE_WPRE( 6, (SINGLE_BLOCK_W_SIZE*loop)+6)
		LOADSCHEDULE_WPRE( 7, (SINGLE_BLOCK_W_SIZE*loop)+7)
		LOADSCHEDULE_WPRE( 8, (SINGLE_BLOCK_W_SIZE*loop)+8)
		LOADSCHEDULE_WPRE( 9, (SINGLE_BLOCK_W_SIZE*loop)+9)
		LOADSCHEDULE_WPRE(10, (SINGLE_BLOCK_W_SIZE*loop)+10)
		LOADSCHEDULE_WPRE(11, (SINGLE_BLOCK_W_SIZE*loop)+11)
		LOADSCHEDULE_WPRE(12, (SINGLE_BLOCK_W_SIZE*loop)+12)
		LOADSCHEDULE_WPRE(13, (SINGLE_BLOCK_W_SIZE*loop)+13)
		LOADSCHEDULE_WPRE(14, (SINGLE_BLOCK_W_SIZE*loop)+14)
		LOADSCHEDULE_WPRE(15, (SINGLE_BLOCK_W_SIZE*loop)+15)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+16)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+17)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+18)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+19)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+20)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+21)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+22)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+23)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+24)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+25)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+26)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+27)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+28)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+29)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+30)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+31)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+32)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+33)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+34)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+35)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+36)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+37)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+38)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+39)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+40)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+41)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+42)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+43)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+44)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+45)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+46)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+47)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+48)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+49)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+50)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+51)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+52)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+53)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+54)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+55)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+56)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+57)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+58)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+59)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+60)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+61)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+62)
		SCHEDULE_WPRE((SINGLE_BLOCK_W_SIZE*loop)+63)

		loop += get_global_size(0); //(blockDim.x * gridDim.x * blockDim.y * gridDim.y);
	}
}