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

#include "bitcracker.h"

__global__ void w_block_evaluate(unsigned char salt[SALT_SIZE], int totNumIteration, unsigned char padding[40], uint32_t * w_blocks_d) { // unsigned char block[64]
	
	uint64_t loop = (threadIdx.x+blockIdx.x*blockDim.x);
	unsigned char block[SINGLE_BLOCK_W_SIZE];
	
	int i, j;

	for(i=0; i<SALT_SIZE; i++)
		block[i] = salt[i];
	
	i+=8;
	
	for(j=0; j<40; i++, j++)
	{
		block[i] = padding[j];
	}
	
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

		loop += (blockDim.x * gridDim.x);
	}
}

int w_block_precomputed(unsigned char * salt, uint32_t * w_blocks_d)
{
	unsigned char * salt_d;
	unsigned char * padding, * padding_d;
	cudaEvent_t	startW, stopW;
	float timeElapsedW;
	uint64_t msgLen;

	if(salt == NULL || w_blocks_d == NULL)
		return BIT_FAILURE;

	padding = (unsigned char *) Calloc(PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding+1, 0, 31);
	msgLen = (FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (int i = 0; i < 8; i++)
		padding[PADDING_SIZE-1-i] = (uint8_t)(msgLen >> (i * 8));

	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &salt_d, (SALT_SIZE * sizeof(unsigned char)) ) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy( salt_d, salt, (SALT_SIZE * sizeof(unsigned char)), cudaMemcpyHostToDevice) );
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &padding_d, (PADDING_SIZE * sizeof(unsigned char)) ) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy( padding_d, padding, (PADDING_SIZE * sizeof(unsigned char)), cudaMemcpyHostToDevice) );
	
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&startW));
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&stopW));
	BITCRACKER_CUDA_CHECK( cudaEventRecord(startW) );
	w_block_evaluate<<<1024,16>>>(salt_d, ITERATION_NUMBER, padding_d, w_blocks_d);
	BITCRACKER_CUDA_CHECK( cudaEventRecord(stopW));
	BITCRACKER_CUDA_CHECK( cudaEventSynchronize(stopW));
	BITCRACKER_CUDA_CHECK( cudaEventElapsedTime(&timeElapsedW, startW, stopW) );
	//fprintf(stdout, "%d W words in %f ms (%f sec) \n", (SINGLE_BLOCK_SHA_SIZE*ITERATION_NUMBER), timeElapsedW, (timeElapsedW/1000.0));

	BITCRACKER_CUDA_CHECK( cudaEventDestroy(startW));
	BITCRACKER_CUDA_CHECK( cudaEventDestroy(stopW));
	
	BITCRACKER_CUDA_CHECK( cudaFree(salt_d) );
	BITCRACKER_CUDA_CHECK( cudaFree(padding_d) );
	free(padding);

	/*
	 * Useless
	 * uint32_t * w_blocks_h = NULL;
	 * w_blocks_h = (uint32_t *) Calloc((SINGLE_BLOCK_SHA_SIZE*ITERATION_NUMBER), sizeof(uint32_t));
	 * BITCRACKER_CUDA_CHECK( cudaMemcpy(w_blocks_h, w_blocks_d, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(uint32_t), cudaMemcpyDeviceToHost) );
	*/

	return BIT_SUCCESS;
}