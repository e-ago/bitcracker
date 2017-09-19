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

#include "bitcracker.h"

texture<uint32_t> w_texture;
texture<uint8_t> w_password0;
texture<uint8_t> w_password1;
int 			*deviceFound[2], *hostFound[2];
char			*hostPassword[2], *devicePassword[2];
unsigned char 	outPsw[MAX_INPUT_PASSWORD_LEN+1];
int 			outIndexPsw=0;

static int check_match(int iStream) {
	int i=0;

	if (*hostFound[iStream] >= 0){
		outIndexPsw=*(hostFound[iStream]);
		snprintf((char*)outPsw, MAX_INPUT_PASSWORD_LEN+1, "%s", (char *)(hostPassword[iStream]+(outIndexPsw*FIXED_PASSWORD_BUFFER)));
		for(i=0; i<MAX_INPUT_PASSWORD_LEN; i++)
			if(outPsw[i] == 0x80 || outPsw[i] == 0xffffff80) outPsw[i]='\0';

		return 1;
	}

	return 0;
}
char *cuda_attack(char *dname, uint32_t * w_blocks_d, unsigned char * encryptedVMK, unsigned char * nonce,  int gridBlocks) {

	FILE		*fp;
	int			indexStream, numReadPassword[2], firstLoop, match=0;
	long long	totPsw = 0;

	uint8_t		tmpIV[IV_SIZE], *deviceEncryptedVMK, *deviceIV;


	cudaEvent_t	start[2], stop[2];
	cudaStream_t stream[2];
	float elapsedTime;

	if(dname == NULL || w_blocks_d == NULL || encryptedVMK == NULL)
	{
		fprintf(stderr, "Attack input error\n");
		return NULL;
	}

	if(tot_psw <= 0)
	{
		fprintf(stderr, "Attack tot passwords error: %d\n", tot_psw);
		return NULL;
	}
	
	//-------- IV setup ------
	memset(tmpIV, 0, IV_SIZE);
	memcpy(tmpIV + 1, nonce, NONCE_SIZE);
	if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
	{
		fprintf(stderr, "Attack nonce error\n");
		return NULL;
	}
	*tmpIV = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
	tmpIV[IV_SIZE-1] = 1; 
	// -----------------------

	// ---- Open File Dictionary ----
	if (!memcmp(dname, "-\0", 2)) {
		fp = stdin;
	} else {
		fp = fopen(dname, "r");
		if (!fp) {
			fprintf(stderr, "Can't open dictionary file %s.\n", dname);
			return NULL;
		}
	}
	// -------------------------------

	// ---- HOST VARIABLES ----
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostPassword[0], size_psw, cudaHostAllocDefault) );
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostPassword[1], size_psw, cudaHostAllocDefault) );
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostFound[0], sizeof(uint32_t), cudaHostAllocDefault) );
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostFound[1], sizeof(uint32_t), cudaHostAllocDefault) );
	*hostFound[0] = *hostFound[1] = -1;
	// ------------------------

	// ---- CUDA VARIABLES ----
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &deviceEncryptedVMK, VMK_DECRYPT_SIZE*sizeof(uint8_t)) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy(deviceEncryptedVMK, (encryptedVMK+16), VMK_DECRYPT_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );
	
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &deviceIV, IV_SIZE*sizeof(uint8_t)) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy(deviceIV, tmpIV, IV_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );

	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &devicePassword[0], (size_psw * sizeof(uint8_t)) ) );
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &devicePassword[1], (size_psw * sizeof(uint8_t)) ) );

	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &deviceFound[0], (sizeof(uint32_t)) ) );
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &deviceFound[1], (sizeof(uint32_t)) ) );
	
	BITCRACKER_CUDA_CHECK( cudaMemcpy(deviceFound[0], hostFound[0], sizeof(uint32_t), cudaMemcpyHostToDevice) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy(deviceFound[1], hostFound[1], sizeof(uint32_t), cudaMemcpyHostToDevice) );

	BITCRACKER_CUDA_CHECK( cudaStreamCreate(&(stream[0])) );
	BITCRACKER_CUDA_CHECK( cudaStreamCreate(&(stream[1])) );

	BITCRACKER_CUDA_CHECK( cudaEventCreate(&start[0]) );
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&start[1]) );
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&stop[0]) );
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&stop[1]) );
	// ---------------------

	// -------- TEXTURE --------
	BITCRACKER_CUDA_CHECK(cudaBindTexture(NULL, w_texture, w_blocks_d, (SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(uint32_t))));
	BITCRACKER_CUDA_CHECK(cudaBindTexture(NULL, w_password0, devicePassword[0], (size_psw * sizeof(uint8_t))));
	BITCRACKER_CUDA_CHECK(cudaBindTexture(NULL, w_password1, devicePassword[1], (size_psw * sizeof(uint8_t))));
	// -------------------------

	//	BITCRACKER_CUDA_CHECK (cudaDeviceSetCacheConfig( cudaFuncCachePreferL1 ) );

	printf("Starting CUDA attack:\n\tCUDA Threads: %d\n\tCUDA Blocks: %d\n\tPsw per thread: %d\n\tMax Psw per kernel: %d\n\tDictionary: %s\n\n", 
		ATTACK_DEFAULT_THREADS, gridBlocks, psw_x_thread, tot_psw, (fp == stdin)?"standard input":dname);

	indexStream = 1;
	firstLoop=TRUE;
	while(!feof(fp)) {
		indexStream ^= 1;
		numReadPassword[indexStream] = readFilePassword(&hostPassword[indexStream], tot_psw, fp);
	
		BITCRACKER_CUDA_CHECK( cudaMemcpyAsync(devicePassword[indexStream], hostPassword[indexStream], size_psw, cudaMemcpyHostToDevice, stream[indexStream]) );
		
		if(firstLoop == FALSE)
			BITCRACKER_CUDA_CHECK( cudaStreamSynchronize(stream[indexStream^1]) );
	
		BITCRACKER_CUDA_CHECK( cudaEventRecord(start[indexStream], stream[indexStream]) );
		decrypt_vmk<<<gridBlocks, ATTACK_DEFAULT_THREADS, 0, stream[indexStream]>>>(indexStream, numReadPassword[indexStream], deviceFound[indexStream], deviceEncryptedVMK, deviceIV, strict_check);
		BITCRACKER_CUDA_CHECK_LAST_ERROR();
		BITCRACKER_CUDA_CHECK( cudaEventRecord(stop[indexStream], stream[indexStream]) );		
		BITCRACKER_CUDA_CHECK( cudaMemcpyAsync(hostFound[indexStream], deviceFound[indexStream], sizeof(unsigned int), cudaMemcpyDeviceToHost, stream[indexStream]) );
	
		if(firstLoop == FALSE)
		{
			totPsw += numReadPassword[indexStream^1];
			BITCRACKER_CUDA_CHECK( cudaEventElapsedTime(&elapsedTime, start[indexStream^1], stop[indexStream^1]) );
			
			printf("CUDA Kernel execution:\n\tStream %d\n\tEffective number psw: %d\n\tTime: %f sec\n\tPasswords x second: %8.2f pw/sec\n", 
							indexStream^1, numReadPassword[indexStream^1], ATTACK_DEFAULT_THREADS, gridBlocks, (elapsedTime/1000.0), numReadPassword[indexStream^1]/(elapsedTime/1000.0));
			
			match=check_match(indexStream^1);
			if(match) break;
		}

    	firstLoop = FALSE;
	}

	BITCRACKER_CUDA_CHECK( cudaStreamSynchronize(stream[indexStream]) );
	
	if (fp != stdin)
		fclose(fp);

	if (*hostFound[indexStream^1] < 0) {
		totPsw += numReadPassword[indexStream];
		BITCRACKER_CUDA_CHECK( cudaEventElapsedTime(&elapsedTime, start[indexStream], stop[indexStream]) );
		printf("CUDA Kernel execution:\n\tStream %d\n\tEffective number psw: %d\n\tTime: %f sec\n\tPasswords x second: %8.2f pw/sec\n", 
			indexStream, numReadPassword[indexStream], (elapsedTime/1000.0), numReadPassword[indexStream]/(elapsedTime/1000.0));

		match=check_match(indexStream);
	}

	if(match==1)
		printf("\n\n================================================\nCUDA attack completed\nPasswords evaluated: %d\nPassword found: [%s]\n================================================\n\n", totPsw, outPsw);
	else
		printf("\n\n================================================\nCUDA attack completed\nPasswords evaluated: %d\nPassword not found!\n================================================\n\n", totPsw);

	BITCRACKER_CUDA_CHECK( cudaUnbindTexture(&w_password0) );
	BITCRACKER_CUDA_CHECK( cudaUnbindTexture(&w_password1) );

	BITCRACKER_CUDA_CHECK( cudaFreeHost(hostPassword[0]) );
	BITCRACKER_CUDA_CHECK( cudaFreeHost(hostPassword[1]) );
	BITCRACKER_CUDA_CHECK( cudaFree(devicePassword[0]) );
	BITCRACKER_CUDA_CHECK( cudaFree(devicePassword[1]) );
	BITCRACKER_CUDA_CHECK( cudaFree(deviceFound[0]) );
	BITCRACKER_CUDA_CHECK( cudaFree(deviceFound[1]) );
	BITCRACKER_CUDA_CHECK( cudaStreamDestroy(stream[0]) );
	BITCRACKER_CUDA_CHECK( cudaStreamDestroy(stream[1]) );
	BITCRACKER_CUDA_CHECK( cudaUnbindTexture(&w_texture) );
	

	return NULL;
}


#define END_STRING 0x80 //0xFF
__global__ void decrypt_vmk(int numStream, int tot_psw_kernel, int *found, unsigned char * vmkKey, unsigned char * IV, int strict_check) {
    
    int gIndex = (threadIdx.x+blockIdx.x*blockDim.x);
	uint32_t hash0;
	uint32_t hash1;
	uint32_t hash2;
	uint32_t hash3;
	uint32_t hash4;
	uint32_t hash5;
	uint32_t hash6;
	uint32_t hash7;

	uint32_t schedule0;
	uint32_t schedule1;
	uint32_t schedule2;
	uint32_t schedule3;
	uint32_t schedule4;
	uint32_t schedule5;
	uint32_t schedule6;
	uint32_t schedule7;
	uint32_t schedule8;
	uint32_t schedule9;
	uint32_t schedule10;
	uint32_t schedule11;
	uint32_t schedule12;
	uint32_t schedule13;
	uint32_t schedule14;
	uint32_t schedule15;
	uint32_t schedule16;
	uint32_t schedule17;
	uint32_t schedule18;
	uint32_t schedule19;
	uint32_t schedule20;
	uint32_t schedule21;
	uint32_t schedule22;
	uint32_t schedule23;
	uint32_t schedule24;
	uint32_t schedule25;
	uint32_t schedule26;
	uint32_t schedule27;
	uint32_t schedule28;
	uint32_t schedule29;
	uint32_t schedule30;
	uint32_t schedule31;

	uint32_t a,b,c,d,e,f,g,h;
	int index_generic;
	uint32_t first_hash0;
	uint32_t first_hash1;
	uint32_t first_hash2;
	uint32_t first_hash3;
	uint32_t first_hash4;
	uint32_t first_hash5;
	uint32_t first_hash6;
	uint32_t first_hash7;

	uint32_t indexW=(gIndex*FIXED_PASSWORD_BUFFER);
	int8_t curr_fetch=0;

	while(gIndex < tot_psw_kernel)
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

//----------------------------------------------------- FIRST HASH ------------------------------------------------
		indexW=(gIndex*FIXED_PASSWORD_BUFFER);
		curr_fetch=0;
		index_generic=MAX_INPUT_PASSWORD_LEN;
		if(numStream == 0)
		{
			schedule0 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;
			schedule1 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;
			schedule2 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;
			schedule3 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;

			schedule4 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule5 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch; /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1; /* stop=1; */ }
			curr_fetch+=2;

			schedule6 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule7 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule8 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule9 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule10 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule11 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule12 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule13 = ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password0, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password0, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password0, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
		}
		else
		{
			schedule0 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;
			schedule1 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;
			schedule2 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;
			schedule3 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			curr_fetch+=2;

			schedule4 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule5 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule6 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule7 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule8 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule9 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule10 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule11 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule12 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
			curr_fetch+=2;

			schedule13 = ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch)) << 24) | 0 | ((uint32_t)tex1Dfetch(w_password1, (indexW+curr_fetch+1)) <<  8) | 0;
			if(tex1Dfetch(w_password1, (indexW+curr_fetch)) == END_STRING) { index_generic=curr_fetch;  /* stop=1; */ }
			if(tex1Dfetch(w_password1, (indexW+curr_fetch+1)) == END_STRING) { index_generic=curr_fetch+1;  /* stop=1; */ }
		}


		if(index_generic == MAX_INPUT_PASSWORD_LEN) schedule13 = schedule13 | ((uint32_t)0x8000);

		schedule14=0;
		index_generic*=2;
		schedule15 = ((uint8_t)((index_generic << 3) >> 8)) << 8 | ((uint8_t)(index_generic << 3));

		ALL_SCHEDULE_LAST16()

		ROUND(a, b, c, d, e, f, g, h,  schedule0, 0x428A2F98)
		ROUND(h, a, b, c, d, e, f, g,  schedule1, 0x71374491)
		ROUND(g, h, a, b, c, d, e, f,  schedule2, 0xB5C0FBCF)
		ROUND(f, g, h, a, b, c, d, e,  schedule3, 0xE9B5DBA5)
		ROUND(e, f, g, h, a, b, c, d,  schedule4, 0x3956C25B)
		ROUND(d, e, f, g, h, a, b, c,  schedule5, 0x59F111F1)
		ROUND(c, d, e, f, g, h, a, b,  schedule6, 0x923F82A4)
		ROUND(b, c, d, e, f, g, h, a,  schedule7, 0xAB1C5ED5)
		ROUND(a, b, c, d, e, f, g, h,  schedule8, 0xD807AA98)
		ROUND(h, a, b, c, d, e, f, g,  schedule9, 0x12835B01)
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

		ALL_SCHEDULE32()

		ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
		ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
		ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
		ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
		ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
		ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
		ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
		ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
		ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
		ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)
		
		first_hash0 += a;
		first_hash1 += b;
		first_hash2 += c;
		first_hash3 += d;
		first_hash4 += e;
		first_hash5 += f;
		first_hash6 += g;
		first_hash7 += h;



//----------------------------------------------------- SECOND HASH ------------------------------------------------
		//old loadschedule
		schedule0 = first_hash0;
		schedule1 = first_hash1;
		schedule2 = first_hash2;
		schedule3 = first_hash3;
		schedule4 = first_hash4;
		schedule5 = first_hash5;
		schedule6 = first_hash6;
		schedule7 = first_hash7;
		schedule8 = 0x80000000;
		schedule9 = 0;
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

		ROUND(a, b, c, d, e, f, g, h,  schedule0, 0x428A2F98)
		ROUND(h, a, b, c, d, e, f, g,  schedule1, 0x71374491)
		ROUND(g, h, a, b, c, d, e, f,  schedule2, 0xB5C0FBCF)
		ROUND(f, g, h, a, b, c, d, e,  schedule3, 0xE9B5DBA5)
		ROUND(e, f, g, h, a, b, c, d,  schedule4, 0x3956C25B)
		ROUND(d, e, f, g, h, a, b, c,  schedule5, 0x59F111F1)
		ROUND(c, d, e, f, g, h, a, b,  schedule6, 0x923F82A4)
		ROUND(b, c, d, e, f, g, h, a,  schedule7, 0xAB1C5ED5)
		ROUND(a, b, c, d, e, f, g, h,  schedule8, 0xD807AA98)
		ROUND(h, a, b, c, d, e, f, g,  schedule9, 0x12835B01)
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

		ALL_SCHEDULE32()

		ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
		ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
		ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
		ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
		ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
		ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
		ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
		ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
		ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
		ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
		ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
		ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
		ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
		ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
		ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
		ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
		ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
		ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
		ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
		ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
		ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
		ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
		ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
		ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
		ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
		ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
		ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
		ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
		ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
		ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
		ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
		ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)
		
		first_hash0 += a;
		first_hash1 += b;
		first_hash2 += c;
		first_hash3 += d;
		first_hash4 += e;
		first_hash5 += f;
		first_hash6 += g;
		first_hash7 += h;

		//----------------------------------------------------- LOOP HASH ------------------------------------------------
		
		hash0=0;
		hash1=0;
		hash2=0;
		hash3=0;
		hash4=0;
		hash5=0;
		hash6=0;
		hash7=0;

		indexW=0;
	//#pragma unroll 1048576
		for(index_generic=0; index_generic < ITERATION_NUMBER/2; index_generic++)
		{
			a = UINT32_C(0x6A09E667);
			b = UINT32_C(0xBB67AE85);
			c = UINT32_C(0x3C6EF372);
			d = UINT32_C(0xA54FF53A);
			e = UINT32_C(0x510E527F);
			f = UINT32_C(0x9B05688C);
			g = UINT32_C(0x1F83D9AB);
			h = UINT32_C(0x5BE0CD19);

			schedule0 = hash0;
			schedule1 = hash1;
			schedule2 = hash2;
			schedule3 = hash3;
			schedule4 = hash4;
			schedule5 = hash5;
			schedule6 = hash6;
			schedule7 = hash7;

			schedule8 = first_hash0;
			schedule9 = first_hash1;
			schedule10 = first_hash2;
			schedule11 = first_hash3;
			schedule12 = first_hash4;
			schedule13 = first_hash5;
			schedule14 = first_hash6;
			schedule15 = first_hash7;

			ALL_SCHEDULE_LAST16()

			ROUND(a, b, c, d, e, f, g, h,  schedule0, 0x428A2F98)
			ROUND(h, a, b, c, d, e, f, g,  schedule1, 0x71374491)
			ROUND(g, h, a, b, c, d, e, f,  schedule2, 0xB5C0FBCF)
			ROUND(f, g, h, a, b, c, d, e,  schedule3, 0xE9B5DBA5)
			ROUND(e, f, g, h, a, b, c, d,  schedule4, 0x3956C25B)
			ROUND(d, e, f, g, h, a, b, c,  schedule5, 0x59F111F1)
			ROUND(c, d, e, f, g, h, a, b,  schedule6, 0x923F82A4)
			ROUND(b, c, d, e, f, g, h, a,  schedule7, 0xAB1C5ED5)
			ROUND(a, b, c, d, e, f, g, h,  schedule8, 0xD807AA98)
			ROUND(h, a, b, c, d, e, f, g,  schedule9, 0x12835B01)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

			ALL_SCHEDULE32()

			ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
			ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
			ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
			ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
			ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
			ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
			ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
			ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
			ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
			ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)

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

			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  0, 0x428A2F98, 0)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  1, 0x71374491, 0)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, 0)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, 0)
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
			
			hash0 += a;
			hash1 += b;
			hash2 += c;
			hash3 += d;
			hash4 += e;
			hash5 += f;
			hash6 += g;
			hash7 += h;

			indexW += SINGLE_BLOCK_W_SIZE;
		}

		for(index_generic=ITERATION_NUMBER/2; index_generic < ITERATION_NUMBER; index_generic++)
		{
			a = UINT32_C(0x6A09E667);
			b = UINT32_C(0xBB67AE85);
			c = UINT32_C(0x3C6EF372);
			d = UINT32_C(0xA54FF53A);
			e = UINT32_C(0x510E527F);
			f = UINT32_C(0x9B05688C);
			g = UINT32_C(0x1F83D9AB);
			h = UINT32_C(0x5BE0CD19);

			schedule0 = hash0;
			schedule1 = hash1;
			schedule2 = hash2;
			schedule3 = hash3;
			schedule4 = hash4;
			schedule5 = hash5;
			schedule6 = hash6;
			schedule7 = hash7;

			schedule8 = first_hash0;
			schedule9 = first_hash1;
			schedule10 = first_hash2;
			schedule11 = first_hash3;
			schedule12 = first_hash4;
			schedule13 = first_hash5;
			schedule14 = first_hash6;
			schedule15 = first_hash7;

			ALL_SCHEDULE_LAST16()

			ROUND(a, b, c, d, e, f, g, h,  schedule0, 0x428A2F98)
			ROUND(h, a, b, c, d, e, f, g,  schedule1, 0x71374491)
			ROUND(g, h, a, b, c, d, e, f,  schedule2, 0xB5C0FBCF)
			ROUND(f, g, h, a, b, c, d, e,  schedule3, 0xE9B5DBA5)
			ROUND(e, f, g, h, a, b, c, d,  schedule4, 0x3956C25B)
			ROUND(d, e, f, g, h, a, b, c,  schedule5, 0x59F111F1)
			ROUND(c, d, e, f, g, h, a, b,  schedule6, 0x923F82A4)
			ROUND(b, c, d, e, f, g, h, a,  schedule7, 0xAB1C5ED5)
			ROUND(a, b, c, d, e, f, g, h,  schedule8, 0xD807AA98)
			ROUND(h, a, b, c, d, e, f, g,  schedule9, 0x12835B01)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0x243185BE)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0x550C7DC3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0x72BE5D74)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0x80DEB1FE)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0x9BDC06A7)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0xC19BF174)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0xE49B69C1)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0xEFBE4786)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x0FC19DC6)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x240CA1CC)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x2DE92C6F)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4A7484AA)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5CB0A9DC)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x76F988DA)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x983E5152)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0xA831C66D)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0xB00327C8)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0xBF597FC7)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0xC6E00BF3)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xD5A79147)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0x06CA6351)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0x14292967)

			ALL_SCHEDULE32()

			ROUND(a, b, c, d, e, f, g, h, schedule0, 0x27B70A85)
			ROUND(h, a, b, c, d, e, f, g, schedule1, 0x2E1B2138)
			ROUND(g, h, a, b, c, d, e, f, schedule2, 0x4D2C6DFC)
			ROUND(f, g, h, a, b, c, d, e, schedule3, 0x53380D13)
			ROUND(e, f, g, h, a, b, c, d, schedule4, 0x650A7354)
			ROUND(d, e, f, g, h, a, b, c, schedule5, 0x766A0ABB)
			ROUND(c, d, e, f, g, h, a, b, schedule6, 0x81C2C92E)
			ROUND(b, c, d, e, f, g, h, a, schedule7, 0x92722C85)
			ROUND(a, b, c, d, e, f, g, h, schedule8, 0xA2BFE8A1)
			ROUND(h, a, b, c, d, e, f, g, schedule9, 0xA81A664B)
			ROUND(g, h, a, b, c, d, e, f, schedule10, 0xC24B8B70)
			ROUND(f, g, h, a, b, c, d, e, schedule11, 0xC76C51A3)
			ROUND(e, f, g, h, a, b, c, d, schedule12, 0xD192E819)
			ROUND(d, e, f, g, h, a, b, c, schedule13, 0xD6990624)
			ROUND(c, d, e, f, g, h, a, b, schedule14, 0xF40E3585)
			ROUND(b, c, d, e, f, g, h, a, schedule15, 0x106AA070)
			ROUND(a, b, c, d, e, f, g, h, schedule16, 0x19A4C116)
			ROUND(h, a, b, c, d, e, f, g, schedule17, 0x1E376C08)
			ROUND(g, h, a, b, c, d, e, f, schedule18, 0x2748774C)
			ROUND(f, g, h, a, b, c, d, e, schedule19, 0x34B0BCB5)
			ROUND(e, f, g, h, a, b, c, d, schedule20, 0x391C0CB3)
			ROUND(d, e, f, g, h, a, b, c, schedule21, 0x4ED8AA4A)
			ROUND(c, d, e, f, g, h, a, b, schedule22, 0x5B9CCA4F)
			ROUND(b, c, d, e, f, g, h, a, schedule23, 0x682E6FF3)
			ROUND(a, b, c, d, e, f, g, h, schedule24, 0x748F82EE)
			ROUND(h, a, b, c, d, e, f, g, schedule25, 0x78A5636F)
			ROUND(g, h, a, b, c, d, e, f, schedule26, 0x84C87814)
			ROUND(f, g, h, a, b, c, d, e, schedule27, 0x8CC70208)
			ROUND(e, f, g, h, a, b, c, d, schedule28, 0x90BEFFFA)
			ROUND(d, e, f, g, h, a, b, c, schedule29, 0xA4506CEB)
			ROUND(c, d, e, f, g, h, a, b, schedule30, 0xBEF9A3F7)
			ROUND(b, c, d, e, f, g, h, a, schedule31, 0xC67178F2)

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

			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  0, 0x428A2F98, 0)
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  1, 0x71374491, 0)
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, 0)
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, 0)
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
			
			hash0 += a;
			hash1 += b;
			hash2 += c;
			hash3 += d;
			hash4 += e;
			hash5 += f;
			hash6 += g;
			hash7 += h;

			indexW += SINGLE_BLOCK_W_SIZE;
		}

		schedule0 = __byte_perm(((uint32_t *)(IV))[0], 0, 0x0123) ^ hash0;
        schedule1 = __byte_perm(((uint32_t *)(IV+4))[0], 0, 0x0123) ^ hash1;
        schedule2 = __byte_perm(((uint32_t *)(IV+8))[0], 0, 0x0123) ^ hash2;
        schedule3 = __byte_perm(((uint32_t *)(IV+12))[0], 0, 0x0123) ^ hash3;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);

		hash0 ^= LOP3LUT_XOR( 
						LOP3LUT_XOR( (TS2[(hash7 >> 24) ] & 0x000000FF), (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000), (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000)), 
							(TS1[(hash7 ) & 0xFF] & 0x0000FF00), 0x01000000
					); //RCON[0];
		hash1 ^= hash0; hash2 ^= hash1; hash3 ^= hash2;

		schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule4 >> 24], TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]) , TS3[schedule7 & 0xFF] , hash0);
		schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule5 >> 24], TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]) , TS3[schedule4 & 0xFF] , hash1);
		schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule6 >> 24], TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]) , TS3[schedule5 & 0xFF] , hash2);
		schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule7 >> 24], TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]) , TS3[schedule6 & 0xFF] , hash3);

		hash4 ^= (TS3[(hash3 >> 24)       ] & 0xFF000000) ^
				  (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash3 >>  8) & 0xFF] & 0x0000FF00) ^ 
				  (TS2[(hash3      ) & 0xFF] & 0x000000FF);
		hash5 ^= hash4;
		hash6 ^= hash5;
		hash7 ^= hash6;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);
		
		hash0 ^= (TS2[(hash7 >> 24)       ] & 0x000000FF) ^
				  (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
				  (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash7      ) & 0xFF] & 0x0000FF00) ^ 0x02000000; //RCON[1];
		hash1 ^= hash0; hash2 ^= hash1; hash3 ^= hash2;

		schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule4 >> 24], TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]) , TS3[schedule7 & 0xFF] , hash0);
		schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule5 >> 24], TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]) , TS3[schedule4 & 0xFF] , hash1);
		schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule6 >> 24], TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]) , TS3[schedule5 & 0xFF] , hash2);
		schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule7 >> 24], TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]) , TS3[schedule6 & 0xFF] , hash3);

		hash4 ^= (TS3[(hash3 >> 24)       ] & 0xFF000000) ^
				  (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash3 >>  8) & 0xFF] & 0x0000FF00) ^ 
				  (TS2[(hash3      ) & 0xFF] & 0x000000FF);
		hash5 ^= hash4;
		hash6 ^= hash5;
		hash7 ^= hash6;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);


		hash0 ^= (TS2[(hash7 >> 24)       ] & 0x000000FF) ^
				  (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
				  (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash7      ) & 0xFF] & 0x0000FF00) ^ 0x04000000; //RCON[2];
		hash1 ^= hash0; hash2 ^= hash1; hash3 ^= hash2;

		schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule4 >> 24], TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]) , TS3[schedule7 & 0xFF] , hash0);
		schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule5 >> 24], TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]) , TS3[schedule4 & 0xFF] , hash1);
		schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule6 >> 24], TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]) , TS3[schedule5 & 0xFF] , hash2);
		schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule7 >> 24], TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]) , TS3[schedule6 & 0xFF] , hash3);


		hash4 ^= (TS3[(hash3 >> 24)       ] & 0xFF000000) ^
				  (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash3 >>  8) & 0xFF] & 0x0000FF00) ^ 
				  (TS2[(hash3      ) & 0xFF] & 0x000000FF);
		hash5 ^= hash4;
		hash6 ^= hash5;
		hash7 ^= hash6;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);
		
		hash0 ^= (TS2[(hash7 >> 24)       ] & 0x000000FF) ^
				  (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
				  (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash7      ) & 0xFF] & 0x0000FF00) ^ 0x08000000; //RCON[3];
		hash1 ^= hash0; hash2 ^= hash1; hash3 ^= hash2;

		schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule4 >> 24], TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]) , TS3[schedule7 & 0xFF] , hash0);
		schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule5 >> 24], TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]) , TS3[schedule4 & 0xFF] , hash1);
		schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule6 >> 24], TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]) , TS3[schedule5 & 0xFF] , hash2);
		schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule7 >> 24], TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]) , TS3[schedule6 & 0xFF] , hash3);
		
		hash4 ^= (TS3[(hash3 >> 24)       ] & 0xFF000000) ^
				  (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash3 >>  8) & 0xFF] & 0x0000FF00) ^ 
				  (TS2[(hash3      ) & 0xFF] & 0x000000FF);
		hash5 ^= hash4;
		hash6 ^= hash5;
		hash7 ^= hash6;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);

		hash0 ^= (TS2[(hash7 >> 24)       ] & 0x000000FF) ^
				  (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
				  (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash7      ) & 0xFF] & 0x0000FF00) ^ 0x10000000; //RCON[4];
		hash1 ^= hash0; hash2 ^= hash1; hash3 ^= hash2;

		schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule4 >> 24], TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]) , TS3[schedule7 & 0xFF] , hash0);
		schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule5 >> 24], TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]) , TS3[schedule4 & 0xFF] , hash1);
		schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule6 >> 24], TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]) , TS3[schedule5 & 0xFF] , hash2);
		schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule7 >> 24], TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]) , TS3[schedule6 & 0xFF] , hash3);

		hash4 ^= (TS3[(hash3 >> 24)       ] & 0xFF000000) ^
				  (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash3 >>  8) & 0xFF] & 0x0000FF00) ^ 
				  (TS2[(hash3      ) & 0xFF] & 0x000000FF);
		hash5 ^= hash4;
		hash6 ^= hash5;
		hash7 ^= hash6;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);


		hash0 ^= (TS2[(hash7 >> 24)       ] & 0x000000FF) ^
				  (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
				  (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash7      ) & 0xFF] & 0x0000FF00) ^ 0x20000000; //RCON[5];
		hash1 ^= hash0; hash2 ^= hash1; hash3 ^= hash2;

		schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule4 >> 24], TS1[(schedule5 >> 16) & 0xFF], TS2[(schedule6 >> 8) & 0xFF]) , TS3[schedule7 & 0xFF] , hash0);
		schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule5 >> 24], TS1[(schedule6 >> 16) & 0xFF], TS2[(schedule7 >> 8) & 0xFF]) , TS3[schedule4 & 0xFF] , hash1);
		schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule6 >> 24], TS1[(schedule7 >> 16) & 0xFF], TS2[(schedule4 >> 8) & 0xFF]) , TS3[schedule5 & 0xFF] , hash2);
		schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule7 >> 24], TS1[(schedule4 >> 16) & 0xFF], TS2[(schedule5 >> 8) & 0xFF]) , TS3[schedule6 & 0xFF] , hash3);

		hash4 ^= (TS3[(hash3 >> 24)       ] & 0xFF000000) ^
				  (TS0[(hash3 >> 16) & 0xFF] & 0x00FF0000) ^
				  (TS1[(hash3 >>  8) & 0xFF] & 0x0000FF00) ^ 
				  (TS2[(hash3      ) & 0xFF] & 0x000000FF);
		hash5 ^= hash4;
		hash6 ^= hash5;
		hash7 ^= hash6;

		schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule0 >> 24], TS1[(schedule1 >> 16) & 0xFF], TS2[(schedule2 >> 8) & 0xFF]) , TS3[schedule3 & 0xFF] , hash4);
		schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule1 >> 24], TS1[(schedule2 >> 16) & 0xFF], TS2[(schedule3 >> 8) & 0xFF]) , TS3[schedule0 & 0xFF] , hash5);
		schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule2 >> 24], TS1[(schedule3 >> 16) & 0xFF], TS2[(schedule0 >> 8) & 0xFF]) , TS3[schedule1 & 0xFF] , hash6);
		schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[schedule3 >> 24], TS1[(schedule0 >> 16) & 0xFF], TS2[(schedule1 >> 8) & 0xFF]) , TS3[schedule2 & 0xFF] , hash7);

		hash0 ^= (TS2[(hash7 >> 24)       ] & 0x000000FF) ^
			  (TS3[(hash7 >> 16) & 0xFF] & 0xFF000000) ^
			  (TS0[(hash7 >>  8) & 0xFF] & 0x00FF0000) ^
			  (TS1[(hash7      ) & 0xFF] & 0x0000FF00) ^ 0x40000000; //RCON[6];
		hash1 ^= hash0;
		hash2 ^= hash1;
		hash3 ^= hash2;

		schedule0 = (TS2[(schedule4 >> 24)       ] & 0xFF000000) ^
			 (TS3[(schedule5 >> 16) & 0xFF] & 0x00FF0000) ^
			 (TS0[(schedule6 >>  8) & 0xFF] & 0x0000FF00) ^
			 (TS1[(schedule7      ) & 0xFF] & 0x000000FF) ^ hash0;

		schedule1 = (TS2[(schedule5 >> 24)       ] & 0xFF000000) ^
			 (TS3[(schedule6 >> 16) & 0xFF] & 0x00FF0000) ^
			 (TS0[(schedule7 >>  8) & 0xFF] & 0x0000FF00) ^
			 (TS1[(schedule4      ) & 0xFF] & 0x000000FF) ^ hash1;

		schedule2 = (TS2[(schedule6 >> 24)       ] & 0xFF000000) ^
			 (TS3[(schedule7 >> 16) & 0xFF] & 0x00FF0000) ^
			 (TS0[(schedule4 >>  8) & 0xFF] & 0x0000FF00) ^
			 (TS1[(schedule5      ) & 0xFF] & 0x000000FF) ^ hash2;

		schedule3 = (TS2[(schedule7 >> 24)       ] & 0xFF000000) ^
			 (TS3[(schedule4 >> 16) & 0xFF] & 0x00FF0000) ^
			 (TS0[(schedule5 >>  8) & 0xFF] & 0x0000FF00) ^
			 (TS1[(schedule6      ) & 0xFF] & 0x000000FF) ^ hash3;

		schedule4 = __byte_perm(schedule0, 0, 0x0123);
		schedule5 = __byte_perm(schedule1, 0, 0x0123);
		schedule6 = __byte_perm(schedule2, 0, 0x0123);
		schedule7 = __byte_perm(schedule3, 0, 0x0123);
		
		if (
			((vmkKey[0] ^ ((uint8_t) schedule4)) == 0x2c) &&
			((vmkKey[1] ^ ((uint8_t) (schedule4 >> 8))) == 0x00) &&
			((vmkKey[9] ^ ((uint8_t) (schedule6 >> 8))) == 0x20)
		)
		{
			if(
				(strict_check == 0 && ((vmkKey[8] ^ ((uint8_t) schedule6)) <= 0x05))
				||
				(strict_check == 1 && ((vmkKey[8] ^ ((uint8_t) schedule6)) == 0x03))
			)
			{
				printf("schedule4=%x, char: %x, >>8: %x\n", schedule4, (uint8_t)schedule4, (uint8_t) (schedule4 >> 8));
				printf("(vmkKey[0] ^ ((uint8_t) schedule4)): %x\n", (vmkKey[0] ^ ((uint8_t) schedule4)));
				printf("(vmkKey[1] ^ ((uint8_t) (schedule4 >> 8))): %x\n", (vmkKey[1] ^ ((uint8_t) (schedule4 >> 8))));
				printf("schedule6=%x, char: %x, >>8: %x\n", schedule6, (uint8_t)schedule6, (uint8_t) (schedule6 >> 8));
				printf("(vmkKey[8] ^ ((uint8_t) schedule6)): %x\n", (vmkKey[8] ^ ((uint8_t) schedule6)));
				printf("(vmkKey[9] ^ ((uint8_t) (schedule6 >> 8))): %x\n", (vmkKey[9] ^ ((uint8_t) (schedule6 >> 8))));

				*found = gIndex;
				break;
			}	
		}

		gIndex += (blockDim.x * gridDim.x);
	}

	return;
}
