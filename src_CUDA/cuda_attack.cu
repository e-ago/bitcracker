#include "bitcracker.h"

int			*deviceFound, *hostFound;
char			*hostPassword;
unsigned char		outPsw[MAX_INPUT_PASSWORD_LEN+1];
int			outIndexPsw=0;

static int check_match() {
	int i=0;

	if (hostFound[0] >= 0){
		outIndexPsw=(hostFound[0]);
		snprintf((char*)outPsw, PSW_CHAR_SIZE, "%s", (char *)(hostPassword+(outIndexPsw*PSW_CHAR_SIZE)));
		for(i=0; i<MAX_INPUT_PASSWORD_LEN; i++)
			if(outPsw[i] == 0x80 || outPsw[i] == 0xffffff80) outPsw[i]='\0';

		return 1;
	}

	return 0;
}

char *cuda_attack(
	char *dname, uint32_t * w_blocks_d, 
	unsigned char * encryptedVMK, 
	unsigned char * nonce,  unsigned char * encryptedMAC,
	int gridBlocks)
{
	FILE		*fp;
	int		numReadPassword, match=0, done=0, w_blocks_h[4], cudaThreads=CUDA_THREADS_NO_MAC;
	long long	totReadPsw = 0;
	uint8_t		vmkIV[IV_SIZE], *d_vmkIV, *d_vmk;
	uint8_t		macIV[IV_SIZE], *d_macIV, *d_mac;
	uint8_t		computeMacIV[IV_SIZE], *d_computeMacIV;
	cudaEvent_t	start, stop;
	cudaStream_t	stream;
	float 		elapsedTime;
	uint32_t		*hostPasswordInt, *devicePasswordInt;

	// cudaTextureObject_t texObj_blocks = 0;
	// cudaTextureObject_t texObj_pswd = 0;

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
	
	//-------- vmkIV setup ------
	memset(vmkIV, 0, IV_SIZE);
	vmkIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
	memcpy(vmkIV + 1, nonce, NONCE_SIZE);
	if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
	{
		fprintf(stderr, "Attack nonce error\n");
		return NULL;
	}
	vmkIV[IV_SIZE-1] = 1; 
	// -----------------------

	if(mac_comparison == 1)
	{
		cudaThreads=CUDA_THREADS_WITH_MAC;

		//-------- macIV setup ------
		memset(macIV, 0, IV_SIZE);
		macIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
		memcpy(macIV + 1, nonce, NONCE_SIZE);
		if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
		{
			fprintf(stderr, "Attack nonce error\n");
			return NULL;
		}
		macIV[IV_SIZE-1] = 0; 
		// -----------------------

		//-------- computeMacIV setup ------
		memset(computeMacIV, 0, IV_SIZE);
		computeMacIV[0] = 0x3a;
		memcpy(computeMacIV + 1, nonce, NONCE_SIZE);
		if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
		{
			fprintf(stderr, "Attack nonce error\n");
			return NULL;
		}
		computeMacIV[IV_SIZE-1] = 0x2c; 
		// -----------------------
	}

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

	// ---- HOST VARS ----
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostPasswordInt, tot_psw * PSW_INT_SIZE * sizeof(uint32_t), cudaHostAllocDefault) );
	memset(hostPasswordInt, tot_psw * PSW_INT_SIZE * sizeof(uint32_t), 0);
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostPassword, tot_psw*PSW_CHAR_SIZE*sizeof(char), cudaHostAllocDefault) );
	BITCRACKER_CUDA_CHECK( cudaHostAlloc( (void ** ) &hostFound, sizeof(uint32_t), cudaHostAllocDefault) );
	*hostFound = -1;
	// ------------------------

	// ---- CUDA VARS ----
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &d_vmk, VMK_FULL_SIZE*sizeof(uint8_t)) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy(d_vmk, (encryptedVMK), VMK_FULL_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );
	
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &d_vmkIV, IV_SIZE*sizeof(uint8_t)) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy(d_vmkIV, vmkIV, IV_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );

	if(mac_comparison == 1)
	{
		BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &d_mac, MAC_SIZE*sizeof(uint8_t)) );
		BITCRACKER_CUDA_CHECK( cudaMemcpy(d_mac, encryptedMAC, MAC_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );

		BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &d_macIV, IV_SIZE*sizeof(uint8_t)) );
		BITCRACKER_CUDA_CHECK( cudaMemcpy(d_macIV, macIV, IV_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );
	
		BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &d_computeMacIV, IV_SIZE*sizeof(uint8_t)) );
		BITCRACKER_CUDA_CHECK( cudaMemcpy(d_computeMacIV, computeMacIV, IV_SIZE*sizeof(uint8_t), cudaMemcpyHostToDevice) );
	}

	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &devicePasswordInt, (tot_psw * PSW_INT_SIZE * sizeof(uint32_t)) ) );	
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &deviceFound, (sizeof(uint32_t)) ) );
	BITCRACKER_CUDA_CHECK( cudaMemcpy(deviceFound, hostFound, sizeof(uint32_t), cudaMemcpyHostToDevice) );
	BITCRACKER_CUDA_CHECK( cudaStreamCreate(&(stream)) );
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&start) );
	BITCRACKER_CUDA_CHECK( cudaEventCreate(&stop) );
	
	// ---------------------

#if 0
	// Allocate CUDA array in device memory
    cudaChannelFormatDesc channelDesc_blocks = cudaCreateChannelDesc(32, 0, 0, 0, cudaChannelFormatKindFloat);

	// Specify texture
	struct cudaResourceDesc resDesc_blocks;
	memset(&resDesc_blocks, 0, sizeof(resDesc_blocks));
	resDesc_blocks.resType = cudaResourceTypeLinear;
	resDesc_blocks.res.linear.devPtr = w_blocks_d;
	resDesc_blocks.res.linear.desc = channelDesc_blocks;
	resDesc_blocks.res.linear.sizeInBytes = (SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(uint32_t));

	// Specify texture object parameters
	struct cudaTextureDesc texDesc_blocks;
	memset(&texDesc_blocks, 0, sizeof(texDesc_blocks));
	texDesc_blocks.addressMode[0] = cudaAddressModeWrap;
	texDesc_blocks.filterMode = cudaFilterModeLinear;
	texDesc_blocks.readMode = cudaReadModeElementType;
	texDesc_blocks.normalizedCoords = 1;

	// Create texture object
	cudaCreateTextureObject(&texObj_blocks, &resDesc_blocks, &texDesc_blocks, NULL);
	
	// Allocate CUDA array in device memory
	cudaChannelFormatDesc channelDesc_pswd = cudaCreateChannelDesc(32, 0, 0, 0, cudaChannelFormatKindFloat);

	// Specify texture
	struct cudaResourceDesc resDesc_pswd;
	memset(&resDesc_pswd, 0, sizeof(resDesc_pswd));
	resDesc_pswd.resType = cudaResourceTypeLinear;
	resDesc_pswd.res.linear.devPtr = devicePasswordInt;
	resDesc_pswd.res.linear.desc = channelDesc_pswd;
	resDesc_pswd.res.linear.sizeInBytes = (tot_psw * PSW_INT_SIZE * sizeof(uint32_t));

	// Specify texture object parameters
	struct cudaTextureDesc texDesc_pswd;
	memset(&texDesc_pswd, 0, sizeof(texDesc_pswd));
	texDesc_pswd.addressMode[0] = cudaAddressModeWrap;
	texDesc_pswd.filterMode = cudaFilterModeLinear;
	texDesc_pswd.readMode = cudaReadModeElementType;
	texDesc_pswd.normalizedCoords = 1;

	// Create texture object
	cudaCreateTextureObject(&texObj_pswd, &resDesc_pswd, &texDesc_pswd, NULL);
#endif

	BITCRACKER_CUDA_CHECK( cudaMemcpy(w_blocks_h, w_blocks_d, 4*sizeof(int), cudaMemcpyDeviceToHost) );

	// BITCRACKER_CUDA_CHECK (cudaDeviceSetCacheConfig( cudaFuncCachePreferL1 ) );

	printf("Type of attack: %s\nCUDA Threads: %d\nCUDA Blocks: %d\nPsw per thread: %d\nMax Psw per kernel: %d\nDictionary: %s\nStrict Check (-s): %s\nMAC Comparison (-m): %s\n\n", 
		(attack_mode==MODE_USER_PASS)?"User Password":"Recovery Password", cudaThreads, gridBlocks, psw_x_thread, tot_psw, (fp == stdin)?"standard input":dname, (strict_check == 1)?"Yes":"No", (mac_comparison == 1)?"Yes":"No");

	uint32_t s0 =  ((uint32_t)salt[0] ) << 24 | ((uint32_t)salt[1] ) << 16 | ((uint32_t)salt[2] ) <<  8 | ((uint32_t)salt[3]); 
	uint32_t s1 =  ((uint32_t)salt[4] ) << 24 | ((uint32_t)salt[5] ) << 16 | ((uint32_t)salt[6] ) <<  8 | ((uint32_t)salt[7]); 
	uint32_t s2 =  ((uint32_t)salt[8] ) << 24 | ((uint32_t)salt[9] ) << 16 | ((uint32_t)salt[10])  <<  8 | ((uint32_t)salt[11]);
	uint32_t s3 =  ((uint32_t)salt[12])  << 24 | ((uint32_t)salt[13])  << 16 | ((uint32_t)salt[14])  <<  8 | ((uint32_t)salt[15]);

	while(!done) {
		numReadPassword = readFilePassword(&hostPasswordInt, &hostPassword, tot_psw, fp);
		if(numReadPassword <= 0) { done=1; continue; }
		BITCRACKER_CUDA_CHECK( cudaMemcpyAsync(devicePasswordInt, hostPasswordInt, tot_psw * PSW_INT_SIZE * sizeof(uint32_t), cudaMemcpyHostToDevice, stream) );
		BITCRACKER_CUDA_CHECK( cudaEventRecord(start, stream) );
		if(mac_comparison == 1)
		{
			//Slower attack with MAC verification
			decrypt_vmk_with_mac<<<gridBlocks, CUDA_THREADS_WITH_MAC, 0, stream>>>( 
												numReadPassword, deviceFound, 
												d_vmk, d_vmkIV, d_mac, d_macIV, d_computeMacIV,
												w_blocks_h[0], w_blocks_h[1], w_blocks_h[2], w_blocks_h[3],
												s0, s1, s2, s3, attack_mode,
												w_blocks_d, devicePasswordInt// texObj_blocks, texObj_pswd
											);
		}
		else
		{
			//Faster attack
			decrypt_vmk<<<gridBlocks, CUDA_THREADS_NO_MAC, 0, stream>>>(
											numReadPassword, deviceFound, d_vmk, d_vmkIV, strict_check, 
											w_blocks_h[0], w_blocks_h[1], w_blocks_h[2], w_blocks_h[3],
											s0, s1, s2, s3, attack_mode,
											w_blocks_d, devicePasswordInt);
		}

		BITCRACKER_CUDA_CHECK_LAST_ERROR();
		BITCRACKER_CUDA_CHECK( cudaEventRecord(stop, stream) );
		BITCRACKER_CUDA_CHECK( cudaMemcpyAsync(hostFound, deviceFound, sizeof(unsigned int), cudaMemcpyDeviceToHost, stream) );
		BITCRACKER_CUDA_CHECK( cudaStreamSynchronize(stream) );
		totReadPsw += numReadPassword;
		BITCRACKER_CUDA_CHECK( cudaEventElapsedTime(&elapsedTime, start, stop) );

		printf("CUDA Kernel execution:\n\tEffective passwords: %d\n\tPasswords Range:\n\t\t%s\n\t\t.....\n\t\t%s\n\tTime: %f sec\n\tPasswords x second: %8.2f pw/sec\n", 
						numReadPassword, 
						(char *)hostPassword, 
						(char *)(hostPassword+((numReadPassword-1)*PSW_CHAR_SIZE)), 
						(elapsedTime/1000.0), numReadPassword/(elapsedTime/1000.0));
		
		match=check_match();
		if(match) done=1;
    		if(feof(fp)) done=1;
	}

	if (fp != stdin)
		fclose(fp);

	if(match==1)
		printf("\n\n================================================\nCUDA attack completed\nPasswords evaluated: %lld\nPassword found: %s\n================================================\n\n", totReadPsw, outPsw);
	else
		printf("\n\n================================================\nCUDA attack completed\nPasswords evaluated: %lld\nPassword not found!\n================================================\n\n", totReadPsw);

	BITCRACKER_CUDA_CHECK( cudaFreeHost(hostPassword) );
	BITCRACKER_CUDA_CHECK( cudaFree(devicePasswordInt) );
	BITCRACKER_CUDA_CHECK( cudaFree(deviceFound) );
	BITCRACKER_CUDA_CHECK( cudaStreamDestroy(stream) );
	
	// BITCRACKER_CUDA_CHECK( cudaDestroyTextureObject(texObj_blocks) );
	// BITCRACKER_CUDA_CHECK( cudaDestroyTextureObject(texObj_pswd) );

	return NULL;
}

#define END_STRING 0x80 //0xFF
__global__ void decrypt_vmk(int tot_psw_kernel, int *found, unsigned char * vmkKey, 
	unsigned char * IV, int strict_check, int v0, int v1, int v2, int v3,
	uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3, int method,
	uint32_t * w_blocks_d, uint32_t * dev_passwd)
	{
    
		uint32_t schedule0, schedule1, schedule2, schedule3, schedule4, schedule5, schedule6, schedule7, schedule8, schedule9;
	 uint32_t schedule10, schedule11, schedule12, schedule13, schedule14, schedule15, schedule16, schedule17, schedule18, schedule19;
	 uint32_t schedule20, schedule21, schedule22, schedule23, schedule24, schedule25, schedule26, schedule27, schedule28, schedule29;
	 uint32_t schedule30, schedule31;
	 uint32_t first_hash0, first_hash1, first_hash2, first_hash3, first_hash4, first_hash5, first_hash6, first_hash7;
	 uint32_t hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	 uint32_t a, b, c, d, e, f, g, h;
 
		 int gIndex = (threadIdx.x+blockIdx.x*blockDim.x);
	 int index_generic;
	 int indexW=(gIndex*PSW_INT_SIZE);
	 int8_t redo=0;
 
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
		 indexW=(gIndex*PSW_INT_SIZE);
		 redo=0;
		 schedule0 = dev_passwd[indexW+0]; //(uint32_t) (tex1D<float>(texObj_pswd, (indexW+0)));
		 schedule1 = dev_passwd[indexW+1];
		 schedule2 = dev_passwd[indexW+2];
		 schedule3 = dev_passwd[indexW+3];
		 schedule4 = dev_passwd[indexW+4];
		 schedule5 = dev_passwd[indexW+5];
		 schedule6 = dev_passwd[indexW+6];
		 schedule7 = dev_passwd[indexW+7];
		 schedule8 = dev_passwd[indexW+8];
		 schedule9 = dev_passwd[indexW+9];
		 schedule10 = dev_passwd[indexW+10];
		 schedule11 = dev_passwd[indexW+11];
		 schedule12 = dev_passwd[indexW+12];
		 schedule13 = dev_passwd[indexW+13];
		 schedule14 = dev_passwd[indexW+14];
		 //Input password is shorter than FIRST_LENGHT
		 if(schedule14 == 0xFFFFFFFF) schedule14=0;
		 else if(method == MODE_USER_PASS) redo=1;
		 schedule15 = dev_passwd[indexW+15];
 
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
 
		 //User password only
		 if(method == MODE_USER_PASS)
		 {
			 if(redo == 1)
			 {
				 schedule0 = dev_passwd[indexW+16];
				 schedule1 = dev_passwd[indexW+17];
				 schedule2 = dev_passwd[indexW+18];
				 schedule3 = dev_passwd[indexW+19];
				 schedule4 = dev_passwd[indexW+20];
				 schedule5 = dev_passwd[indexW+21];
				 schedule6 = dev_passwd[indexW+22];
				 schedule7 = dev_passwd[indexW+23];
				 schedule8 = dev_passwd[indexW+24];
				 schedule9 = dev_passwd[indexW+25];
				 schedule10 = dev_passwd[indexW+26];
				 schedule11 = dev_passwd[indexW+27];
				 schedule12 = dev_passwd[indexW+28];
				 schedule13 = dev_passwd[indexW+29];
				 schedule14 = dev_passwd[indexW+30];
				 schedule15 = dev_passwd[indexW+31];
 
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
 
 //----------------------------------------------------- SECOND HASH ------------------------------------------------
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
			 ALL_ROUND_B1_1()
			 ALL_SCHEDULE32()
			 ALL_ROUND_B1_2()
 
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
 
			 ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h,  0, 0x428A2F98, v0)
			 ROUND_SECOND_BLOCK_CONST(h, a, b, c, d, e, f, g,  1, 0x71374491, v1)
			 ROUND_SECOND_BLOCK_CONST(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, v2)
			 ROUND_SECOND_BLOCK_CONST(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, v3)
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d,  4, 0x3956C25B, w_blocks_d[indexW+4])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c,  5, 0x59F111F1, w_blocks_d[indexW+5])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b,  6, 0x923F82A4, w_blocks_d[indexW+6])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a,  7, 0xAB1C5ED5, w_blocks_d[indexW+7])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  8, 0xD807AA98, w_blocks_d[indexW+8])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  9, 0x12835B01, w_blocks_d[indexW+9])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 10, 0x243185BE, w_blocks_d[indexW+10])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 11, 0x550C7DC3, w_blocks_d[indexW+11])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 12, 0x72BE5D74, w_blocks_d[indexW+12])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 13, 0x80DEB1FE, w_blocks_d[indexW+13])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 14, 0x9BDC06A7, w_blocks_d[indexW+14])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 15, 0xC19BF174, w_blocks_d[indexW+15])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 16, 0xE49B69C1, w_blocks_d[indexW+16])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 17, 0xEFBE4786, w_blocks_d[indexW+17])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 18, 0x0FC19DC6, w_blocks_d[indexW+18])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 19, 0x240CA1CC, w_blocks_d[indexW+19])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 20, 0x2DE92C6F, w_blocks_d[indexW+20])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 21, 0x4A7484AA, w_blocks_d[indexW+21])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 22, 0x5CB0A9DC, w_blocks_d[indexW+22])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 23, 0x76F988DA, w_blocks_d[indexW+23])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 24, 0x983E5152, w_blocks_d[indexW+24])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 25, 0xA831C66D, w_blocks_d[indexW+25])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 26, 0xB00327C8, w_blocks_d[indexW+26])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 27, 0xBF597FC7, w_blocks_d[indexW+27])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 28, 0xC6E00BF3, w_blocks_d[indexW+28])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 29, 0xD5A79147, w_blocks_d[indexW+29])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 30, 0x06CA6351, w_blocks_d[indexW+30])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 31, 0x14292967, w_blocks_d[indexW+31])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 32, 0x27B70A85, w_blocks_d[indexW+32])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 33, 0x2E1B2138, w_blocks_d[indexW+33])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 34, 0x4D2C6DFC, w_blocks_d[indexW+34])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 35, 0x53380D13, w_blocks_d[indexW+35])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 36, 0x650A7354, w_blocks_d[indexW+36])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 37, 0x766A0ABB, w_blocks_d[indexW+37])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 38, 0x81C2C92E, w_blocks_d[indexW+38])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 39, 0x92722C85, w_blocks_d[indexW+39])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 40, 0xA2BFE8A1, w_blocks_d[indexW+40])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 41, 0xA81A664B, w_blocks_d[indexW+41])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 42, 0xC24B8B70, w_blocks_d[indexW+42])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 43, 0xC76C51A3, w_blocks_d[indexW+43])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 44, 0xD192E819, w_blocks_d[indexW+44])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 45, 0xD6990624, w_blocks_d[indexW+45])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 46, 0xF40E3585, w_blocks_d[indexW+46])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 47, 0x106AA070, w_blocks_d[indexW+47])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 48, 0x19A4C116, w_blocks_d[indexW+48])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 49, 0x1E376C08, w_blocks_d[indexW+49])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 50, 0x2748774C, w_blocks_d[indexW+50])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 51, 0x34B0BCB5, w_blocks_d[indexW+51])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 52, 0x391C0CB3, w_blocks_d[indexW+52])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 53, 0x4ED8AA4A, w_blocks_d[indexW+53])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 54, 0x5B9CCA4F, w_blocks_d[indexW+54])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 55, 0x682E6FF3, w_blocks_d[indexW+55])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 56, 0x748F82EE, w_blocks_d[indexW+56])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 57, 0x78A5636F, w_blocks_d[indexW+57])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 58, 0x84C87814, w_blocks_d[indexW+58])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 59, 0x8CC70208, w_blocks_d[indexW+59])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 60, 0x90BEFFFA, w_blocks_d[indexW+60])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 61, 0xA4506CEB, w_blocks_d[indexW+61])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 62, 0xBEF9A3F7, w_blocks_d[indexW+62])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 63, 0xC67178F2, w_blocks_d[indexW+63])
			 
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
			 ALL_ROUND_B1_1()
			 ALL_SCHEDULE32()
			 ALL_ROUND_B1_2()
 
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
 
			 ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h,  0, 0x428A2F98, v0)
			 ROUND_SECOND_BLOCK_CONST(h, a, b, c, d, e, f, g,  1, 0x71374491, v1)
			 ROUND_SECOND_BLOCK_CONST(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, v2)
			 ROUND_SECOND_BLOCK_CONST(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, v3)
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d,  4, 0x3956C25B, w_blocks_d[indexW+4])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c,  5, 0x59F111F1, w_blocks_d[indexW+5])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b,  6, 0x923F82A4, w_blocks_d[indexW+6])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a,  7, 0xAB1C5ED5, w_blocks_d[indexW+7])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  8, 0xD807AA98, w_blocks_d[indexW+8])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  9, 0x12835B01, w_blocks_d[indexW+9])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 10, 0x243185BE, w_blocks_d[indexW+10])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 11, 0x550C7DC3, w_blocks_d[indexW+11])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 12, 0x72BE5D74, w_blocks_d[indexW+12])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 13, 0x80DEB1FE, w_blocks_d[indexW+13])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 14, 0x9BDC06A7, w_blocks_d[indexW+14])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 15, 0xC19BF174, w_blocks_d[indexW+15])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 16, 0xE49B69C1, w_blocks_d[indexW+16])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 17, 0xEFBE4786, w_blocks_d[indexW+17])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 18, 0x0FC19DC6, w_blocks_d[indexW+18])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 19, 0x240CA1CC, w_blocks_d[indexW+19])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 20, 0x2DE92C6F, w_blocks_d[indexW+20])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 21, 0x4A7484AA, w_blocks_d[indexW+21])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 22, 0x5CB0A9DC, w_blocks_d[indexW+22])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 23, 0x76F988DA, w_blocks_d[indexW+23])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 24, 0x983E5152, w_blocks_d[indexW+24])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 25, 0xA831C66D, w_blocks_d[indexW+25])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 26, 0xB00327C8, w_blocks_d[indexW+26])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 27, 0xBF597FC7, w_blocks_d[indexW+27])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 28, 0xC6E00BF3, w_blocks_d[indexW+28])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 29, 0xD5A79147, w_blocks_d[indexW+29])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 30, 0x06CA6351, w_blocks_d[indexW+30])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 31, 0x14292967, w_blocks_d[indexW+31])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 32, 0x27B70A85, w_blocks_d[indexW+32])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 33, 0x2E1B2138, w_blocks_d[indexW+33])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 34, 0x4D2C6DFC, w_blocks_d[indexW+34])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 35, 0x53380D13, w_blocks_d[indexW+35])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 36, 0x650A7354, w_blocks_d[indexW+36])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 37, 0x766A0ABB, w_blocks_d[indexW+37])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 38, 0x81C2C92E, w_blocks_d[indexW+38])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 39, 0x92722C85, w_blocks_d[indexW+39])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 40, 0xA2BFE8A1, w_blocks_d[indexW+40])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 41, 0xA81A664B, w_blocks_d[indexW+41])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 42, 0xC24B8B70, w_blocks_d[indexW+42])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 43, 0xC76C51A3, w_blocks_d[indexW+43])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 44, 0xD192E819, w_blocks_d[indexW+44])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 45, 0xD6990624, w_blocks_d[indexW+45])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 46, 0xF40E3585, w_blocks_d[indexW+46])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 47, 0x106AA070, w_blocks_d[indexW+47])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 48, 0x19A4C116, w_blocks_d[indexW+48])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 49, 0x1E376C08, w_blocks_d[indexW+49])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 50, 0x2748774C, w_blocks_d[indexW+50])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 51, 0x34B0BCB5, w_blocks_d[indexW+51])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 52, 0x391C0CB3, w_blocks_d[indexW+52])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 53, 0x4ED8AA4A, w_blocks_d[indexW+53])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 54, 0x5B9CCA4F, w_blocks_d[indexW+54])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 55, 0x682E6FF3, w_blocks_d[indexW+55])
			 ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 56, 0x748F82EE, w_blocks_d[indexW+56])
			 ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 57, 0x78A5636F, w_blocks_d[indexW+57])
			 ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 58, 0x84C87814, w_blocks_d[indexW+58])
			 ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 59, 0x8CC70208, w_blocks_d[indexW+59])
			 ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 60, 0x90BEFFFA, w_blocks_d[indexW+60])
			 ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 61, 0xA4506CEB, w_blocks_d[indexW+61])
			 ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 62, 0xBEF9A3F7, w_blocks_d[indexW+62])
			 ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 63, 0xC67178F2, w_blocks_d[indexW+63])
 
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

 //----------------------------------------------------- FINAL CHECK ------------------------------------------------
 
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
			 ((vmkKey[4] ^ ((uint8_t) schedule5)) == 0x01) &&
			 ((vmkKey[5] ^ ((uint8_t) (schedule5 >> 8))) == 0x00) &&
			 ((vmkKey[9] ^ ((uint8_t) (schedule6 >> 8))) == 0x20)
		 )
		 {
			 if(
				 (strict_check == 0 && ((vmkKey[8] ^ ((uint8_t) schedule6)) <= 0x05))
				 ||
				 (strict_check == 1 && ((vmkKey[8] ^ ((uint8_t) schedule6)) == 0x03))
			 )
			 {
				 *found = gIndex;
				 break;
			 }	
		 }
 
		 gIndex += (blockDim.x * gridDim.x);
	 }
 
	 return;
 }

__device__ void encrypt(
	uint32_t k0, uint32_t k1, uint32_t k2, uint32_t k3, uint32_t k4, uint32_t k5, uint32_t k6, uint32_t k7,
	uint32_t m0, uint32_t m1, uint32_t m2, uint32_t m3, 
	uint32_t * output0, uint32_t * output1, uint32_t * output2, uint32_t * output3
)
{
	uint32_t enc_schedule0, enc_schedule1, enc_schedule2, enc_schedule3, enc_schedule4, enc_schedule5, enc_schedule6, enc_schedule7;
	uint32_t local_key0, local_key1, local_key2, local_key3, local_key4, local_key5, local_key6, local_key7;

	local_key0=k0;
	local_key1=k1;
	local_key2=k2;
	local_key3=k3;
	local_key4=k4;
	local_key5=k5;
	local_key6=k6;
	local_key7=k7;

	enc_schedule0 = __byte_perm(m0, 0, 0x0123) ^ local_key0;
	enc_schedule1 = __byte_perm(m1, 0, 0x0123) ^ local_key1;
	enc_schedule2 = __byte_perm(m2, 0, 0x0123) ^ local_key2;
	enc_schedule3 = __byte_perm(m3, 0, 0x0123) ^ local_key3;

	enc_schedule4 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule0 >> 24], TS1[(enc_schedule1 >> 16) & 0xFF], TS2[(enc_schedule2 >> 8) & 0xFF]) , TS3[enc_schedule3 & 0xFF] , local_key4);
	enc_schedule5 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule1 >> 24], TS1[(enc_schedule2 >> 16) & 0xFF], TS2[(enc_schedule3 >> 8) & 0xFF]) , TS3[enc_schedule0 & 0xFF] , local_key5);
	enc_schedule6 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule2 >> 24], TS1[(enc_schedule3 >> 16) & 0xFF], TS2[(enc_schedule0 >> 8) & 0xFF]) , TS3[enc_schedule1 & 0xFF] , local_key6);
	enc_schedule7 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule3 >> 24], TS1[(enc_schedule0 >> 16) & 0xFF], TS2[(enc_schedule1 >> 8) & 0xFF]) , TS3[enc_schedule2 & 0xFF] , local_key7);

	local_key0 ^= LOP3LUT_XOR( 
					LOP3LUT_XOR( (TS2[(local_key7 >> 24) ] & 0x000000FF), (TS3[(local_key7 >> 16) & 0xFF] & 0xFF000000), (TS0[(local_key7 >>  8) & 0xFF] & 0x00FF0000)), 
						(TS1[(local_key7 ) & 0xFF] & 0x0000FF00), 0x01000000
				); //RCON[0];
	local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

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
	local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

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
	local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

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
	local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

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
	local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

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
	local_key1 ^= local_key0; local_key2 ^= local_key1; local_key3 ^= local_key2;

	enc_schedule0 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule4 >> 24], TS1[(enc_schedule5 >> 16) & 0xFF], TS2[(enc_schedule6 >> 8) & 0xFF]) , TS3[enc_schedule7 & 0xFF] , local_key0);
	enc_schedule1 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule5 >> 24], TS1[(enc_schedule6 >> 16) & 0xFF], TS2[(enc_schedule7 >> 8) & 0xFF]) , TS3[enc_schedule4 & 0xFF] , local_key1);
	enc_schedule2 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule6 >> 24], TS1[(enc_schedule7 >> 16) & 0xFF], TS2[(enc_schedule4 >> 8) & 0xFF]) , TS3[enc_schedule5 & 0xFF] , local_key2);
	enc_schedule3 = LOP3LUT_XOR(LOP3LUT_XOR(TS0[enc_schedule7 >> 24], TS1[(enc_schedule4 >> 16) & 0xFF], TS2[(enc_schedule5 >> 8) & 0xFF]) , TS3[enc_schedule6 & 0xFF] , local_key3);

	local_key4 ^= (TS3[(local_key3 >> 24)] & 0xFF000000) ^
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

	local_key0 ^= (TS2[(local_key7 >> 24)] & 0x000000FF) ^
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

	output0[0] = __byte_perm(enc_schedule0, 0, 0x0123);
	output1[0] = __byte_perm(enc_schedule1, 0, 0x0123);
	output2[0] = __byte_perm(enc_schedule2, 0, 0x0123);
	output3[0] = __byte_perm(enc_schedule3, 0, 0x0123);

}

__global__ void decrypt_vmk_with_mac(
					int tot_psw_kernel, int *found, 
					unsigned char * vmkKey, unsigned char * vmkIV,
					unsigned char * mac, unsigned char * macIV, unsigned char * computeMacIV,
					int v0, int v1, int v2, int v3,
					uint32_t s0, uint32_t s1, uint32_t s2, uint32_t s3,
					int method,
					uint32_t * w_blocks_d, uint32_t * dev_passwd
)
{
	uint32_t schedule0, schedule1, schedule2, schedule3, schedule4, schedule5, schedule6, schedule7, schedule8, schedule9;
	uint32_t schedule10, schedule11, schedule12, schedule13, schedule14, schedule15, schedule16, schedule17, schedule18, schedule19;
	uint32_t schedule20, schedule21, schedule22, schedule23, schedule24, schedule25, schedule26, schedule27, schedule28, schedule29;
	uint32_t schedule30, schedule31;
	uint32_t first_hash0, first_hash1, first_hash2, first_hash3, first_hash4, first_hash5, first_hash6, first_hash7;
	uint32_t hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7;
	uint32_t a, b, c, d, e, f, g, h;

	int gIndex = (threadIdx.x+blockIdx.x*blockDim.x);
	int index_generic;
	int indexW=(gIndex *PSW_INT_SIZE);
	int8_t redo=0;

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
		indexW=(gIndex *PSW_INT_SIZE);
		redo=0;
		schedule0 = (uint32_t) dev_passwd[indexW+0];
		schedule1 = (uint32_t) dev_passwd[indexW+1];
		schedule2 = (uint32_t) dev_passwd[indexW+2];
		schedule3 = (uint32_t) dev_passwd[indexW+3];
		schedule4 = (uint32_t) dev_passwd[indexW+4];
		schedule5 = (uint32_t) dev_passwd[indexW+5];
		schedule6 = (uint32_t) dev_passwd[indexW+6];
		schedule7 = (uint32_t) dev_passwd[indexW+7];
		schedule8 = (uint32_t) dev_passwd[indexW+8];
		schedule9 = (uint32_t) dev_passwd[indexW+9];
		schedule10 = (uint32_t) dev_passwd[indexW+10];
		schedule11 = (uint32_t) dev_passwd[indexW+11];
		schedule12 = (uint32_t) dev_passwd[indexW+12];
		schedule13 = (uint32_t) dev_passwd[indexW+13];
		schedule14 = (uint32_t) dev_passwd[indexW+14];
		//Input password is shorter than FIRST_LENGHT
		if(schedule14 == 0xFFFFFFFF) schedule14=0;
		else if(method == MODE_USER_PASS) redo=1;
		schedule15 = (uint32_t) dev_passwd[indexW+15];

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

		//User password only
		if(method == MODE_USER_PASS)
		{
			if(redo == 1)
			{
				schedule0 = (uint32_t) dev_passwd[indexW+16];
				schedule1 = (uint32_t) dev_passwd[indexW+17];
				schedule2 = (uint32_t) dev_passwd[indexW+18];
				schedule3 = (uint32_t) dev_passwd[indexW+19];
				schedule4 = (uint32_t) dev_passwd[indexW+20];
				schedule5 = (uint32_t) dev_passwd[indexW+21];
				schedule6 = (uint32_t) dev_passwd[indexW+22];
				schedule7 = (uint32_t) dev_passwd[indexW+23];
				schedule8 = (uint32_t) dev_passwd[indexW+24];
				schedule9 = (uint32_t) dev_passwd[indexW+25];
				schedule10 = (uint32_t) dev_passwd[indexW+26];
				schedule11 = (uint32_t) dev_passwd[indexW+27];
				schedule12 = (uint32_t) dev_passwd[indexW+28];
				schedule13 = (uint32_t) dev_passwd[indexW+29];
				schedule14 = (uint32_t) dev_passwd[indexW+30];
				schedule15 = (uint32_t) dev_passwd[indexW+31];

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

//----------------------------------------------------- SECOND HASH ------------------------------------------------
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
			ALL_ROUND_B1_1()
			ALL_SCHEDULE32()
			ALL_ROUND_B1_2()

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

			ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h,  0, 0x428A2F98, v0)
			ROUND_SECOND_BLOCK_CONST(h, a, b, c, d, e, f, g,  1, 0x71374491, v1)
			ROUND_SECOND_BLOCK_CONST(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, v2)
			ROUND_SECOND_BLOCK_CONST(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, v3)

			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d,  4, 0x3956C25B, w_blocks_d[indexW+4])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c,  5, 0x59F111F1, w_blocks_d[indexW+5])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b,  6, 0x923F82A4, w_blocks_d[indexW+6])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a,  7, 0xAB1C5ED5, w_blocks_d[indexW+7])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  8, 0xD807AA98, w_blocks_d[indexW+8])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  9, 0x12835B01, w_blocks_d[indexW+9])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 10, 0x243185BE, w_blocks_d[indexW+10])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 11, 0x550C7DC3, w_blocks_d[indexW+11])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 12, 0x72BE5D74, w_blocks_d[indexW+12])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 13, 0x80DEB1FE, w_blocks_d[indexW+13])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 14, 0x9BDC06A7, w_blocks_d[indexW+14])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 15, 0xC19BF174, w_blocks_d[indexW+15])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 16, 0xE49B69C1, w_blocks_d[indexW+16])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 17, 0xEFBE4786, w_blocks_d[indexW+17])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 18, 0x0FC19DC6, w_blocks_d[indexW+18])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 19, 0x240CA1CC, w_blocks_d[indexW+19])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 20, 0x2DE92C6F, w_blocks_d[indexW+20])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 21, 0x4A7484AA, w_blocks_d[indexW+21])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 22, 0x5CB0A9DC, w_blocks_d[indexW+22])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 23, 0x76F988DA, w_blocks_d[indexW+23])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 24, 0x983E5152, w_blocks_d[indexW+24])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 25, 0xA831C66D, w_blocks_d[indexW+25])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 26, 0xB00327C8, w_blocks_d[indexW+26])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 27, 0xBF597FC7, w_blocks_d[indexW+27])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 28, 0xC6E00BF3, w_blocks_d[indexW+28])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 29, 0xD5A79147, w_blocks_d[indexW+29])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 30, 0x06CA6351, w_blocks_d[indexW+30])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 31, 0x14292967, w_blocks_d[indexW+31])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 32, 0x27B70A85, w_blocks_d[indexW+32])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 33, 0x2E1B2138, w_blocks_d[indexW+33])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 34, 0x4D2C6DFC, w_blocks_d[indexW+34])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 35, 0x53380D13, w_blocks_d[indexW+35])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 36, 0x650A7354, w_blocks_d[indexW+36])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 37, 0x766A0ABB, w_blocks_d[indexW+37])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 38, 0x81C2C92E, w_blocks_d[indexW+38])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 39, 0x92722C85, w_blocks_d[indexW+39])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 40, 0xA2BFE8A1, w_blocks_d[indexW+40])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 41, 0xA81A664B, w_blocks_d[indexW+41])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 42, 0xC24B8B70, w_blocks_d[indexW+42])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 43, 0xC76C51A3, w_blocks_d[indexW+43])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 44, 0xD192E819, w_blocks_d[indexW+44])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 45, 0xD6990624, w_blocks_d[indexW+45])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 46, 0xF40E3585, w_blocks_d[indexW+46])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 47, 0x106AA070, w_blocks_d[indexW+47])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 48, 0x19A4C116, w_blocks_d[indexW+48])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 49, 0x1E376C08, w_blocks_d[indexW+49])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 50, 0x2748774C, w_blocks_d[indexW+50])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 51, 0x34B0BCB5, w_blocks_d[indexW+51])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 52, 0x391C0CB3, w_blocks_d[indexW+52])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 53, 0x4ED8AA4A, w_blocks_d[indexW+53])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 54, 0x5B9CCA4F, w_blocks_d[indexW+54])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 55, 0x682E6FF3, w_blocks_d[indexW+55])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 56, 0x748F82EE, w_blocks_d[indexW+56])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 57, 0x78A5636F, w_blocks_d[indexW+57])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 58, 0x84C87814, w_blocks_d[indexW+58])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 59, 0x8CC70208, w_blocks_d[indexW+59])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 60, 0x90BEFFFA, w_blocks_d[indexW+60])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 61, 0xA4506CEB, w_blocks_d[indexW+61])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 62, 0xBEF9A3F7, w_blocks_d[indexW+62])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 63, 0xC67178F2, w_blocks_d[indexW+63])

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
			ALL_ROUND_B1_1()
			ALL_SCHEDULE32()
			ALL_ROUND_B1_2()

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

			ROUND_SECOND_BLOCK_CONST(a, b, c, d, e, f, g, h,  0, 0x428A2F98, v0)
			ROUND_SECOND_BLOCK_CONST(h, a, b, c, d, e, f, g,  1, 0x71374491, v1)
			ROUND_SECOND_BLOCK_CONST(g, h, a, b, c, d, e, f,  2, 0xB5C0FBCF, v2)
			ROUND_SECOND_BLOCK_CONST(f, g, h, a, b, c, d, e,  3, 0xE9B5DBA5, v3)

			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d,  4, 0x3956C25B, w_blocks_d[indexW+4])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c,  5, 0x59F111F1, w_blocks_d[indexW+5])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b,  6, 0x923F82A4, w_blocks_d[indexW+6])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a,  7, 0xAB1C5ED5, w_blocks_d[indexW+7])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h,  8, 0xD807AA98, w_blocks_d[indexW+8])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g,  9, 0x12835B01, w_blocks_d[indexW+9])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 10, 0x243185BE, w_blocks_d[indexW+10])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 11, 0x550C7DC3, w_blocks_d[indexW+11])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 12, 0x72BE5D74, w_blocks_d[indexW+12])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 13, 0x80DEB1FE, w_blocks_d[indexW+13])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 14, 0x9BDC06A7, w_blocks_d[indexW+14])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 15, 0xC19BF174, w_blocks_d[indexW+15])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 16, 0xE49B69C1, w_blocks_d[indexW+16])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 17, 0xEFBE4786, w_blocks_d[indexW+17])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 18, 0x0FC19DC6, w_blocks_d[indexW+18])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 19, 0x240CA1CC, w_blocks_d[indexW+19])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 20, 0x2DE92C6F, w_blocks_d[indexW+20])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 21, 0x4A7484AA, w_blocks_d[indexW+21])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 22, 0x5CB0A9DC, w_blocks_d[indexW+22])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 23, 0x76F988DA, w_blocks_d[indexW+23])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 24, 0x983E5152, w_blocks_d[indexW+24])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 25, 0xA831C66D, w_blocks_d[indexW+25])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 26, 0xB00327C8, w_blocks_d[indexW+26])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 27, 0xBF597FC7, w_blocks_d[indexW+27])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 28, 0xC6E00BF3, w_blocks_d[indexW+28])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 29, 0xD5A79147, w_blocks_d[indexW+29])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 30, 0x06CA6351, w_blocks_d[indexW+30])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 31, 0x14292967, w_blocks_d[indexW+31])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 32, 0x27B70A85, w_blocks_d[indexW+32])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 33, 0x2E1B2138, w_blocks_d[indexW+33])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 34, 0x4D2C6DFC, w_blocks_d[indexW+34])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 35, 0x53380D13, w_blocks_d[indexW+35])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 36, 0x650A7354, w_blocks_d[indexW+36])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 37, 0x766A0ABB, w_blocks_d[indexW+37])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 38, 0x81C2C92E, w_blocks_d[indexW+38])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 39, 0x92722C85, w_blocks_d[indexW+39])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 40, 0xA2BFE8A1, w_blocks_d[indexW+40])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 41, 0xA81A664B, w_blocks_d[indexW+41])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 42, 0xC24B8B70, w_blocks_d[indexW+42])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 43, 0xC76C51A3, w_blocks_d[indexW+43])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 44, 0xD192E819, w_blocks_d[indexW+44])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 45, 0xD6990624, w_blocks_d[indexW+45])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 46, 0xF40E3585, w_blocks_d[indexW+46])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 47, 0x106AA070, w_blocks_d[indexW+47])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 48, 0x19A4C116, w_blocks_d[indexW+48])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 49, 0x1E376C08, w_blocks_d[indexW+49])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 50, 0x2748774C, w_blocks_d[indexW+50])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 51, 0x34B0BCB5, w_blocks_d[indexW+51])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 52, 0x391C0CB3, w_blocks_d[indexW+52])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 53, 0x4ED8AA4A, w_blocks_d[indexW+53])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 54, 0x5B9CCA4F, w_blocks_d[indexW+54])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 55, 0x682E6FF3, w_blocks_d[indexW+55])
			ROUND_SECOND_BLOCK(a, b, c, d, e, f, g, h, 56, 0x748F82EE, w_blocks_d[indexW+56])
			ROUND_SECOND_BLOCK(h, a, b, c, d, e, f, g, 57, 0x78A5636F, w_blocks_d[indexW+57])
			ROUND_SECOND_BLOCK(g, h, a, b, c, d, e, f, 58, 0x84C87814, w_blocks_d[indexW+58])
			ROUND_SECOND_BLOCK(f, g, h, a, b, c, d, e, 59, 0x8CC70208, w_blocks_d[indexW+59])
			ROUND_SECOND_BLOCK(e, f, g, h, a, b, c, d, 60, 0x90BEFFFA, w_blocks_d[indexW+60])
			ROUND_SECOND_BLOCK(d, e, f, g, h, a, b, c, 61, 0xA4506CEB, w_blocks_d[indexW+61])
			ROUND_SECOND_BLOCK(c, d, e, f, g, h, a, b, 62, 0xBEF9A3F7, w_blocks_d[indexW+62])
			ROUND_SECOND_BLOCK(b, c, d, e, f, g, h, a, 63, 0xC67178F2, w_blocks_d[indexW+63])

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

//----------------------------------------------------- MAC COMPARISON ------------------------------------------------

		a = ((uint32_t *)(vmkIV))[0];
		b = ((uint32_t *)(vmkIV+4))[0];
		c = ((uint32_t *)(vmkIV+8))[0];
		d = ((uint32_t *)(vmkIV+12))[0];

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			a, b, c, d,
			&(schedule0), &(schedule1), &(schedule2), &(schedule3)
		);

		schedule0=
			(((uint32_t)(vmkKey[3] ^ ((uint8_t) (schedule0 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[2] ^ ((uint8_t) (schedule0 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[1] ^ ((uint8_t) (schedule0 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[0] ^ ((uint8_t) (schedule0)))) << 0);

		schedule1=
			(((uint32_t)(vmkKey[7] ^ ((uint8_t) (schedule1 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[6] ^ ((uint8_t) (schedule1 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[5] ^ ((uint8_t) (schedule1 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[4] ^ ((uint8_t) (schedule1)))) << 0);

		schedule2=
			(((uint32_t)(vmkKey[11] ^ ((uint8_t) (schedule2 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[10] ^ ((uint8_t) (schedule2 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[9] ^ ((uint8_t) (schedule2 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[8] ^ ((uint8_t) (schedule2)))) << 0);

		schedule3=
			(((uint32_t)(vmkKey[15] ^ ((uint8_t) (schedule3 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[14] ^ ((uint8_t) (schedule3 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[13] ^ ((uint8_t) (schedule3 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[12] ^ ((uint8_t) (schedule3)))) << 0);

		d += 0x01000000;

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			a, b, c, d,
			&(schedule4), &(schedule5), &(schedule6), &(schedule7)
		);

		schedule4=
			(((uint32_t)(vmkKey[19] ^ ((uint8_t) (schedule4 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[18] ^ ((uint8_t) (schedule4 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[17] ^ ((uint8_t) (schedule4 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[16] ^ ((uint8_t) (schedule4)))) << 0);

		schedule5=
			(((uint32_t)(vmkKey[23] ^ ((uint8_t) (schedule5 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[22] ^ ((uint8_t) (schedule5 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[21] ^ ((uint8_t) (schedule5 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[20] ^ ((uint8_t) (schedule5)))) << 0);

		schedule6=
			(((uint32_t)(vmkKey[27] ^ ((uint8_t) (schedule6 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[26] ^ ((uint8_t) (schedule6 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[25] ^ ((uint8_t) (schedule6 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[24] ^ ((uint8_t) (schedule6)))) << 0);

		schedule7=
			(((uint32_t)(vmkKey[31] ^ ((uint8_t) (schedule7 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[30] ^ ((uint8_t) (schedule7 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[29] ^ ((uint8_t) (schedule7 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[28] ^ ((uint8_t) (schedule7)))) << 0);

		d += 0x01000000;

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			a, b, c, d,
			&(schedule8), &(schedule9), &(schedule10), &(schedule11)
		);
		
		schedule8=
			(((uint32_t)(vmkKey[35] ^ ((uint8_t) (schedule8 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[34] ^ ((uint8_t) (schedule8 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[33] ^ ((uint8_t) (schedule8 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[32] ^ ((uint8_t) (schedule8)))) << 0);

		schedule9=
			(((uint32_t)(vmkKey[39] ^ ((uint8_t) (schedule9 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[38] ^ ((uint8_t) (schedule9 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[37] ^ ((uint8_t) (schedule9 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[36] ^ ((uint8_t) (schedule9)))) << 0);

		schedule10=
			(((uint32_t)(vmkKey[43] ^ ((uint8_t) (schedule10 >> 24) ))) << 24) | 
			(((uint32_t)(vmkKey[42] ^ ((uint8_t) (schedule10 >> 16) ))) << 16) | 
			(((uint32_t)(vmkKey[41] ^ ((uint8_t) (schedule10 >> 8) ))) << 8) | 
			(((uint32_t)(vmkKey[40] ^ ((uint8_t) (schedule10)))) << 0);

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			((uint32_t *)(macIV))[0], ((uint32_t *)(macIV+4))[0], ((uint32_t *)(macIV+8))[0], ((uint32_t *)(macIV+12))[0],
			&(schedule16), &(schedule17), &(schedule18), &(schedule19)
		);


		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			((uint32_t *)(computeMacIV))[0], ((uint32_t *)(computeMacIV+4))[0], ((uint32_t *)(computeMacIV+8))[0], ((uint32_t *)(computeMacIV+12))[0],
			&(schedule12), &(schedule13), &(schedule14), &(schedule15)
		);

		schedule28 = schedule0 ^ schedule12;
		schedule29 = schedule1 ^ schedule13;
		schedule30 = schedule2 ^ schedule14;
		schedule31 = schedule3 ^ schedule15;

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			schedule28, schedule29, schedule30, schedule31,
			&(schedule12), &(schedule13), &(schedule14), &(schedule15)
		);

		schedule28 = schedule4 ^ schedule12;
		schedule29 = schedule5 ^ schedule13;
		schedule30 = schedule6 ^ schedule14;
		schedule31 = schedule7 ^ schedule15;

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			schedule28, schedule29, schedule30, schedule31,
			&(schedule12), &(schedule13), &(schedule14), &(schedule15)
		);

		schedule28 = schedule8 ^ schedule12;
		schedule29 = schedule9 ^ schedule13;
		schedule30 = schedule10 ^ schedule14;
		schedule31 = schedule15;

		encrypt(
			hash0, hash1, hash2, hash3, hash4, hash5, hash6, hash7,
			schedule28, schedule29, schedule30, schedule31,
			&(schedule12), &(schedule13), &(schedule14), &(schedule15)
		);

		if (

			(
				schedule12 == ( (uint32_t)
						(((uint32_t)(mac[3] ^ ((uint8_t) (schedule16 >> 24) ))) << 24) | 
						(((uint32_t)(mac[2] ^ ((uint8_t) (schedule16 >> 16) ))) << 16) | 
						(((uint32_t)(mac[1] ^ ((uint8_t) (schedule16 >> 8) ))) << 8) | 
						(((uint32_t)(mac[0] ^ ((uint8_t) (schedule16)))) << 0) )
			)
			&&
			(
				schedule13 == ( (uint32_t)
						(((uint32_t)(mac[7] ^ ((uint8_t) (schedule17 >> 24) ))) << 24) | 
						(((uint32_t)(mac[6] ^ ((uint8_t) (schedule17 >> 16) ))) << 16) | 
						(((uint32_t)(mac[5] ^ ((uint8_t) (schedule17 >> 8) ))) << 8) | 
						(((uint32_t)(mac[4] ^ ((uint8_t) (schedule17)))) << 0) )
			)
			&&
			(
				schedule14 == ( (uint32_t)
						(((uint32_t)(mac[11] ^ ((uint8_t) (schedule18 >> 24) ))) << 24) | 
						(((uint32_t)(mac[10] ^ ((uint8_t) (schedule18 >> 16) ))) << 16) | 
						(((uint32_t)(mac[9] ^ ((uint8_t) (schedule18 >> 8) ))) << 8) | 
						(((uint32_t)(mac[8] ^ ((uint8_t) (schedule18)))) << 0) )
			)
			&&
			(
				schedule15 == ( (uint32_t)
						(((uint32_t)(mac[15] ^ ((uint8_t) (schedule19 >> 24) ))) << 24) | 
						(((uint32_t)(mac[14] ^ ((uint8_t) (schedule19 >> 16) ))) << 16) | 
						(((uint32_t)(mac[13] ^ ((uint8_t) (schedule19 >> 8) ))) << 8) | 
						(((uint32_t)(mac[12] ^ ((uint8_t) (schedule19)))) << 0) )
			)
		)
		{
			*found = gIndex;
			break;
		}

		gIndex += (blockDim.x * gridDim.x);
	}

	return;
}
