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

int gpu_id=0;
int psw_x_thread=8;
int tot_psw=0;
size_t size_psw=0;
size_t tot_word_mem=(SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(uint32_t));
int strict_check=0;

void usage(char *name){
	printf("\nUsage: %s -f <hash_file> -d <dictionary_file>\n\n"
		"Options:\n\n"
		"  -h, --help"
		"\t\t\tShow this help\n"
		"  -f, --hashfile"
		"\t\tPath to your input hash file (HashExtractor output)\n"
		"  -d, --dictionary"
		"\t\tPath to dictionary or alphabet file\n"
		"  -s, --strict"
		"\t\tStrict check (use only in case of false positives)\n"
		"  -g, --gpu"
		"\t\tGPU device number\n"
		"  -t, --passthread"
		"\t\tSet the number of password per thread threads\n"
		"  -b, --blocks"
		"\t\tSet the number of blocks\n\n", name);
}

int getGPUStats()
{
	cudaDeviceProp prop;
	size_t	avail, total;

	if(gpu_id < 0)
	{
		fprintf(stderr, "Invalid device number: %d\n", gpu_id);
		return BIT_FAILURE;
	}

	BITCRACKER_CUDA_CHECK( cudaSetDevice(gpu_id) );
	cudaGetDeviceProperties(&prop, gpu_id);
	BITCRACKER_CUDA_CHECK( cudaMemGetInfo(&avail, &total) );

	printf("\n\n====================================\nSelected device: GPU %s (ID: %d) properties\n====================================\n\n", prop.name, gpu_id);
	printf("Compute capability: %d.%d\n", prop.major, prop.minor ); 
	printf("Clock rate: %d\n", prop.clockRate );
	printf("Clock rate: %.0f MHz (%.02f GHz)\n", prop.clockRate * 1e-3f, prop.clockRate * 1e-6f);
	printf("Memory Clock Rate (KHz): %d\n", prop.memoryClockRate);
    printf("Memory Bus Width (bits): %d\n", prop.memoryBusWidth);
    printf("Peak Memory Bandwidth (GB/s): %f\n", 2.0*prop.memoryClockRate*(prop.memoryBusWidth/8)/1.0e6);
	printf("Device copy overlap: " );
	if (prop.deviceOverlap) printf("Enabled\n" ); else printf("Disabled\n" );
	printf("Async memory engine count: %d\n",  prop.asyncEngineCount);
	printf("Concurrent kernels: %d\n",  prop.concurrentKernels);
	printf("Kernel execition timeout: ");	
	if (prop.kernelExecTimeoutEnabled) printf("Enabled\n" ); else printf("Disabled\n" );
	printf("Total global mem:  %ld bytes\n", prop.totalGlobalMem );
	printf("Free memory: %zd bytes\n", avail);
	printf("Texture Alignment:  %ld\n", prop.textureAlignment );
	printf("Multiprocessor count:  %d\n", prop.multiProcessorCount );
	printf("Shared mem per mp:  %ld\n", prop.sharedMemPerBlock );
	printf("Registers per mp:  %d\n", prop.regsPerBlock );
	printf("Threads in warp:  %d\n", prop.warpSize );
	printf("Max threads per block:  %d\n", prop.maxThreadsPerBlock );
	printf("Max thread dimensions:  (%d, %d, %d)\n", prop.maxThreadsDim[0], prop.maxThreadsDim[1], prop.maxThreadsDim[2] );
	printf("Max grid dimensions:  (%d, %d, %d)\n", prop.maxGridSize[0], prop.maxGridSize[1], prop.maxGridSize[2]);
	printf( "\n");

	printf("For this session, BitCracker requires at least %ld bytes of memory\n", (tot_word_mem+size_psw));  	
  	if(avail < (tot_word_mem+size_psw))
  	{
		fprintf(stderr, "Not enough memory available on device. Minimum required: %zd Free memory: %zd\n", (tot_word_mem+size_psw), avail);
		return BIT_FAILURE;
	}

	return BIT_SUCCESS;
}


int main (int argc, char **argv)
{
	char * input_dictionary=NULL, * input_hash=NULL;
	unsigned char *salt, *nonce, *vmk;
	uint32_t * w_blocks_d;
	
	int gridBlocks = 1;
	int opt, option_index = 0;

	printf("\n---------> BitCracker: BitLocker password cracking tool <---------\n");

	if (argc < 4) {
		printf("Missing argument!\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	//*********************** Options ************************
	while (1) {
		static struct option long_options[] =
			{
				{"help", no_argument, 0, 'h'},
				{"hashfile", required_argument, 0, 'f'},
				{"dictionary", required_argument, 0, 'd'},
				{"passthread", required_argument, 0, 't'},
				{"blocks", required_argument, 0, 'b'},
				{"gpu", required_argument, 0, 'g'},
				{"strict", optional_argument, 0, 's'},
				strict
				{0, 0, 0, 0}
			};

		opt = getopt_long(argc, argv, "hf:d:t:b:g:s", long_options, &option_index);
		if (opt == -1)
			break;
		switch (opt) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_FAILURE);
				break;
			case 'f':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Inut hash file path is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				input_hash=(char *)Calloc(INPUT_SIZE, sizeof(char));
				strncpy(input_hash, optarg, strlen(optarg)+1);
				break;
			case 'd':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Dictionary file path is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				input_dictionary=(char *)Calloc(INPUT_SIZE, sizeof(char));
				strncpy(input_dictionary,optarg, strlen(optarg)+1);
				break;
			case 't':
				psw_x_thread = atoi(optarg);
				if(psw_x_thread <= 0)
				{
					fprintf(stderr, "ERROR: wrong password x thread number\n");
					exit(EXIT_FAILURE);
				}
				break;
			case 'b':
				gridBlocks = atoi(optarg);
				break;
			case 'g':
				gpu_id = atoi(optarg);
				break;
			case 's':
				strict_check = 1;
				break;
			default:
				exit(EXIT_FAILURE);
		}
	}
	
	if (optind < argc) {
		printf ("non-option ARGV-elements: ");
		while (optind < argc)
			printf ("%s ", argv[optind++]);
		putchar ('\n');
		exit(EXIT_FAILURE);
	}
	
	if (input_dictionary == NULL){
		printf("Missing dictionary file!\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (input_hash == NULL){
		printf("Missing input hash file!\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	//***********************************************************

	tot_psw=(ATTACK_DEFAULT_THREADS*gridBlocks*psw_x_thread);
	size_psw = tot_psw * FIXED_PASSWORD_BUFFER * sizeof(uint8_t);
	//****************** GPU device *******************
	if(getGPUStats())
	{
		fprintf(stderr, "Device error... exit!\n");
		goto cleanup;
	}
	//***************************************************

	//****************** Data from target file *******************
	printf("\n====================================\nExtracting data from disk image\n====================================\n\n");

	if(parse_data(input_hash, &salt, &nonce, &vmk) == BIT_FAILURE)
	{
		fprintf(stderr, "Input hash format error... exit!\n");
		goto cleanup;
	}
	//************************************************************

	printf("\n\n====================================\nDictionary attack\n====================================\n\n");
	//****************** W block *******************
	BITCRACKER_CUDA_CHECK( cudaMalloc( (void ** ) &w_blocks_d, tot_word_mem) );
	if(w_block_precomputed(salt, w_blocks_d) == BIT_FAILURE)
	{
		fprintf(stderr, "Words error... exit!\n");
		goto cleanup;
	}
	//**********************************************

	//************* Dictionary Attack *************
	cuda_attack(input_dictionary, w_blocks_d, vmk, nonce, gridBlocks);
	//*********************************************

cleanup:
	BITCRACKER_CUDA_CHECK( cudaFree(w_blocks_d) );
	printf("\n");
	return 0;
}
