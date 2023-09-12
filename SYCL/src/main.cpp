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
#include <chrono>
#include <iostream>

#define TIMER_START() time_start = std::chrono::steady_clock::now();
#define TIMER_END()                                                                         \
    time_end = std::chrono::steady_clock::now();                                            \
    time_total  = std::chrono::duration<double, std::milli>(time_end - time_start).count();
#define TIMER_PRINT(name) std::cout << name <<": " << (time_total - time_total_) / 1e3 << " s\n";

// #ifndef DEBUG_TIME
// #define DEBUG_TIME
// #endif

uint32_t max_num_pswd_per_read = 0;

unsigned char * salt;
size_t tot_word_mem = NUM_HASH_BLOCKS * HASH_BLOCK_NUM_UINT32 * sizeof(uint32_t);

void usage(char *name){
	printf("\nUsage: %s -f <hash_file> -d <dictionary_file> ATTACK TYPE <p|r>\n\n"
		"Options:\n\n"
		"  -h"
		"\t\tShow this help\n"
		"  -f"
		"\t\tPath to your input hash file (HashExtractor output)\n"
		"  -d"
		"\t\tPath to dictionary file\n", name);
}

int main (int argc, char **argv)
{
    std::chrono::steady_clock::time_point time_start;
    std::chrono::steady_clock::time_point time_end;
    double time_total = 0.0;
    double time_total_ = 0.0;

    TIMER_START()

	int opt = 0;
	int pass_batch_size = 60000;
	char * input_hash = NULL;
	char * input_dictionary = NULL;
	unsigned char *nonce;
	unsigned char *vmk;
	unsigned char *mac;
	uint32_t * d_w_words_uint32;

	printf("\n---------> BitCracker: BitLocker password cracking tool <---------\n");

	if (argc < 2) {
		printf("Missing argument!\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	while (1) {
		opt = getopt(argc, argv, "f:d:b:h");
		if (opt == -1)
			break;
		
		switch (opt) {
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
            
			case 'b':
				pass_batch_size = atoi(optarg);
				break;

			case 'h':
				usage(argv[0]);
				exit(EXIT_FAILURE);
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

    // max_num_pswd_per_read = gridBlocks * THREADS_PER_BLOCK * 4;
    // max_num_pswd_per_read = 11520;//11520 passwords can be processed in one pass in PVC-B3
    // max_num_pswd_per_read = 50000;//26624/2;//26624 passwords can be processed in one pass in PVC-B4
    max_num_pswd_per_read = pass_batch_size;
    // max_num_pswd_per_read = 27648; //27648 passwords can be processed in one pass in A100
	// if(getGPUStats())
	// {
	// 	fprintf(stderr, "Device error... exit!\n");
	// 	// goto cleanup;
	// }

	printf("\n\n==================================\n");
    printf("Retrieving Info\n==================================\n\n");
	if(parse_data(input_hash, &salt, &nonce, &vmk, &mac) == BIT_FAILURE)
	{
		fprintf(stderr, "Input hash format error... exit!\n");
		// goto cleanup;
	}

	if(mac == NULL)
	{
        fprintf(stderr, "NULL MAC string error... exit!\n");
		// goto cleanup;
	}

    double duration = 0.0;

#ifdef DEBUG_TIME
    auto time11 = std::chrono::steady_clock::now();
#endif

    // create sycl queue
    sycl::queue qbc;

#ifdef DEBUG_TIME
    auto time12 = std::chrono::steady_clock::now();
    double duration1 = std::chrono::duration<double, std::micro>(time12 - time11).count();
    duration += duration1;
    std::cout << "init: " << duration1 << " us\n\n";

    auto time21 = std::chrono::steady_clock::now();
#endif

    // allocate memory
	d_w_words_uint32 = (uint32_t *)sycl::malloc_device(NUM_HASH_BLOCKS * HASH_BLOCK_NUM_UINT32 * sizeof(uint32_t), qbc);

#ifdef DEBUG_TIME
    auto time22 = std::chrono::steady_clock::now();
    double duration2 = std::chrono::duration<double, std::micro>(time22 - time21).count();
    duration += duration2;
    std::cout << "main() - alloc : duration2: " << duration2 << " us\n\n";
#endif

	if(evaluate_w_block(salt, d_w_words_uint32, duration, qbc) == BIT_FAILURE)
	{
		fprintf(stderr, "Words error... exit!\n");
		goto cleanup;
	}

	std::cout << "================================================\n";
    std::cout << "                  Attack\n";
	std::cout << "================================================\n";

	time_total_ = attack(input_dictionary, d_w_words_uint32, vmk, nonce, mac, pass_batch_size, duration, qbc);

cleanup:
    free(input_hash);
    free(input_dictionary);

	sycl::free(d_w_words_uint32, qbc);

    // std::cout << "Total time for whole calculation: " << duration / 1e6 << " s\n\n";
    TIMER_END()
    TIMER_PRINT("bitcracker - total time for whole calculation")

	return 0;
}
