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

#include "bitcracker.h"

/* John The Ripper function */
char *strtokm(char *s1, const char *delims)
{
	static char *last = NULL;
	char *endp;

	if (!s1)
		s1 = last;
	if (!s1 || *s1 == 0)
		return last = NULL;
	endp = strpbrk(s1, delims);
	if (endp) {
		*endp = '\0';
		last = endp + 1;
	} else
		last = NULL;
	return s1;
}

void * Calloc(size_t len, size_t size) {
	void * ptr = NULL;
	if( size <= 0)
	{
		fprintf(stderr, "Critical error: requested memory size is 0\n");
		exit(EXIT_FAILURE);
	}

	ptr = (void *)calloc(len, size);
	if( ptr == NULL )
	{
		fprintf(stderr, "Critical error: Memory allocation\n");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

int parse_data(char *input_hash, unsigned char ** salt, unsigned char ** nonce,	unsigned char ** vmk, unsigned char ** mac)
{
	if(!input_hash)
	{
		fprintf(stderr, "No input hash provided\n");
		return BIT_FAILURE;
	}

	FILE * fphash = nullptr;
	fphash = fopen(input_hash, "r");
	if (!fphash) {
		fprintf(stderr, "! %s : %s\n", input_hash, strerror(errno));
		return BIT_FAILURE;
	}

	char * hash;
	char * p;
	int i, j;
    int salt_size, iterations, vmk_size, nonce_size;
	char temp[3];
	const char zero_string[17]="0000000000000000";

	(*salt)  = (unsigned char *) Calloc(SALT_SIZE,  sizeof(unsigned char));
	(*nonce) = (unsigned char *) Calloc(NONCE_SIZE, sizeof(unsigned char));
	(*vmk)   = (unsigned char *) Calloc(VMK_SIZE,   sizeof(unsigned char));
	(*mac)   = (unsigned char *) Calloc(MAC_SIZE,   sizeof(unsigned char));

	hash = (char *) Calloc(INPUT_HASH_SIZE, sizeof(char));

	if(fgets(hash, INPUT_HASH_SIZE, fphash) == NULL)
	{
		fprintf(stderr, "No correct input hash provided\n");
		goto out;
	}

	// printf("Reading hash file \"%s\"\n%s", input_hash, hash);
	printf("Reading hash file \"%s\"\n", input_hash);

	if (strncmp(hash, HASH_TAG, HASH_TAG_LEN) != 0)
	{
		fprintf(stderr, "Wrong hash format\n");
		goto out;
	}

	hash += HASH_TAG_LEN;
	p = strtokm(hash, "$");
	
	p = strtokm(NULL, "$"); // salt length
	salt_size = atoi(p);
	if(salt_size != SALT_SIZE)
	{
		fprintf(stderr, "Wrong Salt size\n");
		goto out;
	}

	p = strtokm(NULL, "$"); // salt
	for (i = 0, j = 0; i < salt_size * 2; i += 2, j++)
	{
		temp[0] = p[i];
		temp[1] = p[i + 1];
        temp[2] = '\0';
        long int ret = strtol(temp, NULL, 16);
		(*salt)[j] = (unsigned char)(ret);
	}

	p = strtokm(NULL, "$"); // iterations
	iterations = atoi(p);
	if(iterations != NUM_HASH_BLOCKS)
	{
		fprintf(stderr, "Wrong Iterations parameter\n");
		goto out;
	}
	
	p = strtokm(NULL, "$"); // nonce length
	nonce_size = atoi(p);
	if(nonce_size != NONCE_SIZE)
	{
		fprintf(stderr, "Wrong Nonce size\n");
		goto out;
	}

	p = strtokm(NULL, "$"); // nonce
	for (i = 0, j = 0; i < nonce_size*2; i+=2, j++)
	{
		temp[0] = p[i];
		temp[1] = p[i + 1];
        temp[2] = '\0';
		long int ret = strtol(temp, NULL, 16);
		(*nonce)[j] = (unsigned char)(ret);
	}

	p = strtokm(NULL, "$"); // vmk size
	vmk_size = atoi(p);
	if(vmk_size != VMK_SIZE)
	{
		fprintf(stderr, "Wrong VMK size\n");
		goto out;
	}
	
	p = strtokm(NULL, "$"); // mac
	for (i = 0, j = 0; i < MAC_SIZE*2; i+=2, j++)
	{
		temp[0] = p[i];
		temp[1] = p[i + 1];
        temp[2] = '\0';
		long int ret = strtol(temp, NULL, 16);
		(*mac)[j] = (unsigned char)(ret);
	}

	if(!memcmp((*mac), zero_string, MAC_SIZE))
	{
		free(*mac);
		(*mac)=NULL;
	}

    // vmk
	for (j=0; i < vmk_size*2; i+=2, j++)
	{
		temp[0] = p[i];
		temp[1] = p[i + 1];
        temp[2] = '\0';
		long int ret = strtol(temp, NULL, 16);
		(*vmk)[j] = (unsigned char)(ret);
	}

	fclose(fphash);

	return BIT_SUCCESS;

	out:
		fclose(fphash);

		free(*salt);
		free(*nonce);
		free(*vmk);
		free(*mac);
        free(hash);

		return BIT_FAILURE;
}

static int print_once = 0;
uint32_t read_password(
    uint32_t ** buf_uint32, // a 32 uint32 slot for each password
    char ** buf_char,       // a 64 char slot for each password
    uint32_t max_num_pswd_per_read,
    FILE *fp)
{
    int j, k, size;
	uint32_t num_pswd = 0;          // count of passwords
	char this_pswd[PSWD_NUM_CHAR];  // temporary storage for current password
	
	if (fp == NULL || feof(fp) || buf_uint32 == NULL || buf_char == NULL) {
        return 0;
    }
	
	memset(this_pswd, 0, PSWD_NUM_CHAR);            // clear this_pswd, then
	while(fgets(this_pswd, PSWD_NUM_CHAR, fp)) {    // read current password into this_pswd
		size = strlen(this_pswd) - 1;
		
        // print warning
		if((size < MIN_INPUT_PASSWORD_LEN || size > SECOND_LENGHT) && print_once == 0) {
			fprintf(stderr, "WARNING: During USER PASSWORD attack, "
                            "only passwords between %d and %d character are considered. "
                            "Passwords like %s will be ignored.\n",
                            MIN_INPUT_PASSWORD_LEN, SECOND_LENGHT, this_pswd);
			print_once = 1;
		}
		
        // if not good password, continue to next
		if(size < MIN_INPUT_PASSWORD_LEN || size > SECOND_LENGHT || this_pswd[0] == '\n') {
            continue;
        }
		
        // save this password to buf_char
        memset((*buf_char) + (num_pswd * PSWD_NUM_CHAR), 0, PSWD_NUM_CHAR);
		memcpy((*buf_char) + (num_pswd * PSWD_NUM_CHAR), this_pswd, size);

        this_pswd[size] = 0x80; // terminate this password with 0x80
		j = 0;  // buf_uint32 element position
        k = 0;  // this_pswd char position
        // For each password, there 32 slots.
        // Each slot is a uint32 and is filled up by 'transformed' two-consecutive-chars of the password.
        // j is half of k
        do {
            ((*buf_uint32) + (num_pswd * PSWD_NUM_UINT32) + j)[0] =  (((uint32_t)this_pswd[k]) << 24) & 0xFF000000;
            k++;
            if(k <= size) {
            ((*buf_uint32) + (num_pswd * PSWD_NUM_UINT32) + j)[0] |= (((uint32_t)this_pswd[k]) <<  8) & 0x0000FF00;
            }
            k++;
            j++;
        } while(k <= size);

        // based on password size, fill up (14 and 15) or (30 and 31) positions
        if(size <= FIRST_LENGHT)
        {
            ((*buf_uint32) + (num_pswd * PSWD_NUM_UINT32) + 14)[0] = 0xFFFFFFFF;
            ((*buf_uint32) + (num_pswd * PSWD_NUM_UINT32) + 15)[0] = (((uint8_t)(((size * 2) << 3) >> 8)) << 8) | ((uint8_t)((size * 2) << 3));
        }
        else
        {
            ((*buf_uint32) + (num_pswd * PSWD_NUM_UINT32) + 30)[0] = 0;
            ((*buf_uint32) + (num_pswd * PSWD_NUM_UINT32) + 31)[0] = (((uint8_t)(((size * 2) << 3) >> 8)) << 8) | ((uint8_t)((size * 2) << 3));
        }

		memset(this_pswd, 0, PSWD_NUM_CHAR);    // clear this_pswd
		num_pswd++;

		if(num_pswd >= max_num_pswd_per_read) {
            break;
        }
	}

	return num_pswd;
}
