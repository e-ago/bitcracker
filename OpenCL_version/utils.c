/*
 * BitCracker: BitLocker password cracking tool, OpenCL version.
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
		fprintf(stderr,"Critical error: memory size is 0\n");
		exit(EXIT_FAILURE);
	}

	ptr = (void *)calloc(len, size);	
	if( ptr == NULL )
	{
		fprintf(stderr,"Critical error: Memory allocation\n");
		exit(EXIT_FAILURE);
	}
	return ptr;
}

void fillBuffer(FILE *fp, unsigned char *buffer, int size)
{
	int k;

	for (k = 0; k < size; k++)
		buffer[k] = (unsigned char)fgetc(fp);
}

void print_hex(unsigned char *str, int len)
{
	int i;

	for (i = 0; i < len; ++i)
		printf("%02x", str[i]);
}

int parse_data(char *input_hash, unsigned char ** salt, unsigned char ** nonce,	unsigned char ** vmk)
{
	char * hash;
	char *p;
	int i, salt_len, iterations, vmk_size, nonce_len;
	FILE * fphash;
	char tmp[2];
	int j=0;

	(*salt) = (unsigned char *) Calloc(SALT_SIZE, sizeof(unsigned char));
	(*nonce) = (unsigned char *) Calloc(NONCE_SIZE, sizeof(unsigned char));
	(*vmk) = (unsigned char *) Calloc(VMK_SIZE, sizeof(unsigned char));
	hash = (char *) Calloc(INPUT_HASH_SIZE, sizeof(char));

	if(!input_hash)
	{
		fprintf(stderr, "No input hash provided\n");
		goto out;
	}

	fphash = fopen(input_hash, "r");
	if (!fphash) {
		fprintf(stderr, "! %s : %s\n", input_hash, strerror(errno));
		goto out;
	}
	fgets(hash, INPUT_HASH_SIZE, fphash);
	fclose(fphash);	
	if(!hash)
	{
		fprintf(stderr, "No correct input hash provided\n");
		goto out;
	}

	printf("Hash file %s:\n%s\n", input_hash, hash);

	if (strncmp(hash, HASH_TAG, HASH_TAG_LEN) != 0)
	{
		fprintf(stderr, "Wrong hash format\n");
		goto out;
	}

	hash += HASH_TAG_LEN;
	
	p = strtokm(hash, "$"); // version
	p = strtokm(NULL, "$"); // salt length

	salt_len = atoi(p);
	if(salt_len != SALT_SIZE)
	{
		fprintf(stderr, "Wrong Salt size\n");
		goto out;
	}

	p = strtokm(NULL, "$"); // salt
	for (i = 0, j = 0; i < salt_len*2; i+=2, j++)
	{
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
		(*salt)[j] = (unsigned char)(ret); //((ARCH_INDEX(p[i * 2]) * 16) + ARCH_INDEX(p[i * 2 + 1]));
	}

	p = strtokm(NULL, "$"); // iterations
	iterations = atoi(p);
	p = strtokm(NULL, "$"); // nonce length
	nonce_len = atoi(p);
	if(nonce_len != NONCE_SIZE)
	{
		fprintf(stderr, "Wrong Nonce size\n");
		goto out;
	}

	p = strtokm(NULL, "$"); // nonce
	for (i = 0, j = 0; i < NONCE_SIZE*2; i+=2, j++)
	{
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
		(*nonce)[j] = (unsigned char)(ret); //((ARCH_INDEX(p[i * 2]) * 16) + ARCH_INDEX(p[i * 2 + 1]));
	}

	p = strtokm(NULL, "$"); // data_size
	
	vmk_size = atoi(p);
	if(vmk_size != VMK_SIZE)
	{
		fprintf(stderr, "Wrong VMK size\n");
		goto out;
	}
	
	p = strtokm(NULL, "$"); // data
	for (i = 0, j = 0; i < vmk_size*2; i+=2, j++)
	{
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
		(*vmk)[j] = (unsigned char)(ret); //((ARCH_INDEX(p[i * 2]) * 16) + ARCH_INDEX(p[i * 2 + 1]));
	}
	
	return BIT_SUCCESS;

	out:
		free(*salt);
		free(*nonce);
		free(*vmk);

		return BIT_FAILURE;
}

int readFilePassword(char ** buf, int maxNumPsw, FILE *fp) {
	int i=0, size;
	char tmp[FIXED_PASSWORD_BUFFER];
	memset(tmp, 0, FIXED_PASSWORD_BUFFER);

	if (fp == NULL || feof(fp) || buf == NULL)
	        return -1;

	while(fgets(tmp, MAX_INPUT_PASSWORD_LEN+2, fp) && (i < maxNumPsw)) {
		size = (strlen(tmp)-1);
		if(tmp[0] == '\n' || size < 8 || size > MAX_INPUT_PASSWORD_LEN) continue;
		if(size < MAX_INPUT_PASSWORD_LEN) tmp[size] = 0x80; //0xFF;

		memcpy(( (*buf)+(i*FIXED_PASSWORD_BUFFER)), tmp, MAX_INPUT_PASSWORD_LEN);
		memset(tmp, 0, FIXED_PASSWORD_BUFFER);
		i++;
	}

	return i;
}

