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

	printf("\n");
}

int parse_data(char *input_hash, unsigned char ** salt, unsigned char ** nonce,	unsigned char ** vmk, unsigned char ** mac)
{
	char * hash;
	char *p;
	int i, salt_size, iterations, vmk_size, nonce_size;
	FILE * fphash;
	char tmp[2];
	int j=0, auth_method=0;
	const char zero_string[17]="0000000000000000";

	(*salt) = (unsigned char *) Calloc(SALT_SIZE, sizeof(unsigned char));
	(*nonce) = (unsigned char *) Calloc(NONCE_SIZE, sizeof(unsigned char));
	(*vmk) = (unsigned char *) Calloc(VMK_SIZE, sizeof(unsigned char));
	(*mac) = (unsigned char *) Calloc(MAC_SIZE, sizeof(unsigned char));

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
	if(!hash)
	{
		fprintf(stderr, "No correct input hash provided\n");
		goto out;
	}

	printf("Reading hash file \"%s\"\n%s", input_hash, hash);

	if (strncmp(hash, HASH_TAG, HASH_TAG_LEN) != 0)
	{
		fprintf(stderr, "Wrong hash format\n");
		goto out;
	}

	hash += HASH_TAG_LEN;
	p = strtokm(hash, "$"); // version

	//take care of all the possible errors
	auth_method = atoi(p);
	if( (auth_method == 0 || auth_method == 1) && attack_mode == MODE_RECV_PASS)
	{
		fprintf(stderr, "Input Hash error: you choose the -r option (Recovery Password) but the input hash MUST be used with -u option (User Password).\n");
		goto out;
	}
	else if(auth_method == 2 && attack_mode == MODE_USER_PASS)
	{
		fprintf(stderr, "Input Hash error: you choose the -u option (User Password) but the input hash MUST be used with -r option (Recovery Password).\n");
		goto out;
	}
		
	p = strtokm(NULL, "$"); // salt length
	salt_size = atoi(p);
	if(salt_size != SALT_SIZE)
	{
		fprintf(stderr, "Wrong Salt size\n");
		goto out;
	}

	p = strtokm(NULL, "$"); // salt
	for (i = 0, j = 0; i < salt_size*2; i+=2, j++)
	{
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
		(*salt)[j] = (unsigned char)(ret);
	}

	p = strtokm(NULL, "$"); // iterations
	iterations = atoi(p);
	if(iterations != ITERATION_NUMBER)
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
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
		(*nonce)[j] = (unsigned char)(ret);
	}

	p = strtokm(NULL, "$"); // data_size
	
	vmk_size = atoi(p);
	if(vmk_size != VMK_SIZE)
	{
		fprintf(stderr, "Wrong VMK size\n");
		goto out;
	}
	
	p = strtokm(NULL, "$"); // data
	for (i = 0, j = 0; i < MAC_SIZE*2; i+=2, j++)
	{
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
		(*mac)[j] = (unsigned char)(ret);
	}

	if(mac_comparison == 1 && !memcmp((*mac), zero_string, MAC_SIZE))
	{
		free(*mac);
		(*mac)=NULL;
	}

	for (j=0; i < vmk_size*2; i+=2, j++)
	{
		tmp[0] = p[i];
		tmp[1] = p[i+1];
		long int ret = strtol(tmp, NULL, 16);
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

		return BIT_FAILURE;
}

static int print_once=0;
int readFilePassword(uint32_t ** buf_i, char ** buf_c, int maxNumPsw, FILE *fp) {
	int i=0, j=0, k=0, size=0, count=0;
	char tmp[PSW_CHAR_SIZE], tmp2[PSW_CHAR_SIZE], *p;
	memset(tmp, 0, PSW_CHAR_SIZE);
	
	if (fp == NULL || feof(fp) || buf_i == NULL)
	        return -1;

	while(fgets(tmp, PSW_CHAR_SIZE, fp)) {
		j=0; k=0; count=0;
		size = (strlen(tmp)-1);
		
		if(attack_mode == MODE_USER_PASS && ( size > SECOND_LENGHT || size < MIN_INPUT_PASSWORD_LEN) && print_once == 0)
		{
			fprintf(stderr, "WARNING: During USER PASSWORD attack, only passwords between %d and %d character are considered. Passwords like %s will be ignored.\n", MIN_INPUT_PASSWORD_LEN, SECOND_LENGHT, tmp);
			print_once=1;
		}
		
		if(tmp[0] == '\n' || size < MIN_INPUT_PASSWORD_LEN || size > SECOND_LENGHT)
			continue;

		memcpy(( (*buf_c)+(i*PSW_CHAR_SIZE)), tmp, size);

		if(attack_mode == MODE_RECV_PASS) //Recovery password
		{
			memset(tmp2, 0, PSW_CHAR_SIZE);
			p = strtokm(tmp, "-");
			do
			{
				//Dislocker, Recovery Password checks
				if( ((atoi(p) % 11) != 0) || (atoi(p) >= 720896) ) break;
				int8_t check_digit = (int8_t) ( p[0] - p[1] + p[2] - p[3] + p[4] - 48 ) % 11;
				if( check_digit < 0 ) check_digit = (int8_t) check_digit + 11;
				if( check_digit != (p[5] - 48)) break;

				((uint16_t*)(tmp2+count))[0] = (uint16_t)(atoi(p) / 11);
				p = strtokm(NULL, "-");
				count+=2;

			} while(p != NULL);

			if(count != (RECOVERY_PASS_BLOCKS*2)) continue;
			
			((*buf_i)+(i*PSW_INT_SIZE))[0] = 	( (((uint32_t)tmp2[0]  ) << 24) & 0xFF000000) |
								( (((uint32_t)tmp2[0+1]) << 16) & 0x00FF0000) |	
								( (((uint32_t)tmp2[0+2])  << 8) & 0x0000FF00)  |
								( (((uint32_t)tmp2[0+3])  << 0) & 0x000000FF);

			((*buf_i)+(i*PSW_INT_SIZE))[1] = 	( (((uint32_t)tmp2[4]) << 24) & 0xFF000000) |
								( (((uint32_t)tmp2[4+1]) << 16) & 0x00FF0000) |	
								( (((uint32_t)tmp2[4+2]) << 8) & 0x0000FF00)  |
								( (((uint32_t)tmp2[4+3]) << 0) & 0x000000FF);

			((*buf_i)+(i*PSW_INT_SIZE))[2] = 	( (((uint32_t)tmp2[8]) << 24) & 0xFF000000) |
								( (((uint32_t)tmp2[8+1]) << 16) & 0x00FF0000) |	
								( (((uint32_t)tmp2[8+2]) << 8) & 0x0000FF00)  |
								( (((uint32_t)tmp2[8+3]) << 0) & 0x000000FF);

			((*buf_i)+(i*PSW_INT_SIZE))[3] = 	( (((uint32_t)tmp2[12]) << 24) & 0xFF000000) |
								( (((uint32_t)tmp2[12+1]) << 16) & 0x00FF0000) |	
								( (((uint32_t)tmp2[12+2]) << 8) & 0x0000FF00)  |
								( (((uint32_t)tmp2[12+3]) << 0) & 0x000000FF);

			((*buf_i)+(i*PSW_INT_SIZE))[4] = 0x80000000;
			((*buf_i)+(i*PSW_INT_SIZE))[5] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[6] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[7] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[8] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[9] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[10] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[11] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[12] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[13] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[14] = 0;
			((*buf_i)+(i*PSW_INT_SIZE))[15] = 0x80;
		}
		else //User Password
		{
			tmp[size] = 0x80;
			do
			{
				((*buf_i)+(i*PSW_INT_SIZE)+j)[0] = ( (((uint32_t)tmp[k]) << 24) & 0xFF000000);
				k++;

				if(k <= size)
					((*buf_i)+(i*PSW_INT_SIZE)+j)[0] = ((*buf_i)+(i*PSW_INT_SIZE)+j)[0] | ( (((uint32_t)tmp[k]) << 8) & 0x0000FF00);

				j++;
				k++;
			} while(k <= size);

			if(size <= FIRST_LENGHT)
			{
				((*buf_i)+(i*PSW_INT_SIZE)+14)[0] = 0xFFFFFFFF;
				((*buf_i)+(i*PSW_INT_SIZE)+15)[0] = ((uint8_t)(((size*2) << 3) >> 8)) << 8 | ((uint8_t)((size*2) << 3));
			}
			else
			{
				((*buf_i)+(i*PSW_INT_SIZE)+30)[0] = 0;
				((*buf_i)+(i*PSW_INT_SIZE)+31)[0] = ((uint8_t)(((size*2) << 3) >> 8)) << 8 | ((uint8_t)((size*2) << 3));
			}
		}


		memset(tmp, 0, PSW_CHAR_SIZE);
		i++;

		if(i >= maxNumPsw) break;
	}

	return i;
}

