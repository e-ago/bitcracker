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

int readData(char * encryptedImagePath, unsigned char ** salt, unsigned char ** mac, unsigned char ** nonce, unsigned char ** encryptedVMK)
{
	int match = 0;
	const char signature[9] = "-FVE-FS-";
	int version = 0;
	unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
	unsigned char key_protection_type[2] = { 0x00, 0x20 };
	unsigned char value_type[2] = { 0x00, 0x05 };
	char c;
	int i = 0;
	int j, fileLen;

	if( !salt || !mac || !nonce || !encryptedVMK ) {
		fprintf(stderr, "Input error\n");
		return BIT_FAILURE;
	}


	FILE * encryptedImage = fopen(encryptedImagePath, "r");
	if (!encryptedImage) {
		fprintf(stderr, "! %s : %s\n", encryptedImagePath, strerror(errno));
		return BIT_FAILURE;
	}

	fseek(encryptedImage, 0, SEEK_END);
	fileLen = ftell(encryptedImage);
	fseek(encryptedImage, 0, SEEK_SET);
	for (j = 0; j < fileLen; j++) {
		c = fgetc(encryptedImage);
		while (i < 8 && (unsigned char)c == signature[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 8) {
			match = 1;
			fprintf(stderr, "Signature found at 0x%08lx\n", (ftell(encryptedImage) - i - 1));
			fseek(encryptedImage, 1, SEEK_CUR);
			version = fgetc(encryptedImage);
			fprintf(stderr, "Version: %d ", version);
			if (version == 1)
				fprintf(stderr, "(Windows Vista)\n");
			else if (version == 2)
				fprintf(stderr, "(Windows 7 or later)\n");
			else {
				fprintf(stderr, "\nInvalid version, looking for a signature with valid version...\n");
			}
		}
		i = 0;
		while (i < 4 && (unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}

		if (i == 4) {
			fprintf(stderr, "VMK entry found at 0x%08lx\n", (ftell(encryptedImage) - i - 3));
			fseek(encryptedImage, 27, SEEK_CUR);
			if (
					( (unsigned char)fgetc(encryptedImage) == key_protection_type[0]) &&
					( (unsigned char)fgetc(encryptedImage) == key_protection_type[1])
			   ) 
			{
				fprintf(stderr, "Key protector with user password found\n");
				fseek(encryptedImage, 12, SEEK_CUR);
				fillBuffer(encryptedImage, *salt, SALT_SIZE);
				fseek(encryptedImage, 83, SEEK_CUR);
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) || ((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
					//ret failure?	
				}

				fseek(encryptedImage, 3, SEEK_CUR);
				fillBuffer(encryptedImage, *nonce, NONCE_SIZE);
				fillBuffer(encryptedImage, *mac, MAC_SIZE);
				fillBuffer(encryptedImage, *encryptedVMK, VMK_SIZE);
				break;
			}
		}

		i = 0;
	}

	fclose(encryptedImage);

	if (match == 0) {
		fprintf(stderr, "Error while extracting data: No signature found!\n");
		return BIT_FAILURE;
	}

	return BIT_SUCCESS;
}

int readFilePassword(char *buf, int maxNumPsw, FILE *fp) {
        int i=0, size;
        char tmp[MAX_INPUT_PASSWORD_LEN+2];
        memset(tmp, 0, MAX_INPUT_PASSWORD_LEN);

        if (fp == NULL || feof(fp) || buf == NULL)
                return -1;

        while(fgets(tmp, MAX_INPUT_PASSWORD_LEN+2, fp) && (i < maxNumPsw)) {
                size = (strlen(tmp)-1);
                if(tmp[0] == '\n' || size < 8 || size > 16)
                        continue;

                if(size < 16)
                        tmp[size] = 0x80; //0xFF;

                memcpy((buf+(i*MAX_INPUT_PASSWORD_LEN)), tmp, MAX_INPUT_PASSWORD_LEN);
                memset(tmp, 0, MAX_INPUT_PASSWORD_LEN);
                i++;
        }

        return i;
}

