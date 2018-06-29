/*
 * BitCracker: BitLocker password cracking tool, Hash Extractor.
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>

#define __USE_FILE_OFFSET64
#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64

#define INPUT_SIZE 1024

#define SALT_SIZE 16
#define MAC_SIZE 16
#define NONCE_SIZE 12
#define IV_SIZE 16
#define VMK_SIZE 44

#define SIGNATURE_LEN 9
#define VMK_SALT_JUMP 12
#define VMK_AES_TYPE 0x0005

#define FILE_OUT_HASH_USER "hash_user_pass.txt"
#define FILE_OUT_HASH_RECV "hash_recv_pass.txt"

#define FRET_CHECK(ret)								\
        if(ret < 0)									\
        {										\
        	fprintf(stderr, "ftell error %s (%d)\n", strerror(errno),errno);	\
        	exit(EXIT_FAILURE);							\
        }

//Fixed
static unsigned char p_salt[SALT_SIZE], p_nonce[NONCE_SIZE], p_mac[MAC_SIZE], p_vmk[VMK_SIZE];
static unsigned char r_salt[SALT_SIZE], r_nonce[NONCE_SIZE], r_mac[MAC_SIZE], r_vmk[VMK_SIZE];
const char signature[SIGNATURE_LEN] = "-FVE-FS-";
unsigned char vmk_entry[4] = { 0x02, 0x00, 0x08, 0x00 };
unsigned char key_protection_clear[2] = { 0x00, 0x00 };
unsigned char key_protection_tpm[2] = { 0x00, 0x01 };
unsigned char key_protection_start_key[2] = { 0x00, 0x02 };
unsigned char key_protection_recovery[2] = { 0x00, 0x08 };
unsigned char key_protection_password[2] = { 0x00, 0x20 };
unsigned char value_type[2] = { 0x00, 0x05 };
unsigned char padding[16] = {0};

int userPasswordFound=0, recoveryPasswordFound=0, found_ccm=0;
long int fp_before_aes=0, fp_before_salt=0;
FILE *outFileUser, *outFileRecv, * encryptedImage;
int salt_pos[2] = {12, 32};
int aes_pos[2] = {147, 67};

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


static int usage(char *name){
	printf("\nUsage: %s -i <Image of encrypted memory unit> -o <output files path>\n\n"
		"Options:\n\n"
		"  -h"
		"\t\tShow this help\n"
		"  -i"
		"\t\tImage path of encrypted memory unit encrypted with BitLocker\n"
		"  -o"
		"\t\tOutputs path (i.e. /some/path/for/outputs/). Default: current directory\n\n", name);

	return EXIT_FAILURE;
}


static void fillBuffer(FILE *fp, unsigned char *buffer, int size)
{
	for (int k = 0; k < size; k++)
		buffer[k] = (unsigned char)fgetc(fp);
}

static void print_hex(unsigned char *str, int len, FILE *out)
{
	int i;

	for (i = 0; i < len; ++i)
		fprintf(out, "%02x", str[i]);
}

int rp_search_salt_aes() {
	uint8_t a,b;
	int ret=0;

	for(int x=0; x < 2; x++)
	{
		ret=fseek(encryptedImage, salt_pos[x], SEEK_CUR);
		FRET_CHECK(ret)

		fillBuffer(encryptedImage, r_salt, SALT_SIZE);
		printf("Salt: ");
		print_hex(r_salt, SALT_SIZE, stdout);
		printf("\n");
		fp_before_aes=ftell(encryptedImage);
		FRET_CHECK(fp_before_aes)
		fprintf(stderr, "Searching AES-CCM from 0x%lx\n", fp_before_aes);

		for(int y=0; y < 2; y++)
		{
			ret=fseek(encryptedImage, aes_pos[y], SEEK_CUR);
			FRET_CHECK(ret)

			fprintf(stderr, "Trying offset 0x%lx....\n", ftell(encryptedImage));
			a=(uint8_t)fgetc(encryptedImage);
			b=(uint8_t)fgetc(encryptedImage);
			if (( a != value_type[0]) || (b != value_type[1])) {
				fprintf(stderr, "Error: VMK not encrypted with AES-CCM (0x%x,0x%x)\n", a, b);
				found_ccm=0;
			}
			else 
			{
				fprintf(stderr, "VMK encrypted with AES-CCM!!\n");
				found_ccm=1;
				ret=fseek(encryptedImage, 3, SEEK_CUR);
				FRET_CHECK(ret)
			}

			if(found_ccm == 1) break;
		}

		if(found_ccm == 1) break;
	}

	return 0;
}


int parse_image(char * encryptedImagePath, char * outHashUser, char * outHashRecovery)
{
	long int fileLen=0, j=0;
	int version = 0, i = 0, match = 0, ret = 0;
	unsigned char c,d;

	encryptedImage = fopen(encryptedImagePath, "r");

	if (!encryptedImage || !outHashUser || !outHashRecovery) {
		fprintf(stderr, "! %s : %s\n", encryptedImagePath, strerror(errno));
		return 1;
	}

	ret=fseek(encryptedImage, 0, SEEK_END);
	FRET_CHECK(ret)

	fileLen = ftell(encryptedImage);
	FRET_CHECK(fileLen)
	printf("Encrypted device %s opened, size %ldMB\n", encryptedImagePath, ((fileLen/1024)/1024));
	ret=fseek(encryptedImage, 0, SEEK_SET);
	FRET_CHECK(ret)

	//printf("sizeof off_t=%ld, long int=%ld, ULONG_MAX=%lu LONG_MAX=%ld\n", sizeof(off_t), sizeof(long int), ULONG_MAX, LONG_MAX);

	for (j = 0; j < fileLen; j++) {
		c = fgetc(encryptedImage);
		while (i < 8 && (unsigned char)c == signature[i]) {
			c = fgetc(encryptedImage);
			i++;
		}
		if (i == 8) {
			match = 1;
			fprintf(stderr, "\nSignature found at 0x%lx\n", (ftell(encryptedImage) - i - 1));
			ret=fseek(encryptedImage, 1, SEEK_CUR);
			version = fgetc(encryptedImage);
			fprintf(stderr, "Version: %d ", version);
			if (version == 1)
				fprintf(stderr, "(Windows Vista)\n");
			else if (version == 2)
				fprintf(stderr, "(Windows 7 or later)\n");
			else {
				fprintf(stderr, "\nInvalid version, looking for a signature with valid version...\n");
				match = 0;
			}
		}
		if(match == 0) { i=0; continue; }

		i = 0;
		while (i < 4 && (unsigned char)c == vmk_entry[i]) {
			c = fgetc(encryptedImage);
			i++;
		}

		if (i == 4) {
			fprintf(stderr, "\nVMK entry found at 0x%lx\n", (ftell(encryptedImage) - i));
			ret=fseek(encryptedImage, 27, SEEK_CUR);
			FRET_CHECK(ret)
			c = (unsigned char)fgetc(encryptedImage);
			d = (unsigned char)fgetc(encryptedImage);

			fp_before_salt = ftell(encryptedImage);
			FRET_CHECK(fp_before_salt)

			if ((c == key_protection_clear[0]) && (d == key_protection_clear[1])) 
				fprintf(stderr, "VMK not encrypted.. stored clear! (0x%lx)\n", fp_before_salt);
			else if ((c == key_protection_tpm[0]) && (d == key_protection_tpm[1])) 
				fprintf(stderr, "VMK encrypted with TPM...not supported! (0x%lx)\n", fp_before_salt);
			else if ((c == key_protection_start_key[0]) && (d == key_protection_start_key[1])) 
				fprintf(stderr, "VMK encrypted with Startup Key...not supported! (0x%lx)\n", fp_before_salt);
			else if ((c == key_protection_recovery[0]) && (d == key_protection_recovery[1]) && recoveryPasswordFound == 0) 
			{
				fprintf(stderr, "\nVMK encrypted with Recovery Password found at 0x%lx\n", fp_before_salt);
				rp_search_salt_aes();
				if (found_ccm == 0)
				{
					match=0;
					i=0;
					continue;
				}
				
				fillBuffer(encryptedImage, r_nonce, NONCE_SIZE);
				fprintf(stdout, "RP Nonce: ");
				print_hex(r_nonce, NONCE_SIZE, stdout);
				
				fillBuffer(encryptedImage, r_mac, MAC_SIZE);
				fprintf(stdout, "\nRP MAC: ");
				print_hex(r_mac, MAC_SIZE, stdout);
				
				fprintf(stdout, "\nRP VMK: ");
				fillBuffer(encryptedImage, r_vmk, VMK_SIZE);
				print_hex(r_vmk, VMK_SIZE, stdout);
				fprintf(stdout, "\n\n");
				fflush(stdout);
				recoveryPasswordFound=1;
			}
			else if ((c == key_protection_password[0]) && (d == key_protection_password[1]) && userPasswordFound == 0) 
			{
				fprintf(stderr, "\nVMK encrypted with User Password found at %lx\n", fp_before_salt);
				ret=fseek(encryptedImage, 12, SEEK_CUR);
				FRET_CHECK(ret)
				fillBuffer(encryptedImage, p_salt, SALT_SIZE);
				ret=fseek(encryptedImage, 83, SEEK_CUR);
				FRET_CHECK(ret)
				if (((unsigned char)fgetc(encryptedImage) != value_type[0]) || ((unsigned char)fgetc(encryptedImage) != value_type[1])) {
					fprintf(stderr, "Error: VMK not encrypted with AES-CCM\n");
					match=0;
					i=0;
					continue;
				}
				else fprintf(stderr, "VMK encrypted with AES-CCM\n");

				ret=fseek(encryptedImage, 3, SEEK_CUR);
				FRET_CHECK(ret)

				fillBuffer(encryptedImage, p_nonce, NONCE_SIZE);
				fprintf(stdout, "UP Nonce: ");
				print_hex(p_nonce, NONCE_SIZE, stdout);

				fillBuffer(encryptedImage, p_mac, MAC_SIZE);
				fprintf(stdout, "\nUP MAC: ");
				print_hex(p_mac, MAC_SIZE, stdout);

				fillBuffer(encryptedImage, p_vmk, VMK_SIZE);
				fprintf(stdout, "\nUP VMK: ");
				print_hex(p_vmk, VMK_SIZE, stdout);
				fprintf(stdout, "\n\n");
				fflush(stdout);
				userPasswordFound=1;
			}
		}

		i = 0;
		//if(userPasswordFound == 1 || recoveryPasswordFound == 1) break;
	}

	fclose(encryptedImage);

	if (userPasswordFound == 0 && recoveryPasswordFound == 0) {
		fprintf(stderr, "Error while extracting data: No signature found!\n");
		return 1;
	} else {
		if(userPasswordFound == 1)
		{
			printf("\nUser Password hash:\n$bitlocker$0$%d$", SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, stdout); // hack, this should actually be entire AES-CCM encrypted block (which includes vmk)
			print_hex(p_vmk, VMK_SIZE, stdout);
			printf("\n");

			outFileUser = fopen(outHashUser, "w");
			if (!outFileUser) {
				fprintf(stderr, "Error creating ./%s : %s\n", outHashUser, strerror(errno));
				return 1;
			}

			fprintf(outFileUser, "$bitlocker$0$%d$", SALT_SIZE);
			print_hex(p_salt, SALT_SIZE, outFileUser);
			fprintf(outFileUser, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(p_nonce, NONCE_SIZE, outFileUser);
			fprintf(outFileUser, "$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(p_mac, MAC_SIZE, outFileUser); 
			print_hex(p_vmk, VMK_SIZE, outFileUser);
			fprintf(outFileUser, "\n");

			fclose(outFileUser);
		}

		if(recoveryPasswordFound == 1)
		{
			printf("\nRecovery Key hash:\n$bitlocker$2$%d$", SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, stdout);
			printf("$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(r_nonce, NONCE_SIZE, stdout);
			printf("$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, stdout); // hack, this should actually be entire AES-CCM encrypted block (which includes vmk)
			print_hex(r_vmk, VMK_SIZE, stdout);
			printf("\n");

			outFileRecv = fopen(outHashRecovery, "w");
			if (!outFileRecv) {
				fprintf(stderr, "Error creating ./%s : %s\n", outHashRecovery, strerror(errno));
				return 1;
			}

			fprintf(outFileRecv, "$bitlocker$2$%d$", SALT_SIZE);
			print_hex(r_salt, SALT_SIZE, outFileRecv);
			fprintf(outFileRecv, "$%d$%d$", 0x100000, NONCE_SIZE); // fixed iterations , fixed nonce size
			print_hex(r_nonce, NONCE_SIZE, outFileRecv);
			fprintf(outFileRecv, "$%d$", VMK_SIZE + MAC_SIZE);
			print_hex(r_mac, MAC_SIZE, outFileRecv); 
			print_hex(r_vmk, VMK_SIZE, outFileRecv);
			fprintf(outFileRecv, "\n");
			
			fclose(outFileRecv);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	int opt;
	char * imagePath=NULL;
	char * outPath=NULL;
	char * outHashUser=NULL;
	char * outHashRecovery=NULL;
	errno = 0;
	
	while (1) {
		opt = getopt(argc, argv, "hi:o:");
		if (opt == -1)
			break;
		switch (opt)
		{
			case 'h':
				usage(argv[0]);
				exit(EXIT_FAILURE);
				break;

			case 'i':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Input string is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				imagePath=(char *)Calloc(INPUT_SIZE, sizeof(char));
				strncpy(imagePath, optarg, strlen(optarg)+1);
				break;

			case 'o':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Input string is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				outHashUser = (char*)Calloc( (strlen(optarg)+strlen(FILE_OUT_HASH_USER)+2), sizeof(char));
				memcpy(outHashUser, optarg, strlen(optarg));
				outHashUser[strlen(optarg)] = '/';
				memcpy(outHashUser+strlen(optarg)+1, FILE_OUT_HASH_USER, strlen(FILE_OUT_HASH_USER));

				outHashRecovery = (char*)Calloc( (strlen(optarg)+strlen(FILE_OUT_HASH_RECV)+2), sizeof(char));
				memcpy(outHashRecovery, optarg, strlen(optarg));
				outHashRecovery[strlen(optarg)] = '/';
				memcpy(outHashRecovery+strlen(optarg)+1, FILE_OUT_HASH_RECV, strlen(FILE_OUT_HASH_RECV));
				
				break;

			default:
				break;
		}
	}

	if(!imagePath)
	{
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	
	if(outHashUser == NULL) //Current directory
	{
		outHashUser = (char*)Calloc( (strlen(FILE_OUT_HASH_USER)+1), sizeof(char));
		memcpy(outHashUser, FILE_OUT_HASH_USER, strlen(FILE_OUT_HASH_USER));
	}

	if(outHashRecovery == NULL) //Current directory
	{
		outHashRecovery = (char*)Calloc( (strlen(FILE_OUT_HASH_RECV)+1), sizeof(char));
		memcpy(outHashRecovery, FILE_OUT_HASH_RECV, strlen(FILE_OUT_HASH_RECV));
	}

	printf("\n---------> BitCracker Hash Extractor <---------\n");
	if(parse_image(imagePath, outHashUser, outHashRecovery))
		fprintf(stderr, "\nError while parsing input device image\n");
	else
	{
		if(userPasswordFound) printf("\nOutput file for user password attack: \"%s\"\n", outHashUser);
		if(recoveryPasswordFound) printf("\nOutput file for recovery password attack: \"%s\"\n", outHashRecovery);
	}

	free(outHashUser);
	free(outHashRecovery);

	return 0;
}

