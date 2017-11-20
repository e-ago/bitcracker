/*
 * BitCracker: BitLocker password cracking tool, OpenCL version.
 * Copyright (C) 2013-2017  Elena Ago <elena dot ago at gmail dot com>
 *                          Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
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

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/time.h>

#ifdef __APPLE__            
    #include <OpenCL/opencl.h>          
#else           
    #include <CL/cl.h>      
    #include <CL/cl_ext.h> 
    #pragma OPENCL EXTENSION cl_nv_device_attribute_query : enable
#endif

#ifndef CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV
  /* cl_nv_device_attribute_query extension - no extension #define since it has no functions */
  #define CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV       0x4000
  #define CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV       0x4001
  #define CL_DEVICE_REGISTERS_PER_BLOCK_NV            0x4002
  #define CL_DEVICE_WARP_SIZE_NV                      0x4003
  #define CL_DEVICE_GPU_OVERLAP_NV                    0x4004
  #define CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV            0x4005
  #define CL_DEVICE_INTEGRATED_MEMORY_NV              0x4006
#endif

#define MIN(a,b) (((a)<(b))?(a):(b))
#define AUTHENTICATOR_LENGTH 16
#define AES_CTX_LENGTH 256
#define FALSE 0
#define TRUE 1
#define SALT_SIZE 16
#define MAC_SIZE 16
#define NONCE_SIZE 12
#define IV_SIZE 16

#define VMK_SIZE 60
#define VMK_HEADER_SIZE 12
#define VMK_BODY_SIZE 32
#define VMK_FULL_SIZE 44

#define DICT_BUFSIZE    (50*1024*1024)
#define MAX_PLEN 32

#ifndef UINT32_C
#define UINT32_C(c) c ## UL
#endif

#define HASH_SIZE 8 //32
#define ROUND_SHA_NUM 64
#define SINGLE_BLOCK_SHA_SIZE 64
#define SINGLE_BLOCK_W_SIZE 64
#define PADDING_SIZE 40
#define ITERATION_NUMBER 0x100000
#define WORD_SIZE 4
#define INPUT_SIZE 2048
#define FIXED_PART_INPUT_CHAIN_HASH 88
#define MAX_INPUT_PASSWORD_LEN 27
#define FIXED_PASSWORD_BUFFER 32

#define BLOCK_UNIT 32
#define HASH_SIZE_STRING 32

#define HASH_TAG              "$bitlocker$"
#define HASH_TAG_LEN          (sizeof(HASH_TAG) - 1)
#define INPUT_HASH_SIZE         210

#define ATTACK_DEFAULT_THREADS 1024

#define BIT_SUCCESS 0
#define BIT_FAILURE 1

#define MAX_SOURCE_SIZE (0x100000)          

#define LOCAL_THREAD 768
#define MAX_NUM_PLATFORMS 10
#define MAX_DEVICE_NAME_SIZE 2048

static const char *getErrorString(cl_int error)
{
    switch(error){
        // run-time and JIT compiler errors
        case 0: return "CL_SUCCESS";
        case -1: return "CL_DEVICE_NOT_FOUND";
        case -2: return "CL_DEVICE_NOT_AVAILABLE";
        case -3: return "CL_COMPILER_NOT_AVAILABLE";
        case -4: return "CL_MEM_OBJECT_ALLOCATION_FAILURE";
        case -5: return "CL_OUT_OF_RESOURCES";
        case -6: return "CL_OUT_OF_HOST_MEMORY";
        case -7: return "CL_PROFILING_INFO_NOT_AVAILABLE";
        case -8: return "CL_MEM_COPY_OVERLAP";
        case -9: return "CL_IMAGE_FORMAT_MISMATCH";
        case -10: return "CL_IMAGE_FORMAT_NOT_SUPPORTED";
        case -11: return "CL_BUILD_PROGRAM_FAILURE";
        case -12: return "CL_MAP_FAILURE";
        case -13: return "CL_MISALIGNED_SUB_BUFFER_OFFSET";
        case -14: return "CL_EXEC_STATUS_ERROR_FOR_EVENTS_IN_WAIT_LIST";
        case -15: return "CL_COMPILE_PROGRAM_FAILURE";
        case -16: return "CL_LINKER_NOT_AVAILABLE";
        case -17: return "CL_LINK_PROGRAM_FAILURE";
        case -18: return "CL_DEVICE_PARTITION_FAILED";
        case -19: return "CL_KERNEL_ARG_INFO_NOT_AVAILABLE";

        // compile-time errors
        case -30: return "CL_INVALID_VALUE";
        case -31: return "CL_INVALID_DEVICE_TYPE";
        case -32: return "CL_INVALID_PLATFORM";
        case -33: return "CL_INVALID_DEVICE";
        case -34: return "CL_INVALID_CONTEXT";
        case -35: return "CL_INVALID_QUEUE_PROPERTIES";
        case -36: return "CL_INVALID_COMMAND_QUEUE";
        case -37: return "CL_INVALID_HOST_PTR";
        case -38: return "CL_INVALID_MEM_OBJECT";
        case -39: return "CL_INVALID_IMAGE_FORMAT_DESCRIPTOR";
        case -40: return "CL_INVALID_IMAGE_SIZE";
        case -41: return "CL_INVALID_SAMPLER";
        case -42: return "CL_INVALID_BINARY";
        case -43: return "CL_INVALID_BUILD_OPTIONS";
        case -44: return "CL_INVALID_PROGRAM";
        case -45: return "CL_INVALID_PROGRAM_EXECUTABLE";
        case -46: return "CL_INVALID_KERNEL_NAME";
        case -47: return "CL_INVALID_KERNEL_DEFINITION";
        case -48: return "CL_INVALID_KERNEL";
        case -49: return "CL_INVALID_ARG_INDEX";
        case -50: return "CL_INVALID_ARG_VALUE";
        case -51: return "CL_INVALID_ARG_SIZE";
        case -52: return "CL_INVALID_KERNEL_ARGS";
        case -53: return "CL_INVALID_WORK_DIMENSION";
        case -54: return "CL_INVALID_WORK_GROUP_SIZE";
        case -55: return "CL_INVALID_WORK_ITEM_SIZE";
        case -56: return "CL_INVALID_GLOBAL_OFFSET";
        case -57: return "CL_INVALID_EVENT_WAIT_LIST";
        case -58: return "CL_INVALID_EVENT";
        case -59: return "CL_INVALID_OPERATION";
        case -60: return "CL_INVALID_GL_OBJECT";
        case -61: return "CL_INVALID_BUFFER_SIZE";
        case -62: return "CL_INVALID_MIP_LEVEL";
        case -63: return "CL_INVALID_GLOBAL_WORK_SIZE";
        case -64: return "CL_INVALID_PROPERTY";
        case -65: return "CL_INVALID_IMAGE_DESCRIPTOR";
        case -66: return "CL_INVALID_COMPILER_OPTIONS";
        case -67: return "CL_INVALID_LINKER_OPTIONS";
        case -68: return "CL_INVALID_DEVICE_PARTITION_COUNT";

        // extension errors
        case -1000: return "CL_INVALID_GL_SHAREGROUP_REFERENCE_KHR";
        case -1001: return "CL_PLATFORM_NOT_FOUND_KHR";
        case -1002: return "CL_INVALID_D3D10_DEVICE_KHR";
        case -1003: return "CL_INVALID_D3D10_RESOURCE_KHR";
        case -1004: return "CL_D3D10_RESOURCE_ALREADY_ACQUIRED_KHR";
        case -1005: return "CL_D3D10_RESOURCE_NOT_ACQUIRED_KHR";
        default: return "Unknown OpenCL error";
    }
}

#define CL_ERROR(errNum)                                     \
    if (errNum != CL_SUCCESS)                                   \
    {                                                           \
        fprintf(stdout, "Error in line %u in file %s: %s (%d)!!!\n\n", __LINE__, __FILE__, getErrorString(errNum), errNum);    \
        exit(EXIT_FAILURE);                                                                                                     \
    }

extern int gpu_id;
extern int platform_id;
extern int psw_x_thread;
extern int tot_psw;
extern size_t size_psw;
extern int strict_check;
extern int mac_comparison;

extern int MAX_PASSWD_SINGLE_KERNEL;
extern int DEV_NVIDIA;
extern int DEV_INTEL;
extern int DEV_AMD;
extern int CC_SM50;
//extern long int GPU_MAX_MEM_ALLOC_SIZE;
extern int GPU_MAX_COMPUTE_UNITS;
extern int GPU_MAX_WORKGROUP_SIZE;
extern long int GPU_MAX_GLOBAL_MEM;

// OpenCL Vars
extern cl_context          cxGPUContext;        // OpenCL context
extern cl_command_queue    cqCommandQueue;// OpenCL command que
extern cl_platform_id      cpPlatforms[MAX_NUM_PLATFORMS];      // OpenCL platform
extern cl_uint             uiNumDevices;    // OpenCL total number of devices
extern cl_device_id*       cdDevices;       // OpenCL device(s)

unsigned int * w_block_precomputed(unsigned char * salt);
int readFilePassword(char ** buf, int maxNumPsw, FILE *fp);
int parse_data(char *input_hash, unsigned char ** salt, unsigned char ** nonce, unsigned char ** vmk, unsigned char ** mac);
char * opencl_attack(char *dname, unsigned int * w_blocks,
                    unsigned char * encryptedVMK,
                    unsigned char * nonce, unsigned char * encryptedMAC,
                    int gridBlocks);

void setBufferPasswordSize(size_t avail, size_t * passwordBufferSize, int * numPassword);

void * Calloc(size_t len, size_t size);
void print_hex(unsigned char hash[], int size);

