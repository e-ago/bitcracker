/*
 * BitCracker: BitLocker password cracking tool, OpenCL version.
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
//#pragma OPENCL EXTENSION cl_nv_device_attribute_query : enable

int DEV_NVIDIA=0;
int DEV_INTEL=0;
int DEV_AMD=0;
int CC_SM50=0;

int MAX_PASSWD_SINGLE_KERNEL=16;

long int GPU_MAX_MEM_ALLOC_SIZE=0;
int GPU_MAX_COMPUTE_UNITS=16;
int GPU_MAX_WORKGROUP_SIZE=0;
long int GPU_MAX_GLOBAL_MEM=0;

int gpu_id=0;
int platform_id=0;
int psw_x_thread=8;
int tot_psw=0;
size_t size_psw=0;
size_t tot_word_mem=(SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(uint32_t));

// OpenCL Vars
cl_context          cxGPUContext;        // OpenCL context
cl_command_queue    cqCommandQueue;// OpenCL command que
cl_platform_id      cpPlatforms[MAX_NUM_PLATFORMS];      // OpenCL platform
cl_uint             uiNumDevices;    // OpenCL total number of devices
cl_device_id*       cdDevices;       // OpenCL device(s)


void usage(char *name)
{
	printf("\nUsage: %s -i <disk_image> -d <dictionary_file>\n\n"
		"Options:\n\n"
		"  -h, --help"
		"\t\t\tShow this help\n"
		"  -i, --diskimage"
		"\t\tPath to your disk image\n"
		"  -d, --dictionary file"
		"\t\tPath to dictionary or alphabet file\n"
		"  -p, --platform"
		"\t\tPlatform\n"
		"  -g, --gpu"
		"\t\tGPU device number\n"
		"  -t, --passthread"
		"\t\tSet the number of password per thread threads\n"
		"  -b, --blocks"
		"\t\tSet the number of blocks\n\n", name);
}

int checkDeviceStatistics()
{
	int i, j;
    char* value;
    size_t valueSize, maxWorkGroup;
    cl_uint platformCount;
    cl_platform_id* platforms;
    cl_uint deviceCount;
    cl_device_id* devices;
    cl_uint maxComputeUnits, deviceAddressBits;
    cl_ulong maxAllocSize, maxConstBufSize;
    cl_uint ccMajor, ccMinor, registersPerBlock, warpSize, overlap;
 	char dname[2048];
 	int deviceFound=0;
	size_t	avail, total;

    // get all platforms
    clGetPlatformIDs(0, NULL, &platformCount);
    platforms = (cl_platform_id*) malloc(sizeof(cl_platform_id) * platformCount);
    clGetPlatformIDs(platformCount, platforms, NULL);
 
    
    for (i = 0; i < platformCount; i++)
    {
        // get all devices
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL, 0, NULL, &deviceCount);
        devices = (cl_device_id*) malloc(sizeof(cl_device_id) * deviceCount);
        clGetDeviceIDs(platforms[i], CL_DEVICE_TYPE_ALL, deviceCount, devices, NULL);
		
    	printf("\n# Platform: %d, # Devices: %d\n", i, deviceCount);
        // for each device print critical attributes
        for (j = 0; j < deviceCount; j++)
        {

            // print device name
            clGetDeviceInfo(devices[j], CL_DEVICE_NAME, 0, NULL, &valueSize);
            value = (char*) malloc(valueSize);
            clGetDeviceInfo(devices[j], CL_DEVICE_NAME, valueSize, value, NULL);
	        free(value);

			if (platform_id == i && gpu_id == j)
			{
	            printf("\n====================================\nSelected device: %s (ID: %d) properties\n====================================\n\n", value, j);
	 			deviceFound=1; 			
			}
			else
	            printf("\n====================================\nDevice %s (ID: %d) properties\n====================================\n\n", value, j);				
 
            // print hardware device version
            clGetDeviceInfo(devices[j], CL_DEVICE_VERSION, 0, NULL, &valueSize);
            value = (char*) malloc(valueSize);
            clGetDeviceInfo(devices[j], CL_DEVICE_VERSION, valueSize, value, NULL);
            printf("Hardware version: %s\n", value);
            free(value);
 
            // print software driver version
            clGetDeviceInfo(devices[j], CL_DRIVER_VERSION, 0, NULL, &valueSize);
            value = (char*) malloc(valueSize);
            clGetDeviceInfo(devices[j], CL_DRIVER_VERSION, valueSize, value, NULL);
            printf("Software version: %s\n", value);
            free(value);
 
            // print c version supported by compiler for device
            clGetDeviceInfo(devices[j], CL_DEVICE_OPENCL_C_VERSION, 0, NULL, &valueSize);
            value = (char*) malloc(valueSize);
            clGetDeviceInfo(devices[j], CL_DEVICE_OPENCL_C_VERSION, valueSize, value, NULL);
            printf("OpenCL C version: %s\n", value);
            free(value);
 			
 			clGetDeviceInfo(devices[j], CL_DEVICE_GLOBAL_MEM_SIZE, sizeof(maxAllocSize), &maxAllocSize, NULL);
            printf("Max Global Memory Size: %lld\n", maxAllocSize);
			GPU_MAX_GLOBAL_MEM=maxAllocSize;
			maxAllocSize=0;
            clGetDeviceInfo(devices[j], CL_DEVICE_MAX_MEM_ALLOC_SIZE, sizeof(maxAllocSize), &maxAllocSize, NULL);
            printf("Max Global Memory Alloc Size: %lld\n", maxAllocSize);
			GPU_MAX_MEM_ALLOC_SIZE=maxAllocSize;

            clGetDeviceInfo(devices[j], CL_DEVICE_MAX_CONSTANT_BUFFER_SIZE, sizeof(maxConstBufSize), &maxConstBufSize, NULL);
            printf("Max Const Memory Buffer Size: %lld\n", maxConstBufSize);
            clGetDeviceInfo(devices[j], CL_DEVICE_ADDRESS_BITS, sizeof(deviceAddressBits), &deviceAddressBits, NULL);
            printf("Device Address Bits: %d\n", deviceAddressBits);

            // print parallel compute units
            clGetDeviceInfo(devices[j], CL_DEVICE_MAX_COMPUTE_UNITS, sizeof(maxComputeUnits), &maxComputeUnits, NULL);
            printf("Parallel compute units: %d\n", maxComputeUnits);
			GPU_MAX_COMPUTE_UNITS=maxComputeUnits;

 			clGetDeviceInfo(devices[j], CL_DEVICE_MAX_WORK_GROUP_SIZE, sizeof(maxWorkGroup), &maxWorkGroup, NULL);
            printf("Max Workgroup Size: %zd\n", maxWorkGroup);
			GPU_MAX_WORKGROUP_SIZE=maxWorkGroup;
			
            clGetDeviceInfo(devices[j], CL_DEVICE_VENDOR, sizeof(dname), dname, NULL);
			printf("Vendor: %s\n", dname);

			if(strstr(dname, "NVIDIA") != NULL)
			{
				DEV_NVIDIA=1;
				/*
				  |------------------------------------------------------------------------------------------------------------------|
				  | CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV  |  cl_uint  |  Returns the major revision number that defines the CUDA    |
				  |                                        |           |  compute capability of the device.                          |
				  |------------------------------------------------------------------------------------------------------------------|
				  | CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV  |  cl_uint  |  Returns the minor revision number that defines the CUDA    |
				  |                                        |           |  compute capability of the device.                          |
				  |------------------------------------------------------------------------------------------------------------------|
				  | CL_DEVICE_REGISTERS_PER_BLOCK_NV       |  cl_unit  |  Maximum number of 32-bit registers available to a          | 
				  |                                        |           |  work-group; this number is shared by all work-groups       |
				  |                                        |           |  simultaneously resident on a multiprocessor.               |
				  |------------------------------------------------------------------------------------------------------------------|
				  | CL_DEVICE_WARP_SIZE_NV                 |  cl_uint  |  Warp size in work-items.                                   |
				  |                                        |           |                                                             |
				  |------------------------------------------------------------------------------------------------------------------|
				  | CL_DEVICE_GPU_OVERLAP_NV               |  cl_bool  |  Returns CL_TRUE if the device can concurrently copy memory |
				  |                                        |           |  between host and device while executing a kernel, or       |  
				  |                                        |           |  CL_FALSE if not.                                           |
				  |------------------------------------------------------------------------------------------------------------------|           
				  | CL_DEVICE_KERNEL_EXEC_TIMEOUT_NV       |  cl_bool  |  CL_TRUE if there is a run time limit for kernels executed  |
				  |                                        |           |  on the device, or CL_FALSE if not.                         |
				  |------------------------------------------------------------------------------------------------------------------|
				  | CL_DEVICE_INTEGRATED_MEMORY_NV         |  cl_bool  |  CL_TRUE if the device is integrated with the memory        |
				  |                                        |           |  subsystem, or CL_FALSE if not.                             |  
				  |------------------------------------------------------------------------------------------------------------------|  
				*/
				clGetDeviceInfo(devices[j], CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof(ccMajor), &ccMajor, NULL);
				clGetDeviceInfo(devices[j], CL_DEVICE_COMPUTE_CAPABILITY_MINOR_NV, sizeof(ccMinor), &ccMinor, NULL);
				printf("CC: %d.%d\n", ccMajor, ccMinor);

				clGetDeviceInfo(devices[j], CL_DEVICE_REGISTERS_PER_BLOCK_NV, sizeof(registersPerBlock), &registersPerBlock, NULL);
				printf("Registers per block: %d\n", registersPerBlock);

				clGetDeviceInfo(devices[j], CL_DEVICE_WARP_SIZE_NV, sizeof(warpSize), &warpSize, NULL);
				printf("Warp Size: %d\n", warpSize);

				clGetDeviceInfo(devices[j], CL_DEVICE_GPU_OVERLAP_NV, sizeof(overlap), &overlap, NULL);
				printf("Overlap Memory and Kernel: %d\n", overlap);
			}	

			if (strstr(dname, "Intel") != NULL) DEV_INTEL=1;
			if ((strstr(dname, "Advanced Micro") != NULL || strstr(dname, "AMD") != NULL || strstr(dname, "ATI") != NULL)) DEV_AMD=1;
        
        	if(deviceFound==1)
        	{
				printf("\nFor this session, BitCracker requires at least %ld bytes of memory\n\n", (tot_word_mem+size_psw));  	
				if(GPU_MAX_GLOBAL_MEM < (tot_word_mem+size_psw))
				{
					fprintf(stderr, "Not enough memory available on device. Minimum required: %zd Tot memory: %ld\n", (tot_word_mem+size_psw), GPU_MAX_GLOBAL_MEM);
					return BIT_FAILURE;
				}
				
				if(GPU_MAX_MEM_ALLOC_SIZE < tot_word_mem || GPU_MAX_MEM_ALLOC_SIZE < size_psw)
				{
					fprintf(stderr, "GPU_MAX_MEM_ALLOC_SIZE: %zd Mem chunk1: %zd Mem chunk2: %zd\n", GPU_MAX_MEM_ALLOC_SIZE, tot_word_mem, size_psw);
					return BIT_FAILURE;
				}

				break;        		
        	}

        }
 
        free(devices);
        if(deviceFound == 1) break;
    }
 
    free(platforms);

    if(deviceFound == 0)
    {
    	fprintf(stderr, "Device not found! Input platform: %d, input device: %d\n", platform_id, gpu_id);
		return BIT_FAILURE;
    }
		
	return BIT_SUCCESS;
}

int createClCtx()
{
	cl_int clErr;
	char * gpuname;
	size_t gpunameSize;

	// ------------------------------- OpenCL setup -------------------------------
    //Get an OpenCL platform
    cl_uint numPlatforms = 0;
    clErr = clGetPlatformIDs(MAX_NUM_PLATFORMS, cpPlatforms, &numPlatforms);
    CL_ERROR(clErr);
     
    /* Get platform/device information */
    clErr = clGetDeviceIDs(cpPlatforms[platform_id], CL_DEVICE_TYPE_ALL, 0, NULL, &uiNumDevices);
    CL_ERROR(clErr);
    cdDevices = (cl_device_id *)malloc(uiNumDevices * sizeof(cl_device_id) );
    clErr = clGetDeviceIDs(cpPlatforms[platform_id], CL_DEVICE_TYPE_ALL, uiNumDevices, cdDevices, NULL);
    CL_ERROR(clErr);

	// print device name
	clGetDeviceInfo(cdDevices[gpu_id], CL_DEVICE_NAME, 0, NULL, &gpunameSize);
	gpuname = (char*) malloc(gpunameSize);
	clGetDeviceInfo(cdDevices[gpu_id], CL_DEVICE_NAME, gpunameSize, gpuname, NULL);
	free(gpuname);

    printf("Setting context on Platform %d, Device '%s' (ID: %d)\n", platform_id, gpuname, gpu_id);

    //Create the context
    cxGPUContext = clCreateContext(0, 1, &(cdDevices[gpu_id]), NULL, NULL, &clErr);
    CL_ERROR(clErr);
     
    // Create a command-queue
    cqCommandQueue = clCreateCommandQueue(cxGPUContext, cdDevices[gpu_id], 0, &clErr);
    CL_ERROR(clErr);
    // --------------------------------------------------------------------------

    return 0;
}

int destroyClCtx()
{
    if(cqCommandQueue)clReleaseCommandQueue(cqCommandQueue);
    if(cxGPUContext)clReleaseContext(cxGPUContext);

    return 0;
}

int main (int argc, char **argv)
{
	char dictionaryFile[INPUT_SIZE]="\0";
	char diskImageFile[INPUT_SIZE];
	unsigned char * salt;
	unsigned char * mac;
	unsigned char * nonce;
	unsigned char * encryptedVMK;
	uint32_t * w_blocks_d;
	long int totGlobalMem;
	
	//int threads = 0;
	int gridBlocks = 4, ret;
	int opt, option_index = 0;
	gpu_id=0;
	platform_id=0;

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
				{"diskimage", required_argument, 0, 'i'},
				{"dictionary", required_argument, 0, 'd'},
				//{"info", required_argument, 0, 'o'},
				//{"cuda.threads", required_argument, 0, 't'},
				{"passthread", required_argument, 0, 't'},
				{"blocks", required_argument, 0, 'b'},
				{"gpu", required_argument, 0, 'g'},
				{"platform", required_argument, 0, 'p'},
				{0, 0, 0, 0}
			};

		opt = getopt_long (argc, argv, "hi:d:t:b:p:g:", long_options, &option_index);
		if (opt == -1)
			break;
		switch (opt) {
			case 'h':
				usage(argv[0]);
				exit(EXIT_FAILURE);
				break;
			case 'i':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Disk image path is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				strncpy(diskImageFile,optarg, strlen(optarg)+1);
				break;
			case 'd':
				if(strlen(optarg) >= INPUT_SIZE)
				{
					fprintf(stderr, "ERROR: Dictionary file path is bigger than %d\n", INPUT_SIZE);
					exit(EXIT_FAILURE);
				}
				strncpy(dictionaryFile,optarg, strlen(optarg)+1);
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
			case 'p':
				platform_id = atoi(optarg);
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
	
	if (dictionaryFile[0] == '\0'){
		printf("Missing dictionary file!\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	if (diskImageFile[0] == '\0'){
		printf("Missing dick image file!\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	//***********************************************************

	if(checkDeviceStatistics())
	{
		fprintf(stderr, "checkDeviceStatistics error... exit!\n");
		exit(EXIT_FAILURE);
	}
	
	if(createClCtx())
	{
		fprintf(stderr, "checkDeviceStatistics error... exit!\n");
		exit(EXIT_FAILURE);
	}

	//****************** Data from target file *******************
	printf("\n====================================\nExtracting data from disk image\n====================================\n\n");
	salt = (unsigned char *) Calloc(SALT_SIZE, sizeof(unsigned char));
	mac = (unsigned char *) Calloc(MAC_SIZE, sizeof(unsigned char));
	nonce = (unsigned char *) Calloc(NONCE_SIZE, sizeof(unsigned char));
	encryptedVMK = (unsigned char *) Calloc(VMK_SIZE, sizeof(unsigned char));
	if(readData(diskImageFile, &salt, &mac, &nonce, &encryptedVMK) == BIT_FAILURE)
	{
		fprintf(stderr, "Disk image error... exit!\n");
		goto cleanup;
	}
	//************************************************************

	printf("\n\n====================================\nDictionary attack\n====================================\n\n");
	//****************** W block *******************
	uint32_t * w_blocks_h = w_block_precomputed(salt);
	if(!w_blocks_h)
	{
		fprintf(stderr, "Words error... exit!\n");
		goto cleanup;
	}
	//**********************************************

	//************* Dictionary Attack *************
	opencl_attack(dictionaryFile, w_blocks_h, encryptedVMK, nonce, gridBlocks);
	//*********************************************

	cleanup:
		destroyClCtx();
		printf("\n\n");
		return 0;
}
