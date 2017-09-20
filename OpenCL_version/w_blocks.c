#include "bitcracker.h"

unsigned int * w_block_precomputed(unsigned char * salt)
{

	// OpenCL Vars
    cl_device_id		device_id;
    cl_program          cpProgram;       // OpenCL program
    cl_kernel           ckKernelWBlocks;        // OpenCL kernel
    cl_mem              salt_d, padding_d, w_blocks_d;     // OpenCL device buffer
    cl_int              ciErr1;          // Error code var
    size_t szGlobalWorkSize;        // 1D var for Total # of work items
    size_t szLocalWorkSize;         // 1D var for # of work items in the work group 
    int                 i; 
    FILE                *fp_kernel;       

    //Very very ugly...
    const char fileNameWBlocks[] = "./OpenCL_version/kernel_wblocks.cl";
    size_t source_size_wbocks;     
    char *source_str_wbocks;

	unsigned char * padding;
	uint64_t msgLen;
	unsigned int * w_blocks_h;
	int iter_num;

    size_t len = 0;
    cl_int ret = CL_SUCCESS, ret_cl_log = CL_SUCCESS, ret_info_kernel = CL_SUCCESS;

	if(salt == NULL)
		return FALSE;

    //------- READ CL FILE ------            
    /* Load kernel source file */       
    fp_kernel = fopen(fileNameWBlocks, "rb");     
    if (!fp_kernel) {      
        fprintf(stderr, "Failed to load kernel.\n");    
        return NULL;
    }       
    source_str_wbocks = (char *)malloc(MAX_SOURCE_SIZE);       
    source_size_wbocks = fread(source_str_wbocks, 1, MAX_SOURCE_SIZE, fp_kernel);        
    fclose(fp_kernel);
    // -----------------------

    padding = (unsigned char *) Calloc(PADDING_SIZE, sizeof(unsigned char));
	padding[0] = 0x80;
	memset(padding+1, 0, 31);
	msgLen = (FIXED_PART_INPUT_CHAIN_HASH << 3);
	for (i = 0; i < 8; i++)
		padding[PADDING_SIZE-1-i] = (uint8_t)(msgLen >> (i * 8));

    // ------------------------------- Data setup -------------------------------
    // Allocate the OpenCL buffer memory objects for source and result on the device GMEM
    salt_d = clCreateBuffer(cxGPUContext, CL_MEM_READ_ONLY, SALT_SIZE * sizeof(char), NULL, &ciErr1);
    CL_ERROR(ciErr1);
    
    padding_d = clCreateBuffer(cxGPUContext, CL_MEM_READ_ONLY, PADDING_SIZE * sizeof(char), NULL, &ciErr1);
    CL_ERROR(ciErr1); 

    w_blocks_d = clCreateBuffer(cxGPUContext,  CL_MEM_WRITE_ONLY, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(int), NULL, &ciErr1);
    CL_ERROR(ciErr1);

   	w_blocks_h = (unsigned int *) Calloc((SINGLE_BLOCK_SHA_SIZE*ITERATION_NUMBER), sizeof(int));
   	if(!w_blocks_h)
   		goto out;

    // --------------------------------------------------------------------------

    // ------------------------------- Kernel setup -------------------------------
    /* Create kernel from source */     
    cpProgram = clCreateProgramWithSource(cxGPUContext, 1, (const char **)&source_str_wbocks, (const size_t *)&source_size_wbocks, &ciErr1);        
    CL_ERROR(ciErr1);
    ciErr1 = clBuildProgram(cpProgram, 1, &(cdDevices[gpu_id]), "-I .", NULL, NULL);
    CL_ERROR(ciErr1);

    ret = clGetProgramBuildInfo(cpProgram, cdDevices[gpu_id], CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
    CL_ERROR(ret);
    char *buffer = calloc(len, sizeof(char));
    ret_cl_log = clGetProgramBuildInfo(cpProgram, cdDevices[gpu_id], CL_PROGRAM_BUILD_LOG, len, buffer, NULL);
    CL_ERROR(ret_cl_log);
    if(ret != CL_SUCCESS)
        printf("BUILD LOG: \n%s\n\n", buffer);   

    // Create the kernel
    ckKernelWBlocks = clCreateKernel(cpProgram, "opencl_bitcracker_wblocks", &ciErr1);
    CL_ERROR(ciErr1);
    // --------------------------------------------------------------------------

    // ------------------------------- Write static buffers -------------------------------
    ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, salt_d, CL_TRUE, 0, SALT_SIZE * sizeof(unsigned char), salt, 0, NULL, NULL);      
    CL_ERROR(ciErr1);
    ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, padding_d, CL_TRUE, 0, PADDING_SIZE * sizeof(unsigned char), padding, 0, NULL, NULL);      
    CL_ERROR(ciErr1);  
    // --------------------------------------------------------------------------

    // Set the Argument values
    iter_num = ITERATION_NUMBER;
    ciErr1 = clSetKernelArg(ckKernelWBlocks, 0, sizeof(cl_int), (void*)&iter_num);
    CL_ERROR(ciErr1);
    ciErr1 = clSetKernelArg(ckKernelWBlocks, 1, sizeof(cl_mem), (void*)&salt_d);
    CL_ERROR(ciErr1);
    ciErr1 = clSetKernelArg(ckKernelWBlocks, 2, sizeof(cl_mem), (void*)&padding_d);
    CL_ERROR(ciErr1);
    ciErr1 = clSetKernelArg(ckKernelWBlocks, 3, sizeof(cl_mem), (void*)&w_blocks_d);
    CL_ERROR(ciErr1);
    
    // ---------------------- Launch kernel

    //printf("\n--- KERNEL INFO ---\n");
    size_t workgroup_size;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelWBlocks, cdDevices[gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(size_t), &workgroup_size, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_WORK_GROUP_SIZE: %zd\n", workgroup_size);

    cl_ulong localMemSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelWBlocks, cdDevices[gpu_id], CL_KERNEL_LOCAL_MEM_SIZE, sizeof(cl_ulong), &localMemSize, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_LOCAL_MEM_SIZE: %lld\n", localMemSize);

    size_t preferredWorkGroupSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelWBlocks, cdDevices[gpu_id], CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof(size_t), &preferredWorkGroupSize, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE: %zd\n", preferredWorkGroupSize);

    cl_ulong privateMemSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelWBlocks, cdDevices[gpu_id], CL_KERNEL_PRIVATE_MEM_SIZE, sizeof(cl_ulong), &privateMemSize, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_PRIVATE_MEM_SIZE: %lld\n", privateMemSize);
    //printf("--------------------------\n");

    // --------------------------------------------------------------------------


    //-------- Initialize input data --------  
    szLocalWorkSize = workgroup_size;
    szGlobalWorkSize = 16*szLocalWorkSize;  //TOT THREADS 
    //printf("Global Work Size: %zd, Local Work Size: %zd\n", szGlobalWorkSize, szLocalWorkSize);
	
    time_t start,end;
    double dif;
    time (&start);
    
	ciErr1 = clEnqueueNDRangeKernel(cqCommandQueue, ckKernelWBlocks, 1, NULL, &szGlobalWorkSize, &szLocalWorkSize, 0, NULL, NULL);
	CL_ERROR(ciErr1);

    /* Copy result to host */       
    ciErr1 = clEnqueueReadBuffer(cqCommandQueue, w_blocks_d, CL_TRUE, 0, SINGLE_BLOCK_SHA_SIZE*ITERATION_NUMBER*sizeof(unsigned int), w_blocks_h, 0, NULL, NULL);
    CL_ERROR(ciErr1);

    time (&end);
    dif = difftime (end,start);
    //printf ("W Blocks computed in %.2lf seconds\n\n", dif);


    ret = clFlush(cqCommandQueue);       
    ret = clFinish(cqCommandQueue);

//	fprintf(stdout, "%d W words in %f ms (%f sec) \n", (SINGLE_BLOCK_SHA_SIZE*ITERATION_NUMBER), timeElapsedW, (timeElapsedW/1000.0));

out:

	if(ckKernelWBlocks)clReleaseKernel(ckKernelWBlocks);  
    if(cpProgram)clReleaseProgram(cpProgram);
    
	clReleaseMemObject(salt_d);
	clReleaseMemObject(padding_d);
	clReleaseMemObject(w_blocks_d);
	
	free(padding);
	free(source_str_wbocks);

	/*
	 * Useless
	 * unsigned int * w_blocks_h = NULL;
	 * w_blocks_h = (unsigned int *) Calloc((SINGLE_BLOCK_SHA_SIZE*ITERATION_NUMBER), sizeof(unsigned int));
	 * BITCRACKER_CUDA_CHECK( cudaMemcpy(w_blocks_h, w_blocks_d, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(unsigned int), cudaMemcpyDeviceToHost) );
	*/

	return w_blocks_h;
}