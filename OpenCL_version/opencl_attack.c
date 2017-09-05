/*
 * BitCracker: BitLocker password cracking tool, OpenCL version.
 * Copyright (C) 2013-2017  Elena Ago <elena dot ago at gmail dot com>
 *                          Massimo Bernaschi <massimo dot bernaschi at gmail dot com>
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

#define TIMER_DEF(n)     struct timeval temp_1_##n={0,0}, temp_2_##n={0,0}
#define TIMER_START(n)   gettimeofday(&temp_1_##n, (struct timezone*)0)
#define TIMER_STOP(n)    gettimeofday(&temp_2_##n, (struct timezone*)0)
#define TIMER_ELAPSED(n) ((temp_2_##n.tv_sec-temp_1_##n.tv_sec)*1.e6+(temp_2_##n.tv_usec-temp_1_##n.tv_usec))

unsigned char   outPsw[MAX_INPUT_PASSWORD_LEN+2];
int             *hostFound, match;
unsigned char   *hostPassword;

static int check_match() {
    int i=0;

    if (hostFound[0] >= 0){
        snprintf((char*)outPsw, MAX_INPUT_PASSWORD_LEN+1, "%s", hostPassword+(hostFound[0]*FIXED_PASSWORD_BUFFER) );
        for(i=0; i<MAX_INPUT_PASSWORD_LEN; i++)
            if(outPsw[i] == 0x80 || outPsw[i] == 0xffffff80) outPsw[i]='\0';

        return 1;
    }

    return 0;
}


char *opencl_attack(char *dname, unsigned int * w_blocks, unsigned char * encryptedVMK, unsigned char * nonce,  int gridBlocks)
{
    cl_device_id        device_id;
    cl_program          cpProgram;       // OpenCL program
    cl_kernel           ckKernelAttack;        // OpenCL kernel
    cl_mem              deviceEncryptedVMK, deviceIV, devicePassword, deviceFound, w_blocks_d;     // OpenCL device buffer
    cl_int              ciErr1, ciErr2, ccMajor;          // Error code var
    size_t              szGlobalWorkSize;        // 1D var for Total # of work items
    size_t              szLocalWorkSize;         // 1D var for # of work items in the work group 

    int                 numReadPassword, numPassword, passwordBufferSize, ret, totPsw=0; 
    char                tmpIV[IV_SIZE];
    FILE                *fp_kernel, *fp_file_passwords;
    char                fileNameAttack[] = "./kernel_attack.cl";
    size_t              source_size_attack, source_size;
    char                *source_str_attack;
    size_t len = 0;
    cl_int ret_cl = CL_SUCCESS, ret_cl_log = CL_SUCCESS, ret_info_kernel = CL_SUCCESS;

    //------- READ CL FILE ------            
    /* Load kernel source file */       
    fp_kernel = fopen(fileNameAttack, "rb");     
    if (!fp_kernel) {      
        fprintf(stderr, "Failed to load kernel.\n");    
        return NULL;
    }       
    fseek(fp_kernel, 0, SEEK_END);
    source_size = ftell(fp_kernel);
    fseek(fp_kernel, 0, SEEK_SET);

    source_str_attack = (char *)calloc(source_size+1, sizeof(char *));       
    source_size_attack = fread(source_str_attack, sizeof(char), source_size, fp_kernel);
    if (source_size_attack != source_size)
        fprintf(stderr,
                "Error reading source: expected %zu, got %zu bytes.\n",
                source_size, source_size_attack);     
    fclose(fp_kernel);     
    // -----------------------

    if(dname == NULL || encryptedVMK == NULL || w_blocks == NULL)
    {
        fprintf(stderr, "crack_dict input error\n");
        return NULL;
    }

    //-------- IV setup ------
    memset(tmpIV, 0, IV_SIZE);
    memcpy(tmpIV + 1, nonce, NONCE_SIZE);
    if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
    {
        fprintf(stderr, "Nonce error\n");
        return NULL;
    }
    *tmpIV = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
    tmpIV[IV_SIZE-1] = 1; 
    // --------------------------------------------------------------------------



    // ---- Open File Dictionary ----
    if (!memcmp(dname, "-\0", 2)) {
        fp_file_passwords= stdin;
    } else {
        fp_file_passwords= fopen(dname, "r");
        if (!fp_file_passwords) {
            fprintf(stderr, "Cannot open file %s.\n", dname);
            return NULL;
        }
    }
    // --------------------------------------------------------------------------
   

    // ------------------------------- Kernel setup -------------------------------
    /* Create kernel from source */     
    cpProgram = clCreateProgramWithSource(cxGPUContext, 1, (const char **)&source_str_attack, NULL /* (const size_t *)&source_size_attack*/, &ciErr1);        
    CL_ERROR(ciErr1);

    clGetDeviceInfo(cdDevices[gpu_id], CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof(ccMajor), &ccMajor, NULL);
    if(ccMajor >= 5)
        CC_SM50=1;
    CC_SM50=0;
    if(DEV_NVIDIA == 1 && CC_SM50 == 1)
        ciErr1 = clBuildProgram(cpProgram, 1, &(cdDevices[gpu_id]), "-I . -cl-nv-verbose -D DEV_NVIDIA_SM50=1", NULL, NULL);
    else if(DEV_NVIDIA == 1)
        ciErr1 = clBuildProgram(cpProgram, 1, &(cdDevices[gpu_id]), "-I . -cl-nv-verbose -D DEV_NVIDIA_SM50=0", NULL, NULL);
    else
        ciErr1 = clBuildProgram(cpProgram, 1, &(cdDevices[gpu_id]), "-I . -D DEV_NVIDIA_SM50=0", NULL, NULL);

    CL_ERROR(ciErr1);

    ret_cl = clGetProgramBuildInfo(cpProgram, cdDevices[gpu_id], CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
    CL_ERROR(ret_cl);
    char *buffer = (char * )calloc(len+1, sizeof(char));
    ret_cl_log = clGetProgramBuildInfo(cpProgram, cdDevices[gpu_id], CL_PROGRAM_BUILD_LOG, len+1, (void *)buffer, NULL);
    CL_ERROR(ret_cl_log);
    if(ret_cl != CL_SUCCESS)
        printf("BUILD LOG: \n%s\n\n", buffer);

    // Create the kernel
    ckKernelAttack = clCreateKernel(cpProgram, "opencl_bitcracker_attack", &ciErr1);
    CL_ERROR(ciErr1);

    //printf("\n--- KERNEL INFO ---\n");
    size_t workgroup_size;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(size_t), &workgroup_size, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_WORK_GROUP_SIZE: %zd\n", workgroup_size);

    cl_ulong localMemSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_LOCAL_MEM_SIZE, sizeof(cl_ulong), &localMemSize, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_LOCAL_MEM_SIZE: %lld\n", localMemSize);

    size_t preferredWorkGroupSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof(size_t), &preferredWorkGroupSize, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE: %zd\n", preferredWorkGroupSize);

    cl_ulong privateMemSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_PRIVATE_MEM_SIZE, sizeof(cl_ulong), &privateMemSize, NULL);
    CL_ERROR(ret_info_kernel);
    //printf("CL_KERNEL_PRIVATE_MEM_SIZE: %lld\n", privateMemSize);
    //printf("--------------------------\n");
    // --------------------------------------------------------------------------

    //-------- Initialize input data --------  
    if(GPU_MAX_WORKGROUP_SIZE > (int)workgroup_size)
        GPU_MAX_WORKGROUP_SIZE = workgroup_size;

    numPassword = GPU_MAX_WORKGROUP_SIZE*gridBlocks*MAX_PASSWD_SINGLE_KERNEL;
    passwordBufferSize = numPassword * MAX_INPUT_PASSWORD_LEN * sizeof(unsigned char);

    hostPassword = (unsigned char *) calloc(passwordBufferSize, sizeof(unsigned char));
    hostFound = (int *) calloc(1, sizeof(int));
    // --------------------------------------------------------------------------


    // ------------------------------- Data setup -------------------------------
    // Allocate the OpenCL buffer memory objects for source and result on the device GMEM
    deviceEncryptedVMK = clCreateBuffer(cxGPUContext, CL_MEM_READ_WRITE, VMK_DECRYPT_SIZE*sizeof(unsigned char), NULL, &ciErr1);
    CL_ERROR(ciErr1);
    
   // deviceIV = clCreateBuffer(cxGPUContext, CL_MEM_READ_ONLY, IV_SIZE*sizeof(unsigned char), NULL, &ciErr1);
    //CL_ERROR(ciErr1); 

    devicePassword = clCreateBuffer(cxGPUContext, CL_MEM_READ_ONLY, passwordBufferSize*sizeof(unsigned char), NULL, &ciErr1);
    CL_ERROR(ciErr1);   

    deviceFound = clCreateBuffer(cxGPUContext,  CL_MEM_WRITE_ONLY, sizeof(unsigned int), NULL, &ciErr1);
    CL_ERROR(ciErr1);

    w_blocks_d = clCreateBuffer(cxGPUContext,  CL_MEM_READ_ONLY, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(unsigned int), NULL, &ciErr1);
    CL_ERROR(ciErr1);
    // --------------------------------------------------------------------------

    

    // ------------------------------- Write static buffers -------------------------------
    /*
        schedule0 = __byte_perm(((unsigned int *)(IV))[0], 0, 0x0123) ^ hash0;
        schedule1 = __byte_perm(((unsigned int *)(IV+4))[0], 0, 0x0123) ^ hash1;
        schedule2 = __byte_perm(((unsigned int *)(IV+8))[0], 0, 0x0123) ^ hash2;
        schedule3 = __byte_perm(((unsigned int *)(IV+12))[0], 0, 0x0123) ^ hash3;
    */

    unsigned int tmp_global = ((unsigned int *)(tmpIV))[0];
    unsigned int IV0=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 
    
    tmp_global = ((unsigned int *)(tmpIV+4))[0];
    unsigned int IV4=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 
   
    tmp_global = ((unsigned int *)(tmpIV+8))[0];
    unsigned int IV8=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 
    
    tmp_global = ((unsigned int *)(tmpIV+12))[0];
    unsigned int IV12=(unsigned int )(((unsigned int )(tmp_global & 0xff000000)) >> 24) | (unsigned int )((unsigned int )(tmp_global & 0x00ff0000) >> 8) | (unsigned int )((unsigned int )(tmp_global & 0x0000ff00) << 8) | (unsigned int )((unsigned int )(tmp_global & 0x000000ff) << 24); 

    ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, w_blocks_d, CL_TRUE, 0, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(int), w_blocks, 0, NULL, NULL);      
    CL_ERROR(ciErr1);  
    
    ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, deviceEncryptedVMK, CL_TRUE, 0, VMK_DECRYPT_SIZE*sizeof(char), encryptedVMK, 0, NULL, NULL);      
    CL_ERROR(ciErr1);  

    // --------------------------------------------------------------------------

    szLocalWorkSize = GPU_MAX_WORKGROUP_SIZE;
    szGlobalWorkSize = gridBlocks*szLocalWorkSize;  //TOT THREADS 

    printf("Starting OpenCL attack:\n\tLocal Work Size: %zd\n\tWork Group Number: %d\n\tGlobal Work Size: %zd\n\tPassword per thread: %d\n\tPassword per kernel: %d\n\tDictionary: %s\n\n", 
        szLocalWorkSize, gridBlocks, szGlobalWorkSize, psw_x_thread, numPassword, (fp_file_passwords == stdin)?"standard input":dname);

    int iter=0;
    while(!feof(fp_file_passwords))
    {

        numReadPassword = readFilePassword(&hostPassword, numPassword, fp_file_passwords);

        /* Copy input data to memory buffer */      
        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, devicePassword, CL_TRUE, 0, passwordBufferSize * sizeof(char), hostPassword, 0, NULL, NULL);      
        CL_ERROR(ciErr1);

        hostFound[0] = -1;
        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, deviceFound, CL_TRUE, 0, sizeof(int), hostFound, 0, NULL, NULL);      
        CL_ERROR(ciErr1);     

        // Set the Argument values
        ciErr1 = clSetKernelArg(ckKernelAttack, 0, sizeof(cl_int), (void*)&numReadPassword);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 1, sizeof(cl_mem), (void*)&devicePassword);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 2, sizeof(cl_mem), (void*)&deviceFound);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 3, sizeof(cl_mem), (void*)&deviceEncryptedVMK);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 4, sizeof(cl_mem), (void*)&w_blocks_d);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 5, sizeof(cl_int), (void*)&IV0);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 6, sizeof(cl_int), (void*)&IV4);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 7, sizeof(cl_int), (void*)&IV8);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 8, sizeof(cl_int), (void*)&IV12);
        CL_ERROR(ciErr1);
        // --------------------------------------------------------
       
        // Launch kernel
       
        time_t start,end;
        double dif;
        TIMER_DEF(0);
        
        TIMER_START(0);
        time (&start);
        
        ciErr1 = clEnqueueNDRangeKernel(cqCommandQueue, ckKernelAttack, 1, NULL, &szGlobalWorkSize, &szLocalWorkSize, 0, NULL, NULL);
        CL_ERROR(ciErr1);

        /* Copy result to host */       
        ciErr1 = clEnqueueReadBuffer(cqCommandQueue, deviceFound, CL_TRUE, 0, sizeof(unsigned int), hostFound, 0, NULL, NULL);
        CL_ERROR(ciErr1);

        time (&end);
        TIMER_STOP(0);

        dif = difftime (end,start);

        printf("OpenCL Kernel execution #%d\n\tEffective number psw: %d\n\tTime: %f sec\n\tPasswords x second: %10.2f pw/sec\n", 
                iter, numReadPassword, TIMER_ELAPSED(0)/1.0E+6, numReadPassword/(TIMER_ELAPSED(0)/1.0E+6));
  //      printf ("TIME timer: %d passwords in %.2lf seconds => %.2f pwd/s\n", numReadPassword, dif, (double)(numReadPassword/dif) );

        
        ret = clFlush(cqCommandQueue);       
        ret = clFinish(cqCommandQueue);


        totPsw += numReadPassword;
        
        if (hostFound[0] >= 0) {
            match=check_match();
            break;
        }

        iter++;
    }

    if(match==1)
        printf("\n\n================================================\nOpenCL attack completed\nPasswords evaluated: %d\nPassword found: [%s]\n================================================\n\n", totPsw, outPsw);
    else
        printf("\n\n================================================\nOpenCL attack completed\nPasswords evaluated: %d\nPassword not found!\n================================================\n\n", totPsw);


out1:
    printf("\nTot passwords evaluated: %d\n", totPsw);


    /* Display result */        
    if (fp_file_passwords != stdin)
        fclose(fp_file_passwords);      

out:

    /* Finalization */
    
    if(ckKernelAttack)clReleaseKernel(ckKernelAttack); 
    if(cpProgram)clReleaseProgram(cpProgram);
    
   // if(deviceIV)clReleaseMemObject(deviceIV);
    if(w_blocks_d)clReleaseMemObject(w_blocks_d);
    if(devicePassword)clReleaseMemObject(devicePassword);
    if(deviceEncryptedVMK)clReleaseMemObject(deviceEncryptedVMK);
    if(deviceFound)clReleaseMemObject(deviceFound);
      
    free(source_str_attack);       
                        
    if(match==0)
        printf("Password not found\n");

    return NULL; 
}