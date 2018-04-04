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

#include "bitcracker.h"

#define TIMER_DEF(n)     struct timeval temp_1_##n={0,0}, temp_2_##n={0,0}
#define TIMER_START(n)   gettimeofday(&temp_1_##n, (struct timezone*)0)
#define TIMER_STOP(n)    gettimeofday(&temp_2_##n, (struct timezone*)0)
#define TIMER_ELAPSED(n) ((temp_2_##n.tv_sec-temp_1_##n.tv_sec)*1.e6+(temp_2_##n.tv_usec-temp_1_##n.tv_usec))

int             *deviceFound, *hostFound;
char            *hostPassword;
int             *hostPasswordInt, *devicePasswordInt;
unsigned char   outPsw[PSW_CHAR_SIZE+1];
int             outIndexPsw=0, match=0;

static int check_match() {
    int i=0;

    if (hostFound[0] >= 0){
        snprintf((char*)outPsw, PSW_CHAR_SIZE+1, "%s", hostPassword+(hostFound[0]*PSW_CHAR_SIZE) );
        for(i=0; i<PSW_CHAR_SIZE; i++)
            if(outPsw[i] == 0x80 || outPsw[i] == 0xff) outPsw[i]='\0'; //0xffffff80

        return 1;
    }

    return 0;
}


char *opencl_attack(char *dname, unsigned int * w_blocks,
                    unsigned char * encryptedVMK,
                    unsigned char * nonce, unsigned char * encryptedMAC,
                    int gridBlocks)
{
    cl_device_id        device_id;
    cl_program          cpProgram;  
    cl_kernel           ckKernelAttack; 
    char                vmkIV[IV_SIZE], macIV[IV_SIZE], computeMacIV[IV_SIZE];
    cl_mem              d_vmk, d_mac, d_macIV, d_computeMacIV;
    cl_mem              devicePassword, deviceFound, w_blocks_d;
    cl_int              ciErr1, ciErr2, ccMajor;     
    size_t              szGlobalWorkSize;   
    size_t              szLocalWorkSize;    

    int                 numReadPassword, tot_psw, ret, totReadPsw=0; //passwordBufferSize
    FILE                *fp_kernel, *fp_file_passwords;
    //Really ugly...
    char                fileNameAttack[] = "./src_OpenCL/kernel_attack.cl";
    size_t              source_size_attack, source_size;
    char                *source_str_attack;
    size_t len = 0;
    cl_int ret_cl = CL_SUCCESS, ret_cl_log = CL_SUCCESS, ret_info_kernel = CL_SUCCESS;
    char optProgram[128];
    
    unsigned int vmkIV0, vmkIV4, vmkIV8, vmkIV12;
    unsigned int macIV0, macIV4, macIV8, macIV12;
    unsigned int cMacIV0, cMacIV4, cMacIV8, cMacIV12;

    //------- READ CL FILE ------            
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

    //-------- vmkIV setup ------
    memset(vmkIV, 0, IV_SIZE);
    vmkIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
    memcpy(vmkIV + 1, nonce, NONCE_SIZE);
    if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
    {
        fprintf(stderr, "Attack nonce error\n");
        return NULL;
    }
    vmkIV[IV_SIZE-1] = 1; 
    // -----------------------

    if(mac_comparison == 1)
    {
        //-------- macIV setup ------
        memset(macIV, 0, IV_SIZE);
        macIV[0] = (unsigned char)(IV_SIZE - 1 - NONCE_SIZE - 1);
        memcpy(macIV + 1, nonce, NONCE_SIZE);
        if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
        {
            fprintf(stderr, "Attack nonce error\n");
            return NULL;
        }
        macIV[IV_SIZE-1] = 0; 
        // -----------------------

        //-------- computeMacIV setup ------
        memset(computeMacIV, 0, IV_SIZE);
        computeMacIV[0] = 0x3a;
        memcpy(computeMacIV + 1, nonce, NONCE_SIZE);
        if(IV_SIZE-1 - NONCE_SIZE - 1 < 0)
        {
            fprintf(stderr, "Attack nonce error\n");
            return NULL;
        }
        computeMacIV[IV_SIZE-1] = 0x2c; 
        // -----------------------
    }

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
    cpProgram = clCreateProgramWithSource(cxGPUContext, 1, (const char **)&source_str_attack, NULL /* (const size_t *)&source_size_attack*/, &ciErr1);        
    CL_ERROR(ciErr1);

    clGetDeviceInfo(cdDevices[gpu_id], CL_DEVICE_COMPUTE_CAPABILITY_MAJOR_NV, sizeof(ccMajor), &ccMajor, NULL);
    CC_SM50=0;
    if(ccMajor >= 5) CC_SM50=1;


    memset(optProgram, 0, 128);
    if(DEV_NVIDIA == 1)
        snprintf(optProgram, 128, "-I . -cl-nv-verbose -D DEV_NVIDIA_SM50=%d -D STRICT_CHECK=%d -D ATTACK_MODE=%d", CC_SM50, strict_check, attack_mode);
    else
        snprintf(optProgram, 128, "-I . -D DEV_NVIDIA_SM50=0 -D STRICT_CHECK=%d -D ATTACK_MODE=%d", strict_check, attack_mode);

    ciErr1 = clBuildProgram(cpProgram, 1, &(cdDevices[gpu_id]), optProgram, NULL, NULL);
    ret_cl = clGetProgramBuildInfo(cpProgram, cdDevices[gpu_id], CL_PROGRAM_BUILD_LOG, 0, NULL, &len);
    CL_ERROR(ret_cl);
    char *buffer = (char * )calloc(len+1, sizeof(char));
    ret_cl_log = clGetProgramBuildInfo(cpProgram, cdDevices[gpu_id], CL_PROGRAM_BUILD_LOG, len+1, (void *)buffer, NULL);
    CL_ERROR(ret_cl_log);
    if(ret_cl == CL_SUCCESS && ciErr1 != CL_SUCCESS)
    {
        printf("Kernel Attack Build Log: \n%s\n\n", buffer);
        CL_ERROR(ciErr1);
    }

    if(mac_comparison == 1)
    {
        ckKernelAttack = clCreateKernel(cpProgram, "opencl_bitcracker_attack_mac", &ciErr1);
        CL_ERROR(ciErr1);
    }
    else
    {    
        ckKernelAttack = clCreateKernel(cpProgram, "opencl_bitcracker_attack", &ciErr1);
        CL_ERROR(ciErr1);
    }

    size_t workgroup_size;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_WORK_GROUP_SIZE, sizeof(size_t), &workgroup_size, NULL);
    CL_ERROR(ret_info_kernel);

    cl_ulong localMemSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_LOCAL_MEM_SIZE, sizeof(cl_ulong), &localMemSize, NULL);
    CL_ERROR(ret_info_kernel);

    size_t preferredWorkGroupSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_PREFERRED_WORK_GROUP_SIZE_MULTIPLE, sizeof(size_t), &preferredWorkGroupSize, NULL);
    CL_ERROR(ret_info_kernel);

    cl_ulong privateMemSize;
    ret_info_kernel = clGetKernelWorkGroupInfo(ckKernelAttack, cdDevices[gpu_id], CL_KERNEL_PRIVATE_MEM_SIZE, sizeof(cl_ulong), &privateMemSize, NULL);
    CL_ERROR(ret_info_kernel);
    // --------------------------------------------------------------------------

    //-------- Initialize input data --------  
    if(GPU_MAX_WORKGROUP_SIZE > (int)workgroup_size)
        GPU_MAX_WORKGROUP_SIZE = workgroup_size;

    tot_psw = GPU_MAX_WORKGROUP_SIZE*gridBlocks*MAX_PASSWD_SINGLE_KERNEL;

    hostPassword = (char *) Calloc(tot_psw*PSW_CHAR_SIZE, sizeof(char));
    hostPasswordInt = (int *) Calloc(tot_psw*PSW_INT_SIZE, sizeof(int));
    hostFound = (int *) Calloc(1, sizeof(int));
    // --------------------------------------------------------------------------

    // ------------------------------- Data setup -------------------------------
    d_vmk = clCreateBuffer(cxGPUContext, CL_MEM_READ_WRITE, VMK_FULL_SIZE*sizeof(unsigned char), NULL, &ciErr1);
    CL_ERROR(ciErr1);
    
    devicePassword = clCreateBuffer(cxGPUContext, CL_MEM_READ_ONLY, tot_psw*PSW_INT_SIZE*sizeof(unsigned int), NULL, &ciErr1);
    CL_ERROR(ciErr1);   

    deviceFound = clCreateBuffer(cxGPUContext,  CL_MEM_WRITE_ONLY, sizeof(unsigned int), NULL, &ciErr1);
    CL_ERROR(ciErr1);

    w_blocks_d = clCreateBuffer(cxGPUContext,  CL_MEM_READ_ONLY, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(unsigned int), NULL, &ciErr1);
    CL_ERROR(ciErr1);

    if(mac_comparison == 1)
    {
        d_mac = clCreateBuffer(cxGPUContext,  CL_MEM_READ_ONLY, MAC_SIZE * sizeof(char), NULL, &ciErr1);
        CL_ERROR(ciErr1);

        d_macIV = clCreateBuffer(cxGPUContext,  CL_MEM_READ_ONLY, IV_SIZE * sizeof(char), NULL, &ciErr1);
        CL_ERROR(ciErr1);

        d_computeMacIV = clCreateBuffer(cxGPUContext,  CL_MEM_READ_ONLY, IV_SIZE * sizeof(char), NULL, &ciErr1);
        CL_ERROR(ciErr1);
    }
    // --------------------------------------------------------------------------

    // ------------------------------- Write buffers -------------------------------
    vmkIV0 = ((unsigned int *)(vmkIV))[0];
    vmkIV4 = ((unsigned int *)(vmkIV+4))[0];
    vmkIV8 = ((unsigned int *)(vmkIV+8))[0];
    vmkIV12 = ((unsigned int *)(vmkIV+12))[0];

    if(mac_comparison == 1)
    {
        macIV0 = ((unsigned int *)(macIV))[0];
        macIV4 = ((unsigned int *)(macIV+4))[0];
        macIV8 = ((unsigned int *)(macIV+8))[0];
        macIV12 = ((unsigned int *)(macIV+12))[0];

        cMacIV0 = ((unsigned int *)(computeMacIV))[0];
        cMacIV4 = ((unsigned int *)(computeMacIV+4))[0];
        cMacIV8 = ((unsigned int *)(computeMacIV+8))[0];
        cMacIV12 = ((unsigned int *)(computeMacIV+12))[0];
    }

    ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, w_blocks_d, CL_TRUE, 0, SINGLE_BLOCK_SHA_SIZE * ITERATION_NUMBER * sizeof(int), w_blocks, 0, NULL, NULL);      
    CL_ERROR(ciErr1);  
    
    ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, d_vmk, CL_TRUE, 0, VMK_FULL_SIZE*sizeof(char), encryptedVMK, 0, NULL, NULL);      
    CL_ERROR(ciErr1);

    if(mac_comparison == 1)
    {
        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, d_mac, CL_TRUE, 0, MAC_SIZE*sizeof(char), encryptedMAC, 0, NULL, NULL);      
        CL_ERROR(ciErr1);  

        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, d_macIV, CL_TRUE, 0, IV_SIZE*sizeof(char), macIV, 0, NULL, NULL);      
        CL_ERROR(ciErr1);  

        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, d_computeMacIV, CL_TRUE, 0, IV_SIZE*sizeof(char), computeMacIV, 0, NULL, NULL);      
        CL_ERROR(ciErr1);  
    }
    // ----------------------------------------------------------------------------

    szLocalWorkSize = GPU_MAX_WORKGROUP_SIZE;
    szGlobalWorkSize = gridBlocks*szLocalWorkSize;

    printf("Type of attack: %s\n\tLocal Work Size: %zd\n\tWork Group Number: %d\n\tGlobal Work Size: %zd\n\tPassword per thread: %d\n\tPassword per kernel: %d\n\tDictionary: %s\n\tStrict Check (-s): %s\n\tMAC Comparison (-m): %s\n\t\n\n", 
        (attack_mode==MODE_USER_PASS)?"User Password":"Recovery Password", szLocalWorkSize, gridBlocks, szGlobalWorkSize, psw_x_thread, tot_psw, (fp_file_passwords == stdin)?"standard input":dname, (strict_check == 1)?"Yes":"No", (mac_comparison == 1)?"Yes":"No");

    int iter=0;
    while(!feof(fp_file_passwords))
    {
        numReadPassword = readFilePassword(&hostPasswordInt, &hostPassword, tot_psw, fp_file_passwords);
        if(numReadPassword <= 0) break;
        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, devicePassword, CL_TRUE, 0, tot_psw*PSW_INT_SIZE*sizeof(unsigned int), hostPasswordInt, 0, NULL, NULL);
        CL_ERROR(ciErr1);

        hostFound[0] = -1;
        ciErr1 = clEnqueueWriteBuffer(cqCommandQueue, deviceFound, CL_TRUE, 0, sizeof(int), hostFound, 0, NULL, NULL);      
        CL_ERROR(ciErr1);     

        ciErr1 = clSetKernelArg(ckKernelAttack, 0, sizeof(cl_int), (void*)&numReadPassword);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 1, sizeof(cl_mem), (void*)&devicePassword);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 2, sizeof(cl_mem), (void*)&deviceFound);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 3, sizeof(cl_mem), (void*)&d_vmk);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 4, sizeof(cl_mem), (void*)&w_blocks_d);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 5, sizeof(cl_int), (void*)&vmkIV0);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 6, sizeof(cl_int), (void*)&vmkIV4);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 7, sizeof(cl_int), (void*)&vmkIV8);
        CL_ERROR(ciErr1);

        ciErr1 |= clSetKernelArg(ckKernelAttack, 8, sizeof(cl_int), (void*)&vmkIV12);
        CL_ERROR(ciErr1);

        if(mac_comparison == 1)
        {
            ciErr1 |= clSetKernelArg(ckKernelAttack, 9, sizeof(cl_mem), (void*)&d_mac);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 10, sizeof(cl_int), (void*)&macIV0);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 11, sizeof(cl_int), (void*)&macIV4);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 12, sizeof(cl_int), (void*)&macIV8);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 13, sizeof(cl_int), (void*)&macIV12);
            CL_ERROR(ciErr1);


            ciErr1 |= clSetKernelArg(ckKernelAttack, 14, sizeof(cl_int), (void*)&cMacIV0);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 15, sizeof(cl_int), (void*)&cMacIV4);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 16, sizeof(cl_int), (void*)&cMacIV8);
            CL_ERROR(ciErr1);

            ciErr1 |= clSetKernelArg(ckKernelAttack, 17, sizeof(cl_int), (void*)&cMacIV12);
            CL_ERROR(ciErr1);
        }
        // --------------------------------------------------------
              
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

        printf("OpenCL Kernel execution #%d\n\tEffective number psw: %d\n\tPasswords Range:\n\t\t%s\n\t\t.....\n\t\t%s\n\tTime: %f sec\n\tPasswords x second: %10.2f pw/sec\n", 
                iter, numReadPassword, 
                (char *)(hostPassword),
                (char *)(hostPassword+(PSW_CHAR_SIZE*(numReadPassword-1))),
                TIMER_ELAPSED(0)/1.0E+6, numReadPassword/(TIMER_ELAPSED(0)/1.0E+6));

        ret = clFlush(cqCommandQueue);       
        ret = clFinish(cqCommandQueue);

        totReadPsw += numReadPassword;
        
        if (hostFound[0] >= 0) {
            match=check_match();
            break;
        }
        
        iter++;
    }

    if(match==1)
        printf("\n\n================================================\nOpenCL attack completed\nPasswords evaluated: %d\nPassword found: [%s]\n================================================\n\n", totReadPsw, outPsw);
    else
        printf("\n\n================================================\nOpenCL attack completed\nPasswords evaluated: %d\nPassword not found!\n================================================\n\n", totReadPsw);

out1:
    printf("\nTot passwords evaluated: %d\n", totReadPsw);

    /* Display result */
    if (fp_file_passwords != stdin)
        fclose(fp_file_passwords);

out:
    /* Finalization */
    if(ckKernelAttack)clReleaseKernel(ckKernelAttack); 
    if(cpProgram)clReleaseProgram(cpProgram);
    if(w_blocks_d)clReleaseMemObject(w_blocks_d);
    if(devicePassword)clReleaseMemObject(devicePassword);
    if(d_vmk)clReleaseMemObject(d_vmk);
    if(deviceFound)clReleaseMemObject(deviceFound);
      
    free(source_str_attack);       
                        
    if(match==0)
        printf("Password not found\n");

    return NULL; 
}