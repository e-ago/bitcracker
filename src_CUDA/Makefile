# Please add right gencode for older CUDA/GPU: -gencode arch=compute_35,code=sm_35 -gencode arch=compute_52,code=sm_52 -gencode arch=compute_60,code=sm_60

bitcracker_cuda:
	nvcc -gencode arch=compute_70,code=sm_70 -gencode arch=compute_80,code=sm_80 -Xptxas -v -o bitcracker_cuda main.cu cuda_attack.cu utils.cu w_blocks.cu

clean:
	rm -rf *.o
	rm -rf ../build/bitcracker_cuda
