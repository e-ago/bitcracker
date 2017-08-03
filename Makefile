bitcracker_cuda:
	nvcc -gencode arch=compute_35,code=sm_35 -gencode arch=compute_52,code=sm_52 -gencode arch=compute_60,code=sm_60 -Xptxas -v -o bitcracker-gpu main.cu cuda_attack.cu utils.cu w_blocks.cu

clean:
	rm -rf *.o
	rm -rf bitcracker-gpu
