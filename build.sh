#!/usr/bin/env bash

mkdir -p ./build

printf "\n====== Build BitCracker Hash Extractor ======\n"
cd Hash_Extractor && make clean && make
cd ..
mv Hash_Extractor/bitcracker_hash build 2> /dev/null

printf "\n====== Build BitCracker CUDA version ======\n"
cd CUDA_version && make clean && make
cd ..
mv CUDA_version/bitcracker_cuda build 2> /dev/null

printf "\n====== Build BitCracker OpenCL version ======\n"
cd OpenCL_version && make clean && make
cd ..
mv OpenCL_version/bitcracker_opencl build 2> /dev/null

printf "\n====== Executables in build directory ======\n"
