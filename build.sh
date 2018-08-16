#!/usr/bin/env bash

mkdir -p ./build

printf "\n====== Build BitCracker Hash Extractor ======\n"
cd src_HashExtractor && make clean && make
cd ..
mv src_HashExtractor/bitcracker_hash build 2> /dev/null

printf "\n====== Build BitCracker Recovery Password generator ======\n"
cd src_RPGenerator && make clean && make
cd ..
mv src_RPGenerator/bitcracker_rpgen build 2> /dev/null

printf "\n====== Build BitCracker CUDA version ======\n"
cd src_CUDA && make clean && make
cd ..
mv src_CUDA/bitcracker_cuda build 2> /dev/null

printf "\n====== Build BitCracker OpenCL version ======\n"
cd src_OpenCL && make clean && make
cd ..
mv src_OpenCL/bitcracker_opencl build 2> /dev/null

printf "\n====== Executables in build directory ======\n"
