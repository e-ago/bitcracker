# BitCracker

BitCracker is the first open source password cracking tool for storage devices (original CUDA source code is from [here](https://github.com/e-ago/bitcracker)).

## SYCL version

- The CUDA code was converted to SYCL using Intel's DPC++ Compatiblity Tool (DPCT) available [here](https://www.intel.com/content/www/us/en/developer/tools/oneapi/dpc-compatibility-tool.html#gs.52d73b).
- Timing code was later added for performance measurement purpose.
- The same SYCL code runs on Intel GPUs & CPUs as well as NVIDIA (tested on A100 and H100) and AMD (tested on MI100 and MI250) GPUs.

# Current Version:
- Initial release of the workload

# Build Instructions
Notes
- icpx compiler mentioned below is included in oneAPI Base Toolkit available [here](https://www.intel.com/content/www/us/en/developer/tools/oneapi/base-toolkit-download.html).
- clang++ compiler mentioned below is available [here](https://github.com/intel/llvm/blob/sycl/sycl/doc/GetStartedGuide.md).

## To build for SYCL

For Intel GPU -  
First source icpx compiler. Then,

```
cd SYCL
mkdir build
cd build
CXX=icpx cmake -DGPU_AOT=pvc ..
make -sj
```
Note:
- To enable AOT compilation, please use the flag `-DGPU_AOT=pvc` for PVC as shown above.

For AMD GPU -  
First source clang++ compiler. Then,
```
cd SYCL
mkdir build
cd build
CXX=clang++ cmake -DUSE_AMDHIP_BACKEND=gfx90a ..
make -sj
```
Note:
- We use the flag `-DUSE_AMDHIP_BACKEND=gfx90a` for MI250. Use the correct value for your GPU.

For NVIDIA GPU -  
First source clang++ compiler. Then,
```
cd SYCL
mkdir build
cd build
CXX=clang++ cmake -DUSE_NVIDIA_BACKEND=YES -DUSE_SM=80 ..
make -sj
```
Note:
- We use the flag `-DUSE_SM=80` for A100 or `-DUSE_SM=90` for H100.

# Run instructions

After building, to run the workload, cd into the SYCL/build folder, if not already there. Then

```
# PVC 1 tile:
ONEAPI_DEVICE_SELECTOR=level_zero:0.0 ./bitcracker -f ../hash_pass/img_win8_user_hash.txt -d ../hash_pass/user_passwords_60000.txt -b 60000
```
```
# PVC 2 tiles:
ONEAPI_DEVICE_SELECTOR=level_zero:0 ./bitcracker -f ../hash_pass/img_win8_user_hash.txt -d ../hash_pass/user_passwords_60000.txt -b 60000
```
```
# AMD GPU:
ONEAPI_DEVICE_SELECTOR=hip:0 ./bitcracker -f ../hash_pass/img_win8_user_hash.txt -d ../hash_pass/user_passwords_60000.txt -b 60000
```
```
# NVIDIA GPU:
ONEAPI_DEVICE_SELECTOR=cuda:0 ./bitcracker -f ../hash_pass/img_win8_user_hash.txt -d ../hash_pass/user_passwords_60000.txt -b 60000
```
# Output

Output gives the total time for running the whole workload.
