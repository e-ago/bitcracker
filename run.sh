#!/usr/bin/env bash

#Show help
./CUDA_version/bitcracker_cuda -h

#Image encrypted with Windows 8.1 Enterprise
./CUDA_version/bitcracker_cuda -i ./Images/imgWin8 -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

#Image encrypted with Windows 7 Pro
./CUDA_version/bitcracker_cuda -i ./Images/imgWin7 -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

#Image encrypted with Windows 10 Enteprise using BitLocker compatible mode
./CUDA_version/bitcracker_cuda -i ./Images/imgWin10Compatible.vhd -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

#Image encrypted with Windows 10 Enteprise using BitLocker non-compatible mode
./CUDA_version/bitcracker_cuda -i ./Images/imgWin10NonCompatible.vhd -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

