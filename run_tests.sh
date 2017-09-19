#!/usr/bin/env bash


mkdir -p test_hash

printf "\n\n************ Extract BitLocker hash from encrypted memory units ************\n\n"

#Image encrypted with Windows 8.1 Enterprise
./build/bitcracker_hash -o test_hash/imgWin8.txt -i ./Images/imgWin8
printf "\n\n"

#Image encrypted with Windows 7 Pro
./build/bitcracker_hash -o test_hash/imgWin7.txt -i ./Images/imgWin7
printf "\n\n"

#Image encrypted with Windows 10 Enteprise using BitLocker compatible mode
./build/bitcracker_hash -o test_hash/imgWin10Compatible.txt -i ./Images/imgWin10Compatible.vhd
printf "\n\n"

#Image encrypted with Windows 10 Enteprise using BitLocker non-compatible mode
./build/bitcracker_hash -o test_hash/imgWin10NonCompatible.txt -i ./Images/imgWin10NonCompatible.vhd
printf "\n\n"

#Image encrypted with Windows 10 Enteprise using BitLocker non-compatible mode, long password (27 chars)
./build/bitcracker_hash -o test_hash/imgWin10NonCompatibleLong27.txt -i ./Images/imgWin10NonCompatibleLong27.vhd


printf "\n\n************ Testing BitCracker CUDA version ************\n\n"
#Show help
./build/bitcracker_cuda -h

./build/bitcracker_cuda -f ./test_hash/imgWin8.txt -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

./build/bitcracker_cuda -f ./test_hash/imgWin7.txt -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

./build/bitcracker_cuda -f ./test_hash/imgWin10Compatible.txt -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

./build/bitcracker_cuda -f ./test_hash/imgWin10NonCompatible.txt -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0

./build/bitcracker_cuda -f ./test_hash/imgWin10NonCompatibleLong27.txt -d ./Dictionary/test_passwords.txt -t 1 -b 1 -g 0
