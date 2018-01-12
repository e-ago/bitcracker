#!/usr/bin/env bash

NGPU=0;
SINGLE_BLOCK="$SINGLE_BLOCK";
mkdir -p test_hash

printf "\n\n************ Extract BitLocker hash from encrypted memory units ************\n\n"

#Image encrypted with Windows 8.1 Enterprise
./build/bitcracker_hash -o test_hash -i ./Images/imgWin8
mv ./test_hash/hash_user_pass.txt test_hash/imgWin8_user_password.txt
mv ./test_hash/hash_recv_pass.txt test_hash/imgWin8_recovery_password.txt
printf "\n\n"

#Image encrypted with Windows 7 Pro
./build/bitcracker_hash -o test_hash -i ./Images/imgWin7
mv test_hash/hash_user_pass.txt test_hash/imgWin7_user_password.txt
mv test_hash/hash_recv_pass.txt test_hash/imgWin7_recovery_password.txt
printf "\n\n"

#Image encrypted with Windows 10 Enteprise using BitLocker Compatible Mode
./build/bitcracker_hash -o test_hash -i ./Images/imgWin10Compat.vhd
mv test_hash/hash_user_pass.txt test_hash/imgWin10Compat_user_password.txt
mv test_hash/hash_recv_pass.txt test_hash/imgWin10Compat_recovery_password.txt
printf "\n\n"

#Image encrypted with Windows 10 Enteprise using BitLocker Not Compatible Mode
./build/bitcracker_hash -o test_hash -i ./Images/imgWin10NotCompat.vhd
mv test_hash/hash_user_pass.txt test_hash/imgWin10NotCompat_user_password.txt
mv test_hash/hash_recv_pass.txt test_hash/imgWin10NotCompat_recovery_password.txt
printf "\n\n"


printf "\n\n************ Testing BitCracker CUDA version ************\n\n"
#Print help
./build/bitcracker_cuda -h

#Windows 8.1
./build/bitcracker_cuda -f ./test_hash/imgWin8_user_password.txt -d ./Dictionary/user_passwords.txt $SINGLE_BLOCK -u
#Same test with MAC verification
./build/bitcracker_cuda -f ./test_hash/imgWin8_user_password.txt -d ./Dictionary/user_passwords.txt $SINGLE_BLOCK -m -u

#Windows 7
./build/bitcracker_cuda -f ./test_hash/imgWin7_user_password.txt -d ./Dictionary/user_passwords.txt $SINGLE_BLOCK -u

#Windows 10 Compatbile Mode
./build/bitcracker_cuda -f ./test_hash/imgWin10Compat_user_password.txt -d ./Dictionary/user_passwords.txt $SINGLE_BLOCK -u
./build/bitcracker_cuda -f ./test_hash/imgWin10Compat_recovery_password.txt -d ./Dictionary/recovery_passwords.txt $SINGLE_BLOCK -r
#Same test with MAC verification
./build/bitcracker_cuda -f ./test_hash/imgWin10Compat_recovery_password.txt -d ./Dictionary/recovery_passwords.txt $SINGLE_BLOCK -r -m

#Windows 10 Not Compatbile Mode
./build/bitcracker_cuda -f ./test_hash/imgWin10NotCompat_user_password.txt -d ./Dictionary/user_passwords.txt $SINGLE_BLOCK -u
./build/bitcracker_cuda -f ./test_hash/imgWin10NotCompat_recovery_password.txt -d ./Dictionary/recovery_passwords.txt $SINGLE_BLOCK -r
#Same test with MAC verification
./build/bitcracker_cuda -f ./test_hash/imgWin10NotCompat_recovery_password.txt -d ./Dictionary/recovery_passwords.txt $SINGLE_BLOCK -r -m
