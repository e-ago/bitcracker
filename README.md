# BitCracker

BitCracker is the first open source password cracking tool for memory units encrypted with BitLocker (using the password authentication method).

## Introduction

BitLocker (formerly BitLocker Drive Encryption) is a full-disk encryption feature available in recent Windows versions (Ultimate and Enterprise editions of Windows Vista and Windows 7, the Pro and Enterprise editions of Windows 8, 8.1 and 10).
BitCracker is a mono-GPU (OpenCL and CUDA) password cracking tool for memory units encrypted with the password authentication method of BitLocker (see picture below).

![alt text](http://openwall.info/wiki/_media/john/bitcracker_img1.png)

Our attack has been tested on several memory units encrypted with BitLocker running on Windows 7, Window 8.1,  Windows 10 (compatible and not compatible mode) and BitLocker To Go.

## Requirements

Minimum requirements for CUDA implementation:
- CUDA 7.5
- NVIDIA GPU with CC 3.5 or later
- NVIDIA GPU with Kepler arch or later

Minimum memory requirement is 256 Mb; it may increase depending on the number of passwords processed by each kernel.

## How To

Use the *build.sh* script to build 3 executables:

- Hash extractor
- BitCracker CUDA version
- BitCracker OpenCL version

The script stores the executables in the *build* directory.

### Step 1: Extract the image

You need to extract the image of your memory device encrypted with BitLocker.
For example, you can use the *dd* command:

```
sudo dd if=/dev/disk2 of=/path/to/imageEncrypted conv=noerror,sync
4030464+0 records in
4030464+0 records out
2063597568 bytes transferred in 292.749849 secs (7049013 bytes/sec)
```


### Step 2: Extract the hash

Use *bitcracker_hash* to extract an hash describing your target image. It also verifies if the target memory unit satisfies BitCracker's requirements.

```
./build/bitcracker_hash -o hashFile.txt -i path/to/imageEncrypted

Opening file path/to/imageEncrypted

Signature found at 0x00010003
Version: 8 
Invalid version, looking for a signature with valid version...

Signature found at 0x02110000
Version: 2 (Windows 7 or later)
VMK entry found at 0x021100c2
VMK encrypted with user password found!

path/to/imageEncrypted result hash:
$bitlocker$0$16$91a4ec232ab95bbb8e8ef964308c6b47$1048576$12$306af9dca50fd30103000000$60$00000000000000000000000000000000509aab04f2161082ed6153d6ea8ad51d45c1ae6ae77cdc470789472640f409a1c2ede715ea5a6bbc320e2312
```

The resulting hash is printed inside the *hashFile.txt*.

### Step 3: Start the attack

Now you can start the BitCracker attack; use the *-h* to see all the options.

```
./build/bitcracker_cuda -f hashFile.txt -d dictionary.txt -t 1 -b 1 -g 0

====================================
Selected device: GPU Tesla K80 (ID: 0) properties
====================================
…………
Hash file outFile.txt: $bitlocker$0$16$91a4ec232ab95bbb8e8ef964308c6b47$1048576$12$306af9dca50fd30103000000$60$00000000000000000000000000000000509aab04f2161082ed6153d6ea8ad51d45c1ae6ae77cdc470789472640f409a1c2ede715ea5a6bbc320e2312 ====================================
Dictionary attack
====================================

Starting CUDA attack:
  CUDA Threads: 1024
  CUDA Blocks: 1
  Psw per thread: 1
  Max Psw per kernel: 1024
  Dictionary: dictionary.txt

CUDA Kernel execution:
  Stream 0
  Effective number psw: 7
  Time: 28.583404 sec
  Passwords x second: 0.24 pw/sec

================================================
CUDA attack completed
Passwords evaluated: 7
Password found: [donaldduck]
================================================
```

## Notes

In case of false positives you can use the -s option, that is a more restrictive check on the correctness of the final result. Altough this check is empirically verified and it works with all the encrypted images in this repo, we can't guarantee that it doesn't lead to false negatives. Use -s option only if BitCracker returns several false positives.

Currently, BitCracker accepts passwords between 8 (minimum password length) and 27 characters (implementation reasons).

BitCracker doesn't provide any mask attack, cache mechanism or smart dictionary creation; therefore you need to provide your own input dictionary.

## Examples

In the the run_test.sh script there are several attack examples using the images (of encrypted memory devices)provided in this repo:
* imgWin7: BitLocker on Windows 7 Enteprise edition OS
* imgWin8: BitLocker on Windows 8 Enteprise edition OS
* imgWin10Compatible.vhd: BitLocker (compatible mode) on Windows 10 Enteprise edition OS, 
* imgWin10NotCompatible.vhd: BitLocker (not compatible mode) on Windows 10 Enteprise edition OS, 
* imgWin10NotCompatibleLong27.vhd: BitLocker (not compatible mode) on Windows 10 Enteprise edition OS with the longest possible password (27 characters)

## Performance

Here we report the best performance of BitCracker implementations tested on different GPUs.

| GPU Acronim  |       GPU       | Arch    | CC  | # SM | Clock  | CUDA |
| ------------ | --------------- | ------- | --- | ---- | ------ | ---- |
| GFT          | GeForce Titan   | Kepler  | 3.5 | 14   | 835    | 7.0  |
| GTK80        | Tesla K80       | Kepler  | 3.5 | 13   | 875    | 7.5  |
| GFTX         | GeForce Titan X | Maxwell | 5.2 | 24   | 1001   | 7.5  |
| GTP100       | Telsa P100      | Pascal  | 6.1 | 56   | 1328   | 8.0  |
| AMDM         | Radeon Malta    | -       | -   | -    | -      | -    |

Performance:

| Version  | GPU    | -t  | -b | Passwords x kernel | Passwords/sec | Hash/sec   |
| -------- | ------ | --- | -- | ------------------ | ------------- | ---------- |
| CUDA     | GFT    | 8   | 13 | 106.496            | 303           | 635 MH/s   |
| CUDA     | GTK80  | 8   | 14 | 114.688            | 370           | 775 MH/s   |
| CUDA     | GFTX   | 8   | 24 | 106.608            | 933           | 1.957 MH/s |
| CUDA     | GTP100 | 8   | 56 | 458.752            | 1.363         | 2.858 MH/s |
| OpenCL   | AMDM   | 32  | 64 | 524.288            | 241           | 505 MH/s   |
| OpenCL   | GFTX   | 8   | 24 | 196.608            | 884           | 1.853 MH/s |

## John The Ripper

We released the OpenCL version as a format of John The Ripper (bleeding jumbo):
* Wiki page: http://openwall.info/wiki/john/OpenCL-BitLocker <br />
* JtR source code: https://github.com/magnumripper/JohnTheRipper

## Next Release

In the next relese:
- The maximum password length will be dynamic
- Optional MAC verification (to avoid any false positive)

## References, credits and contacts

This is a research project in collaboration with the National Research Council of Italy released under GPLv2 license.<br />
Copyright (C) 2013-2017  Elena Ago (elena dot ago at gmail dot com) and Massimo Bernaschi (massimo dot bernaschi at gmail dot com)<br />
We will provide some additional info about BitCracker's attack in a future paper.

Although we use the GPLv2 licence, we are open to collaborations.
For any additional info, collaborations or bug report please contact elena dot ago at gmail dot com