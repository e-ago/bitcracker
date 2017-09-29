BitCracker
========

BitCracker is the first open source password cracking tool for memory units encrypted with BitLocker (using the password authentication method).

Introduction
===

BitLocker (formerly BitLocker Drive Encryption) is a full-disk encryption feature available in recent Windows versions (Ultimate and Enterprise editions of Windows Vista and Windows 7, the Pro and Enterprise editions of Windows 8, 8.1 and 10).
BitCracker is a mono-GPU (OpenCL and CUDA) password cracking tool for memory units encrypted with the password authentication method of BitLocker (see picture below).

![alt text](http://openwall.info/wiki/_media/john/bitcracker_img1.png)

Our attack has been tested on several memory units encrypted with BitLocker running on Windows 7, Window 8.1,  Windows 10 (compatible and non-compatible mode) and BitLocker To Go.

Requirements
===

Minimum requirements for CUDA implementation:
- CUDA 7.5
- NVIDIA GPU with CC 3.5 or later
- NVIDIA GPU with Kepler architecture or later

Minimum memory requirement is 256 Mb; it may increase depending on the number of passwords processed by each kernel.

How To
===

Use the build.sh script to build 3 executables:

- Hash extractor
- BitCracker CUDA version
- BitCracker OpenCL version

The executables are stored in the build directory.
<br>
Before starting the attack, you need to run bitcracker_hash to extract the hash describing the encrypted memory unit. It also verifies if the input memory unit satisfies BitCracker's requirements.

```
> ./build/bitcracker_hash -h

Usage: ./build/bitcracker_hash -i <Encrypted memory unit> -o <output file>

Options:

  -h, --help		Show this help
  -i, --image		Path of memory unit encrypted with BitLocker
  -o, --outfile		Output file
```

The extracted hash is fully compatible with the John The Ripper format (see next Section).<br>

Then you can use the output hash file to run the BitCracker attack.

```
> ./build/bitcracker_cuda -h

Usage: ./build/bitcracker_cuda -f <hash_file> -d <dictionary_file>

Options:

  -h, --help		Show this help
  -f, --hashfile 	Path to your input hash file (HashExtractor output)
  -s, --strict		Strict check (use only in case of false positives)
  -d, --dictionary	Path to dictionary or alphabet file
  -g, --gpu 		GPU device number
  -t, --passthread	Set the number of password per thread threads
  -b, --blocks		Set the number of blocks
```

Note: In case of false positives you can use the -s option, that is a more restrictive check on the correctness of the final result. Altough this check is empirically verified and it works with all the encrypted images in this repo, we can't guarantee that it doesn't lead to false negatives. Use -s option only if BitCracker returns several false positives.

In the the run_test.sh script there are several attack examples using the encrypted images provided in this repo:
* imgWin7: memory unit encrypted with BitLocker using Windows 7 Enteprise edition OS
* imgWin8: memory unit encrypted with BitLocker using Windows 8 Enteprise edition OS
* imgWin10Compatible.vhd: memory unit encrypted with BitLocker (compatible mode) using Windows 10 Enteprise edition OS, 
* imgWin10NonCompatible.vhd: memory unit encrypted with BitLocker (NON compatible mode) using Windows 10 Enteprise edition OS, 
* imgWin10NonCompatibleLong27.vhd: memory unit encrypted with BitLocker (NON compatible mode) using Windows 10 Enteprise edition OS with the longest possible password (27 characters)

Currently, BitCracker accepts passwords between 8 (minimum password length) and 27 characters (implementation reasons).

BitCracker doesn't provide any mask attack, cache mechanism or smart dictionary creation; therefore you need to provide your own input dictionary.

Performance
===

Here we report the best performance of BitCracker implementations tested on different GPUs.

| GPU Acronim  |       GPU       | Arch    | CC  | # SM | Clock  | CUDA |
| ------------ | --------------- | ------- | --- | ---- | ------ | ---- |
| GFT          | GeForce Titan   | Kepler  | 3.5 | 14   | 835    | 7.0  |
| GTK80        | Tesla K80       | Kepler  | 3.5 | 13   | 875    | 7.5  |
| GFTX         | GeForce Titan X | Maxwell | 5.2 | 24   | 1001   | 7.5  |
| GTP100       | Telsa P100      | Pascal  | 6.1 | 56   | 1328   | 8.0  |
| AMDM         | Radedon Malta   | -       | -   | -    | -      | -    |

Performance:

| Version  | GPU    | -t  | -b | Passwords x kernel | Passwords/sec | Hash/sec   |
| -------- | ------ | --- | -- | ------------------ | ------------- | ---------- |
| CUDA     | GFT    | 8   | 13 | 106.496            | 303           | 635 MH/s   |
| CUDA     | GTK80  | 8   | 14 | 114.688            | 370           | 775 MH/s   |
| CUDA     | GFTX   | 8   | 24 | 106.608            | 933           | 1.957 MH/s |
| CUDA     | GTP100 | 8   | 56 | 458.752            | 1.363         | 2.858 MH/s |
| OpenCL   | AMDM   | 32  | 64 | 524.288            | 241           | 505 MH/s   |
| OpenCL   | GFTX   | 8   | 24 | 196.608            | 884           | 1.853 MH/s |

John The Ripper
===

We released the OpenCL version as a plugin of John The Ripper (bleeding jumbo):
* Wiki page: http://openwall.info/wiki/john/OpenCL-BitLocker <br />
* JtR source code: https://github.com/magnumripper/JohnTheRipper

Next Release
===

In the next relese:
- The maximum password lenght will be dynamic
- Improve strict check with optional MAC verification to avoid any false positive

References, credits and contacts
===

This is a research project in collaboration with the National Research Council of Italy released under GPLv2 license.<br />
Copyright (C) 2013-2017  Elena Ago (elena dot ago at gmail dot com) and Massimo Bernaschi (massimo dot bernaschi at gmail dot com)<br />
We will provide some additional info about BitCracker's attack in a future paper.

Although we use the GPLv2 licence, we are open to collaborations.
For any additional info, collaborations or bug report please contact elena dot ago at gmail dot com