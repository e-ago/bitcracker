Bitcracker
========

BitCracker is the first open source BitLocker password cracker tool

Introduction
===

BitLocker is a full-disk encryption feature available in recent Windows versions (Vista, 7, 8.1 and 10) Pro and Enterprise.
BitCracker is a mono-GPU password cracking tool for memory units encrypted with the password authentication mode of BitLocker (see picture below).

![alt text](http://openwall.info/wiki/_media/john/bitcracker_img1.png)

Our attack has been tested on several memory units encrypted with BitLocker running on Windows 7, Window 8.1 and Windows 10 (both compatible and non-compatible mode).
here we present two implementations: CUDA and OpenCL.

Requirements
===

For CUDA implementation, you need at least CUDA 7.5 and an NVIDIA GPU with minimum cc3.5 (i.e. Kepler arch) 

Build
===

Use the buil.sh script to run makefiles within CUDA_version and OpenCL_version

Limitations
===

For the moment, BitCracker is able to evaluate passwords having lenght 

Dictionary
===

BitCracker doesn't provide any mask attack, cache mechanism or smart dictionary creation; thus you need to provide your own input dictionary.


Performance
===

Here we report best performance of BitCracker implementations tested on different GPUs

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

We released the OpenCL version as a plugin of the John The Ripper (bleeding jumbo) suite.

http://openwall.info/wiki/john/OpenCL-BitLocker


References, credits and contacts
===





