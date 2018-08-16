# BitCracker

BitCracker is the first open source password cracking tool for storage devices (Hard Disk, USB Pendrive, SD card, etc...) encrypted with [BitLocker](https://technet.microsoft.com/en-us/library/cc766295(v=ws.10).aspx), an encryption feature available on Windows Vista, 7, 8.1 and 10 (Ultimate, Pro and Enterprise editions). BitLocker offers a number of different authentication methods to encrypt a storage device like Trusted Platform Module (TPM), Smart Card, Recovery Password, User supplied password.

By means of a dictionary attack, BitCracker tries to find the correct User Password or Recovery Password to decrypt the encrypted storage device. It has been implemented in [CUDA](http://docs.nvidia.com/cuda) and [OpenCL](https://www.khronos.org/opencl).

**CRITICAL ERROR FIXED IN COMMITS 7b2a6b6 (CUDA version) and 5f09d7f (OpenCL version): bad loop termination! Please re-run your tests.**

## Requirements

To run the BitCracker-CUDA, minimal requirements are:
- an [NVIDIA GPU](https://en.wikipedia.org/wiki/List_of_Nvidia_graphics_processing_units) with CC 3.5 or later
- CUDA 7.5 or newer

To run the BitCracker-OpenCL, minimal requirements are any GPU or CPU supporting OpenCL (you can find some help [here](https://www.khronos.org/conformance/adopters/conformant-products#opencl).

BitCracker requires at least 260 MB of device memory.

We strongly recommend to run your attack on a GPU rather than CPU for performance reasons (see section [Performance](https://github.com/e-ago/bitcracker#performance)).

## Build

Running the `build.sh` script generates 4 executables inside the `build` directory: `bitcracker_hash`, `bitcracker_rpgen`, `bitcracker_cuda`, `bitcracker_opencl`.

In order to build `bitcracker_cuda` coherently with your NVIDIA GPU and CUDA version, you need to modify the `src_CUDA/Makefile` chosing the correct SM version. As a reference, you can use the following table:

| GPU Architecture | Suggested CUDA |          Makefile 	 |
| ---------------- | -------------- | -------------------------- |
| Kepler           | CUDA 7.5       | arch=compute_35,code=sm_35 |
| Maxwell          | CUDA 8.0       | arch=compute_52,code=sm_52 |
| Pascal           | CUDA 9.0       | arch=compute_60,code=sm_60 |
| Volta            | CUDA 9.0       | arch=compute_70,code=sm_70 |

## Prepare the attack

You need to create the image of your storage device encrypted with BitLocker using, as an example, the *dd* command:

```
sudo dd if=/dev/disk2 of=/path/to/imageEncrypted.img conv=noerror,sync
4030464+0 records in
4030464+0 records out
2063597568 bytes transferred in 292.749849 secs (7049013 bytes/sec)
```

Then you need to run the `bitcracker_hash` executable on your `imageEncrypted.img` in order to:
- check if the image has a valid format and can be attacked by BitCracker
- check if the the original storage device hash been encrypted with an User Password or a Recovery Password
- extract the hash describing the image

If the execution completes correctly, `bitcracker_hash` produces 1 or 2 output files:

* hash_user_pass.txt : if the device was encrypted with a User Password, this file contains the hash you need to start the User Password attack mode.
* hash_recv_pass.txt : the hash you need to start the Recovery Password attack mode

**BDE encrypted volumes could have different formats for different authentication methods. If `bitcracker_hash` is not able to find the Recovery Password on your encrypted image, please open an issue or contact me**

An example:
```
/build/bitcracker_hash -o test_hash -i ./Images/imgWin7

---------> BitCracker Hash Extractor <---------
Opening file ./Images/imgWin7

....

Signature found at 0x02208000
Version: 2 (Windows 7 or later)

VMK entry found at 0x022080bc
VMK encrypted with user password found!
VMK encrypted with AES-CCM

VMK entry found at 0x0220819c
VMK encrypted with Recovery key found!
VMK encrypted with AES-CCM

User Password hash:
$bitlocker$0$16$89a5bad722db4a729d3c7b9ee8e76a29$1048576$12$304a4ac192a2cf0103000000$60$24de9a6128e8f8ffb97ac72d21de40f63dbc44acf101e68ac0f7e52ecb1be4a8ee30ca1e69fbe98400707ba3977d5f09b14e388c885f312edc5c85c2

Recovery Key hash:
$bitlocker$2$16$8b7be4f7802275ffbdad3766c7f7fa4a$1048576$12$304a4ac192a2cf0106000000$60$6e72f6ef6ba688e72211b8cf8cc722affd308882965dc195f85614846f5eb7d9037d4d63bcc1d6e904f0030cf2e3a95b3e1067447b089b7467f86688

Output file for user password attack: "hash_user_pass.txt"
Output file for recovery password attack: "hash_recv_pass.txt"
```

## User Password Attack

You can use this type of attack if the storage device has been encrypted with an user supplied password as shown in the following image.
![alt text](http://openwall.info/wiki/_media/john/bitcracker_img1.png)
BitCracker performs a dictionary attack, thus you need to provide a wordlist of possibile user passwords.

To start the attack you need:
- the `hash_user_pass.txt` file
- a wordlist of possibile user passwords (you need to provide it by yourself)

A command line example:

```./build/bitcracker_cuda -f hash_user_pass.txt -d wordlist.txt -t 1 -b 1 -g 0 -u```

Where:
- `-f` : path to the `hash_user_pass.txt` file
- `-d` : path to your wordlist
- `-t` : number of passwords processed by each CUDA thread
- `-b` : number of CUDA blocks
- `-g` : NVIDIA GPU device ID
- `-u` : specify your want an user password attack

For all the available options, type `./build/bitcracker_cuda -h`.
In order to have the best performance, please refer to the table in [Performance](https://github.com/e-ago/bitcracker#performance) section to properly set the `t` and `b` options according to your NVIDIA GPU.

Same considerations can be applied for the `bitcracker_opencl` executable.

An output example:

```
====================================
Selected device: GPU Tesla K80 (ID: 0)
====================================
....
Reading hash file "hash_user_pass.txt"
$bitlocker$0$16$0a8b9d0655d3900e9f67280adc27b5d7$1048576$12$b0599ad6c6a1cf0103000000$60$c16658f54140b3d90be6de9e03b1fe90033a2c7df7127bcd16cb013cf778c12072142c484c9c291a496fc0ebd8c21c33b595a9c1587acfc6d8bb9663

====================================
Attack
====================================

Type of attack: User Password
CUDA Threads: 1024
CUDA Blocks: 1
Psw per thread: 1
Max Psw per kernel: 1024
Dictionary: wordlist.txt
Strict Check (-s): No
MAC Comparison (-m): No

CUDA Kernel execution:
	Stream 0
	Effective number psw: 12
	Passwords Range:
		abcdefshhf
		.....
		blablalbalbalbla12
	Time: 28.651947 sec
	Passwords x second:     0.42 pw/sec

================================================
....
Password found: paperino
================================================
```

Currently BitCracker is able to process input passwords with a length between 8 and 55 characters.

## Recovery Password Attack

During the encryption of a storage device, (regardless the authentication method) BitLocker asks the user to store somewhere a Recovery Password that can be used to restore the access to the encrypted storage device in the event that she/he can't unlock the drive normally.
Thus the Recovery Password is a kind of *passe-partout* for all the authentication methods and it consists of a 48-digit key like this:

> 236808-089419-192665-495704-618299-073414-538373-542366

See [Microsoft docs](https://docs.microsoft.com/en-us/windows/device-security/bitlocker/bitlocker-recovery-guide-plan) for further details.

As for the user password, BitCracker is able to perform a dictionary attack to find the correct Recovery Password generated by BitLocker to encrypt the storage device. **Please note that currently we are able to attack the Recovery Password only if the storage device hasn't been encrypted with the TPM.**

To start the attack you need:
- the `hash_recv_pass.txt` file
- a wordlist of possibile recovery passwords

Generate and store all the possibile passwords it's an hard problem. For this reason, we created a Recovery Password generator named `bitcracker_rpgen`. With this tool you can create a bunch of Recovery Passwords wordlists you can use for your attacks. As an example:

```./build/bitcracker_rpgen -n 300 -p 10000000 -s 000000-000011-000022-000033-000044-000055-008459-015180```

This generates:
- `-n` : number of wordlists
- `-p` : number of Recovery Passwords per wordlist
- `-s` : generate Recovery Passwords starting from this one

You can use the default configuration running without options:
```
./build/bitcracker_rpgen

************* BitCracker Recovery Password wordlists generator *************

Running with this configuration:
### Create 100 wordlists
### Recovery Passwords per wordlist=5000000
### Allow duplicates=No
### Generate starting from=000000-000011-000022-000033-000044-000055-000066-000077

Creating wordlist "bitcracker_wlrp_0.txt" with 5000000 passwords
First password=000000-000011-000022-000033-000044-000055-000066-000077
Last password= 000000-000011-000022-000033-000044-000055-000902-217822
...
```

Note that the `-s` option can be used to restart the generation from your last generated Recovery Password (instead of restarting everytime from the initial one).
The `-d` option enables the possibility to have duplicates in the same Recovery Password. For example:
`000000-000011-000055-000055-000044-000055-000902-217822`

For all the available options, type `./build/bitcracker_rpgen -h`.

A command line example:

```./build/bitcracker_cuda -f hash_recv_pass.txt -d bitcracker_wlrp_0.txt -t 1 -b 1 -g 0 -r```

Where options are the same as in case of User Password but instead of `-u` you need to specify `-r`. An output example:

```
====================================
Selected device: GPU Tesla K80 (ID: 0)
====================================

...
Reading hash file "hash_recv_pass.txt"
$bitlocker$2$16$432dd19f37dd413a88552225628c8ae5$1048576$12$a0da3fc75f6cd30106000000$60$3e57c68216ef3d2b8139fdb0ec74254bdf453e688401e89b41cae7c250739a8b36edd4fe86a597b5823cf3e0f41c98f623b528960a4bee00c42131ef


====================================
Attack
====================================

Type of attack: Recovery Password
CUDA Threads: 1024
CUDA Blocks: 1
Psw per thread: 8
Max Psw per kernel: 8192
Dictionary: wordlist.txt
Strict Check (-s): No
MAC Comparison (-m): No

CUDA Kernel execution:
	Effective passwords: 6014
	Passwords Range:
		390775-218680-136708-700645-433191-416240-153241-612216
		.....
		090134-625383-540826-613283-563497-710369-160182-661364
	Time: 193.358937 sec
	Passwords x second:    31.10 pw/sec


================================================
CUDA attack completed
Passwords evaluated: 6014
Password found: 111683-110022-683298-209352-468105-648483-571252-334455
================================================
```


## False Positives

By default, BitCracker does a fast attack (for both User and Recovery password modes) which may return some false positive. In this case you can re-run your attack with the `-m` option which enables the MAC verification (slower solution).

## Examples

To test BitCracker on your system before starting the real attack, we provided several images of encrypted storage devices.

* imgWin7: BitLocker on Windows 7 Enteprise edition OS
* imgWin8: BitLocker on Windows 8 Enteprise edition OS
* imgWin10Compat.vhd: BitLocker (compatible mode) on Windows 10 Pro edition OS
* imgWin10NotCompat.vhd: BitLocker (not compatible mode) on Windows 10 Pro edition OS
* imgWin10NotCompatLongPsw.vhd : BitLocker (not compatible mode) on Windows 10 Pro edition OS with a longer user password

You can attack those images with both User and Recovery password modes, using the wordlists stored in the `Dictionary` folder.

## Performance

Here we report the best BitCracker performances in case of fast attack (default) to the User Password (-u option).

| GPU Acronim  |       GPU       | Arch    | CC  | # SM | Clock  | CUDA |
| ------------ | --------------- | ------- | --- | ---- | ------ | ---- |
| GFT          | GeForce Titan   | Kepler  | 3.5 | 14   | 835    | 7.0  |
| GTK80        | Tesla K80       | Kepler  | 3.5 | 13   | 875    | 7.5  |
| GFTX         | GeForce Titan X | Maxwell | 5.2 | 24   | 1001   | 7.5  |
| GTP100       | Tesla P100      | Pascal  | 6.1 | 56   | 1328   | 8.0  |
| GTV100       | Tesla V100      | Volta   | 7.0 | 80   | 1290   | 9.0  |
| AMDM         | Radeon Malta    | -       | -   | -    | -      | -    |

Performance:

| Version  | GPU    | -t  | -b | Passwords x kernel | Passwords/sec | Hash/sec   |
| -------- | ------ | --- | -- | ------------------ | ------------- | ---------- |
| CUDA     | GFT    | 8   | 13 | 106.496            | 303           | 635 MH/s   |
| CUDA     | GTK80  | 8   | 14 | 114.688            | 370           | 775 MH/s   |
| CUDA     | GFTX   | 8   | 24 | 106.608            | 933           | 1.957 MH/s |
| CUDA     | GTP100 | 1   | 56 | 57.344             | 1.418         | 2.973 MH/s |
| CUDA     | GTV100 | 1   | 80 | 81.920             | 3.252         | 6.820 MH/s |
| OpenCL   | AMDM   | 32  | 64 | 524.288            | 241           | 505 MH/s   |
| OpenCL   | GFTX   | 8   | 24 | 196.608            | 884           | 1.853 MH/s |

N.B. Each password requires about 2.097.152 SHA-256

## John The Ripper

We released BitCracker as the [OpenCL-BitLocker](http://openwall.info/wiki/john/OpenCL-BitLocker) format in [John The Ripper](https://github.com/magnumripper/JohnTheRipper) (`--format=bitlocker-opencl`).
The hash files generated by `bitcracker_hash` (see *How To* section) are fully compatible with the John format.<br>
On the GTV100 password rate is about 3150p/s. JtR team developed the CPU version of this attack (`--format=bitlocker`); on a CPU Intel(R) Xeon(R) v4 2.20GHz, password rate is about 78p/s.

## Hashcat

This is a work in progress...

## Changelog

08/16 : New `bitcracker_rpgen` executable to generate wordlists of possible Recovery Passwords<br>
06/14 : User Password attack mode now supports passwords length up to 55

#### What's next

* Provide a multi-GPU implementation
* Provide a Qt interface

## References, credits and contacts

Plase share and test our project: we need your feedback! 

Special thanks go to the John The Ripper team and [Dislocker](https://github.com/Aorimn/dislocker) and [LibBDE](https://github.com/libyal/libbde) projects.

This is a research project in collaboration with the National Research Council of Italy released under GPLv2 license.<br />
Copyright (C) 2013-2017  Elena Ago (elena dot ago at gmail dot com) and Massimo Bernaschi (massimo dot bernaschi at gmail dot com)<br />
We will provide some additional info about BitCracker's attack in a future paper.

Although we use the GPLv2 licence, we are open to collaborations.
For any additional info, collaborations or bug report please contact us or open an issue
