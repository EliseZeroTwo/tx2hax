# DTBHax

## Overview

This section is a writeup of a vulnerability present in the third stage bootloader for the Tegra X2 provided by NVidia known as CBoot.

This vulnerability allows an attacker to gain persistant coldboot code execution in the context of the third stage bootloader.

### Vulnerability

When loading partitions, there are two possibilities for where the partition is loaded to:

* A static address
* A freshly allocated buffer on the heap

The majority of partitions fall into the second catagory. One of the exeptions to this is the DTB partition. The DTB is loaded into memory at `0x9200_0000`.

This is before CBoot is located in memory (`0x9600_0000`), but is very close.

There is no size constraint on the partition that is loaded, the loader will load the partition with the length specified at that address.

This allows an attacker to overwrite the partition size in the GPT on the QSPI flash, and have CBoot overwrite itself in memory with the contents of the attacker controlled partition.
