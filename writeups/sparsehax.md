# SparseHax

## Overview

This section is a writeup of exploiting a vulnerability in the Fastboot implementation in the third stage Bootloader (CBoot) provided by NVidia for the Tegra X2, specifically on the Magic Leap One.

## SparseFS

The Fastboot implementation supports flashing partitions. For partitions that may contain a lot of empty space, SparseFS is supported. They also support sending the SparseFS payload in chunks, for partitions which are too large to send at once due to memory constraints.

Magic Leap utilises this, alongside a signed blob of hashes of each unpacked chunk to validate each chunk as it is sent, before flashing it to the storage.

## Vulnerability

NVidia publishes the source code for CBoot, here is the function that is responsible for unpacking a SparseFS partition, adjusted for brevity:

```c
tegrabl_error_t tegrabl_sparse_unsparse(
		struct tegrabl_unsparse_state *unsparse_state,
		const void *buff, uint64_t length)
{
	tegrabl_error_t error = TEGRABL_NO_ERROR;
	uint64_t size = 0;
	uint64_t remaining = unsparse_state->remaining;
	uint64_t offset = unsparse_state->offset;
	uint32_t i = 0;
	const uint8_t *sparse_buffer = (const uint8_t *)buff;
	uint8_t *tmp_buff = NULL;
	struct tegrabl_sparse_image_header *image_header = &unsparse_state->image_header;
	struct tegrabl_sparse_chunk_header *curr_header = &unsparse_state->chunk_header;
	tegrabl_unsparse_state_type_t state = unsparse_state->state;


	while (length || TEGRABL_UNSPARSE_PARTIAL_CHUNK_DONT_CARE == state) {
		switch (state) {
		case TEGRABL_UNSPARSE_PARTIAL_IMAGE_HEADER:
			size = MIN(length, remaining);
			tmp_buff = (uint8_t *)image_header;
			memcpy(tmp_buff + offset, sparse_buffer, size);
			remaining -= size;
			length -= size;
			offset += size;
			sparse_buffer += size;

			if (remaining != 0) {
				continue;
			}

			/* If all header is received then process further */
			error = tegrabl_sparse_validate_header(image_header,
					unsparse_state->max_unsparse_size);
			if (error != TEGRABL_NO_ERROR) {
				pr_debug("sparse header validation failed\n");
				goto fail;
			}

			/* Header is followed by chunk header */
			memset(curr_header, 0x0, sizeof(*curr_header));
			state = TEGRABL_UNSPARSE_PARTIAL_CHUNK_HEADER;
			remaining = image_header->chunk_hdr_sz;
			offset = 0;
			break;

		case TEGRABL_UNSPARSE_PARTIAL_CHUNK_HEADER:
			size = MIN(length, remaining);
			tmp_buff = (uint8_t *)curr_header;

			if (offset < sizeof(*curr_header)) {
				memcpy(tmp_buff + offset, sparse_buffer, size);
			}

			remaining -= size;
			length -= size;
			offset += size;
			sparse_buffer += size;


    /*
     * Rest of the match block cut out for brevity
     */
		}
	}
}
```

The `memcpy` in the `TEGRABL_UNSPARSE_PARTIAL_CHUNK_HEADER` state has an attacker controlled size, has a stack buffer as a destination, and the source is attacker supplied data.

## Going from a stack smash to code execution

We do not have a copy of CBoot running on the Magic Leap One, so it was not possible to know exactly where the SparseFS image was ending up in memory.

From the publiclly available CBoot sources, we can see that there is no ASLR at this point.

The largest size payload we can send at once that the device will accept is 0x2000000 bytes.

The CBoot memory map indicates that CBoot gets loaded at 0x80000000, and the heap must live somewhere after this address

I knew that the device would reboot on invalid memory accesses, so I had one-bit debugging available (does the device hang, or does it reboot?) for testing code execution.

I wrote a minimal Fastboot client in Rust and started programatically generating and sending a SparseFS partition that began with a repeated address to smash the stack with, followed by a NOP slide, ending in A `B .` instruction to cause an infinite loop. Every time the device reset, it adjusted the address that the stack gets sprayed with.

Our search space was not very large, considering we can cover 0x0200_0000 bytes every attempt, and that memory map indicates the heap should be after CBoot.

This worked and the device eventually hung. In order to ensure I had execution, I changed the payload to end in the device reboot SMC and sent it again, this time observing the device rebooting.

## Dumping CBoot, Pt. 1

The reboot timing was consistant down to 15 milliseconds, and proved to be the simplest way towards dumping CBoot from the device. Utilising the Microsecond counter on the SoC, I began attempting to encode bytes in how long the device loops for before resetting. This was slow, taking up to 25.5 seconds extra per byte to reset, but I let it run and dumped the `.start` function successfully, proving that I could exfiltrate data.

A friend of mine plotted the timings after I mentioned this to them, and it turned out to be ~20x faster to exfiltrate in 4-bit chunks compared to 8-bit chunks, as 4-bit chunks added at most ~1.5 seconds per reboot. This left us with a data transfer rate of around a byte every 3 seconds.

At this rate though it would take ~30 days to obtain the entirety of CBoot, which was too slow.

## Dumping CBoot, Pt. 2: Instruction Heuristics

Knowing that CBoot already has a functioning USB stack implemented, the next step was utilising it.

Compiling the upstream CBoot and looking at the generated assembly for the USB functions, one of them had instruction that was unique enough, and the other two needed USB functions had unique instructions in their caller, and a caller of a caller.

Updating the payload to scan memory for these instructions with the target register masked away, and dumping the instructions around it to find the entrypoint of the function utilising the previous method worked, and provided a way to find the USB functions on device.

Calling these functions directly from the payload worked, and the payload could now speak back to the host, so I could dump the full CBoot binary from memory now transferring it back with it's own USB functions.

## Side Track: Obtaining the SBK

When a Tegra device is in secure mode, a 16-byte long Secure Boot Key is burned to the fuses, and the BootROM loads it into a keyslot of the Security Engine and marks the keyslot as unreadable.

On the Tegra X1, there was an issue with the Security Engine where you could overwrite AES keyslots in 4-byte chunks, and brute-forcing 4-bytes is far within the realm of feasability, and a small test proved the Tegra X2's Security Engine was vulnerable to the same issue.

Using the Security Engine, I encrypted 16 zero bytes with the keyslot the Secure Boot Key was stored in, overwrote the first 4 bytes of the keyslot with zeros, encrypted 16 zero bytes with it, overwrote the next 4 bytes of the keyslot with zeros, and repeated until I had 5 samples of encrypting 16 null bytes, going from encrypting with the full SBK to encrypting with only the final 4 bytes of the SBK with the rest of the bytes set to zero.

A more powerful device can utilise these samples to brute force the key in less than 5 seconds, which left me with the Secure Boot Key.
