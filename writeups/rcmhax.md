# RCMHax

## Introduction

This section is a writuep of unpatchable vulnerabilites in the Tegra X2, both in the BootROM and in the USB controller.

Together, they allow an attacker to trivially load and execute arbitrary code in the context of the BootROM from coldboot.

The Tegra X2 BootROM has a USB recovery mode present, similarly to the Tegra X1. However the Tegra X2 is using the rewritten BootROM that has this vulnerability patched. The vulnerabilities found can be exploited via the USB recovery mode.

## Writing Further Than Intended

The main receive loop for the USB Recovery Mode looks like this:

```c
uint32_t rcm_receive_message(void *dst) {
    const uint32_t MAX_TRANSFER_SIZE = 0x10000;
    const uint32_t RCM_HEADER_SIZE = 0x5b0;

    bool received_header = false;
    uint32_t length_from_header = 0;
    uint32_t total_bytes_received = 0;

    do {
        uint32_t bytes_received = 0;
        uint32_t result = xusb_receive(dst + total_bytes_received, MAX_TRANSFER_SIZE, &bytes_received);

        if (result != 0)
            return result;
        
        total_bytes_received += bytes_received;

        if (!received_header) {
            if (total_bytes_received < RCM_HEADER_SIZE)
                continue;

            length_from_header = *(uint32_t *)dst;

            if (
                length_from_header > 0x305af // If message length is too large
                || length_from_header < 0x400 // If message length is too small
                || (length_from_header & 0b1111) != 0 // If message length is not 0x10 byte aligned
            ) {
                rcm_send_error_code(8);
                return 13;
            }

            received_header = true;
        }
    } while (total_bytes_received != length_from_header);

    return 0;
}
```

This function has two issues:

1. It always requests to receive up to 0x10000 bytes over USB, regardless of how many bytes are left in the message. This allows us to overflow the buffer by up to 0xfa51 bytes, which isn't abusable alone.
2. The loop condition is checking if the total amount of bytes received is exactly equal to the attacker-controlled message length.

This allows an attacker to bypass the size limit and send as much data as wanted over USB, by sending a single 0x5b0 byte long chunk for the header with the size set to any number within the range `0x400..0x5b0`.

## Exploitation: Overview

The writes to memory happen from the USB controller, not the BPMP. The BootROM's stack lives in BPMP-local memory, which prevents us from overwriting it utilising this.

Importantly though, writing to an address that the USB controller cannot access does not cause an error to be raised by by the USB controller, it just ignores the failed write and continues. This means an attacker can loop around and overwrite memory before the buffer by overflowing the pointer that the BPMP requests data to be read into. The BPMP is 32-bit so this doesn't take too long (~100 seconds).

The only area of memory that is currently accessible by the USB controller is SysRAM, which the BootROM only uses for a few things, mostly data structures used for interacting with other devices on the SoC, such as the USB controller.

Present here was the ring buffers for each of the [USB endpoints](https://beyondlogic.org/usbnutshell/usb3.shtml#Endpoints). These are where the BootROM queues Transfer Request Blocks (TRBs from here onwards) for the USB controller to consume. There are several different types of TRBs, but they are all 0x10 bytes long and identifiable by a variant tag in the upper 6 bits of byte 13.

One of the TRB types is called a Link TRB. A Link TRB is placed at the end of the ring buffer to tell the BootROM where the next ring buffer begins, so you can chain together multiple ring buffers if you want to. The BootROM doesn't make use of this, but still utilises a Link TRB at the end of each endpoint's ring buffer, pointing back to the start of the same ring buffer.

Link TRBs are handled after queueing a TRB into the ringbuffer, which looks something like this:

```c
memcpy(ring_buffer_head_ptr, trb, 0x10); // Enqueue TRB

volatile uint32_t *next_trb = ring_buffer_head_ptr + 0x10;

// If the TRB type is a LinkTRB
if (next_trb[3] & 0xfc00 == 0x1800) {
    // ...

    // The plus 0x10000000 is adjustment from Hardware
    // SysRAM -> BPMP's mapping of SysRAM
    ring_buffer_head_ptr = (next_trb[0] & 0xfffffff0) + 0x10000000
} else {
    // We haven't reached the end of the ring yet, so the
    // next pointer is just the next item in the
    // Ring
    ring_buffer_head_ptr = next_trb;
}
```

If we corrupt the pointer in a Link TRB, we can get the BPMP to queue the next TRB it sends to any address we want. However, cannot control the contents of a TRB.

My first attempt was using the transfer attempt TRB as it begins with the pointer that the data should be recieved to. I immediately faced two issues though:

1. The addresses in the TRB are adjusted by 0x1000_0000 due to the BootROM mapping SysRAM higher than it actually is in the system address map to work around a hardware problem.
2. Addresses read from the Link TRB have the lower 4 bits masked away, as TRBs have to be 0x10 byte aligned, so any return address we overwrite on the stack has to also be 0x10 byte aligned, which there was none.

It's also not possible to just overwrite the BootROM in memory utilising this, as the BootROM is RO in memory.

At this point, I realised it wasn't going to be as easy as I was initially hoping when finding this vulnerability.

## Exploitation: Patches

The BootROM utilises a patching method where patches are stored in fuses which the BootROM reads and utilises and uses to configure a patch controller during initialisation. These patches are only adjustable before the SoC leaves the factory.

For patches which require doing more than changing a single instruction, they utilise syscalls for inserting hooks where they want to patch a function, and handling the actual patch in the syscall handler for that patch.

During initialisation, the BootROM copies the syscall handler to BPMP-local memory, and unpacks the patches that utilise it after it.

The syscall handler lives at 0x0d48_1c28 and looks like this:

```arm
push    {r0, r1, r2}
mov     r2, lr
sub     r2, r2, #0x2
ldr     r2, [r2] // Load the syscall number into r2
and     r2, r2, #0xff
lsl     r2, r2, #0x1
ldr     r0, =0x103c4
ldr     r1, =0x1040c
sub     r1, r1, r0
ldr     r0, =0xd481c28
add     r0, r0, r1
add     r2, r2, r0
orr     r2, r2, #0x1
pop     {r0, r1}
bx      r2  // (SVC number * 2) + 0xd481c70
```

An example control TRB has the following format:

```
00 00 00 00 00 00 00 00 00 00 00 00 21 10 00 00
```

Which convieniently is the representation of the following ARM instructions:

```arm
00000000 // andeq r0, r0, r0 (a NOP)
00000000 // andeq r0, r0, r0 (a NOP)
00000000 // andeq r0, r0, r0 (a NOP)
21100000 // andeq r1, r0, r1, lsr #32 (sets r1 to 0 if the CPSR has the Zero flag set, otherwise a NOP)
```

I utilised a control TRB to overwrite 4 instructions in it, resulting in this:

```arm
push    {r0, r1, r2}
mov     r2, lr
sub     r2, r2, #0x2
ldr     r2, [r2] // Load the syscall number into r2
and     r2, r2, #0xff
lsl     r2, r2, #0x1
andeq   r0, r0, r0
andeq   r0, r0, r0
andeq   r0, r0, r0
andeq   r1, r1, r1, lsr #32
add     r0, r0, r1
add     r2, r2, r0
orr     r2, r2, #0x1
pop     {r0, r1}
bx      r2  // (SVC number * 2) + 0xd481c70
```

When the handler is called now, it will branch and exchange to thumb to whatever R0 was before the syscall was executed, plus `syscall number * 2`, and if the Z flag is 0, R1 is also added to it.

## Exploitation: Triggering the Patched Syscall Handler

We can trigger syscall number 0x34 whilst the USB stack is running by sending a control request to get the device descriptor. This will still be processed when the Ep0 endpoint has died, because the USB controller on the TX2 does not raise an error when Ep0 is pointing to an invalid location (it does for Ep1Out).

When we trigger this syscall, the registers which can effect our branch location have the following values:

* `r0` = 0x40002600 (a SysRAM pointer)
* `r1` = 0xd484e8a (a BTCM pointer)
* `lr` = 0x19b8e

Lets follow through the relevant instructions in the patched handler when this specific syscall happens:

```
mov     r2, lr // Loads 0x19b8e into R2
sub     r2, r2, #0x2 // Subtracts 2 from R2, setting R2 to 0x19b8c
ldr     r2, [r2] // Load from the address stored in R2 (0x19b8c), into R2 (0x4639DF34)
and     r2, r2, #0xff // Mask away all but the lowest 8 bits from R2, so R2 now contains the syscall number (0x34)
lsl     r2, r2, #0x1 // Multiply R2 by 2, storing the result in R2 (0x68)

andeq   r1, r1, r1, lsr #32 // Sets R1 to 0

add     r0, r0, r1 // NOP as R1 is 0, R0 remains 0x40002600
add     r2, r2, r0 // Add R0 (0x40002600) and R2 (0x68), storing the result in R2 (0x40002668)
orr     r2, r2, #0x1 /// Bitwise Or R2 (0x40002668) and 1, storing the result in R2 (0x40002669)

bx      r2 // Branch to 0x40002669, exchanging to thumb
```

And there we have it, that's a branch to SysRAM where our payload awaits.
