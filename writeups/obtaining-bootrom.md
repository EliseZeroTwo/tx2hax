## Obtaining the BootROM

This section covers the process of obtaining the BootROM from the Tegra X2.

It cannot just be read out of memory as it is no longer visible in memory once it finishes running and hands off execution to the first stage bootloader (MB1), excluding the first 0x1000 bytes (named the "non-secure" part of the BootROM).

### Non-Secure Section

Looking at the non-secure part of the BootROM, there is still an internal debug UART loader present in it that was also present in the Tegra X1 BootROM.

The debug loader receives a payload over UART and executes it without signature checking. There are two seperate conditions that can result in this code-path being taken:

1. The "Failure Analysis Mode" fuse is not blown, the "NVidia Production Mode" fuse is not blown, and the "ODM Production Mode" fuse is not blown
2. The "Failure Analysis Mode" fuse is blown

However, the second path was not interesting as it will clear the secure-mode flag which prevents the loaded binary from reading the secure part of the BootROM.

This was a target for fault injection.

### Making a Base-"Board"

I obtained two Tegra X2 modules cheaply, and did not want to purchase a base-board just for this if possible, and after looking at pinout of the Tegra X2 that NVidia provides for manufacturing of custom base-boards, decided I could just make my own by sticking magnet wire into the connector.

<Insert Photo of messy wiring here>

This worked reliably enough to get the BootROM running, and the Tegra X2 showing up in recovery mode over USB on a host device.

### Fault Injection

I am not going into detail here on how voltage glitching works, instead at the end of this writeup are links to articles which I found to be useful resources.

The SoC exposes it's power rails on the back of the Tegra X2 modules via decoupling capacitors, which is accessible by undoing a few screws. I desoldered all of the decoupling capacitors on the SoC power rail, and messily soldered a MOSFET in the place where one of them previously lived.

I reused firmware I had previously written for the RP2040/RP2350 for performing the same attack on a Tegra X1+ to support the Tegra X2, and left it to run overnight searching for offsets.

This, surprisingly, did not work. After speaking with a friend, and recording the voltage drop with an oscilliscope, it was clear the voltage was not being dropped down low enough, fast enough.

This was trivially addressed by adding a second MOSFET, and resulted in being able to reliably glitch the fuse check in the BootROM to make it enter the debug UART loader.

### Success

With the ability to run arbitrary code in the context of the BootROM, it was possible to read the BootROM from memory and send it back to the host over UART.
