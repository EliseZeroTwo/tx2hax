# tx2hax

## Overview

This repository contains implementations of several exploits for vulnerabilities for the Tegra X2.

The [`rcmhax`](./rcmhax) folder contains an exploit implementation, and a sample payload, for getting code execution inside the BootROM of Tegra X2's via the USB Recovery Mode.

The [`ml1hax`](./ml1hax) folder contains implementations of `sparsehax` and `dtbhax` for Magic Leap One headsets.

## Writeups

There are text based writeups available in the [writeups](./writeups) directory, specifically:

* [`sparsehax`](./writeups/sparsehax.md)
* [`dtbhax`](./writeups/dtbhax.md)
* [Obtaining the BootROM](./writeups/obtaining-bootrom.md)
* [`rcmhax`](./writeups/rcmhax.md)

And additionally a [talk at 39C3](https://fahrplan.events.ccc.de/congress/2025/fahrplan/event/making-the-magic-leap-past-nvidia-s-secure-bootchain-and-breaking-some-tesla-autopilots-along-the-way).
