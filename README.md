# HWK Emulator for UFS HWK box by SarasSoft

This project emulates communication between box and UFS tools so they work without actual HWK module or with not authorized one.

Since HWK server is not working anymore(or extremly rare) this is the only solution to use latest UFS tools.

## Build Environment

This project is built using Microsoft Visual Studio 6.0 (VS6).

Emulator project compiles into DLL that is injected using emulator injector project.

## What does it emulate?

This project emulates box serial number, HWK authorization flow and software authorization checks.

HWK firmware is tied to box serial number, so it's necessary to emulate it.

Also this projects emulates physical drives count and info, software authorization checks are based on it.
By emulating it, you are able to use software on different PCs without ludicrous drive info checks, in case you replaced your drive,
or if you launched software with usb flash drive connected(yes, original HWK will fail checks if you have less than 3 physical drives and you connected usb flash drive).

## Acknowledgements

Parts of this project are inspired by reversing HwkKiller.
All credit for HWK authorization logic and hashing functions goes to the original authors.