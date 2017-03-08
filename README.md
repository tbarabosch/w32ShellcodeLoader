This repository contains a small tool to load x86 shellcode on Windows NT. Though it was only tested on Windows 8.1 and Visual Studio Community 2017, it should work with other versions as well.

## How does it work?

The tool loads the shellcode to RWX memory from a binary file (passed as only argument). At the shellcode's end it adds a trampoline to regain control of the control flow and to gracefully exit. Then, it dives head first into the shellcode.

## Usage

ShellcodeLoader.exe PATH_TO_SHELLCODE_FILE

### Example

I pushed an example shellcode that spawns an instance of calc.exe. The example was taken from Peter Ferrie's collection of shellcodes, which can be found on [github](https://github.com/peterferrie/win-exec-calc-shellcode).

```
ShellcodeLoader.exe ..\w32-exec-calc-shellcode.bin
Successfully read shellcode to 0x190000 with size of 0x48 bytes.
--------------------------------------------------------------------------------
31 D2 52 68 63 61 6C 63  54 59 52 51 64 8B 72 30  |  1.RhcalcTYRQd.r0
8B 76 0C 8B 76 0C AD 8B  30 8B 7E 18 8B 5F 3C 8B  |  .v..v...0.~.._<.
5C 1F 78 8B 74 1F 20 01  FE 8B 54 1F 24 0F B7 2C  |  \.x.t. ...T.$..,
17 42 42 AD 81 3C 07 57  69 6E 45 75 F0 8B 74 1F  |  .BB..<.WinEu..t.
1C 01 FE 03 3C AE FF D7                           |  ....<...
--------------------------------------------------------------------------------
Writing trampoline to clean up function 0x008F1361 after shellcode.
Executing shellcode...
Executed shellcode successfully.
```
