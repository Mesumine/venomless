# Summary 

Venomless is a custom shellcode generator designed to provide either a reverse shell or a cmd. The biggest feature is that it can output a keystone engine python script with all of the assembly for the payload. This can then be customized to avoid bad characters and signatures. 

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

