; Architecture: x86
.386
.model flat, stdcall
option casemap : none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\advapi32.inc
includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib
includelib \masm32\lib\advapi32.lib

printf proto C, :VARARG
scanf proto C, :VARARG
malloc proto C :VARARG
free proto C :VARARG
.data
    expected_output db "0123456789ABCDEF",0
    base10Prompt db "Enter your base10 number:",0
    int_format db "%d",0
    other_basePrompt db 0Ah,"Enter your desired destination base(2-16):",0
    invalid_base db 0Ah,"Invalid base",0
    result db 0Ah,"Your base%d number is:",0
    stack_overflowPrompt db 0Ah,"Stack overflow!",0Ah,0
    output_format db "%c",0
    base10_num DWORD ?
    desired_base DWORD ?
.code
start:
    invoke printf, OFFSET base10Prompt
    invoke scanf, OFFSET int_format, OFFSET base10_num
    invoke printf, OFFSET other_basePrompt
    invoke scanf, OFFSET int_format, OFFSET desired_base
    mov ecx, desired_base
    lea eax, [ecx-2]
    cmp eax, 0Eh
    ja handling_invalid_base
    
    invoke printf, OFFSET result, desired_base
    mov esi, base10_num
    mov ebx, desired_base
    xor edi, edi
    test esi, esi
    jnz if_less
    jmp exit
if_less:
    jle exit
alloc_mem:
    invoke malloc, 8
    mov ecx,eax
    test ecx, ecx
    jnz base_convert2

    invoke printf, OFFSET stack_overflowPrompt
    jmp base_convert
base_convert2:
    mov eax, esi
    mov [ecx+4], edi
    cdq
    mov edi, ecx
    idiv ebx
    mov [ecx], edx
base_convert:
    mov eax, esi
    cdq
    idiv ebx
    mov esi, eax
    test esi, esi
    jg alloc_mem
    
    test edi, edi
    jz exit
iterate_output:
    mov esi, [edi]
    push edi
    mov edi, [edi+4]
    call free   ; call manually here cause edi is effected
    add esp, 4
    movzx eax, expected_output[esi]
    invoke printf, OFFSET output_format, eax
    test edi, edi
    jnz iterate_output
    jmp exit
   
handling_invalid_base:
    invoke printf, OFFSET invalid_base
    jmp exit    
    

exit:
    invoke ExitProcess, 0
    end start
