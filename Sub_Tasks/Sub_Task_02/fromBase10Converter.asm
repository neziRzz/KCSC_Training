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
    stack_underflowPrompt db 0Ah,"Stack underflow!",0Ah,0
    output_format db "%c",0
    base10_num DWORD ?
    desired_base DWORD ?
.code
base_conversion proc; esi = base number, ebx = desired base
    push ecx
    mov esi, base10_num
    mov edi, desired_base
    xor ecx, ecx
    mov [ebp-4], ecx
    test esi, esi
    jnz if_less

if_less:
    jle return
base_convert: ; divide until base10 num reaches 0, remainders pushed into stack  
    mov eax, esi
    lea ecx, [ebp-4]
    cdq
    idiv edi
    mov esi, eax ; save result for next division
    call push_
    test esi, esi
    jg base_convert
    
    mov ecx, [ebp-4]
pop_and_print: ; 
    lea ecx, [ebp-4]
    call pop_
    movsx eax, expected_output[eax] ; remainders range from 0-15 (0-F)
    invoke printf, OFFSET output_format, eax
    mov ecx, [ebp-4]
    test ecx, ecx
    jnz pop_and_print
return:
    pop ecx ; restore initial registers state
    ret   
base_conversion endp 

push_ proc ; push to stack
    push eax
    push ebx
    push esi
    push edi
    
    mov ebx, edx ; remainder
    mov edi, ecx
    invoke malloc, 8 ;(x86: 4 byte data, 4 address, for x64 malloc twice the initial value)
    mov esi, eax
    test esi, esi
    jnz push_to_stack
    
    invoke printf, OFFSET stack_overflowPrompt
    pop edi ; restore initial registers state
    pop esi
    pop ebx
    pop eax
    ret
push_to_stack:
    mov eax, [edi]
    mov [edi], esi
    pop edi
    mov [esi], ebx
    mov [esi+4], eax
    pop esi ; restore initial registers state
    pop ebx
    pop eax
    ret
push_ endp

pop_ proc ; pop from stack
    mov edx, ecx
    mov eax, [edx]
    test eax, eax
    jnz pop_from_stack
    
    invoke printf, OFFSET stack_underflowPrompt
    ret
pop_from_stack:
    mov ecx, [eax+4]
    push esi
    mov esi, [eax]
    push eax
    mov [edx], ecx
    call free
    add esp, 4
    mov eax, esi
    pop esi
    ret
pop_ endp
    
start:
    invoke printf, OFFSET base10Prompt
    invoke scanf, OFFSET int_format, OFFSET base10_num
    invoke printf, OFFSET other_basePrompt
    invoke scanf, OFFSET int_format, OFFSET desired_base
    mov ecx, desired_base
    lea eax, [ecx-2] 
    cmp eax, 0Eh ; check whether base outside of range
    ja handling_invalid_base
    invoke printf, OFFSET result, desired_base
    call base_conversion   
exit:
    invoke ExitProcess, 0
handling_invalid_base: ; for handling non base10 and conversion outside of base (2-16)
    invoke printf, OFFSET invalid_base
    jmp exit    
end start
