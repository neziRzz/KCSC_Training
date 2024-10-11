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

.686 ; for cmovg instruction

printf proto C :VARARG
scanf proto C :VARARG
malloc proto C  :VARARG
free proto C    :VARARG
.data
    ms1 db "Enter your nth Fibonacci number:",0Ah,0
    ms2 db "Your nth Fibonacci number is:%s",0
    ms3 db "Your nth Fibonacci number is:%d",0
    int_format db "%d",0
    nth_term DWORD ?
    temp_nth_term DWORD ?
    temp_var_1 DWORD ?
    temp_var_2 DWORD ?
    temp_var_3 DWORD ?
    temp_var_4 DWORD ?
    temp_var_5 DWORD ?
    mem_block_addr DWORD ?
    mem_block_addr2 DWORD ?
    mem_block_addr3 DWORD ?
    term_counter DWORD ?
    
.code
fib:
    mov eax, ecx
    mov temp_nth_term, eax
    test eax, eax
    jnz cmp_eax_1
    
    invoke printf, "0\n"
    jmp exit 
cmp_eax_1:
    cmp eax, 1
    jnz init_fib
    
    invoke printf, "0\n"
    jmp exit
init_fib:
    invoke malloc, 0F4240h
    mov mem_block_addr, eax
    invoke malloc, 0F4240h
    mov edi, eax
    mov mem_block_addr2, edi
    invoke malloc, 0F4240h
    mov ecx, mem_block_addr
    mov ebx, eax
    mov eax, 30h
    mov mem_block_addr3, ebx
    mov [ecx], ax
    mov eax, 31h
    mov [edi], ax
    mov eax, nth_term
    cmp eax, 2
    jl print_result
    
    dec eax
    mov term_counter, eax
lea_label:
    lea edx, [ecx+1]
get_len:
    
    mov al, [ecx]
    inc ecx
    test al, al
    jnz get_len
    
    mov esi, edi
    sub ecx, edx
    lea edx, [esi+1]
get_len2:
    mov al, [esi]
    inc esi
    test al, al
    jnz get_len2
    
    mov ebx, mem_block_addr2
    sub esi, edx
    mov edx, mem_block_addr
    cmp ecx, esi
    mov eax, esi
    cmovg eax, ecx
    dec ebx
    mov temp_var_1, eax
    dec edx
    xor eax, eax
    xor edi, edi
    add ebx, esi
    mov temp_var_2, eax
    mov temp_var_3, eax
    add edx, ecx
init_temp_var:
    mov temp_var_4, edx
    mov temp_var_5, ebx
    cmp edi, temp_var_1
    jl cmp_edi_ecx
    
    test eax, eax
    jz branch1
cmp_edi_ecx:
    cmp edi,ecx
    jge clear_edx
    
    movsx edx, byte ptr [edx]
    sub edx, 30h
    jmp cmp_edi_esi
clear_edx:
    xor edx, edx
    jmp cmp_edi_esi
    
cmp_edi_esi:
    cmp edi, esi
    jge clear_eax
    
    movsx eax, byte ptr [ebx]    
    sub eax, 30h
    jmp finger_math
clear_eax:
    xor eax, eax
    jmp finger_math
finger_math:
    lea ebx, [eax+edx]
    inc temp_var_3
    add ebx, temp_var_2
    mov eax, 66666667h
    imul ebx
    sar edx, 2
    mov eax, edx
    shr eax, 1Fh
    add eax, edx
    mov dl, al
    mov temp_var_2, eax
    shl al, 2
    add dl, al
    mov eax, mem_block_addr3
    add dl, dl
    sub bl, dl
    mov edx, temp_var_4
    add bl, 30h
    dec edx
    mov [eax+edi], bl
    inc edi
    mov ebx, temp_var_5
    mov eax, temp_var_2
    dec ebx
    jmp init_temp_var
branch1:
    mov ecx, temp_var_3
    xor esi, esi
    mov ebx, mem_block_addr3
    mov eax, ecx
    cdq
    sub eax, edx
    mov edi, eax
    sar edi, 1
    test edi, edi
    jle finger_math2
    
    lea edx, [ebx-1]
    add edx, ecx
iterate:
    mov al, [edx]
    lea edx, [edx-1]
    mov cl, [ebx+esi]
    mov [ebx+esi], al
    inc esi
    mov [edx+1], cl
    cmp esi, edi
    jl iterate
    
    mov ecx, temp_var_3
finger_math2:
    sub term_counter, 1
    mov edi, ebx
    mov eax, mem_block_addr
    mov byte ptr [ecx+ebx], 0
    mov ebx, eax
    mov ecx, mem_block_addr2
    mov mem_block_addr, ecx
    mov mem_block_addr2, edi
    mov mem_block_addr3, ebx
    jnz lea_label
   
print_result:
    push edi
    push OFFSET ms2
    call printf
    add esp, 4
    push mem_block_addr
    call free
    add esp, 4
    push edi
    call free
    add esp,4
    push ebx
    call free
    add esp, 4
    jmp exit  
    
start:
    invoke printf, OFFSET ms1
    invoke scanf, OFFSET int_format, OFFSET nth_term
    cmp nth_term, 1
    jz print_1st_term
    mov ecx, nth_term
    call fib
print_1st_term:
    invoke printf, OFFSET ms3, 1
    jmp exit
exit:
    invoke ExitProcess, 0
end start
