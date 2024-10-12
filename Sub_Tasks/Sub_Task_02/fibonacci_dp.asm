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

.686 ; for cmovg instruction

printf proto C, :VARARG
scanf proto C, :VARARG
malloc proto C  :VARARG
free proto C    :VARARG
.data
    ms1 db "Enter your nth Fibonacci number:",0Ah,0
    ms2 db "Your nth Fibonacci number is:%s",0
    
    int_format db "%d",0
    nth_term DWORD ?
    temp_nth_term DWORD ?
    temp_var_1 DWORD ?
    temp_var_2 DWORD ?
    temp_var_3 DWORD ?
    temp_var_4 DWORD ?
    temp_var_5 DWORD ?
    mem_block_addr DWORD ?
    temp_var_6 DWORD ?
    temp_var_7 DWORD ?
    term_counter DWORD ?
    
.code
add_2_big_num proc
    push ebx
    mov eax, ecx
    mov temp_var_5, edx
    push esi
    mov esi, eax
    mov temp_var_6, eax
    push edi
    lea ecx, [esi+1]
get_len3:
    mov al, [esi]
    inc esi
    test al, al
    jnz get_len3
    
    mov edi, edx
    sub esi, ecx
    lea ecx, [edi+1]
get_len4:
    mov al, [edi]
    inc edi
    test al, al
    jnz get_len4

    sub edi, ecx
    cmp esi, edi
    mov eax, edi
    cmovg eax, esi
    mov temp_var_2, eax
    add eax, 2
    invoke malloc, eax
    mov ecx, temp_var_5
    dec ecx
    mov temp_var_4, eax
    add ecx, edi
    xor edx, edx
    mov temp_var_5, ecx
    xor ebx, ebx
    mov ecx, temp_var_6
    xor eax, eax
    dec ecx
    add ecx, esi
    mov temp_var_6, ecx
    mov ecx, temp_var_4
label1:
    mov temp_var_3, eax
    mov temp_var_7, ebx
    cmp eax, temp_var_2
    jl cmp_eax_esi
    
    test edx, edx
    jz label2
    
    cmp eax, esi
    jge clear_ecx
label2:
    mov eax, ebx
    xor esi, esi
    cdq
    sub eax, edx
    mov edi, eax
    sar edi, 1
    test edi, edi
    jle return1
    
    mov ebx, temp_var_4
    lea edx, [ebx-1]
    add edx, temp_var_7
    jmp iterate
return1:
    pop edi
    pop esi
    mov byte ptr [ebx+ecx], 0
    mov eax, ecx
    pop ebx
    ret
iterate:
    mov al, [edx]
    lea edx, [edx-1]
    mov cl, [ebx+esi]
    mov [ebx+esi], al
    inc esi
    mov [edx+1], cl
    cmp esi, edi
    jl iterate

    mov eax, temp_var_7
    pop edi
    pop esi
    mov byte ptr [eax+ebx], 0
    mov eax, ebx
    pop ebx
    ret
    
cmp_eax_esi:
    cmp eax, esi
    jge clear_ecx
    
    mov ecx, temp_var_6
    movsx ecx, byte ptr [ecx]
    sub ecx, 30h
    jmp cmp_eax_edi
    
clear_ecx:
    xor ecx, ecx
    jmp cmp_eax_edi
cmp_eax_edi:
    cmp eax, edi
    jge clear_eax
    
    mov eax, temp_var_5
    movsx eax, byte ptr [eax]
    sub eax, 30h 
    jmp finger_math
clear_eax:
    xor eax, eax
    jmp finger_math
finger_math:
    lea ebx, [eax+ecx]
    dec temp_var_6
    add ebx, edx
    mov eax, 66666667h
    imul ebx
    sar edx, 2
    mov ecx, edx
    shr ecx, 1Fh
    add ecx, edx
    mov al, cl
    mov temp_var_1, ecx
    mov edx, temp_var_1
    shl al, 2
    add cl, al
    mov eax, temp_var_3
    add cl, cl
    sub bl, cl
    mov ecx, temp_var_4
    add bl, 30h 
    mov [eax+ecx], bl
    inc eax
    mov ebx, temp_var_7
    inc ebx
    dec temp_var_5
    jmp label1

add_2_big_num endp
fib proc
    push esi
    mov esi, ecx
    test esi, esi
    jnz cmp_term_to_1

    invoke malloc, 2
    mov ecx, 30h
    mov [eax], cx
    pop esi
    ret
cmp_term_to_1:
    cmp esi, 1
    jnz init_fib
    
    invoke malloc, 2
    mov ecx, 31h 
    mov [eax], cx
    pop esi
    ret
init_fib:
    invoke malloc, 0FFFFFh
    mov ebx, eax    
    invoke malloc, 0FFFFFh 
    mov edi, eax
    invoke malloc, 0FFFFFh
    mov mem_block_addr, eax
    mov eax, 30h
    mov [ebx], ax
    mov eax, 31h ; '1'
    mov [edi], ax
    cmp esi, 2
    jl if_term_is_2
    
    dec esi
    mov temp_nth_term, esi
fib_loop:
    mov edx, edi
    mov ecx, ebx
    call add_2_big_num
    push ebx             
    mov  esi, eax
    call free
    add  esp, 4
    mov  ebx, edi
    sub  temp_nth_term, 1
    mov  edi, esi
    jnz  fib_loop
if_term_is_2:
    mov ecx, edi
    lea edx, [ecx+1]
get_len:
    mov al, [ecx]
    inc ecx
    test al, al
    jnz get_len
    
    sub ecx, edx
    lea eax, [ecx+1]
    invoke malloc, eax
    mov esi, eax
    mov temp_nth_term, eax
    mov edx, edi
    sub esi, edi
get_len2:
    mov  cl, [edx]
    lea  edx, [edx+1]
    mov  [edx+esi-1], cl
    test cl, cl
    jnz get_len2            
    invoke free, ebx            
    invoke free, edi
    invoke free, mem_block_addr
    mov eax, temp_nth_term
    pop esi
    ret
fib endp   
start:
    invoke printf, OFFSET ms1
    invoke scanf, OFFSET int_format, OFFSET nth_term
    mov ecx, nth_term
    call fib
    mov esi, eax
    invoke printf, OFFSET ms2, esi
exit:
    invoke ExitProcess, 0
end start
