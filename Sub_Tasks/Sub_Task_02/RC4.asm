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

.data
    
    string_format db "%s",0
    promptKey       db "Enter key(no_spaces_allowed): ", 0
    promptPlaintext db 0Ah,"Enter plaintext(no_spaces_allowed): ", 0
    encryptedPrompt db "Encrypted Data: ", 0
    cypher_format db "%02X ",0
    key byte 256 dup(0)
    plaintext byte 256 dup(0)
    key_len DWORD ?
    plaintext_len DWORD ?
    s_box byte 256 dup(0)
    t_box byte 256 dup(0)
    
.code
start:
    invoke printf, OFFSET promptKey
    invoke scanf, OFFSET string_format, OFFSET key
    invoke printf, OFFSET promptPlaintext
    invoke scanf, OFFSET string_format, OFFSET plaintext
    invoke lstrlen, OFFSET plaintext
    mov plaintext_len, eax
    invoke lstrlen, OFFSET key
    mov key_len, eax
    xor eax, eax
    mov edi, key_len
    mov esi, plaintext_len
    
    xor ebx, ebx
    xor ecx, ecx
init_tbox_sbox:    
    mov eax, ecx
    mov [s_box+ecx], cl
    cdq
    idiv edi
    mov al, [key+edx]
    mov [t_box+ecx], al
    inc ecx
    cmp ecx, 100h
    jnz init_tbox_sbox
    
    xor edi, edi
KSA: ;init KSA
    mov dl, [edi+s_box]
    movzx eax, [edi+t_box]
    add ebx, eax
    movzx ecx, dl
    add ebx, ecx
    and ebx, 800000FFh
    jns swap
    
    dec ebx
    or ebx, 0FFFFFF00h
    inc ebx
swap:
    mov al, [ebx+s_box]
    mov [ebx+s_box], dl
    mov [edi+s_box], al
    inc edi
    cmp edi, 100h
    jl KSA
    
    xor edi, edi
    xor edx, edx
    test esi, esi
    jle print_cyphertext
    
    xor ebx, ebx
smthin: ;indices_handling
    inc ebx
    and ebx, 800000FFh
    jns next_label
    
    dec ebx
    or ebx, 0FFFFFF00h
    inc ebx
next_label: ;indices_handling   
    mov cl, [ebx+s_box]
    movzx eax, cl
    add edi, eax
    and edi, 800000FFh
    jns encrypt_routine 
    
    dec edi
    or  edi, 0FFFFFF00h
    inc edi
    
encrypt_routine: ; PRNG
    mov al, [edi+s_box]
    mov [edi+s_box], cl
    mov [ebx+s_box], al
    movzx ecx, [edi+s_box]
    movzx eax, al
    add ecx, eax
    movzx eax, cl
    movzx eax, [eax+s_box]
    xor al, [edx+plaintext]
    mov [edx+t_box], al
    inc edx
    cmp edx, esi
    jl  smthin
    
print_cyphertext:
    invoke printf, OFFSET encryptedPrompt
    xor edi, edi

iterate_cyphertext:
    movzx eax, [edi+t_box]
    invoke printf, OFFSET cypher_format, eax
    inc edi
    cmp edi, esi
    jl iterate_cyphertext
    jmp exit
exit:
    invoke ExitProcess, 0
    end start
