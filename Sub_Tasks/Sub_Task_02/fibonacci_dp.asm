;Architecture: x86
.386
.model flat, stdcall                                  ; NOTE: This program is in x86, output can't be bigger than 0xFFFFFFFF
option casemap : none
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib

printf proto C 
scanf proto C
malloc proto C
free proto C
.data
    ms1 db "Enter nth Fibonacci number:",0Ah,0
    ms2 db "Ur %uth Fibonacci number is:%u",0Ah,0
    uint_format db "%u",0
    num DWORD ?
.code
clean_up:
    mov edi, [eax+esi*4]
    push eax
    call free
    add esp, 4 
    mov esi, num
    jmp print_num
iterate:
    lea ecx, [edi]
    add eax, [ecx+4]
    lea edi, [ecx+4]
    mov [ecx+8], eax
    mov eax, [edi]
    sub ebx, 1
    jnz iterate
    mov eax, [ebp-0Ch]
    pop ebx
    jmp clean_up
check_if_1:
    cmp esi, 1
    jnz check_if_2
    mov edi, esi
    jmp print_num
check_if_2:
    mov ecx, 4
    lea eax, [esi+1]
    mul ecx
    push eax
    call malloc
    add esp, 4
    mov [ebp-0Ch],eax
    mov dword ptr [eax], 0
    mov dword ptr [eax+4], 1
    cmp esi, 2
    jb clean_up
    push ebx
    mov edi, eax
    lea ebx, [esi-1]
    xor eax, eax
    jmp iterate
start:
    push OFFSET ms1
    call printf
    add esp, 4
    push OFFSET num
    push OFFSET uint_format
    call scanf
    add esp, 8
    mov esi, num
    test esi, esi
    jnz check_if_1
    xor edi, edi
    jmp print_num
print_num:
    push edi
    push esi
    push OFFSET ms2
    call printf
    add esp, 0Ch
    push 0
    call ExitProcess
end start
