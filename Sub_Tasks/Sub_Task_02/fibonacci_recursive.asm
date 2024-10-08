; Architecture: x86
.386                                                ; NOTE: Since this is recursion-based, this may take a very long time to execute with 
.model flat, stdcall                                ; large n, also this program can only handle 32-bits integers as output, any bigger 
option casemap : none                               ; than that will cause overflow
include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
includelib \masm32\lib\kernel32.lib
include \masm32\include\user32.inc
includelib \masm32\lib\user32.lib
includelib \masm32\lib\msvcrt.lib

printf proto C 
scanf proto C
.data
    ms1 db "Enter nth Fibonacci number:",0Ah,0
    ms2 db "Ur nth Fibonacci number is:%d",0Ah,0
    int_format db "%d",0
    num DWORD ?
.code
fib proc
    push edi
    mov edi, ecx
    cmp edi, 2
    jge recur

    mov eax, edi
    pop edi
    ret
recur:
    push esi
    lea ecx, [edi-2]
    call fib 

    lea ecx, [edi-1]
    mov esi, eax
    call fib

    add eax, esi
    pop esi
    pop edi
    ret
fib endp
start:
    push OFFSET ms1
    call printf
    add esp, 4
    push OFFSET num
    push OFFSET int_format
    call scanf

    add esp, 8
    mov esi, num
    cmp esi, 2
    jl final    
    lea ecx, [esi-2]
    call fib

    lea ecx, [esi-1]
    mov edx, eax
    call fib
    lea esi, [eax+edx]
final:
    push esi
    push OFFSET ms2
    call printf

    add esp, 8
    push 0
    call ExitProcess
end start
