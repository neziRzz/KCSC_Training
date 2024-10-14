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
    lf db 10, 0
    prompt db "Enter n: ", 0Ah,0
    format db "nth Fibonacci num is:%s", 0
    format_for_special_case db "nth Fibonacci num is:%s", 0
    input_format db "%d", 0
    
.data?
    num1 db 0FFFFh dup (?)        ; Holds Fib(n-2) (change this to increase num capacity)
    num2 db 0FFFFh dup (?)        ; Holds Fib(n-1) (change this to increase num capacity)
    num3 db 0FFFFh dup (?)        ; Holds the current Fibonacci term (Fib(n) 0-9999)
    term_str db 4 dup (?)        ; Input for N
    term_int dd ?                ; Integer value of N
    count dd ?                ; Counter for current Fibonacci iteration


.code

; add 2 large numbers and move the sum to num3
add_nums proc
    push eax
    push ebx
    push ecx
    push edx
    push esi
    push edi
    
    mov esi, eax
    mov edi, ebx
    
    call strlen
    mov edx, eax
    sub edx, 1
    mov eax, ebx
    call strlen
    mov ebx, eax
    sub ebx, 1
    
    xor ax, ax

add_loop:

    add al, byte ptr [esi+edx]
    add al, byte ptr [edi+ebx]
    sub al, '0'
    sub al, '0'

    movzx ax, al
    push ecx
    mov cl, 10
    div cl
    pop ecx
    
    add ah, '0'
    mov byte ptr [ecx], ah
    inc ecx
    dec edx
    dec ebx
    
    cmp edx, 0
    jl one_left1
    
    cmp ebx, 0
    jl one_left2
    
    jmp add_loop
    
one_left1:
    cmp ebx, 0
    jl last_step
one_left1_loop:

    add al, byte ptr [edi+ebx]
    sub al, '0'
    
    movzx ax, al
    push ecx
    mov cl, 10
    div cl
    pop ecx
    
    add ah, '0'
    mov byte ptr [ecx], ah
    inc ecx
    dec ebx
    
    cmp ebx, 0
    jl last_step
    jmp one_left1_loop
    
one_left2:
    cmp edx, 0
    jl last_step
one_left2_loop:

    add al, byte ptr [esi+edx]
    sub al, '0'
    
    movzx ax, al
    push ecx
    mov cl, 10
    div cl
    pop ecx
    
    add ah, '0'
    mov byte ptr [ecx], ah
    inc ecx
    dec edx
    
    cmp edx, 0
    jl last_step
    
    jmp one_left2_loop

last_step:
    cmp al, 0
    je final
    
    add al, '0'
    mov byte ptr [ecx], al
    inc ecx
final:
    mov byte ptr [ecx], 0
    
    pop edi
    pop esi
    pop edx
    pop ecx
    mov eax, ecx
    call reverse
    pop ebx
    pop eax
    
    ret

add_nums endp


; copy string from ebx (src) to eax (dest)
copy proc
    push eax
    push ebx
    push ecx
    push edx
    
    xor edx, edx
    
copy_loop:
    mov cl, byte ptr [ebx+edx]
    mov byte ptr [eax+edx], cl
    
    cmp cl, 0
    je final
    inc edx
    jmp copy_loop
    
final:
    pop edx
    pop ecx
    pop ebx
    pop eax
    
    ret

copy endp


; Convert string to integer (src: git)
atoi proc
    push ebx
    push ecx
    push edx
    push esi
    mov esi, eax
    mov eax, 0
    mov ecx, 0

mul_loop:
    xor ebx, ebx
    mov bl, byte ptr [esi+ecx]
    
    cmp bl, 48
    jl finish

    cmp bl, 57
    jg finish

    sub bl, 48
    mov edx, 10
    mul edx
    add eax, ebx
    inc ecx
    jmp mul_loop
finish:
    pop esi
    pop edx
    pop ecx
    pop ebx
    ret

atoi endp


; Reverse string to get most significant digit first
reverse proc
    push edx
    push ecx
    push ebx
    push eax

    push eax
    mov ebx, eax
    call strlen

    add ebx, eax
    sub ebx, 1
    pop eax

swap_loop:
    mov cl, byte ptr [eax]
    mov dl, byte ptr [ebx]
    mov byte ptr [eax], dl
    mov byte ptr [ebx], cl

    inc eax
    dec ebx
    cmp eax, ebx
    jl swap_loop

    pop eax
    pop ebx
    pop ecx
    pop edx
    ret

reverse endp


; get len of string
strlen proc
    push ebx
    mov ebx, eax

next_char:
    cmp byte ptr [eax], 0
    je finish
    inc eax
    jmp next_char

finish:
    sub eax, ebx
    pop ebx
    ret

strlen endp  


start:

    push offset prompt
    call printf


    push offset term_int
    push offset input_format
    call scanf

    ; initial fib sequence: num1 = "0", num2 = "1"
    mov byte ptr [num1], '0'
    mov byte ptr [num1+1], 0
    mov byte ptr [num2], '1'
    mov byte ptr [num2+1], 0
    
    ; handling base cases
    mov eax, term_int
    mov count, eax
    cmp count, 0
    je print_num1   ; If N == 0, print num1 ("0")

    cmp count, 1
    je print_num2   ; If N == 1, print num2 ("1")

    ; for N >= 2, start Fibonacci calculation
fib_loop:
    ; add num1 and num2, result goes into num3
    mov eax, offset num1
    mov ebx, offset num2
    mov ecx, offset num3
    call add_nums
    
    ; copy num2 to num1
    mov eax, offset num1
    mov ebx, offset num2
    call copy
    
    ; copy num3 to num2
    mov eax, offset num2
    mov ebx, offset num3
    call copy
    
    ; decrement count and check if it's the Nth Fibonacci number
    dec count
    cmp count, 1
    je print_num3   ; If N == count, print num3
    
    jmp fib_loop

print_num1:
    ; Print num1 ("0")
    push offset num1
    push offset format_for_special_case
    call printf
    jmp done

print_num2:
    ; Print num2 ("1")
    push offset num2
    push offset format_for_special_case
    call printf
    jmp done

print_num3:
    ; Print num3 (Nth Fibonacci term)
    push offset num3
    push offset format_for_special_case
    call printf
    jmp done

done:
    ; Exit the program
    push 0
    call ExitProcess

end start
