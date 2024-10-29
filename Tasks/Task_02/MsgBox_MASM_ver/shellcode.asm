.386
.model flat, stdcall
option casemap : none

.code
start:

get_kernel32:

    xor ecx, ecx
    mul ecx
    ASSUME FS:NOTHING
    mov eax, fs:[ecx+30h]
    ASSUME FS:ERROR
    mov eax, [eax + 0Ch]
    mov esi, [eax + 014h]
    lodsd
    xchg esi, eax
    lodsd
    mov ebx, [eax + 010h]

get_address_based_on_name:
    mov edx, [ebx+ 03Ch]
    add edx, ebx
    mov edx, [edx + 078h]
    add edx, ebx
    mov esi, [edx + 020h]
    add esi, ebx
    xor ecx, ecx

get_procAddr:
    inc ecx
    lodsd
    add eax, ebx
    cmp DWORD PTR [eax], 050746547h
    jnz get_procAddr
    cmp DWORD PTR [eax+4], 041636F72h
    jnz get_procAddr
    cmp DWORD PTR [eax+8], 065726464h
    jnz get_procAddr

get_procAddrFunc:
    mov esi, [edx+024h]
    add esi, ebx
    mov cx, [esi + ecx*2]
    dec ecx
    mov esi, [edx + 01Ch]
    add esi, ebx
    mov edx, [esi + ecx*4]
    add edx, ebx
    mov ebp, edx

get_LoadLibA:
    xor ecx, ecx
    push ecx
    push 041797261h
    push 07262694Ch
    push 064616F4Ch
    push esp
    push ebx
    call edx

get_User32:
    push 061616C6Ch
    sub  word ptr [esp+2], 06161h
    push 0642E3233h
    push 072657355h
    push esp
    call eax    

get_MsgBox:
    push 6141786Fh
    sub word ptr [esp+03h], 061h
    push 042656761h
    push 07373654Dh
    push esp
    push eax
    call ebp

init_MsgBoxA:
    add esp, 010h
    xor edx, edx
    xor ecx, ecx
    
    push edx
    push "DDDX"
    mov edi, esp
    push edx
    push "ugn"
    mov ecx, esp
    push edx
    push edi
    push ecx
    push edx
    call eax
exit:
    add esp, 010h
    push 061737365h
    sub word ptr [esp+3], 061h
    push 636F7250h
    push 74697845h
    push esp
    push ebx
    call ebp
    xor ecx, ecx
    push ecx
    call eax

end start
