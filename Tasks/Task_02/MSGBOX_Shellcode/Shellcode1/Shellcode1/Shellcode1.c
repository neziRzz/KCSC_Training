#include <windows.h>
#include <stdio.h>

unsigned char MsgBox_shellcode[] =
"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00\x00\x41"
"\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65\x48\x8b\x52\x60"
"\x3e\x48\x8b\x52\x18\x3e\x48\x8b\x52\x20\x3e\x48\x8b\x72"
"\x50\x3e\x48\x0f\xb7\x4a\x4a\x4d\x31\xc9\x48\x31\xc0\xac"
"\x3c\x61\x7c\x02\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2"
"\xed\x52\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74\x6f"
"\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44\x8b\x40\x20\x49"
"\x01\xd0\xe3\x5c\x48\xff\xc9\x3e\x41\x8b\x34\x88\x48\x01"
"\xd6\x4d\x31\xc9\x48\x31\xc0\xac\x41\xc1\xc9\x0d\x41\x01"
"\xc1\x38\xe0\x75\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1"
"\x75\xd6\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e\x41\x8b"
"\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e\x59\x5a\x41\x58"
"\x41\x59\x41\x5a\x48\x83\xec\x20\x41\x52\xff\xe0\x58\x41"
"\x59\x5a\x3e\x48\x8b\x12\xe9\x49\xff\xff\xff\x5d\x3e\x48"
"\x8d\x8d\x71\x01\x00\x00\x41\xba\x4c\x77\x26\x07\xff\xd5"
"\x49\xc7\xc1\x00\x00\x00\x00\x3e\x48\x8d\x95\x0e\x01\x00"
"\x00\x3e\x4c\x8d\x85\x50\x01\x00\x00\x48\x31\xc9\x41\xba"
"\x45\x83\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
"\x56\xff\xd5\x53\x68\x65\x6c\x6c\x63\x6f\x64\x69\x6e\x67"
"\x20\x69\x73\x20\x6e\x6f\x74\x20\x74\x68\x61\x74\x20\x68"
"\x61\x72\x64\x20\x61\x6d\x20\x69\x20\x72\x69\x67\x68\x74"
"\x3f\x20\x46\x72\x6f\x6d\x20\x6e\x65\x7a\x69\x52\x7a\x20"
"\x77\x69\x74\x68\x20\x6c\x6f\x76\x65\x20\x3c\x33\x00\x31"
"\x76\x31\x20\x6d\x65\x20\x74\x6f\x70\x20\x6c\x61\x6e\x65"
"\x20\x69\x66\x20\x75\x20\x63\x61\x6e\x20\x3a\x73\x6d\x69"
"\x72\x6b\x3a\x00\x75\x73\x65\x72\x33\x32\x2e\x64\x6c\x6c"
"\x00";




int main() {
    
    printf("Have you ever heard about calling MsgBox using shellcode?");
    char* alloc_mem = VirtualAlloc(NULL, sizeof(MsgBox_shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    for (int i = 0; i < sizeof(MsgBox_shellcode); i++) {
        alloc_mem[i] = MsgBox_shellcode[i];

    }
    ((void(*)())alloc_mem)();
    VirtualFree(alloc_mem, sizeof(MsgBox_shellcode), MEM_RELEASE);

    return 0;
}