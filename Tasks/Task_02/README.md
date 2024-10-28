# Shellcode Fundamentals
## Definition and How to write/execute Shellcode
- Trong security context, `Shellcode` là một đoạn code thực thi nhỏ (được viết bằng mã máy `Assembly`) được dùng làm payload để khai thác lỗ hổng trong các phần mềm. Lí do cho việc nó có tên là `Shellcode` là bởi thông thường nó được dùng để khởi tạo các `Command SHELL` để các attacker có thể điểu khiển được thiết bị dính shell, tuy vậy bất kì các đoạn code nhỏ nào có thể thực hiện được tính năng tương tự thì cũng được gọi là `Shellcode `, giả sử ta có một đoạn code C như sau
```C

#include <stdio.h>
int main() {
	char thing[20];
	printf("Enter your thing:");
	scanf("%s", &thing);
	printf("Your thing is:%s", thing);
	return 0;
}
```
- Đoạn code này đơn thuần chỉ nhận input của user rồi in ra output tùy theo input của người dùng, bởi bản chất của `Shellcode` chỉ là đoạn code được viết bằng `Assembly`, ta có thể dễ dàng mô phỏng lại dạng `Shellcode` của chương trình này bằng cách sử dụng các trình disassembler như IDA, Ghidra, radare2, ... Bên dưới là đoạn code `Assembly` của chương trình 

![1](https://github.com/user-attachments/assets/51ea7fb7-38ae-4afc-ba99-8ae5ea55d44f)

- Phần mà mình đã đóng khung đỏ trong hình chính là các opcodes mà chúng ta có thể dùng để tạo ra `Shellcode`, nếu các bạn chưa rõ `Opcodes` là gì thì có thể tham khảo thêm tại [Đây](https://en.wikipedia.org/wiki/Opcode), dựa vào các `Opcodes` ở trên, ta có thể viết ra được `Shellcode` như sau

```
unsigned char shellcode = [0x48 ,0x83 ,0xEC ,0x48,....,0xC3]
```
- Qua đó ta có thể thấy rằng, để tạo ra shellcode, ta đơn giản chỉ cần code ra một chương trình bằng một ngôn ngữ tùy chọn (ưu tiên là C hoặc asm vì chúng gần với mã máy nhất) và sau đó decompile chúng trong một trình disassembler như IDA,... và lấy ra các bytecode của chương trình. Bên dưới mình sẽ ví dụ một chương trình chạy shellcode và các bước để chạy shellcode trong một chương trình
```C
#include <Windows.h>
#include <stdio.h>
int main(){
unsigned char shellcode = [fill shellcode here];
    char* alloc_mem = VirtualAlloc(NULL, sizeof(MsgBox_shellcode), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
    for (int i = 0; i < sizeof(MsgBox_shellcode); i++) {
        alloc_mem[i] = MsgBox_shellcode[i];

    }
    ((void(*)())alloc_mem)();
    VirtualFree(alloc_mem, sizeof(MsgBox_shellcode), MEM_RELEASE);
}
```
- Ta có thể thấy rằng, để viết một chương trình chạy shellcode thường sẽ có các bước như sau
  + B1: Khởi tạo 1 vùng nhớ có thể đọc, ghi và thực thi cho shellcode bằng `VirtualAlloc`
  + B2: Copy các bytecodes trong array shellcode vào vùng nhớ vừa được cấp phát
  + B3: Tiến hành gắn cho vùng nhớ trên con trỏ hàm để gọi hàm và sau khi hàm thực thi xong thì giải phóng vùng nhớ với `VirtualFree`
## Encountered problems and solutions
- Khi sử dụng shellcode để thực thi chương trình, một trong những vấn đề tiêu biểu nhất mà ta sẽ gặp phải là làm thế nào để resolve các external functions. Để giải quyết được điều này, ta có thể sử dụng kĩ thuật `PEB Traversal`
### PEB Traversal
#### What is PEB?
- Khi mà một process chạy, hệ điều hành (Windows) sẽ cấp phát một Process Enviroment Block (PEB) struct cho process đó. PEB được tạo bởi kernel và nó chứa các vùng chứa những thông tin như các modules được load cùng với process, các parameters, các biến môi trường,... bên dưới là các thành phần trong PEB được tham khảo tại [đây](https://learn.microsoft.com/en-us/windows/win32/api/winternl/ns-winternl-peb)
```C
typedef struct _PEB {
  BYTE                          Reserved1[2];
  BYTE                          BeingDebugged;
  BYTE                          Reserved2[1];
  PVOID                         Reserved3[2];
  PPEB_LDR_DATA                 Ldr;
  PRTL_USER_PROCESS_PARAMETERS  ProcessParameters;
  PVOID                         Reserved4[3];
  PVOID                         AtlThunkSListPtr;
  PVOID                         Reserved5;
  ULONG                         Reserved6;
  PVOID                         Reserved7;
  ULONG                         Reserved8;
  ULONG                         AtlThunkSListPtr32;
  PVOID                         Reserved9[45];
  BYTE                          Reserved10[96];
  PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
  BYTE                          Reserved11[128];
  PVOID                         Reserved12[1];
  ULONG                         SessionId;
} PEB, *PPEB;
``` 
- Trong các thành phần của struct trên, thành phần mà ta cần quan tâm cho kĩ thuật kể trên là `Ldr`, thành phần này chứa con trỏ tới struct `PEB_LDR_DATA`, struct này chứa thông tin về các modules được load cùng với process (EXEs/DLLs), bao gồm cả một double-linked list (danh sách liên kết đôi) `InMemoryOrderModuleList` , linked list này có nhiệm vụ tìm các địa chỉ của các DLLs được load cùng với process đang chạy
```C
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
```
- Trong struct trên, một process sẽ dùng `InMemoryOrderModuleList` để enumerate các modules được load. Linked list này chứa các entries cho mỗi module, được mô tả bởi struct `LDR_DATA_TABLE_ENTRY`, struct này cung cấp các thông tin chi tiết của từng module.
```C
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase; 
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
    PVOID      LoadedImports;
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
```
#### Accessing PEB
- Vậy làm thế nào để ta truy cập vào PEB? 1 trong nhiều cách sẽ là bằng cách sử dụng inlie assembly
```C
#include <stdio.h>
#include <Windows.h>

int main() {
    PVOID peb;

    __asm {
        mov eax, fs:[0x30]
        mov peb, eax
    }

    printf("PEB Address: %p\n", peb);
    return 0;
}
```
- Giả sử như trong đoạn code trên sử dụng keyword `__asm` để insert asm instruction trực tiếp. PEB được truy cập thông qua segment register `fs`. `fs` là một segment register được sử dụng trong x32 architecture và nó trỏ tới TEB, trong trường hợp này, `fs:[0x30]` là offset trong TEB chứa con trỏ tới PEB (LƯU Ý : Nếu các bạn có ý định sử dụng inline x64 thì sẽ không khả thi bởi trình compiler C không hỗ trợ. Nên để truy cập PEB trong x64 sẽ phải code bằng asm và sử dụng segment register `gs` với offset là `0x60`)
#### Walking through PEB structure

- Bởi PEB chứa thông tin về các modules được load vào process (`kernel32.dll` và `ntdll.dll`) và được map vào trong process space nên ta có thể sử dụng chúng để resolve dynamically function có trong các DLL đó. Bằng cách này, các chương trình sử dụng kĩ thuật này có thể extract các base addresses của những DLLs (kể trên) và resolve các functions thuộc các DLLs này.

- Ví dụ, `kernel32.dll` chứa 2 functions quan trọng có thể giúp chúng ta resolve các DLLs và functions
  + `LoadLibraryA(libname)`: Dùng để load DLLs được chỉ định vào process
  + `GetProcAddress(hmodule, functionname)`: Dùng để lấy địa chỉ của exported functions hoặc variables trong DLLs được chỉ định bởi `LoadLibraryA`

- Vậy để áp dụng những điều trên để viết ra một chương trình sử dụng kĩ thuật trên để gọi ra `MessageBox`, ta sẽ walk through PEB, để resolve ra `kernel32.dll` và 2 functions `LoadLibraryA` + `GetProcAddress`, và rồi gọi `MessageBox`, bên dưới là các bước cụ thể và source code 
  + B1: Tìm ra và truy cập vào PEB của process hiện hành
  + B2: Truy cập đến struct `PEB_LDR_DATA` bằng thành phần `Ldr` của PEB 
  + B3: Duyệt `InLoadOrderModuleList` tìm `LDR_DATA_TABLE_ENTRY` - > `kernel32.dll` 
  + B4: Khi tìm được entry của `kernel32.dll`, lấy base address của nó
  + B5: Duyệt export table của `kernel32.dll` để resolve địa chỉ cho 2 function `LoadLibraryA` và `GetProcAddress`
  + B6: Load `user32.dll` dùng `LoadLibraryA`
  + B7: Lấy địa chỉ của `MessageBoxA` từ `user32.dll` dùng `GetProcAddress`
  + B8: In message ra màn hình bằng `MessageBoxA`

```C
#include <stdio.h>
#include <windows.h>

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID      DllBase;
    PVOID      EntryPoint;
    ULONG      SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
    ULONG      Flags;
    USHORT     LoadCount;
    USHORT     TlsIndex;
    LIST_ENTRY HashLinks;
    PVOID      SectionPointer;
    ULONG      CheckSum;
    ULONG      TimeDateStamp;
    PVOID      LoadedImports;
    PVOID      EntryPointActivationContext;
    PVOID      PatchInformation;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    BOOLEAN Initialized;
    HANDLE SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, * PPEB_LDR_DATA;

typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    BOOLEAN SpareBool;
    HANDLE Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, * PPEB;

typedef FARPROC(WINAPI* GETPROCADDRESS)(HMODULE, LPCSTR);
typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);
typedef int (WINAPI* MESSAGEBOXA)(HWND, LPCSTR, LPCSTR, UINT);

PVOID GetProcAddressKernel32(HMODULE hModule, LPCSTR lpProcName) {
    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)hModule;
    PIMAGE_NT_HEADERS pNTHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDOSHeader->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + pNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* pAddressOfFunctions = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfFunctions);
    DWORD* pAddressOfNames = (DWORD*)((BYTE*)hModule + pExportDirectory->AddressOfNames);
    WORD* pAddressOfNameOrdinals = (WORD*)((BYTE*)hModule + pExportDirectory->AddressOfNameOrdinals);

    for (DWORD i = 0; i < pExportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)((BYTE*)hModule + pAddressOfNames[i]);
        if (strcmp(functionName, lpProcName) == 0) {
            return (PVOID)((BYTE*)hModule + pAddressOfFunctions[pAddressOfNameOrdinals[i]]);
        }
    }
    return NULL;
}

int main() {
    PEB* peb;
    PLDR_DATA_TABLE_ENTRY module;
    LIST_ENTRY* listEntry;
    HMODULE kernel32baseAddr = NULL;
    GETPROCADDRESS ptrGetProcAddress = NULL;
    LOADLIBRARYA ptrLoadLibraryA = NULL;
    MESSAGEBOXA ptrMessageBoxA = NULL;

    __asm {
        mov eax, fs: [0x30]
        mov peb, eax
    }

    listEntry = peb->Ldr->InLoadOrderModuleList.Flink;
    do {
        module = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        char baseDllName[256];
        int i;
        for (i = 0; i < module->BaseDllName.Length / sizeof(WCHAR) && i < sizeof(baseDllName) - 1; i++) {
            baseDllName[i] = (char)module->BaseDllName.Buffer[i];
        }
        baseDllName[i] = '\0';

        if (_stricmp(baseDllName, "kernel32.dll") == 0) {
            kernel32baseAddr = (HMODULE)module->DllBase;
        }

        listEntry = listEntry->Flink;
    } while (listEntry != &peb->Ldr->InLoadOrderModuleList);

    if (kernel32baseAddr) {
        ptrGetProcAddress = (GETPROCADDRESS)GetProcAddressKernel32(kernel32baseAddr, "GetProcAddress");
        ptrLoadLibraryA = (LOADLIBRARYA)GetProcAddressKernel32(kernel32baseAddr, "LoadLibraryA");
        HMODULE user32Base = ptrLoadLibraryA("user32.dll");
        ptrMessageBoxA = (MESSAGEBOXA)ptrGetProcAddress(user32Base, "MessageBoxA");
        ptrMessageBoxA(NULL, "Yo PEB is cool ngl", "Hello",MB_OK);
    }
    return 0;
}
```
