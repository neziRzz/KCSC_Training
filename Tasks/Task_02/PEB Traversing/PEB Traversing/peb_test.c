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