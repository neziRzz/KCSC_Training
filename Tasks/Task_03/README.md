# Anti Debugging
## Definition
- Trong Reverse Engineering, Anti Debug là kĩ thuật dùng để ngăn cản hoặc làm chậm đi việc debug hoặc reverse một chương trình nào đó. Kĩ thuật này cũng như là các kĩ thuật liên quan thường được sử dụng trong các lĩnh vực bảo vệ copyright như là DRM, nhưng cũng được sử dụng bởi Malware nhằm khiến cho chúng khó bị phát hiện hơn. Các kĩ thuật Anti Debug thường sẽ được phân loại như sau

  + API-based: Sử dụng các WINAPI để check debugger
  + Exception-based: Kiểm tra debugger có làm trigger các exception hay không
  + Process and thread blocks: Kiểm tra sự thay đổi trong các process hay thread blocks
  + Modified code: Kiểm tra sự thay đổi trong code (Ví dụ điển hình chính là cách debugger đặt software breakpoint bằng instruction `int 3`)
  + Timing check: Kiểm tra độ chênh lệch thời gian thực thi giữa 2 instructions liên tiếp
## Some Anti Debugging technique
### IsDebuggerPresent()
- Giả sử ta có đoạn code sau
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check() {
	if (IsDebuggerPresent() == TRUE) {
		return TRUE;
	}
	return FALSE;
}
int main() {
	if (debugger_check() == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
- Function `IsDebuggerPresent()` sẽ xác định tiến trình đang chạy có đang bị debug bởi 1 debugger user-mode hay không. Thông thường thì function này sẽ kiểm tra flag `BeingDebugged` trong `PEB`
### CheckRemoteDebuggerPresent()
- Function `kernel32!CheckRemoteDebuggerPresent()` kiểm tra nếu có debugger (được attached trên một process khác nhưng cùng trong cùng một machine) được attached vào process hiện hành
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check() {
	BOOL bDebuggerOrNot;
	if (CheckRemoteDebuggerPresent(GetCurrentProcess(), &bDebuggerOrNot) == TRUE && bDebuggerOrNot == TRUE) {
		return TRUE;
	}
	return FALSE;
}
int main() {
	if (debugger_check() == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
### NtQueryInformationProcess()
- Function `ntdll!NtQueryInformationProcess()` có thể lấy ra một số các thông tin về process hiện hành. Nó nhận 1 parameter là `ProcessInformationClass` và parameter đó sẽ chỉ định thông tin muốn lấy và define output type của `ProcessInformation` parameter
#### ProcessDebugPort
- Ta có thể lấy số port của debugger đang được attached trên process hiện hành bằng cách sử dụng `ntdll!NtQueryInformationProcess()`. Có một class được documented là `ProcessDebugPort`, class này chứa 1 `DWORD` có giá trị là `0xFFFFFFFF` (-1) nếu như process bị debug
```C
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );
int main() {
    HMODULE hNTDLL = LoadLibraryA("ntdll.dll");
    if (hNTDLL) {
        TNtQueryInformationProcess pfnNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess) {
            DWORD dwProcessDebugPort, dwReturned;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugPort,
                &dwProcessDebugPort,
                sizeof(DWORD),
                &dwReturned);
            if (status == 0 && dwProcessDebugPort == -1) {
                printf("Cu't");
                ExitProcess(-1);
            }
        }
    }
    printf("Hello there!");
	return 0;
}
```
#### ProcessDebugFlags
- 1 Struct trong kernel gọi là `EPROCESS`, 1 process object. Chứa field `NoDebugInherit`. Giá trị đảo lại của field này có thể được lấy dựa trên một undocumented class `ProcessDebugFlags`(0x1F). Vậy, nếu như giá trị được return là 0 thì có nghĩa là process bị debug
```C
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );
int main() {
    HMODULE hNTDLL = LoadLibraryA("ntdll.dll");
    if (hNTDLL) {
        TNtQueryInformationProcess pfnNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess) {
            DWORD dwProcessDebugFlags, dwReturned;
            DWORD ProcessDebugFlags = 0x1F;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugFlags,
                &dwProcessDebugFlags,
                sizeof(DWORD),
                &dwReturned);
            if (status == 0 && dwProcessDebugFlags == 0) {
                printf("Cu't");
                ExitProcess(-1);
            }
        }
    }
    printf("Hello there!");
	return 0;
}
```
#### ProcessDebugObjectHandle
- Khi bắt đầu debug, một kernel object gọi là `debug object` được tạo ra. Ta có thể duyệt các giá trị có trong handle này bằng cách sử dụng một undocumented class là `ProcessDebugObjectHandle`
```C
#include <Windows.h>
#include <winternl.h>
#include <stdio.h>
typedef NTSTATUS(NTAPI* TNtQueryInformationProcess)(
    IN HANDLE           ProcessHandle,
    IN PROCESSINFOCLASS ProcessInformationClass,
    OUT PVOID           ProcessInformation,
    IN ULONG            ProcessInformationLength,
    OUT PULONG          ReturnLength
    );
int main() {
    HMODULE hNTDLL = LoadLibraryA("ntdll.dll");
    if (hNTDLL) {
        TNtQueryInformationProcess pfnNtQueryInformationProcess = GetProcAddress(hNTDLL, "NtQueryInformationProcess");
        if (pfnNtQueryInformationProcess) {
            DWORD dwReturned;
            HANDLE hProcessDebugObject = 0;
            DWORD ProcessDebugObjectHandle = 0x1E;
            NTSTATUS status = pfnNtQueryInformationProcess(
                GetCurrentProcess(),
                ProcessDebugObjectHandle,
                &hProcessDebugObject,
                sizeof(DWORD),
                &dwReturned);
            if (status == 0 && hProcessDebugObject != 0) {
                printf("Cu't");
                ExitProcess(-1);
            }
        }
    }
    printf("Hello there!");
    return 0;
}
```
### Heap Protection
- Nếu như flag `HEAP_TAIL_CHECKING_ENABLED` được set trong `NtGlobalFlag`, chuỗi `0xABABABAB` sẽ được append (2 lần nếu là process 32-bit và 4 lần nếu như là process 64-bit) ở cuối heap block được allocate
- Nếu như flag `HEAP_FREE_CHECKING_ENABLED` được set trong `NtGlobalFlag` chuỗi `0xFEEEFEEE` sẽ được append nếu như cần fill thêm bytes vào khoảng trống trong mem cho đến block tiếp theo
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check()
{
    PROCESS_HEAP_ENTRY HeapEntry = { 0 };
    do
    {
        if (!HeapWalk(GetProcessHeap(), &HeapEntry))
            return FALSE;
    } while (HeapEntry.wFlags != PROCESS_HEAP_ENTRY_BUSY);

    PVOID pOverlapped = (PBYTE)HeapEntry.lpData + HeapEntry.cbData;
    return ((DWORD)(*(PDWORD)pOverlapped) == 0xABABABAB);
}
int main() {
	if (debugger_check() == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
### PEB!BeingDebugged Flag
- Cách này giống với việc ta kiểm tra debugger bằng cách kiểm tra `BeingDebugged` flag trong `PEB` thay vì gọi `IsDebuggerPresent` bằng cách sử dụng inline asm
```C
#include <Windows.h>
#include <stdio.h>
int main() {
	__asm {
		mov eax, fs: [30h]
		cmp byte ptr[eax + 2], 0
		jne debugged
	}
	printf("Hello there!");
	ExitProcess(0);
debugged:
	printf("Cu't");
	return -1;
}
```
### NtGlobalFlag
- Trường `NtGlobalFlag` trong `PEB` (có offset 0x68 trong 32-bit và 0xBC trong 64-bit) mặc định là 0. Attach debugger sẽ không làm thay đổi giá trị của `NtGlobalFlag` nhưng process mà được **TẠO RA BỞI DEBUGGER** thì các flag sau sẽ được set
	+ `FLG_HEAP_ENABLE_TAIL_CHECK ` (0x10)
	+ `FLG_HEAP_ENABLE_FREE_CHECK ` (0x20)
 	+ `FLG_HEAP_VALIDATE_PARAMETERS ` (0x40)
- Debugger sẽ được check bằng việc lấy sum của các flag trên  
```C
#include <Windows.h>
#include <stdio.h>
int main() {
	__asm {
		mov eax, fs: [30h]
		mov al, [eax + 68h]
		and al, 70h
		cmp al, 70h
		jz debugged
	}
	printf("Hello there!");
	ExitProcess(0);
debugged:
	printf("Cu't");
	return -1;
}
```
