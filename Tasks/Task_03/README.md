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
- Chạy đoạn code trên khi không có debugger, ta có kết quả như sau

![image](https://github.com/user-attachments/assets/45d98b30-61c7-4ec9-a867-668fa7105ef9)

- Và ngược lại khi có debugger

![image](https://github.com/user-attachments/assets/072f3251-47f7-4a7c-be8f-aa57aaa07341)



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
- Ta có thể thấy rằng nếu chạy tiến trình bằng debugger, giá trị của `dwProcessDebugPort` sau khi gọi `NtQueryInformationProcess` sẽ là `0xFFFFFFFF` (-1)

![image](https://github.com/user-attachments/assets/709448f1-0ef5-41be-ac9a-2f8fcf454f3c)

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
- Như bên dưới ta có thể thấy, chuỗi `0xABABABAB` sẽ được append 2 lần (64-bit) nếu như process có attached debugger

![image](https://github.com/user-attachments/assets/0769afcc-addd-4d72-b8b5-089c5bb465c2)

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
### Timing Check
- Khi mà một process bị trace bởi debugger, sẽ có một khoảng chênh lệch thời gian lớn giữa các instructions. Độ chênh lệch này có thể được so sánh với sự chênh lệch thực tế bằng một số các method dưới đây. Cách thức hoạt động của các method này là tương đồng nhau, chỉ khác ở việc sử dụng các instruction hay các hàm
#### RDTSC
- Để sử dụng instruction này, flag `PCE` phải set trong `CR4` register, đồng thời đây là 1 instruction user-mode
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check(DWORD64 qwNativeElapsed)
{
    ULARGE_INTEGER Start, End;
    __asm
    {
        xor ecx, ecx
        rdtsc
        mov  Start.LowPart, eax
        mov  Start.HighPart, edx
    }
    // things to do here
    __asm
    {
        xor ecx, ecx
        rdtsc
        mov  End.LowPart, eax
        mov  End.HighPart, edx
    }
    return (End.QuadPart - Start.QuadPart) > qwNativeElapsed;
}
int main() {
	if (debugger_check(0xFF) == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
- Khi ta gọi `rdtsc`, instruction trên sẽ lấy time hiện tại (số giây đã trôi qua tính từ UNIX Epoch) và lưu phần high vào `edx`, phần low vào `eax` giả sử khi ta thực hiện gọi instruction này và giá trị trả về là như sau

![image](https://github.com/user-attachments/assets/d1050dee-fb8b-480e-b89b-d6c501b9d36e)

- TimeStart = 0x87655569ABEC

![image](https://github.com/user-attachments/assets/950aafca-a569-4807-a818-a1487ca4f61b)

- TimeEnd = 0x8772B3A3C317

- Và khi lấy 2 giá trị trên trừ đi cho nhau để tìm ra độ chênh lệch thì kết quả sẽ lớn hơn 0xFF, bởi thời gian để CPU thực hiện các câu lệnh là rất nhanh nên khi độ chênh lệch thời gian lớn như này thì chắc chắn có sự hiện diện của debugger
#### GetLocalTime()
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetLocalTime(&stStart);
    // things to do here
    GetLocalTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return FALSE;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return FALSE;

    uiStart.LowPart = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
int main() {
	if (debugger_check(0xFF) == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
#### GetSystemTime()
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check(DWORD64 qwNativeElapsed)
{
    SYSTEMTIME stStart, stEnd;
    FILETIME ftStart, ftEnd;
    ULARGE_INTEGER uiStart, uiEnd;

    GetSystemTime(&stStart);
    // things to do here
    GetSystemTime(&stEnd);

    if (!SystemTimeToFileTime(&stStart, &ftStart))
        return FALSE;
    if (!SystemTimeToFileTime(&stEnd, &ftEnd))
        return FALSE;

    uiStart.LowPart = ftStart.dwLowDateTime;
    uiStart.HighPart = ftStart.dwHighDateTime;
    uiEnd.LowPart = ftEnd.dwLowDateTime;
    uiEnd.HighPart = ftEnd.dwHighDateTime;
    return (uiEnd.QuadPart - uiStart.QuadPart) > qwNativeElapsed;
}
int main() {
	if (debugger_check(0xFF) == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
#### GetTickCount()
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check(DWORD dwNativeElapsed)
{
	DWORD dwStart = GetTickCount();
	// things to do here
	return (GetTickCount() - dwStart) > dwNativeElapsed;
}
int main() {
	if (debugger_check(0xFF) == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
#### QueryPerformanceCounter()
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check(DWORD64 qwNativeElapsed)
{
	LARGE_INTEGER liStart, liEnd;
	QueryPerformanceCounter(&liStart);
	// things to do here
	QueryPerformanceCounter(&liEnd);
	return (liEnd.QuadPart - liStart.QuadPart) > qwNativeElapsed;
}
int main() {
	if (debugger_check(0xFF) == TRUE) {
		printf("Cu't");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
### Assembly instructions
- Các kĩ thuật dưới đây được dùng với mục đích phát hiện debugger bằng cách kiểm tra cách debugger hoạt động khi CPU thực thi một số các instructions nhất định
#### INT 3
- Instruction `INT 3` (0xCC) là một ngắt được sử dụng như là một `Software Breakpoint`. Khi mà không có debugger, sau khi chạy qua instruction `INT 3`, exception `EXCEPTION_BREAKPOINT` (0x80000003) được gen và sẽ exception handler sẽ được call. Nếu như có sự hiện diện của debugger, luồng control sẽ không được đưa cho execption handler
```C
#include <Windows.h>
#include <stdio.h>

BOOL debugger_check()
{
    __try
    {
        __asm int 3;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
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
- Như ta có thể thấy, khi step qua instruction `INT 3`, chương trình sẽ raise exception

![image](https://github.com/user-attachments/assets/dd45feb0-0e81-4491-9057-0620ffb48f31)

- Và nếu như ta bỏ qua exception và tiếp tục step tiếp thì chương trình sẽ crash

![image](https://github.com/user-attachments/assets/28c00f35-ed7d-4ceb-b950-36e88ac5323e)

- Ngoài dạng ngắn của instruction này (0xCC), còn có một dạng dài hơn là : `CD 03` opcode
- Khi exception `EXCEPTION_BREAKPOINT` xảy ra, hệ điều hành sẽ giảm `EIP` tới vị trí mà được coi là cùa opcode `0xCC` và pass control cho exception handler. Đối với phiên bản dài hơn của `INT 3`, EIP sẽ trỏ vào giữa instruction này (0x03). Nên vì vậy `EIP` phải được chỉnh trong exception handler nếu như ta muốn tiếp tục execution flow sau instruction `INT 3`(nếu không khả năng cao chúng ta sẽ nhận được exception `EXCEPTION_ACCESS_VIOLATION `).
```C
#include <Windows.h>
#include <stdio.h>
BOOL g_bDebugged = FALSE;
int filter(unsigned int code, struct _EXCEPTION_POINTERS* ep)
{
    g_bDebugged = code != EXCEPTION_BREAKPOINT;
    return EXCEPTION_EXECUTE_HANDLER;
}
BOOL debugger_check()
{
    __try
    {
        __asm __emit(0xCD);
        __asm __emit(0x03);
    }
    __except (filter(GetExceptionCode(), GetExceptionInformation()))
    {
        return g_bDebugged;
    }
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
#### INT 2D
- Cũng giống như instruction `INT 3`, khi mà instruction `INT 2D` được execute, sẽ raise exception `EXCEPTION_BREAKPOINT`. Nhưng với `INT 2D`, hệ điều hành sẽ sử dụng ``EIP`` register làm địa chỉ xảy ra exception rồi increase `EIP` lên. Hệ điều hành cũng kiểm tra giá trị của `EAX` trong khi `INT 2D` được thực thi. Nếu như giá trị của `EAX` là 1 trong 3 giá trị sau 1, 3 hoặc 4 trên mọi phiên bản của Windows hoặc là 5 trong Vista+ thì địa chỉ xảy ra exception sẽ được tăng lên 1
- Instruction này có thể gây ra một số vấn đề cho một số debugger bởi sau khi tăng `EIP` thì byte ở sau instruction `INT 2D` sẽ bị bỏ qua và luồn thực thi có thể sẽ bị lỗi
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check()
{
    __try
    {
        __asm xor eax, eax;
        __asm int 0x2d;
        __asm nop;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
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
#### DebugBreak()
- Được chỉ rõ trong [document về DebugBreak](https://docs.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugbreak), "DebugBreak sẽ gây ra breakpoint exception trong process hiện hành. Điều này sẽ khiến cho thread đã gọi hàm này đưa ra tín hiệu cho debugger để xử lí exception này"
- Nếu như chương trình không bị attached bởi debugger, luồng control sẽ được pass cho exception handler. Ngược lại, luồng thực thi sẽ được xử lí bởi debugger
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check()
{
    __try
    {
        DebugBreak();
    }
    __except (EXCEPTION_BREAKPOINT)
    {
        return FALSE;
    }

    return TRUE;
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
#### ICE
- Là một trong những instruction không được document của Intel, có opcode là `0xF1`. Được sử dụng để kiểm tra xem chương trình có bị trace hay không
- Nếu instruction `ICE` được thực thi, exception `EXCEPTION_SINGLE_STEP` (0x80000004) sẽ được raised
- Nếu như chương trình đã bị traced trước đó, debugger sẽ coi exception này như là một exception bình thường được tạo ra bởi việc thực thi instruction này với bit `SingleStep` được set trong `Flags registers`. Vì vậy, khi được chạy trong debugger, exception handler sẽ không được gọi và luồng thực thi sẽ tiếp tục như thường sau `ICE` instruction
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check()
{
    __try
    {
        __asm __emit 0xF1;
        return TRUE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        return FALSE;
    }
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
#### Stack Segment Register
- Đây là một kĩ thuật được sử dụng để kiểm tra xem chương trình có bị trace hay không bằng cách sử dụng các instruction sau
```asm
push ss 
pop ss 
pushf
```
- Sau khi single-stepping trong debugger có chứa đoạn code này, `Trap Flags` sẽ được set. Thông thường ta sẽ không thể thấy được `Trap Flags` bởi debugger sẽ clear flag này sau mỗi một event mà debugger đã qua. Tuy nhiên, nếu ta lưu `EFLAGS` vào stack, thì ta có thể check được `Trap Flags` có được set hay không
```C
#include <Windows.h>
#include <stdio.h>
BOOL debugger_check()
{
    BOOL bTraced = FALSE;

    __asm
    {
        push ss
        pop ss
        pushf
        test byte ptr[esp + 1], 1
        jz movss_not_being_debugged
    }

    bTraced = TRUE;

movss_not_being_debugged:
    // restore stack
    __asm popf;

    return bTraced;
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
### BlockInput()
- Đây là một kĩ thuật khá hay mà mình gặp trong bài `anti3`. Theo [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-blockinput), hàm này sẽ có chức năng block hoặc unblock input từ mouse và keyboard dựa trên arguments được truyền vào nó (Cụ thể là 0 nếu như muốn unblock và 1 nếu như muốn block). Ý tưởng cho việc sử dụng này sẽ là block hoặc unblock hoàn toàn các keyboard và mouse khi chạy qua hàm này, điều này đồng nghĩa với việc ta sẽ không thể nhấn F9,F8 hay di chuột để sử dụng debugger.Bên dưới là một implementation của mình, đoạn code này đơn thuần chỉ là mã hóa XOR nhưng nếu ta áp dụng kĩ thuật này vào những hàm có cơ chế phức tạp hơn thì việc debug sẽ trở nên vô cùng khó khăn. **NOTE: Chương trình có sử dụng hàm này bắt buộc phải được chạy dưới quyền admin thì mới có thể hoạt động**. Các bạn có thể copy đoạn code của mình bên dưới, compile rồi load vào một trình debugger và thử debug :v 
```C
#include <Windows.h>
#include <stdio.h>
unsigned char cypher[] = { 0xa8, 0xb9, 0xa1, 0xae, 0x93, 0xad, 0xa4, 0xa4, 0x93, 0xa8, 0xa9, 0xae, 0xb9, 0xab, 0xab, 0xa9, 0xbe, 0x93, 0xaf, 0xad, 0xa2, 0xb8, 0x93, 0xaa, 0xa5, 0xab, 0xb9, 0xbe, 0xa9, 0x93, 0xa3, 0xb9, 0xb8, 0x93, 0xbb, 0xa4, 0xad, 0xb8, 0x93, 0xa5, 0xa1, 0x93, 0xad, 0xae, 0xa3, 0xb9, 0xb8, 0x93, 0xb8, 0xa3, 0x93, 0xa8, 0xa3, 0x93, 0x94, 0x88, 0x88, 0x88 };

BOOL IsElevated() {
    BOOL fRet = FALSE;
    HANDLE hToken = NULL;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
        TOKEN_ELEVATION Elevation;
        DWORD cbSize = sizeof(TOKEN_ELEVATION);
        if (GetTokenInformation(hToken, TokenElevation, &Elevation, sizeof(Elevation), &cbSize)) {
            fRet = Elevation.TokenIsElevated;
        }
    }
    if (hToken) {
        CloseHandle(hToken);
    }
    return fRet;
}
int main() {
    if (IsElevated() == FALSE) {
        MessageBox(NULL, L"Run me with administrative privilege or fuck off.", L"No lol", MB_OK);
        exit(-1);
    }
	BlockInput(1);
	char* alloc_mem = VirtualAlloc(NULL, sizeof(cypher), (MEM_COMMIT | MEM_RESERVE), PAGE_EXECUTE_READWRITE);
	for (int i = 0; i < sizeof(cypher); i++) {
		alloc_mem[i] = cypher[i];
	}
	for (int i = 0; i < sizeof(cypher); i++) {
		alloc_mem[i] ^= 0xCC;
	}
	VirtualFree(alloc_mem,0,MEM_RELEASE);
	BlockInput(0);
	return 0;
}
``` 
## Conclusion
- Đây là một số các kĩ thuật anti debug mà mình có thể tổng hợp được. Một trong những kĩ năng cần thiết cho các Reverse Engineers là có thế phát hiện và đồng thời code được một số các kĩ thuật anti debug cơ bản.
