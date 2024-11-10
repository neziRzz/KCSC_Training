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
		printf("Lmao fuck off!");
	}
	else {
		printf("Hello there!");
	}
	return 0;
}
```
- Function `IsDebuggerPresent()` sẽ xác định tiến trình đang chạy có đang bị debug bởi 1 debugger user-mode hay không. Thông thương thì function này sẽ kiểm tra flag `BeingDebugged` trong `PEB` 
