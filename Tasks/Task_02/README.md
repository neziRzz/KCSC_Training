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
- Khi sử dụng shellcode để thực thi chương trình, một trong những vấn đề tiêu biểu nhất mà ta sẽ gặp phải là làm thế nào để resolve các external functions. Lí do cho điều này là bởi shellcode không được compile cùng với chương trình mà nó chạy trên  
