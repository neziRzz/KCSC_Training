# Shellcode Fundamentals
## Definition
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

![image](https://github.com/user-attachments/assets/55d15c2e-24de-42be-aa27-afdd09b972d1)
