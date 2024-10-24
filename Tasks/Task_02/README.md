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

![1](https://github.com/user-attachments/assets/51ea7fb7-38ae-4afc-ba99-8ae5ea55d44f)

- Phần mà mình đã đóng khung đỏ trong hình chính là các opcodes mà chúng ta có thể dùng để tạo ra `Shellcode`, nếu các bạn chưa rõ `Opcodes` là gì thì có thể tham khảo thêm tại [Đây](https://en.wikipedia.org/wiki/Opcode), dựa vào các `Opcodes` ở trên, ta có thể viết ra được `Shellcode` như sau

```0x48 ,0x83 ,0xEC ,0x48,....,0xC3 ```

