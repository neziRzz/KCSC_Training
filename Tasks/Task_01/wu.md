**ASM (NASM/MASM) Fundamentals**
---------------------------------------------------------------------------------------------------------------------------------------------
# Intro
 - Một chút về tiểu sử của MASM (Microsoft Macro Assembler). Là một `x86 assembler` sử dụng syntax `Intel` cho 2 hệ điều hành `MS-DOS` và `Microsoft Windows`. Có 2 phiên bản chính là hệ `16-bits` và `32-bits`, và một phiên bản khác cho các architecture thuộc hệ `64-bits` là `ML64`
# Basic Assembly
## Sections
- Một chương trình được code bằng assembly có thể được chia ra làm 3 sections
  + .data section: Được sử dụng để khai báo và khởi tạo vùng nhớ các biến hoặc các hằng số đã được định nghĩa sẵn, size của section này là cố định
  + .text section: Chứa phần code của chương trình
  + .bss section: Dùng để khai báo biến
## Comments
- Comments trong assembly bắt đầu sau kí tự `;`. Comments có thể chứa các kí tự in được hoặc khoảng trống, chúng có thể đứng riêng trên 1 dòng hoặc đứng theo 1 instruction nào đó

  Examples:
  ```asm
  ;this is a comment
  ```
  ```asm
  xor eax, eax ;clear eax
  ```
## Syntax
- Trong assembly, mỗi một câu lệnh khác nhau sẽ chỉ được ghi trên 1 dòng duy nhất. Các câu lệnh được viết theo format như sau
```asm
[label]   mnemonic   [operands]   [;comment]
```
- Những vùng được ghi trong dấu ngoặc vuông là tùy chọn. Một câu lệnh sẽ gồm 2 thành phần chính, phần đầu sẽ là tên của instruction (mnemonic) cần được thực thi và các toán hạng (operands)
  Examples
  ```asm
  xor eax, eax ;clear eax

  add ah, 4 ;add 4 into AH register

  mov cx, 10 ;Transfer 10 into CX register
  ```
## Memory Segments
- Như đã đề cập ở trên về 3 sections của một chương trình được viết bằng assembly, thì 3 sections này cũng được coi là các memory segments

- Cụ thể hơn về các memory segments thì model phân mảnh vùng nhớ (segmented memory model) sẽ có trách nhiệm chia nhỏ các vùng nhớ hệ thống thành các vùng riêng biệt và chúng được referenced bằng các con trỏ ở trong các thanh ghi segments (segment registers). Mỗi segment sẽ chứa những loại data khác nhau. Cụ thể như sau:
```
- Data segment: Bao gồm 2 sections là .data và .bss, section .data được dùng để khai báo vùng nhớ và vị trí của các data được sử dụng trong chương trình. Size của section này là cố định xuyên suốt trong chương trình. .bss section cũng là một vùng nhớ tĩnh chứa các buffer cho các data được khai báo sau của chương trình. Các buffer này được zero-filled.
- Code segment: Được định nghĩa bởi .text section. Segment này chứa các đoạn code (instructions) sẽ được thực thi trong chương trinh. Size của segment này cố định.
- Stack: Segment này chứa các giá trị truyền vào các hàm hay thủ tục ở trong chương trình
```
## Registers
- Thanh ghi (Registers) là các vùng nhớ đặc biệt ở trong CPU.
- Có 8 thanh ghi đa chức năng, thì trong đó ta có thể truy cập vào 4 thanh ghi EAX, EBX, ECX, EDX thông qua biến thể 16 hoặc 8 bits của chúng. Ví dụ với thanh ghi EAX, thì AX sẽ là 16 bits dầu của thanh ghi này, AL sẽ lấy 8 bits thấp nhất và AH sẽ lấy 8 bits tiếp theo. Các thanh ghi khác trong số 4 thanh ghi vừa nêu trên đều được truy cập tương tự. Tuy các thanh ghi này có thể được sử dụng cho nhiều mục đích khác nhau, nhưng chúng thường được sử dụng cho một mục đích cụ thể

![image](https://github.com/user-attachments/assets/eefdae86-fa2c-4131-abbe-88e3fa953414)

- Có 6 thanh ghi segment. Chúng định nghĩa các segments trong memory

![image](https://github.com/user-attachments/assets/3ad1e6c0-689d-4aad-ae6b-6d3933b167f8)

- Và cuối cùng là 2 thanh ghi 32-bit sau

  ![image](https://github.com/user-attachments/assets/a58d1deb-2fb8-4d98-9c75-c4753d05da3b)







