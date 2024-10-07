**ASM (NASM/MASM) Fundamentals**
---------------------------------------------------------------------------------------------------------------------------------------------
# Intro
 - Một chút về tiểu sử của MASM (Microsoft Macro Assembler). Là một `x86 assembler` sử dụng syntax `Intel` cho 2 hệ điều hành `MS-DOS` và `Microsoft Windows`. Có 2 phiên bản chính là hệ `16-bits` và `32-bits`, và một phiên bản khác cho các architecture thuộc hệ `64-bits` là `ML64`
# Basic Assembly
## Sections
- Một chương trình được code bằng assembly có thể được chia ra làm 3 sections
  + .data section: Được sử dụng để khai báo và khởi tạo vùng nhớ các biến hoặc các hằng số đã được định nghĩa sẵn
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
- Data segment: Bao gồm 2 sections là **.data** và **.bss**
```










