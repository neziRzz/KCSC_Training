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











