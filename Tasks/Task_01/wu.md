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
- Thanh ghi (Registers) là các vùng nhớ đặc biệt ở trong CPU
 
- Có 8 thanh ghi đa chức năng, thì trong đó ta có thể truy cập vào 4 thanh ghi EAX, EBX, ECX, EDX thông qua biến thể 16 hoặc 8 bits của chúng. Ví dụ với thanh ghi EAX, thì AX sẽ là 16 bits dầu của thanh ghi này, AL sẽ lấy 8 bits thấp nhất và AH sẽ lấy 8 bits tiếp theo. Các thanh ghi khác trong số 4 thanh ghi vừa nêu trên đều được truy cập tương tự. Tuy các thanh ghi này có thể được sử dụng cho nhiều mục đích khác nhau, nhưng chúng thường được sử dụng cho một mục đích cụ thể

![image](https://github.com/user-attachments/assets/eefdae86-fa2c-4131-abbe-88e3fa953414)

- Có 6 thanh ghi segment. Chúng định nghĩa các segments trong memory

![image](https://github.com/user-attachments/assets/3ad1e6c0-689d-4aad-ae6b-6d3933b167f8)

- Và cuối cùng là 2 thanh ghi 32-bit sau

![image](https://github.com/user-attachments/assets/a58d1deb-2fb8-4d98-9c75-c4753d05da3b)

## Basic Instructions
+ `cmp op1, op2`: Thực hiện so sánh 2 toán hạng `op1` và `op2`, sau đó set các flags CF, OF, SF, ZF, AF, và PF tương ứng. Câu lệnh này thường được sử dụng để xử lí các điều kiện

+ `add op1, op2`: Thực hiện cộng 2 toán hạng `op1` và `op2` với kết quả của phép cộng được lưu vào `op1` và set các flags  OF, SF, ZF, AF, CF, và PF tương ứng
 
+ `sub op1, op2`: Thực hiện trừ 2 toán hạng `op1` và `op2` với kết quả của phép trừ được lưu vào `op1` và set các flags  OF, SF, ZF, AF, CF, và PF tương ứng

+ `mul op1, op2`: Thực hiện nhân không dấu(unsigned) 2 toán hạng `op1` và `op2` với kết quả của phép nhân được lưu vào `op1` và set các flags OF và CF tương ứng. Một điều cần lưu ý với instruction này là tùy thuộc vào data type (BYTE, WORD or DOUBLEWORD) thì kết quả sẽ được lưu vào các toán hạng theo ảnh sau (với x64 thì tương tự, chỉ thêm cặp register RDX:RAX)
     
     ![image](https://github.com/user-attachments/assets/28e24a7d-e69d-47da-93c0-cb0b1983eca3)
     
+ `imul op1, op2(, op3)`:Thực hiện nhân có dấu (signed) 1, 2 hoặc 3 toán hạng `op1`, `op2` và `op3` với kết quả của phép nhân được lưu vào `op1` và set các flags OF và CF tương ứng. Dưới đây là các trường hợp cụ thể cho từng toán hạng và số lượng các toán hạng được sử dụng trong instruction)
     ![image](https://github.com/user-attachments/assets/21c24e86-c29a-4dbf-9a39-4b41a455b7ba)
     
+ `div op1`: Thực hiện chia không dấu (unsigned) AX, DX:AX, EDX:EAX,... cho toán hạng `op1`, với kết quả và phần dư được lưu theo ảnh bên dưới (LƯU Ý: Trước khi sử dụng instruction này thì phải gọi trước đó instruction `xor edx, edx` để tránh integer overflow)

+ `idiv op1`: Thực hiện chia có dấu (unsigned) AX, DX:AX, EDX:EAX,... cho toán hạng `op1`, với kết quả và phần dư được lưu theo ảnh bên dưới (LƯU Ý: Trước khi sử dụng instruction này thì phải gọi trước đó instruction 1 trong 3 instruction `cwd`, `cdq` or `cqo` <tùy vào data type> để tránh integer overflow [References](https://www.felixcloutier.com/x86/cwd:cdq:cqo)
    
    ![image](https://github.com/user-attachments/assets/7a89aad1-55d6-4c3e-9d1b-de5abf6600bb)
## Conditions
- Trong assembly, câu điều kiện (Conditional jumps) sẽ được chia ra làm 2 loại
  + Jump không điều kiện (Unconditional jumps): Được thực hiện bởi câu lệnh `jmp`, loại này thường sẽ chuyển luồng hoạt động của chương trình sang 1 địa chỉ không giống với luồng trước hoặc có thể được dùng để lặp lại một luồng hoạt động nào đó (Luôn được thực thi)
  + Jump có điều kiện (Conditional jumps): Được thực hiện bởi các câu lệnh có format j<điều kiện>. Tùy vào điều kiện là gì thì sẽ chuyển luồng chương trình sang một luồng khác (Chỉ thực thi khi thỏa mãn điều kiện)

- Dưới đây là các câu lệnh sử dụng để xử lí điều kiện
  + `CMP` Instruction: Câu lệnh này so sánh 2 toán hạng, thường xuyên được sử dụng để xử lí các. Căn bản thì instruction này sẽ thực hiện trừ 2 toán hạng với nhau để kiểm tra xem chúng có bằng nhau hay không. Được dùng kèm theo với các jump instructions có điều kiện để branch

 Syntax:
 ```asm
cmp dest, src
 ```

 Example:
```asm
cmp eax, 5 ;compare eax with 5
jz equal  ; jump to equal lable if eax = 5
.
.
.
equal: ...
```
 + Jump không điều kiện (Unconditional jump): Được thực hiện bởi câu lệnh `jmp`, loại này thường sẽ chuyển luồng hoạt động của chương trình sang 1 địa chỉ không giống với luồng trước hoặc có thể được dùng để lặp lại một luồng hoạt động nào đó (Luôn được thực thi)

Syntax:
```asm
jmp label
```
Example:
```asm
mov ecx, 0 ;init ecx
mov eax, 1 ;init eax
mov edx, 1 ;init edx
label:
add cx, 1 ;add 1 into cx
add ax, 2 ;add 2 into ax
add dx, 3 ;add 3 into dx
jmp label ;Unconditional jump into label
```
+ Jump có điều kiện (Conditional jump): Jump có điều kiện (Conditional jumps): Được thực hiện bởi các câu lệnh có format j<điều kiện>. Tùy vào điều kiện là gì thì sẽ chuyển luồng chương trình sang một luồng khác (Chỉ thực thi khi thỏa mãn điều kiện). Dưới đây là các câu lệnh jump có điều kiện (signed data)

![image](https://github.com/user-attachments/assets/b3b5cd9b-9816-4b2a-b073-f75adbb3393a)

(unsigned data)

![image](https://github.com/user-attachments/assets/e6b73c12-2928-41e9-b8b7-a3c2dc3a9e7c)

(dựa theo các eflags)

![image](https://github.com/user-attachments/assets/0bf69e60-2b7b-4d9c-a22e-17313505f0ec)

Example:
```asm
cmp al, bl
je equal
cmp al, cl
je equal
cmp ah, ch
je equal
non_equal:...
equal:...
```
## Label
- Labels là tên cho các địa chỉ đã hoặc sẽ được khởi tạo trong vùng nhớ. Thường sẽ tượng chưng cho các địa điểm trong memory mà chưa được xác định hay chỉ có thể biết được khi mà chương trình được load vào memory để thực thi.

- Có 2 loại label chính:
  + Label được sử dụng để reference cho các memory locations mà ở đó chứa data
  + Label được sử dụng để reference cho các memory locations mà ở đó chương trình sẽ chuyển luồng thực thi (jmp/branch)

Syntax:
```asm
label_name:
```
Example:
(Data)
```asm
section	.text
   global _start     ;must be declared for linker (ld)
	
_start:	            ;tells linker entry point
   mov	edx,len     ;message length
   mov	ecx,msg     ;message to write, 
  .
  .
  .
  .
section	.data
msg: db 'Example', 0xa  ;string to be printed
len equ $ - msg     ;length of the string

```
(jmp/branch)
```asm
cmp ax, 1
jz equal_label
.
.
.
equal_label:
```
# MASM basic
## About MASM
- Một chút về tiểu sử của MASM (Microsoft Macro Assembler). Là một `x86 assembler` sử dụng syntax `Intel` cho 2 hệ điều hành `MS-DOS` và `Microsoft Windows`. Có 2 phiên bản chính là hệ `16-bits` và `32-bits`, và một phiên bản khác cho các architecture thuộc hệ `64-bits` là `ML64`
## Cấu trúc chương trình 
- Một chương trình được code bằng MASM sẽ có cấu trúc như sau

![image](https://github.com/user-attachments/assets/faaa5774-5f84-47fd-b84e-eb6fcaf339f7)

- Ta có thể thấy rằng chương trình sẽ được chia ra làm 3 sections
  + Assembler directives: Chứa các thông tin để khởi tạo assembler như là syntax, memory models, calling conventions, header files,.... Trong đó:
  	+ `.386` ám chỉ instructions set mà chương trình dùng sẽ là `80386`
   	+ `.model flat` ám chỉ memory model mà chương trình sẽ sử dụng (chỉ có flat model là được hỗ trợ đối với các chương trình Win32)
    	+`(.model)stdcall` ám chỉ calling convention mà hàm sử dụng, trong trường hợp này là `stdcall` với các parameters được passed từ phải qua trái (trong stack thì push các arguments vào theo thứ tự như trên)  
  + Data Segment: Khởi tạo và cấp phát vùng nhớ cho các biến do người code định nghĩa
  + Code Segment: Như tên gọi, đây là segment chứa code assembly của chương trình
## Cách triển khai hàm
- Cách triển khai 1 hàm trong NASM (giả sử ta có 1 chương trình in ra string `test`)
```asm
.386 
.model flat, stdcall 
option casemap:none 
include \masm32\include\masm32rt.inc
.data
    msg db "test", 0
.code 
start: 
    push offset msg
    call StdOut
    call ExitProcess
end start
```
  + Tạo lable cho hàm với syntax `ur_func_name:`
  + Kết thúc hàm với syntax `end ur_func_name`
  + Đảm bảo cả hàm phải nằm trong Code Segment
## Một số các syntax đặc biệt
### Push and Pop
- Push và Pop là các câu lệnh giúp ta có thể xử lí stack. Push sẽ lấy một value và đẩy nó lên đầu stack, Pop sẽ tiến hành lấy value ở đỉnh stack ra khỏi stack và lưu nó vào một toán hạng nào đó. Từ đó ta có thể thấy được stack hoạt động theo cơ chế LIFO (Last In First Out)
### Invoke
-  Hàm `Invoke` là 1 hàm chỉ có ở MASM, ta có thể dùng chúng để gọi các hàm mà không cần push các parameters trước đó, qua đó giúp tiết kiệm được thời gian

  Example:
 (dùng `Invoke`)
```asm
invoke SendMessage, [hWnd], WM_CLOSE, 0, 0
```
(không dùng `Invoke`)
```asm
 push 0 
 push 0 
 push WM_CLOSE 
 push [hWnd] 
 call [SendMessage]
```
## Một số các tính năng
### Macros
- MASM có một số các macros để giúp cho việc lập trình trở nên dễ dàng hơn, ta đã thấy một trong số những macros của MASM là `Invoke`. Sau đây là một số các macros thường gặp khác, tính năng của chúng đúng như tên gọi
  + .if, .else, .endif
  + .while, .break, .endw
### Functions
- Giống với các ngôn ngữ bậc cao khác, MASM cho phép chúng ta định nghĩa các hàm để code dễ nhìn hơn. Chúng có syntax như sau
  ```asm
  <tên> proc <var1>:<var1 type>, <var2>:<var2 type>,...
  	<function's code>
  	ret
  <tên> endp
  ```
