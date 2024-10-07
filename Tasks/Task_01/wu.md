**MASM Fundamentals**

-----------------------------------------------------------------------------------------------------------------------------------------

- Một chút về tiểu sử của MASM (Microsoft Macro Assembler). Là một `x86 assembler` sử dụng syntax `Intel` cho 2 hệ điều hành `MS-DOS` và `Microsoft Windows`. Có 2 phiên bản chính là hệ `16-bits` và `32-bits`, và một phiên bản khác cho các architecture thuộc hệ `64-bits` là `ML64`
-----------------------------------------------------------------------------------------------------------------------------------------
- Một chương trình được code bằng MASM sẽ có cấu trúc như sau

![image](https://github.com/user-attachments/assets/faaa5774-5f84-47fd-b84e-eb6fcaf339f7)

- Ta có thể thấy rằng chương trình sẽ được chia ra làm 3 sections
  + Assembler directives: Chứa các thông tin để khởi tạo assembler như là syntax, memory models(Win32 chỉ hỗ trợ flat model), calling conventions, header files,....
  + Data Segment: Khởi tạo và cấp phát vùng nhớ cho các biến do người code định nghĩa
  + Code Segment: Như tên gọi, đây là segment chứa code assembly của chương trình
-----------------------------------------------------------------------------------------------------------------------------------------
- Cách triển khai 1 hàm trong NASM )(giả sử ta có 1 chương trình in ra string `test`)
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
-----------------------------------------------------------------------------------------------------------------------------------------
 - Một số những syntax cơ bản trong MASM (assembly nói chung)
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
-----------------------------------------------------------------------------------------------------------------------------------------
- Trong assembly, câu điều kiện (Conditional jumps) sẽ được chia ra làm 2 loại
  + Jump không điều kiện (Unconditional jumps): Được thực hiện bởi câu lệnh `jmp`, loại này thường sẽ chuyển luồng hoạt động của chương trình sang 1 địa chỉ không giống với luồng trước hoặc có thể được dùng để lặp lại một luồng hoạt động nào đó (Luôn được thực thi)
  + Jump có điều kiện (Conditional jumps): Được thực hiện bởi các câu lệnh có format j<điều kiện>. Tùy vào điều kiện là gì thì sẽ chuyển luồng chương trình sang một luồng khác (Chỉ thực thi khi thỏa mãn điều kiện)
