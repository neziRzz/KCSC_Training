**MASM Fundamentals**

-----------------------------------------------------------------------------------------------------------------------------------------

- Một chút về tiểu sử của MASM (Microsoft Macro Assembler). Là một `x86 assembler` sử dụng syntax `Intel` cho 2 hệ điều hành `MS-DOS` và `Microsoft Windows`. Có 2 phiên bản chính là hệ `16-bits` và `32-bits`, và một phiên bản khác là `64-bits` cho các architecture thuộc hệ `64-bits` là `ML64`

- Một chương trình được code bằng MASM sẽ có cấu trúc như sau

![image](https://github.com/user-attachments/assets/faaa5774-5f84-47fd-b84e-eb6fcaf339f7)

- Ta có thể thấy rằng chương trình sẽ được chia ra làm 3 sections
  + Assembler directives: Chứa các thông tin để khởi tạo assembler như là syntax, memory models(Win32 chỉ hỗ trợ flat model), calling conventions, header files,....
  + Data Segment: Khởi tạo và cấp phát vùng nhớ cho các biến do người code định nghĩa
  + Code Segment: Như tên gọi, đây là segment chứa code assembly của chương trình

 - Một số những syntax tính toán cơ bản trong MASM(assembly nói chung)
   + `add op1, op2`: Thực hiện cộng 2 toán hạng `op1` và `op2` với kết quả của phép cộng được lưu vào `op1` và set các flags  OF, SF, ZF, AF, CF, và PF tương ứng
   + `sub op1, op2`: Thực hiện trừ 2 toán hạng `op1` và `op2` với kết quả của phép trừ được lưu vào `op1` và set các flags  OF, SF, ZF, AF, CF, và PF tương ứng
   + `mul op1, op2`: Thực hiện nhân không dấu(unsigned) 2 toán hạng `op1` và `op2` với kết quả của phép nhân được lưu vào `op1` và set các flags OF và CF tương ứng. Một điều cần lưu ý với instruction này là tùy thuộc vào data type(BYTE, WORD or DOUBLEWORD) thì kết quả sẽ được lưu vào các toán hạng theo ảnh sau (với x64 thì tương tự, chỉ thêm cặp register RDX:RAX)
     ![image](https://github.com/user-attachments/assets/28e24a7d-e69d-47da-93c0-cb0b1983eca3)

   + `imul op1, op2(, op3)`:Thực hiện nhân có dấu(signed)1, 2 hoặc 3 toán hạng `op1`, `op2` và `op3` với kết quả của phép nhân được lưu vào `op1` và set các flags OF và CF tương ứng
