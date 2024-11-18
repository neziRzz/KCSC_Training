# Anti
## Misc
## Detailed Analysis
## Script and Flag
# Anti_1
## Misc
- Đề cho 1 file PE32

![image](https://github.com/user-attachments/assets/78243b7e-9c8d-4f8f-8f0c-f36a3f10b78f)

## Detailed Analysis
- Vì flow của bải này khá là lộn xộn, mình xin phép chỉ phân tích những hàm và flow đáng chú ý

![image](https://github.com/user-attachments/assets/25f20d72-76b5-44d3-b741-9998701a8ba1)

- Chương trình thực hiện lấy input của user, sau khi debug một hồi thì chương trình sẽ raise execption

![image](https://github.com/user-attachments/assets/150dbb79-9d17-44e4-a80f-677a823cbe9c)

- Tuy nhiên ta vẫn có thể tiếp tục debug bằng cách để cho chương trình tự handle execption này

![image](https://github.com/user-attachments/assets/c856b990-8bf5-4303-93cd-067b64d8c403)

- Tiếp tục debug nhưng đến đây thì chương trình đột nhiên thông báo wrong flag

![image](https://github.com/user-attachments/assets/8e8488be-1275-4b5f-aa47-28431b9478ca)
![image](https://github.com/user-attachments/assets/1dde63cf-2832-4791-a521-b26c80aab150)

- Đến đây thì mình không có bất cứ 1 ý tưởng về việc input được xử lí như thế nào, nên mình mở cửa sổ string của IDA và tìm thấy một string khá đặc biệt

![image](https://github.com/user-attachments/assets/2942f7fc-10c9-4c40-981d-4fdc4cd06871)

- XREFs để xem string này được gọi từ đâu

![image](https://github.com/user-attachments/assets/5def4d74-2285-4275-a1e7-5b29fe3fb07d)
![image](https://github.com/user-attachments/assets/0b74f63e-9a5f-4006-ac63-95314063ebf2)

- Hàm `sub_401220`
```C
char __fastcall sub_401220(const char *a1, int a2, int a3)
{
  char result; // al
  signed int v5; // esi
  int i; // ecx

  v5 = strlen(a1);
  for ( i = 0; i < a3; ++i )
  {
    result = a1[i % v5];
    *(_BYTE *)(i + a2) ^= result;
  }
  return result;
}
```
- Hàm này có nhiệm vụ XOR từng phần từ của input với string `BKSEECCCC!!!`, để kiểm chứng các bạn có thể debug
- Tiếp tục trace các instruction, sẽ thấy challenge sử dụng một kĩ thuật anti-debug khá quen thuộc

![image](https://github.com/user-attachments/assets/5903fc35-c4e0-4f14-bb7e-247cd3b4f647)

- Kĩ thuật anti debug được sử dụng trong bài này chính là kiểm tra flag `BeingDebugged` trong struct `PEB`, dấu hiệu nhận biết kĩ thuật này được sử dụng là `large fs:30h`, offset `0x30` trong segment register `fs` (0x60 với segment register `gs`) trỏ tới `PEB` và phần tử thứ 2 `eax+2` trong struct này là flag `BeingDebugged`
- Để bypass được đoạn kiểm tra này, ta có thể sửa flag `ZF` hoặc patch instruction từ `jz` sang `jmp`, khi đó luồng đúng của chương trình sẽ khởi tạo ra cyphertext, ta chỉ cần nhặt chúng ra và viết script

![image](https://github.com/user-attachments/assets/a5801bc6-c16c-427a-a53f-4ca8d85f7615)


## Script and Flag
```python
cyphertext = [0x00, 0x00, 0x00, 0x00, 0x06, 0x38, 0x26, 0x77, 0x30, 0x58, 0x7E, 0x42, 0x2A, 0x7F, 0x3F, 0x29, 
0x1A, 0x21, 0x36, 0x37, 0x1C, 0x55, 0x49, 0x12, 0x30, 0x78, 0x0C, 0x28, 0x30, 0x30, 0x37, 0x1C, 
0x21, 0x12, 0x7E, 0x52, 0x2D, 0x26, 0x60, 0x1A, 0x24, 0x2D, 0x37, 0x72, 0x1C, 0x45, 0x44, 0x43, 
0x37, 0x2C, 0x6C, 0x7A, 0x38
]
key = "BKSEECCCC!!!"
for i in range(len(cyphertext)):
    print(chr(cyphertext[i]^ord(key[i%len(key)])),end='')
```
# Anti_2
## Misc 
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/c993a1af-2772-419a-9190-ca47e7027192)
## Detailed Analysis
- IDA's Pseudocode
- Hàm `main`
```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  void (__noreturn *v4)(); // [rsp+0h] [rbp-8h] BYREF

  v4 = sub_9100;
  return sub_1EAA0(&v4, &off_52F18, a1, a2, 0LL);
}
```
- Hàm xử lí chính của chúng ta sẽ là `sub_9100` nên mình sẽ đi vào phân tích hàm đó

- Hàm `sub_9100` (mình sẽ chỉ nhặt ra những phần đáng chú ý để phân tích)
```C
  v0 = 0;
  v1 = 0LL;
  v2 = 0xF3LL;
  v3 = 0x158LL;
  do
  {
    --v3;
    --v2;
  }
  while ( v2 > 0 );
  __asm { syscall; LINUX - }
  v4 = 291LL;
  if ( v3 )
  {
    ((void (__fastcall *)(int *, __int64, _QWORD))sub_9610)(v25, 291LL, 0LL);
    v5 = (v26 >> 13) - 1;
    if ( v26 <= 0x1FFF )
    {
      v6 = (1 - (v26 >> 13)) / 0x190u + 1;
      v5 += 400 * v6;
      v0 = -146097 * v6;
    }
    v4 = (unsigned int)v25[0]
       + 86400LL
       * (int)(((unsigned int)((__int64 (*)(void))sub_94D0)() >> 4)
             + ((v5 / 100) >> 2)
             + ((1461 * v5) >> 2)
             + v0
             - v5 / 100)
       - 0xE77934880LL;
  }
 ////////////////////
    v12 = (*(_BYTE *)(v7 + v9) ^ (unsigned __int8)v11) == *((_BYTE *)v23 + v9);
    ++v9;
    if ( !v12 )
    {
      v14 = &off_52FA8;
      v15 = 1LL;
      v13[0] = 0LL;
      v16 = "Enter something:\nFailed to read linesrc/main.rsNopeSeems good";
      v17 = 0LL;
      sub_210A0(v13);
      goto LABEL_18;
    }
  }
  v14 = &off_52FB8;
  v15 = 1LL;
  v13[0] = 0LL;
  v16 = "Enter something:\nFailed to read linesrc/main.rsNopeSeems good";
  v17 = 0LL;
  sub_210A0(v13);
```
- Đầu tiên sẽ khởi tạo init code cho syscall bằng cách lấy `v3 - v2`(kết quả là 0x65) tương ứng với việc gọi `ptrace` bằng syscall để check debugger. Một chút về kĩ thuật này, nếu như syscall đến `ptrace` thành công (không có chương trình nào đang trace chương trình gọi `ptrace`) thì giá trị trả về là 0 và tương ứng với việc không có debugger (giống như việc ta chỉ có thể attach 1 debugger per process), ngược lại nếu như giá trị trả về là -1 (đang có process trace) thì có nghĩa là đang có debugger attached. Tùy thuộc vào việc có debugger hay không thì chương trình sẽ gen ra cypher phù hợp. Trong trường hợp có debugger thì `sub_9610` sẽ có nhiệm vụ lấy time hiện tại làm seed cho cypher, điều này lí giải cho việc tại sao mỗi lần debug chương trình thì cypher thay đổi liên tục. Cuối cùng chương trình sẽ đem input của chúng ta XOR với cypher để kiểm tra với một array constant. Vậy để viết script thì ta chỉ cần thay đổi giá trị trả về sau syscall từ -1 về 0 rồi đặt bp tại phần kiểm tra rồi nhặt ra data để viết script
## Script and Flag
```python
test = [0xE8, 0x49, 0x12, 0x6E, 0x4E, 0x47, 0xD8, 0x7A, 0x1B, 0x2E, 
  0xC5, 0x8A, 0x19, 0x15, 0xD5, 0x3E, 0x0B, 0x08, 0x91, 0xC5, 
  0xC0, 0x79, 0x3E, 0xB8, 0xD8, 0x64, 0x95, 0x4D, 0xD4, 0x22, 
  0x54, 0x00, 0x65, 0xBD, 0x83, 0x59, 0x60, 0xB4, 0x4C, 0xC7, 
  0x78, 0xC5, 0xBF, 0xE8, 0x4B, 0x7C, 0x35, 0xDA, 0x14, 0xBB, 
  0x81, 0xE4, 0x26, 0x70, 0xB7, 0x40, 0x7A, 0x31, 0x5D, 0xD1, 
  0x19, 0x84, 0xF0, 0x1D, 0x8C, 0x53, 0xC1, 0xBF, 0x61, 0x4C, 
  0x8A, 0x60, 0x16, 0x0A, 0x73, 0x51, 0x37, 0x9F, 0x2A, 0x31, 
  0xCC, 0xD8, 0x67, 0x96, 0x22, 0x4C, 0x30, 0x36, 0x9C, 0x0C, 
  0x20, 0xF8, 0x08, 0x4E, 0x4E, 0x9F, 0x2F, 0xA9, 0xF3, 0xF0, 
  0x4F, 0x85, 0x51, 0xE2, 0x18, 0x79, 0x57, 0xDA, 0xB6, 0x16, 
  0x31, 0xBC, 0x2A, 0xA7, 0x09, 0x77, 0x6F, 0xFB, 0xC5, 0xB8, 
  0xCB, 0x0D, 0xFB, 0x12, 0x71, 0x42, 0x8A, 0x04, 0x54, 0x67, 
  0xD8, 0xF4, 0x22, 0xD9, 0x0C, 0xF4, 0xAA, 0xDB, 0xC1, 0x48, 
  0x69, 0x96, 0x0E, 0x19, 0xF6, 0x80, 0xC0, 0xA3, 0x7E, 0x00, 
  0x8B, 0xC6, 0xCF, 0xB6, 0xDD, 0x16, 0xF2, 0xCC, 0x57, 0x5B, 
  0x4F, 0x86, 0xC8, 0xB2, 0xD3, 0x00, 0x57, 0x6C, 0xC7, 0x50, 
  0xBF, 0x44, 0xCC, 0x0B, 0xD0, 0x96, 0x69, 0x18, 0xE6, 0x96, 
  0x4D, 0x22, 0xF7, 0x66, 0x9D, 0xAE, 0x3D, 0x1C, 0x0F, 0xE8, 
  0x6F, 0x0E, 0xAD, 0x8E, 0xC5, 0xD9, 0xD3, 0xDB, 0x84, 0x4C, 
  0x16, 0x41, 0x38, 0xE5, 0x01, 0x0E, 0x3D, 0x5E, 0x65, 0x59, 
  0xB2, 0x6E, 0x6C, 0xCF, 0x08, 0x0B, 0x34, 0x27, 0x50, 0x34, 
  0x72, 0xF3, 0x69, 0x93, 0x99, 0xDE, 0x07, 0x84, 0x71, 0xEE, 
  0xA5, 0xF3, 0x99, 0x42, 0x51, 0xE8, 0xD6, 0x22, 0xE1, 0x00, 
  0xC2, 0xF4, 0x9A, 0x68, 0x1D, 0x7C, 0xD7, 0xA9, 0x5C, 0xD2, 
  0xA0, 0x5B, 0xD8, 0x57, 0xF3, 0x88]
cyphertext=[ 0xBF, 0x7F, 0x60, 0x6B, 0x6E, 0xA1, 0xB4, 0x8B, 0x12, 0x01, 
  0x0A, 0x26, 0x4B, 0x53, 0x0A, 0x46, 0xB5, 0x03, 0x22, 0x02, 
  0xA9, 0x10, 0xAF, 0x6A, 0x16, 0x78, 0x2C, 0xD3, 0x1D, 0x09, 
  0xAF, 0x48, 0x32, 0x46, 0xC8, 0x5B, 0x93, 0x49, 0xA9, 0x96, 
  0x7B, 0xE3, 0xF2, 0xF8, 0x0C, 0x74, 0xAB, 0x6C, 0xD0, 0xFF, 
  0xFF, 0xFF]
for i in range(len(cyphertext)):
  print(chr(test[i*4] ^ cyphertext[i]),end='')
```
# Anti_3
## Misc
- Đề cho 1 file PE32

![image](https://github.com/user-attachments/assets/6ef65f87-e49c-4f0c-8133-4ecb47024cf0)
## Detailed Analysis
- Chương trình bắt ta phải chạy với quyền admin, nhập input rồi kiểm tra, nếu sai thì sẽ hiện lên MsgBox như sau

![image](https://github.com/user-attachments/assets/1cce1e29-1112-4838-9662-5f970b881a78)

- Sử dụng cửa sổ Xrefs của IDA, mình sẽ trace ngược lại ra message trên được gọi từ đâu

![image](https://github.com/user-attachments/assets/8377f4a8-73b1-4009-97ca-d9253c29f02a)
```C
  switch ( (unsigned __int16)wParam )
  {
    case 4u:
      GetWindowTextA(::hWnd, String, 256);
      if ( sub_401B40(String) )
      {
        sub_401000((BYTE *)String, &pdwDataLen);
        if ( pdwDataLen >= 0x2E )
        {
          BYTE14(v9) = 0;
          MessageBoxA(0, (LPCSTR)v8, "OK", 0);
          return 0;
        }
        v5 = "Wrong";
      }
      else
      {
        v5 = "Wrong check fail";
      }
      MessageBoxA(0, "oh, no", v5, 0);
      return 0;
```
- Đoạn code này có nhiệm vụ là kiểm tra input của chúng ta, `sub_401B40` sẽ có nhiệm vụ kiểm tra input(mình sẽ phân tích hàm này cụ thể sau), còn `sub_401000` sẽ có nhiệm vụ decrypt 1 cyphertext có sẵn với input do chúng ta nhập vào là key. Vì mục tiêu chính của bài này là để hiểu được các kĩ thuật anti debug nên mình sẽ chỉ tập chung vào phân tích `sub_401B40`, trước khi đi vào phân tích hàm này, khi check cửa sổ Exports của IDA ta có thể thấy rằng bài này có gọi hàm `TlsCallBack`

![image](https://github.com/user-attachments/assets/fcd8e9f5-21f2-4f56-a3fe-a96cfbe7133f)

- Hàm `TlsCallback_0()`
```C
char *__stdcall TlsCallback_0(int a1, int a2, int a3)
{
  struct _LIST_ENTRY *v3; // eax
  char *result; // eax
  void (__stdcall *v5)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp-4h] [ebp-8h] BYREF
  char *v6; // [esp+0h] [ebp-4h]

  v3 = sub_401DF0((void *)0x7B3FA1C0);
  v6 = (char *)sub_401F10(v3, 0x5A3BB3B0);
  v5 = (void (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))v6;
  ((void (__stdcall *)(int, int, _DWORD, int, _DWORD))v6)(-1, 7, &v5, 4, 0);
  result = v6;
  if ( v6 )
  {
    result = (char *)&unk_405018 + 10;
    *((_BYTE *)&unk_405018 + 10) = 116;
  }
  return result;
}
```
- Trong hàm này, 2 hàm `sub_401DF0` và `sub_401F10` thực chất là custom implementation của `LoadLibrary` và `GetProcAddress` sử dụng kĩ thuật `API Hashing` để resolve các DLLs và functions dựa trên giá trị hash của chúng, và trong trường hợp này sẽ resolve `ntdll32.dll` và `NtQueryInformationProcess`(để kiểm chứng có thể debug sau đó xem giá trị trả về của thanh ghi `eax`). Sau đó gọi `NtQueryInformationProcess` với argument thứ 2 là `ProcessDebugPort`(0x7) để check debugger. Các bạn có thể bypass đoạn check này bằng cách chỉnh cờ ZF khi step đến instruction dưới đây

![image](https://github.com/user-attachments/assets/361df950-1fc5-4d9d-abf4-58ca2bfadf11)

- Hàm `sub_401B40` (trước đó mình có chạy debugger nên một số hàm sẽ bị đổi lại tên)
```C
char __thiscall sub_AB1B40(const char *this)
{
  char v2; // cl
  int v3; // esi
  int v4; // ecx
  char v5; // bl
  char v6; // cl
  int v7; // eax
  char v8; // al
  int v9; // eax
  void (__stdcall *v10)(_DWORD); // eax
  char result; // al
  char v12; // bl
  int v13; // eax
  unsigned __int8 v14; // cl
  int v15; // eax
  int v16; // eax
  void (__stdcall *v17)(_DWORD); // eax
  void (__stdcall *v18)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp-4h] [ebp-25Ch] BYREF
  void (__stdcall *v19)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+10h] [ebp-248h]
  int v20; // [esp+14h] [ebp-244h]
  void (__stdcall *v21)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD); // [esp+18h] [ebp-240h]
  char v22; // [esp+1Fh] [ebp-239h]
  char v23[556]; // [esp+20h] [ebp-238h] BYREF
  int v24; // [esp+24Ch] [ebp-Ch]

  if ( strlen(this) < 0x26 )
    return 0;
  sub_AB1FD0(v23, byte_AB501C[(unsigned __int8)byte_AB501C[0] / 0xCu]);
  v2 = v22;
  v3 = 0;
  while ( 2 )
  {
    switch ( dword_AB32C8[v3] )
    {
      case 1:
        v4 = dword_AB3360[v3];
        v5 = this[dword_AB33F8[v3]];
        v22 = NtCurrentPeb()->NtGlobalFlag & 0x70;
        v6 = sub_AB2050(v4);
        v7 = v24;
        if ( v24 >= 256 )
          v7 = 0;
        v24 = v7 + 1;
        v2 = byte_AB329F[v7 + 1] == (char)(v5 ^ v6);
        goto LABEL_9;
      case 2:
        v8 = sub_AB1600(dword_AB3360[v3]);
        goto LABEL_8;
      case 3:
        v8 = sub_AB16C0(dword_AB3360[v3]);
        goto LABEL_8;
      case 4:
        v8 = sub_AB1760(dword_AB3360[v3]);
        goto LABEL_8;
      case 5:
        v8 = sub_AB1950(dword_AB3360[v3]);
        goto LABEL_8;
      case 6:
        v8 = sub_AB1AA0(dword_AB3360[v3]);
LABEL_8:
        v2 = v8;
        goto LABEL_9;
      case 7:
        v20 = dword_AB3360[v3];
        v12 = this[dword_AB33F8[v3]];
        v13 = sub_AB1DF0(2067767744);
        v19 = (void (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))sub_AB1F10(v13, 1513862064);
        v21 = 0;
        v18 = v19;
        v19(-1, 31, &v18, 4, 0);
        v21 = v18;
        v14 = sub_AB2050(v20);
        v15 = v24;
        if ( v24 >= 256 )
          v15 = 0;
        v24 = v15 + 1;
        if ( byte_AB329F[v15 + 1] != (v14 ^ (unsigned __int8)v12) )
          goto LABEL_20;
        v2 = 1;
        goto LABEL_10;
      default:
LABEL_9:
        if ( !v2 )
        {
LABEL_20:
          v16 = sub_AB1DF0(38312619);
          v17 = (void (__stdcall *)(_DWORD))sub_AB1F10(v16, 838910877);
          v17(0);
          byte_AB55B8 = 0;
          return 0;
        }
LABEL_10:
        if ( ++v3 < 38 )
          continue;
        v9 = sub_AB1DF0(38312619);
        v10 = (void (__stdcall *)(_DWORD))sub_AB1F10(v9, 838910877);
        v10(0);
        byte_AB55B8 = 0;
        result = 1;
        break;
    }
    return result;
  }
}
```
- Hàm này sẽ kiểm tra input của chúng ta bằng cách sử dụng một map để access một case bất kì trong các case của switch case trên, mỗi một case sẽ chứa một kĩ thuật anti debug. Sau đây mình sẽ phân tích từng case
  + Case 1
    + Case này sẽ check debug bằng cách kiểm tra flag `NtGlobalFlag` trong `PEB`, nếu chương trình bị debug thì sẽ tiến hành set flag đồng thời phụ thuộc vào flag này thì `sub_AB2050` sẽ gen ra giá trị tương ứng (may thay `sub_AB2050` chỉ có thể gen ra 2 trường hợp giá trị phụ thuộc vào việc chương trình có bị debug hay không nên mình sẽ không phân tích kĩ hàm đó) sau đó input của chúng ta sẽ được XOR với giá trị mà `sub_AB2050` trả về và kiểm tra với phần tử tương ứng tại `byte_AB329F`
   
  
  + Case 2:
    + `sub_AB1600`
```C
bool __fastcall sub_AB1600(int a1, char a2, int a3)
{
  struct _LIST_ENTRY *v4; // eax
  unsigned __int8 (*v5)(void); // eax
  char v6; // bl
  struct _LIST_ENTRY *v7; // eax
  void (__stdcall *v8)(_DWORD); // eax
  int v9; // eax
  unsigned int v11; // [esp+8h] [ebp-8h]

  v4 = sub_AB1DF0((void *)0x6AE69F02);
  v5 = (unsigned __int8 (*)(void))sub_AB1F10(v4, 0x4CCF1A0F);
  v11 = *(_DWORD *)((_BYTE *)NtCurrentPeb()->ProcessHeap + (v5() >= 6u ? 0x34 : 0) + 12) & 0xEFFEFFFF; // get heap flags sum
  v6 = sub_AB2050(a1, v11 != 0x40000062, a3); // check the sum of heap flags with this value for debugger
  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  ++*(_DWORD *)(a1 + 556);
  v7 = sub_AB1DF0((void *)0x2489AAB);
  v8 = (void (__stdcall *)(_DWORD))sub_AB1F10(v7, 0x3200C39D);
  v8(0);
  v9 = *(_DWORD *)(a1 + 556);
  byte_AB55B8 = 0;
  return byte_AB329F[v9] == (char)(a2 ^ v6);
}
```
   + Hàm này sẽ resolve `HeapWalk` bằng kĩ thuật `API Hashing` như mình vừa đề cập và sau đó kiểm tra các `Heap Flags` các bạn có thể tìm hiểu kĩ hơn tại [đây](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-flags). Đối với hệ điều hành 64-bit, `Heap Flags` sẽ được set dựa trên sum của các sub flags sau
       + HEAP_GROWABLE (2)
       + HEAP_TAIL_CHECKING_ENABLED (0x20)
       + HEAP_FREE_CHECKING_ENABLED (0x40)
       + HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000)

  + Nếu như tất cả các flag này đều được set thì sẽ đồng nghĩa với việc có debugger
  + Case 3:
```C
bool __fastcall sub_AB16C0(int a1, char a2, int a3)
{
  struct _LIST_ENTRY *v4; // eax
  unsigned __int8 (*v5)(void); // eax
  bool v6; // dl
  char v7; // cl

  v4 = sub_AB1DF0((void *)0x6AE69F02);
  v5 = (unsigned __int8 (*)(void))sub_AB1F10(v4, 1288641039);
  v6 = (*(_DWORD *)((_BYTE *)NtCurrentPeb()->ProcessHeap + (v5() >= 6u ? 0x34 : 0) + 16) & 0xEFFEFFFF) != 0x40000060; // check the sum of force flags with this value for debugger
  v7 = sub_AB2050(a1, v6, a3);
  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  ++*(_DWORD *)(a1 + 556);
  return byte_AB329F[*(_DWORD *)(a1 + 556)] == (char)(a2 ^ v7);
}
```
   + Tương tự case 2 nhưng sẽ là kiểm tra `Force Flags`. Flag này được set dựa theo sum của các flags sau
     + HEAP_TAIL_CHECKING_ENABLED (0x20)
     + HEAP_FREE_CHECKING_ENABLED (0x40)
     + HEAP_VALIDATE_PARAMETERS_ENABLED (0x40000000) 
  
  + Case 4
```C
bool __fastcall sub_AB1760(int a1, char a2, int a3)
{
  struct _LIST_ENTRY *v4; // eax
  int (*v5)(void); // eax
  int v6; // edi
  struct _LIST_ENTRY *v7; // eax
  void (__cdecl *v8)(int *, _DWORD, int); // eax
  struct _LIST_ENTRY *v9; // eax
  void (__stdcall *v10)(int, int *); // ebx
  char *v11; // edx
  int v12; // eax
  char v13; // cl
  char v14; // dl
  char v15; // cl
  int v18[2]; // [esp+10h] [ebp-20h] BYREF
  __int16 v19; // [esp+1Ah] [ebp-16h]

  v4 = sub_AB1DF0((void *)0x6AE69F02);
  v5 = (int (*)(void))sub_AB1F10(v4, 0x40F6426D);
  v6 = v5();
  v7 = sub_AB1DF0((void *)0x7B3FA1C0);
  v8 = (void (__cdecl *)(int *, _DWORD, int))sub_AB1F10(v7, 0x7B9C69F6);
  v8(v18, 0, 28);
  v9 = sub_AB1DF0((void *)0x6AE69F02);
  v10 = (void (__stdcall *)(int, int *))sub_AB1F10(v9, 0x70495334);
  while ( v19 != 4 )
    v10(v6, v18);
  v11 = (char *)(v18[0] + v18[1]);
  v12 = 0;
  while ( 1 )
  {
    v13 = *v11++;
    if ( v13 != (char)0xAB ) // check for 8 AB sequence here 
      break;
    if ( ++v12 >= 8 ) // loophole here since in 32-bit arch only have 4 AB sequence
    {
      v14 = 1;
      goto LABEL_8;
    }
  }
  v14 = 0;
LABEL_8:
  v15 = sub_AB2050(a1, v14, a3);
  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  ++*(_DWORD *)(a1 + 556);
  return byte_AB329F[*(_DWORD *)(a1 + 556)] == (char)(a2 ^ v15);
}
```
  + Case này sẽ kiểm tra chuỗi `0xABABABAB` có được append trong heap block hay không (check debug), các bạn có thể tìm hiểu thêm về kĩ thuật này tại [đây](https://anti-debug.checkpoint.com/techniques/debug-flags.html#manual-checks-heap-protection). Nhưng có vẻ trong case này không tính đến trường hợp cho các hệ 32-bit bởi đối với hệ 32-bit thì chỉ có 4 sequence AB trong khi trong case này kiểm tra 8 sequence AB (nói cách khác là ta cũng có thể bypass case này bằng việc cho chạy chương trình trên hệ 32-bit)



  + Case 5
```C
char __fastcall sub_441950(int a1, unsigned __int8 a2, int a3)
{
  struct _LIST_ENTRY *v4; // eax
  int (__stdcall *v5)(int, _DWORD); // eax
  int v6; // edi
  struct _LIST_ENTRY *v8; // eax
  int (__stdcall *v9)(int, int *); // eax
  struct _LIST_ENTRY *v10; // eax
  struct _LIST_ENTRY *v11; // eax
  void (__stdcall *v12)(int); // ebx
  char v13; // dl
  char v14; // al
  int (__stdcall *v15)(int, int *); // [esp+8h] [ebp-238h]
  int v17[9]; // [esp+10h] [ebp-230h] BYREF
  char v18[520]; // [esp+34h] [ebp-20Ch] BYREF

  v4 = sub_441DF0((void *)0x6AE69F02);
  v5 = (int (__stdcall *)(int, _DWORD))sub_441F10(v4, 0x3E0C478A);
  v6 = v5(2, 0);
  if ( v6 == -1 )
    return 1;
  v17[0] = 556;
  v8 = sub_441DF0((void *)0x6AE69F02);
  v9 = (int (__stdcall *)(int, int *))sub_441F10(v8, 0x267CF1A5);
  if ( !v9(v6, v17) )
    return 1;
  v10 = sub_441DF0((void *)0x6AE69F02);
  v15 = (int (__stdcall *)(int, int *))sub_441F10(v10, 0x28ED5C0);
  v11 = sub_441DF0((void *)0x6AE69F02);
  v12 = (void (__stdcall *)(int))sub_441F10(v11, 0x4F6CEA0C);
  while ( !(unsigned __int8)sub_441860(v18) )
  {
    if ( !v15(v6, v17) )
    {
      v13 = 0;
      goto LABEL_9;
    }
  }
  v13 = 1;
LABEL_9:
  v14 = sub_442050(a1, v13, a3);
  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  if ( byte_44329F[++*(_DWORD *)(a1 + 556)] == (a2 ^ (unsigned __int8)v14) )
  {
    v12(v6);
    return 1;
  }
  else
  {
    v12(v6);
    return 0;
  }
}
```
   + Case này sẽ resolve `CreateToolhelp32Snapshot`, `Process32First` và `Process32Last` bằng kĩ thuật `API Hashing` mà mình đã đề cập ở trên để kiếm chương trình đang chạy `anti3`, ban đầu mình nghĩ case này sẽ kiểm tra thêm cả parent process của nó rồi kiểm tra với tên các trình debugger với disassembler nữa nhưng có vẻ là không phải (cứ để flow chương trình chạy bình thường tại đây)



  + Case 6
```C
bool __fastcall sub_441AA0(int a1, char a2, int a3)
{
  struct _LIST_ENTRY *v5; // eax
  int (__stdcall *v6)(int); // esi
  char v7; // bl
  char v8; // al
  char v9; // al

  v5 = sub_441DF0((void *)0x2489AAB);
  v6 = (int (__stdcall *)(int))sub_441F10(v5, 838910877);
  v7 = v6(1);
  v8 = v6(1);
  if ( byte_4455B8 )
  {
    if ( v7 == v8 )
      goto LABEL_3;
  }
  else if ( v7 != v8 )
  {
LABEL_3:
    v9 = sub_442050(a1, 1, a3);
    byte_4455B8 = 1;
    goto LABEL_6;
  }
  v9 = sub_442050(a1, 0, a3);
LABEL_6:
  if ( *(int *)(a1 + 556) >= 256 )
    *(_DWORD *)(a1 + 556) = 0;
  ++*(_DWORD *)(a1 + 556);
  return byte_44329F[*(_DWORD *)(a1 + 556)] == (char)(a2 ^ v9);
}
```
   + Case này sử dụng một kĩ thuật khá là `lạ` và bản thân mình thấy rất hay đó chính là resolve `BlockInput` bằng kĩ thuật `API Hashing` mà mình đã đề cập ở trên. `BlockInput` sẽ có nhiệm vụ block mouse cũng như là keyboard input của user (không dùng được chuột với phím thì sao mà debug :v), sau đó kiểm tra giá trị trả về thông qua 2 lần gọi hàm này để check xem hàm có bị tác động thêm vào hay không, từ đó phát hiện debugger. Cái điều mà mình thấy hay nó là ở đây, theo [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-blockinput#return-value) nếu như hàm này đã block input thành công thì giá trị trả về sẽ khác 0 và nếu như đã bị block rồi thì giá trị trả về sẽ = 0, nếu như không có debugger attach vào thì giá trị trả về lần lượt của 2 hàm này sẽ là 1 và 0 tương ứng. Nhưng nếu ta patch lại argument của hàm này để cho `BlockInput` không block thì giá trị trả về sẽ đểu là 0 hoặc là đều là 1, và từ đó có nghĩa là chương trình bị debug, nên ta sẽ phải patch đoạn kiểm tra `v7!=v8` sao cho nó luôn đúng



  + Case 7
```C
      case 7:
        v22 = (void (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))dword_443360[v3];
        v12 = this[dword_4433F8[v3]];
        v13 = sub_441DF0((void *)0x7B3FA1C0);
        v21 = (void (__stdcall *)(_DWORD, _DWORD, _DWORD, _DWORD, _DWORD))sub_441F10(v13, 0x5A3BB3B0);
        v23 = 0;
        v20 = v21;
        v21(-1, 31, &v20, 4, 0);
        v23 = v20;
        v14 = v20 == 0;
        v20 = v22;
        v15 = !v14;
        v16 = sub_442050((int)v25, v15, (int)v20);
        v17 = v26;
        if ( v26 >= 256 )
          v17 = 0;
        v26 = v17 + 1;
        if ( byte_44329F[v17 + 1] != ((unsigned __int8)v16 ^ (unsigned __int8)v12) )
          goto LABEL_23;
        v2 = 1;
        goto LABEL_10;
```
  + Cách kiểm tra debugger của hàm này giống hàm `TLSCallBack_0` nên mình sẽ không phân tích



- Vậy để viết script giải ta có 2 cách. Cách đầu tiên là chạy lần lượt qua các case và nhặt các giá trị được return bởi `sub_442050` (giá trị trả về của hàm này chỉ có 2 trường hợp phụ thuộc vào việc flag check debugger trong từng case ra sao nếu các bạn bypass chuẩn thì giá trị trả ra sẽ chuẩn) và xor với từng phần tử trong `byte_44329F`. Cách thứ hai sẽ là tự build lại hàm `sub_442050` để tự động hóa script hơn. Vì bài này là để học các kĩ thuật anti debug nên mình sẽ làm theo cách 1
## Script and Flag
```python
#manually picking out flag from the binary :skull:
flag = ["a"]*38
flag[9] = 0x5B ^ 0xE
flag[0x12] = 0xDB ^ 0xEB 
flag[0xF] = 0x9D ^ 0xF3
flag[0x3] = 0xC6 ^ 0xF6
flag[0x4] = 0xA7 ^ 0xD1
flag[0x17] = 0x5A ^ 0x6B
flag[0x6] = 0x8A ^ 0xA7
flag[0x7] = 0xF6 ^ 0x8F
flag[0x8] = 0xD ^ 0x3D
flag[0x16] = 0xA5 ^ 0x91
flag[0xA] = 0xDA ^ 0x85
flag[0xB] = 0x74 ^ 0x2B
flag[0x21] = 0xE9 ^ 0x86 
flag[0xD] = ord("h")
flag[0xE] = 0x58 ^ 0x6B
flag[0x1B] = 0x96 ^ 0xDB
flag[0x10] = 0x5B ^ 0x7B
flag[0x25] = 0x5A ^ 0x6E
flag[0x11] = 0xD0 ^ 0x89
flag[0x13] = 0xFC ^ 0x89
flag[0x14] = 0x25 ^ 0x18
flag[0x15] = 0xF6 ^ 0x95
flag[0x5] = 0x54 ^ 0x67
flag[0x22] = 0xB8 ^ 0xCA
flag[0x18] = 0x6E ^ 0x5F
flag[0x19] = 0xCC ^ 0xE2
flag[0x1A] = 0x7A ^ 0x54
flag[0x2] = 0x3F ^ 0x0E
flag[0xC] = 0xA4 ^ 0xD3
flag[0x1D] = 0x1E ^ 0x3E
flag[0x1E] = 0x73 ^ 0x20
flag[0x1F] = 0x3F ^ 0x5A
flag[0x20] = 0x10 ^ 0x7E
flag[0x1C] =  0xE7 ^ 0xD4
flag[0] = 0xF1 ^ 0xB8
flag[0x23] = 0x21 ^ 0x10
flag[0x24] = 0xB6 ^ 0xC2
flag[0x1] = 0xE8 ^ 0xB7
for i in flag:
  if(type(i) == int):
    print(chr(i),end='')
    continue
  print(i,end='')
```
# Anti_4
## Misc
- Đề cho 1 file PE32

![image](https://github.com/user-attachments/assets/2aeac110-0424-434c-875f-46c5099a225a)

## Detailed Analysis
- Hàm `main()`
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  LPTOP_LEVEL_EXCEPTION_FILTER lpTopLevelExceptionFilter; // [esp+0h] [ebp-8h]

  lpTopLevelExceptionFilter = SetUnhandledExceptionFilter(TopLevelExceptionFilter);
  SetUnhandledExceptionFilter(lpTopLevelExceptionFilter);
  return 0;
}
```
- Hàm này sẽ thực hiện gọi `SetUnhandledExceptionFilter()` để xử lí exception. Theo [MSDN](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-setunhandledexceptionfilter) thì sau khi hàm này được gọi, nếu có exception xảy ra trong một process **KHÔNG BỊ DEBUG** thì exception này sẽ được chuyển đến một hàm được chỉ định trong parameter `TopLevelExceptionFilter` để xủ lí, trong hàm `main()` sẽ xảy ra một exception `Divide by zero` (ta không thể thấy exception này trong pseudocode của hàm `main()`)

![image](https://github.com/user-attachments/assets/a95efc6f-df60-4f10-b9c1-dad72df3b2a6)
![image](https://github.com/user-attachments/assets/c7ee6861-61fe-42da-8d59-504bb430298d)

- Vậy để bypass được exception này, ta có thể đặt entry point (set IP) vào thẳng bên trong hàm được chỉ định trong `TopLevelExceptionFilter`. Tuy nhiên khi ta step vào bên trong thì có vẻ như IDA đã không thể decompile được hàm này

![image](https://github.com/user-attachments/assets/bf60537b-d95c-4ad4-897c-30590c3aed9b)

- Lí do cho điều này là bởi tác giả đã đặt byte rác `0xE8`(Call Opcode) vào sau 2 instruction `JNZ` và `JZ` nhằm làm khó việc phân tích. Để xử lí, ta chỉ cần biến instruction `CALL` ở hình trên thành data và `NOP` lại byte rác đó, sau khi `NOP` xong thì ta convert lại về code và redefine lại function

![image](https://github.com/user-attachments/assets/510aaa51-8d59-4649-94aa-51d41f60ea9b)
![image](https://github.com/user-attachments/assets/560d6860-588f-403f-b1ae-6ea2d28da821)
![image](https://github.com/user-attachments/assets/9d96134c-122e-4260-93ab-f279a98a2673)

- Nhấn F5 để gen ra pseudocode
```C
LONG __stdcall TopLevelExceptionFilter(struct _EXCEPTION_POINTERS *ExceptionInfo)
{
  char v2; // [esp+0h] [ebp-1Ch]
  struct _PEB *v3; // [esp+Ch] [ebp-10h]
  bool v4; // [esp+10h] [ebp-Ch]
  int i; // [esp+18h] [ebp-4h]

  v3 = NtCurrentPeb();
  v4 = v3 != (struct _PEB *)-49088 && ((int)v3[84].AtlThunkSListPtr & 0x70) != 0;
  byte_404083 = v4 ^ 0xCD;
  byte_404082 = v3->BeingDebugged ^ 0xAB;
  sub_401050(aEnterFlag, v2);
  sub_4010C0(aS, (char)byte_404640);
  memcpy(&unk_404560, byte_404640, 0x64u);
  dword_404114 = sub_401400();
  for ( i = 0; i < 17; ++i )
    byte_404640[i] ^= 1u;
  sub_401460(&unk_404652);
  return 0;
}
```
- Hàm này đầu tiên sẽ có nhiệm vụ khởi tạo `byte_404082` tùy thuộc vào flag `BeingDebugged` trong `PEB` có được set hay không
- Tiếp đến khởi tạo `dword_404114` tùy theo giá trị trả về của `sub_401400()`

- Hàm `sub_401400()`
```C
int sub_401400()
{
  unsigned int v1; // [esp+4h] [ebp-8h]
  unsigned int i; // [esp+8h] [ebp-4h]

  v1 = (char *)sub_4013F0 - (char *)&loc_401330 - 16;
  for ( i = 0; i < v1 && (*((unsigned __int8 *)&loc_401330 + i) ^ 0x55) != 0x99; ++i )
    ;
  return v1 - i + 0xBEEF;
}
```
- Hàm này sẽ kiểm tra `Software Breakpoint` (Opcode 0xCC) bên trong `loc_401330` bằng cách lấy các byte bên trong hàm `loc_401330` XOR với 0x55 (0x55 ^ 0x99 = 0xCC)
- Quay lại phân tích `TopLevelExceptionFilter`, ta có thể thấy 17 kí tự đầu tiên của input sẽ được XOR với 1. Các kí tự tiếp theo sẽ được xử lí tại `sub_401460`

- Hàm `sub_401460`
```C
int __cdecl sub_401460(int a1)
{
  int i; // [esp+0h] [ebp-4h]

  ((void (__stdcall *)(int *))loc_401330)(&a1);
  for ( i = 0; i < 9; ++i )
    *(_WORD *)(a1 + 2 * i) ^= dword_404114;
  return sub_4011D0(a1 + 19);
}
```
- Ta có thể thấy input cũng được xử lí tại `loc_401330` nhưng khi phân tích hàm này, ta sẽ gặp trường hợp giống với hàm `TopLevelExceptionFilter`

![image](https://github.com/user-attachments/assets/70ef21db-5884-4c41-9df2-8592a67d8b15)

- Lí do thì khá giống với những gì mình đã đề cập, nhưng thay vì chèn 1 byte rác thì là chèn 3, cụ thể là 0xE8, 0x66 và 0xB8, ta sẽ phải `NOP` 3 byte này và redefine lại function

![image](https://github.com/user-attachments/assets/ca017424-7cfe-4c3f-8318-64b2d33cce5d)
![image](https://github.com/user-attachments/assets/29002737-8f63-445d-a853-e05d554e7349)

- Nhấn F5 để gen ra pseudocode
```C
_DWORD *__cdecl sub_401330(_DWORD *a1)
{
  _DWORD *result; // eax
  int i; // [esp+Ch] [ebp-8h]
  int j; // [esp+10h] [ebp-4h]

  for ( i = 0; i < 8; ++i )
    *(_BYTE *)(*a1 + i) ^= byte_404082;
  *a1 += 9;
  for ( j = 0; j < 12; ++j )
    *(_BYTE *)(*a1 + j) = ((2 * *(_BYTE *)(*a1 + j)) | 1) ^ (j + byte_404083);
  result = a1;
  *a1 += 13;
  return result;
}
```
- Hàm này sẽ thực hiện XOR 8 kí tự tiếp theo với `byte_404082`. Tiếp đến, 12 kí tự tiếp đó sẽ được sẽ được biến đổi thông qua một số phép toán dựa trên `byte_404083`
- Quay lại hàm `sub_401460`, 18 kí tự kế tiếp (2 kí tự 1) sẽ được XOR với `dword_404114`. Và các kí tự còn lại sẽ được xử lí thông qua hàm `sub_4011D0`

- Hàm `sub_4011D0`
```C
int __cdecl sub_4011D0(int a1)
{
  int i; // [esp+14h] [ebp-1Ch]

  __asm { int     2Dh; Windows NT - debugging services: eax = type }
  for ( i = 0; i < 5; ++i )
    *(_BYTE *)(i + a1) = (*(_BYTE *)(i + a1) << (8 - i + 1)) | (*(char *)(i + a1) >> (i - 1));
  __debugbreak();
  dword_404658 ^= 0xEFC00CFE;
  sub_401190(a1 + 11);
  return sub_401100();
}
```
- Hàm này có sử dụng 2 kĩ thuật anti-debug là `INT 2D` và `INT 3`. 2 Kĩ thuật này đều có điểm chung là nếu như dưới sự hiện diện của debugger thì sau khi step qua thì exception sẽ không được đưa cho exception handler. Có nghĩa là ta có thể sử dụng kĩ thuật này để giấu luồng thực thi đúng của chương trình ở bên trong các exception handler, kĩ thuật trên không những có thể chống được debugger mà đồng thời cũng có thể khiến cho các trình disassembler decompile sai. Để bypass được kĩ thuật này ta sẽ làm như sau

- Có thể thấy rằng khi step qua instruction này, chương trình lập tức raise exception

![image](https://github.com/user-attachments/assets/dcf3df4f-015b-47ca-b626-6019c6071449)

- Khi ta tiếp tục step thì IDA hiện lên của sổ thông báo như sau

![image](https://github.com/user-attachments/assets/042870fd-93bb-4102-91b0-bc28837181ea)

- Bởi trong kĩ thuật này, nếu như có sự hiện diện của debugger thì exception sẽ không được đưa cho exception handler nên ta sẽ ép chương trình phải xử lí exception này bằng cách nhấn `Yes` và đặt BP tại exception handler để không bị pass mất luồng thực thi

![image](https://github.com/user-attachments/assets/f02a533b-0c06-4429-96ce-92936f607291)

- Khi có luồng đúng, sau khi ta debug thì sẽ có thể thấy rõ là pseudocode đã cho kết quả sai

- Với `INT 3`, hướng tiếp cận của chúng ta tương tự
- Sau khi bypass được hết các anti debug trong hàm này, ta có thể suy ra được luồng chuẩn như sau
  + Đầu tiên chương trình xử lí 5 kí tự của flag với pattern như sau `(*(_BYTE *)(i + a1) << (8 - i) | (*(char *)(i + a1) >> (i))`
  + Tiếp đến 5 kí tự tiếp theo sẽ được xor lần lượt với 0x37, 0x13, 0xFE và 0xC0

- Trong hàm `sub_401190` sẽ xử lí nốt 30 kí tự cuối cùng bằng cách XOR từng kí tự 1 với kí tự trước nó, cuối cùng sẽ kiểm tra input với `byte_404118`. Với các dữ kiện trên ta có thể viết script như bên dưới
## Script and Flag
```python
from z3 import *
cyphertext = [0x74, 0x6F, 0x69, 0x35, 0x4F, 0x65, 0x6D, 0x32, 0x32, 0x79, 
  0x42, 0x32, 0x71, 0x55, 0x68, 0x31, 0x6F, 0x5F, 0xDB, 0xCE, 
  0xC9, 0xEF, 0xCE, 0xC9, 0xFE, 0x92, 0x5F, 0x10, 0x27, 0xBC, 
  0x09, 0x0E, 0x17, 0xBA, 0x4D, 0x18, 0x0F, 0xBE, 0xAB, 0x5F, 
  0x9C, 0x8E, 0xA9, 0x89, 0x98, 0x8A, 0x9D, 0x8D, 0xD7, 0xCC, 
  0xDC, 0x8A, 0xA4, 0xCE, 0xDF, 0x8F, 0x81, 0x89, 0x5F, 0x69, 
  0x37, 0x1D, 0x46, 0x46, 0x5F, 0x5E, 0x7D, 0x8A, 0xF3, 0x5F, 
  0x59, 0x01, 0x57, 0x67, 0x06, 0x41, 0x78, 0x01, 0x65, 0x2D, 
  0x7B, 0x0E, 0x57, 0x03, 0x68, 0x5D, 0x07, 0x69, 0x23, 0x55, 
  0x37, 0x60, 0x14, 0x7E, 0x1D, 0x2F, 0x62, 0x5F, 0x62, 0x5F]
flag = [BitVec('x[%d]'%i,8) for i in range(100)]
s = Solver()
index = 0
for i in range(0,17):
  flag[i] ^= 1
  index +=1
index = 18
for i in range(8):
  flag[index] ^= 0xAB
  index +=1
index = 27
for i in range(12):
  flag[index] = ((2*flag[index])|1) ^ (i + 0xCD)
  index +=1
for i in range(40,57,2):
  flag[i] ^= 0xEF
  flag[i+1] ^= 0xBE
index = 59
for i in range(5):
  flag[index] = (((flag[index] << (8 - i))|(flag[index]>>(i))))&0xFF
  index +=1
index = 65
flag[index] ^= 0x37
flag[index+1] ^= 0x13
flag[index+2] ^= 0xFE
flag[index+3] ^= 0xC0
for i in range(71,100):
  flag[i] ^= flag[i-1]
for i in range(len(flag)):
  s.add(flag[i] == cyphertext[i])
if(s.check() == sat):
  print(s.model())
```
# Anti_5
## Mics
- Đề cho 1 file PE32

![image](https://github.com/user-attachments/assets/a588618b-e0b2-439d-9404-bef49ac682fe)

## Detailed Analysis
- Bài này sử dụng kĩ thuật anti debug bằng cách gọi `TlsCallBack` trước hàm `main`

- Hàm `TlsCallback_0`
```C
BOOL __stdcall TlsCallback_0(int a1, int a2, int a3)
{
  BOOL result; // eax
  HANDLE hProcess; // [esp+4h] [ebp-10h]
  DWORD dwProcessId; // [esp+8h] [ebp-Ch]
  SIZE_T NumberOfBytesWritten; // [esp+Ch] [ebp-8h] BYREF

  result = IsDebuggerPresent();
  if ( !result )
  {
    dwProcessId = GetCurrentProcessId();
    hProcess = OpenProcess(0x1FFFFFu, 0, dwProcessId);
    return WriteProcessMemory(hProcess, (char *)&loc_4013A2 + 1, &unk_403140, 4u, &NumberOfBytesWritten);
  }
  return result;
}
```
- Hàm này sẽ kiểm tra debugger bằng cách gọi hàm `IsDebuggerPresent`. Nếu như không có debugger thì hàm này sẽ thực hiện replace instruction `call sub_401180` ở hàm `main` thành `call sub_401070` (khi debug ta sẽ thấy rõ)

- Hàm `main`
```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax
  int v4; // ecx
  char v6; // [esp+0h] [ebp-30h]
  int j; // [esp+0h] [ebp-30h]
  unsigned int i; // [esp+8h] [ebp-28h]
  char *Buf2; // [esp+Ch] [ebp-24h]
  signed int v10; // [esp+10h] [ebp-20h]
  char *Buffer; // [esp+14h] [ebp-1Ch]
  _DWORD v12[5]; // [esp+18h] [ebp-18h] BYREF

  strcpy((char *)v12, "VdlKe9upfBFkkO0L");
  Buf2 = (char *)malloc(0x100u);
  Buffer = (char *)malloc(0x100u);
  memset(Buffer, 0, 0x100u);
  memset(Buf2, 0, 0x100u);
  memcpy(Buf2, &unk_40315C, 0x30u);
  sub_401410("FLAG : ", v6);
  v3 = __acrt_iob_func(0);
  fgets(Buffer, 256, v3);
  v10 = strlen(Buffer);
  v4 = v10 % 8;
  if ( v10 % 8 )
  {
    for ( i = 0; i < 8 - v4; ++i )
      Buffer[v10 - 1 + i] = 10;
    v10 += 8 - v4;
  }
  for ( j = 0; j < v10 / 8; ++j )
  {
    sub_401180(Buffer, v12);
    if ( memcmp(Buffer, Buf2, 8u) )
    {
      puts("Incorrect");
      exit(0);
    }
    Buffer += 8;
    Buf2 += 8;
  }
  puts("Correct");
  return 1;
}
```
- Hàm `main` đơn thuần chỉ lấy input của chúng ta, sau đó `sub_401180` sẽ có nhiệm vụ encrypt input với key là `VdlKe9upfBFkkO0L`. Cuối cùng thì sẽ thực hiện kiểm tra input sau khi đã được mã hóa với `unk_40315C`
- Như mình đã đề cập bên trên, khi không có debugger thì hàm thực thi đúng của chúng ta sẽ là `sub_401070` nên giờ chúng ta sẽ phân tích hàm đó
```C
int __fastcall sub_401070(unsigned int *a1, _DWORD *a2)
{
  int result; // eax
  unsigned int i; // [esp+14h] [ebp-18h]
  int v4; // [esp+1Ch] [ebp-10h]
  unsigned int v5; // [esp+24h] [ebp-8h]
  unsigned int v6; // [esp+28h] [ebp-4h]

  v6 = *a1;
  v5 = a1[1];
  v4 = 0;
  for ( i = 0; i < 0x20; ++i )
  {
    v4 -= 0x61C88647;
    v6 += (a2[1] + (v5 >> 5)) ^ (v4 + v5) ^ (*a2 + 16 * v5);
    v5 += (a2[3] + (v6 >> 5)) ^ (v4 + v6) ^ (a2[2] + 16 * v6);
  }
  *a1 = v6;
  result = 4;
  a1[1] = v5;
  return result;
}
```
- Hàm này sử dụng thuật toán `TEA` để mã hóa input. Vậy để tìm ra flag ta chỉ cần kiếm thuật toán decrypt trên mạng và viết script. Tuy nhiên bởi thuật toán này hoạt động trên các block 32 bits nên ta sẽ phải chia cyphertext và key ra thành các khối 32 bit theo kiểu little endian. Sau khi decrypt xong thì chỉ cần đảo lại endianess là được
## Script and Flag
```python
def tea_decrypt(cyphertext_block, key):
    delta = 0x9E3779B9
    n = 32
    v0, v1 = cyphertext_block
    k0, k1, k2, k3 = key
    sum_value = delta * n

    for _ in range(n):
        v1 -= ((v0 << 4) + k2) ^ (v0 + sum_value) ^ ((v0 >> 5) + k3)
        v1 &= 0xFFFFFFFF  
        v0 -= ((v1 << 4) + k0) ^ (v1 + sum_value) ^ ((v1 >> 5) + k1)
        v0 &= 0xFFFFFFFF  
        sum_value -= delta
        sum_value &= 0xFFFFFFFF  

    return v0, v1
  
def reverse_endian(block):
    return tuple(int.from_bytes(part.to_bytes(4, byteorder='big'), byteorder='little') for part in block)

def decrypt_all(cyphertext, key):
    plaintext = []
    for i in range(0, len(cyphertext), 2):
        block = (cyphertext[i], cyphertext[i+1])
        decrypted_block = tea_decrypt(block, key)
        reversed_block = reverse_endian(decrypted_block)
        plaintext.append(reversed_block)
    return plaintext

def blocks_to_ascii(blocks):
    ascii_text = ""
    for block in blocks:
        for part in block:
            ascii_text += part.to_bytes(4, byteorder='big').decode('ascii', errors='ignore')
    return ascii_text

cyphertext = [
    0x2A302C19, 0x0254F979, 0xD66CA9B3, 0x04958091,
    0xA3E85929, 0x86BD790F, 0x6C1305AF, 0x2BDB75FE,
    0x5DF0E0AE, 0x89864B88, 0x45AC6633, 0xA6786C9A
]

key = [0x4B6C6456, 0x70753965, 0x6B464266, 0x4C304F6B]

plaintext = decrypt_all(cyphertext, key)

ascii_text = blocks_to_ascii(plaintext)

print(ascii_text)

```
# Anti_6
## Misc
## Detailed Analysis
## Script and Flag
```C
#include <stdio.h>
#include <string.h>
#include <stdint.h>


void ksa(const uint8_t* key, int key_length, uint8_t* S) {
    int i, j = 0;
    uint8_t temp;

 
    for (i = 0; i < 256; i++) {
        S[i] = i;
    }

  
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key[i % key_length]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
}

void prga(const uint8_t* input, uint8_t* output, int length, uint8_t* S) {
    int i = 0, j = 0, k, t;
    uint8_t temp;

    for (k = 0; k < length; k++) {
    
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;

       
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;

       
        t = (S[i] + S[j]) % 256;
        uint8_t keystream_byte = S[t];

   
        output[k] = input[k] ^ keystream_byte;
    }
}
void rc4_decrypt(const unsigned char* key, const uint8_t* cyphertext, uint8_t* plaintext, int length) {
    uint8_t S[256];
    int key_length = strlen((const char*)key);


    ksa(key, key_length, S);

 
    prga(cyphertext, plaintext, length, S);
}

int main() {
    unsigned char key[] = { 0x33, 0xBF, 0xAD,0xDE};
    uint8_t cyphertext[14]; 
    cyphertext[0] = 0x7D;
    cyphertext[1] = 8;
    cyphertext[2] = 0xED;
    cyphertext[3] = 0x47;
    cyphertext[4] = 0xE5;
    cyphertext[5] = 0;
    cyphertext[6] = 0x88;
    cyphertext[7] = 0x3A;
    cyphertext[8] = 0x7A;
    cyphertext[9] = 0x36;
    cyphertext[10] = 2;
    cyphertext[11] = 0x29;
    cyphertext[12] = 0xE4;
    cyphertext[13] = 0;
    int cyphertext_length = sizeof(cyphertext) / sizeof(cyphertext[0]);

    uint8_t plaintext[256] = { 0 }; 


    rc4_decrypt(key, cyphertext, plaintext, cyphertext_length);

    printf("%s\n", plaintext);

    return 0;
}


```
