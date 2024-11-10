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
- Trong hàm này, 2 hàm `sub_401DF0` và `sub_401F10` thực chất là custom implementation của `LoadLibrary` và `GetProcAddress` sử dụng kĩ thuật `API Hashing` để resolve các DLLs và functions dựa trên giá trị hash của chúng, và trong trường hợp này sẽ resolve `ntdll32.dll` và `NtQueryInformationProcess`. Sau đó gọi `NtQueryInformationProcess` với argument thứ 2 là `ProcessDebugPort`(0x7) để check debugger. Các bạn có thể bypass đoạn check này bằng cách chỉnh cờ ZF khi step đến instruction dưới đây

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

