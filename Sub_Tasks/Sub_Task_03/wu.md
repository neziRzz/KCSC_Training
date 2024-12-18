# Math
## Misc
- Đề cho 1 file PE64

![image](https://github.com/user-attachments/assets/5ce33fcd-ede6-4c8a-8e70-d1aade41a722)

## Detailed Analysis
- Hàm `main`
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v3; // al
  const char *v4; // rcx
  __int128 *v6; // [rsp+28h] [rbp-60h] BYREF
  __int128 v7[4]; // [rsp+30h] [rbp-58h] BYREF

  memset(v7, 0, sizeof(v7));
  sub_140002480("Enter flag: ", argv, envp);
  sub_140002500(v7);
  sub_1400035B0(v7);
  v6 = v7;
  v3 = sub_140004680(&v6);
  v4 = "Wrong!";
  if ( v3 )
    v4 = "Correct!";
  puts(v4);
  return 0;
}
```
- Hàm `main` không quá phức tạp, hàm chỉ đơn thuần nhận input từ user, sau đó kiểm tra đúng sai. Nhưng khi phân tích các hàm còn lại ta sẽ thấy có điều đặc biệt

![image](https://github.com/user-attachments/assets/1ba59b3e-c123-44d4-acab-64a78eed7116)

- Các hàm `sub_140002500`, `sub_1400035B0` và `sub_140004680` đều có pattern như này, có thể thấy rõ là các hàm này đã bị obfuscated, tuy nhiên ở cuối các hàm này ta có thể thấy một đoạn call đến một giá trị nào đó

![image](https://github.com/user-attachments/assets/160f82f3-2de3-4601-9a91-652642b4347a)

- Từ đó có thể suy ra rằng các đoạn code bị obfuscated trên chỉ đơn thuần tính toán địa chỉ để thực thi lệnh call kia. Vậy để tiếp tục phân tích, ta sẽ phải debug và set BP vào các lệnh call này. Ta được các kết quả như sau

- Hàm `sub_140002500` chỉ là 1 obfuscated call đến `fgets`
```C
__int64 __fastcall sub_7FF755C323C0(__int64 a1)
{
  FILE *v2; // rax

  v2 = _acrt_iob_func(0);
  common_fgets<char>(a1, 64i64, v2);
  return 0i64;
}
```

- Hàm `sub_1400035B0` là 1 obfuscated call đến check flag routine
```C
__int64 __fastcall sub_7FF755C31170(const char *a1)
{
  int v2; // eax
  int v3; // ebx
  signed int v4; // ebx
  __int64 result; // rax
  __int64 v6; // rbx
  __int64 v7; // rdi
  __int64 v8[3]; // [rsp+28h] [rbp-40h] BYREF

  v2 = strlen(a1);
  v3 = v2 + 7;
  if ( v2 >= 0 )
    v3 = v2;
  v4 = (v3 & 0xFFFFFFF8) + 8;
  result = 'desufnoc';
  *(__int64 *)((char *)&v8[1] + 1) = 'desufnoc';
  if ( v4 >= 8 )
  {
    v6 = (unsigned int)v4 >> 3;
    v7 = 0i64;
    do
    {
      v8[0] = *(_QWORD *)&a1[8 * v7];
      sub_7FF755C31200(v8);
      result = v8[0];
      *(_QWORD *)&a1[8 * v7++] = v8[0];
    }
    while ( v6 != v7 );
  }
  return result;
}
```
- Hàm này sẽ có nhiệm vụ tách 8 kí tự 1 của user để xử lí, sau đó cùng với string `confused`(Little endian nên bị đảo) sẽ được đưa vào hàm `sub_7FF755C31200` để tiếp tục tính toán

- Hàm `sub_7FF755C31200` cũng sử dụng kĩ thuật obfuscate như trên nên cũng sẽ sử dụng cách làm tương tự để tìm hàm chuẩn
```C
char __fastcall sub_7FF7EDF11000(char *a1)
{
  char v1; // r8
  char v2; // r10
  char v3; // r15
  char v4; // dl
  char v5; // si
  char v6; // di
  char v7; // r13
  char v8; // bl
  char v9; // r9
  char result; // al
  char v11; // cl
  int v12; // r11d
  char v14; // [rsp+8h] [rbp-68h]
  char v15; // [rsp+10h] [rbp-60h]
  char v16; // [rsp+18h] [rbp-58h]
  char v17; // [rsp+20h] [rbp-50h]
  char v18; // [rsp+28h] [rbp-48h]

  v1 = *a1;                                     // a[0] -> a[7] = input
                                                // a[9] -> a[15] = confused
  v2 = a1[1];
  v18 = a1[9];
  v17 = a1[10];
  v3 = a1[2];
  v16 = a1[11];
  v4 = a1[3];
  v15 = a1[12];
  v5 = a1[4];
  v14 = a1[13];
  v6 = a1[5];
  v7 = a1[14];
  v8 = a1[6];
  v9 = a1[15];
  result = a1[7];
  v11 = a1[16];
  v12 = 100;
  do
  {
    v2 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v1 + v18)] + v2, 1);
    v3 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v2 + v17)] + v3, 1);
    v4 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v3 + v16)] + v4, 1);
    v5 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v4 + v15)] + v5, 1);
    v6 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v5 + v14)] + v6, 1);
    v8 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v6 + v7)] + v8, 1);
    result = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v9 + v8)] + result, 1);
    v1 = __ROL1__(byte_7FF7EDF2B000[(unsigned __int8)(v11 + result)] + v1, 1);
    --v12;
  }
  while ( v12 );
  a1[1] = v2;
  a1[2] = v3;
  a1[3] = v4;
  a1[4] = v5;
  a1[5] = v6;
  a1[6] = v8;
  a1[7] = result;
  *a1 = v1;
  return result;
}
```
- Tại đây ta có thể thấy rằng input được tính toán theo pattern như sau `_rol1_(map[index]+input,1)` nên ta có thể tìm lại được input ban đầu bằng cách đảo lại thứ tự của vòng `do while` trên (v1 -> v2), thay `_rol1_` thành `_ror_1` và cuối cùng lấy kết quả của cyphertext trừ đi cho `map[index]`, hoặc ta cũng có thể build lại hàm trên và bruteforce (ban đầu mình cũng nghĩ đến z3 nhưng vì một lí do nào đó mà không được)

- Cuối cùng thì input sau khi được biến đổi sẽ được kiểm tra tại đây
```C
bool __fastcall sub_7FF7EDF11150(const void *a1)
{
  return memcmp(a1, &unk_7FF7EDF36000, 0x30ui64) == 0;
}
```
- Input sau khi được biến đổi sẽ được kiểm tra với `unk_7FF7EDF36000`. Với những dữ kiện này, ta có thể dễ dàng viết script như bên dưới
## Script and Flag
```python
def ror(val, bits, bit_size):
    return ((val & (2 ** bit_size - 1)) >> bits % bit_size) | \
           (val << (bit_size - (bits % bit_size)) & (2 ** bit_size - 1))
cyphertext = [0xE5, 0xA8, 0x07, 0x2E, 0xE8, 0x67, 0xB5, 0x0C, 0xF9, 0x05, 
  0xA1, 0xA8, 0xFA, 0x05, 0x0A, 0x66, 0xA0, 0xC1, 0x20, 0x4E, 
  0xE3, 0x7D, 0xD0, 0x04, 0x21, 0x67, 0xEC, 0x9E, 0x7D, 0xBC, 
  0x2D, 0x8D, 0x9B, 0x65, 0xDC, 0x71, 0xE4, 0x57, 0x81, 0x11, 
  0x1A, 0x71, 0x7F, 0x84, 0x2C, 0x88, 0x25, 0x94]
map = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 
  0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 
  0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 
  0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
  0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 
  0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
  0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 
  0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 
  0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 
  0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 
  0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
  0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 
  0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
  0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 
  0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 
  0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
  0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 
  0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
  0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 
  0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
  0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 
  0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 
  0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
dest = [0]*len(cyphertext)
for i in range(0,len(cyphertext),8):
  v1 = cyphertext[i]
  v2 = cyphertext[i+1]
  v18 = ord("c")
  v17 = ord("o")
  v3 = cyphertext[i+2]
  v16 = ord("n")
  v4 = cyphertext[i+3]
  v15 = ord("f")
  v5 = cyphertext[i+4]
  v14 = ord("u")
  v6 = cyphertext[i+5]
  v7 = ord("s")
  v8 = cyphertext[i+6]
  v9 = ord("e")
  result = cyphertext[i+7]
  v11 = ord("d")
  v12 = 100
  while(v12):
    v1 = 0xFF&(ror(v1, 1, 8)) - map[(v11 + result)&0xFF] 
    result = 0xFF&ror(result, 1, 8) - map[(v9 + v8)&0xFF] 
    v8 = 0xFF&ror(v8, 1, 8) - map[(v6 + v7)&0xFF] 
    v6 = 0xFF&ror(v6, 1, 8) - map[(v5 + v14)&0xFF] 
    v5 = 0xFF&ror(v5, 1, 8) - map[(v4 + v15)&0xFF] 
    v4 = 0xFF&ror(v4, 1, 8) - map[(v3 + v16)&0xFF] 
    v3 = 0xFF&ror(v3, 1, 8) - map[(v2 + v17)&0xFF] 
    v2 = 0xFF&ror(v2, 1, 8) - map[(v1 + v18)&0xFF] 
    v12 -=1
  dest[i]=v1
  dest[i+1]=v2
  dest[i+2]=v3
  dest[i+3]=v4
  dest[i+4]=v5
  dest[i+5]=v6
  dest[i+6]=v8
  dest[i+7]=result
for i in dest:
  print(chr(i),end='')
```
# Math 1
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/4fb719cf-cbd2-493f-b02f-9722643172e4)

## Detailed Analysis
- Bởi bài này có rất nhiều những đoạn code không liên quan nên mình sẽ chỉ nhặt một số những đoạn đáng chú ý. Bởi để rev được các bài code bằng Rust thì mã giả sẽ không đáng tin cậy và để thực sự rõ được chương trình đang làm gì thì debug là giải pháp duy nhất  (Its all fun and game until you have to reverse a Rust sample)

```C
  LOWORD(v0) = 0x1110;
  LOWORD(v12) = 0x1918;
  v55 = (unsigned int)v12;
  v13 = v65;
  do
  {
    v16 = 4LL;
    if ( v11 < 4 )
      v16 = v11;
    v72 = v11;
    v61 = v0;
    if ( v11 == 1 )
    {
      v53 = 0;
      v17 = 0;
      v18 = 0;
    }
    else
    {
      v18 = v13[1];
      if ( v11 == 2 )
      {
        v53 = 0;
        v17 = 0;
      }
      else
      {
        v17 = v13[2];
        if ( v11 == 3 )
          v53 = 0;
        else
          v53 = v13[3];
      }
    }
```
- Đoạn code bên trên đầu tiên sẽ khởi tạo 2 seed `v0` và `v12`. Sau đó chia input của user ra làm 4 kí tự 1 (2 block 16 bits)

```C
   if ( (void **)v23 == v57 )
      {
        alloc::raw_vec::RawVec$LT$T$C$A$GT$::grow_one::hcb77b4cc7fe90c59(&v57, 2LL);
        v27 = (__int64)v58;
      }
      v30 = (v29 + __ROL2__(v28, 9)) ^ v25;
      *(_WORD *)(v27 + 2 * v23) = v30;
      v59 = v23 + 1;
      v31 = v64;
      if ( v64 == v62 )
        alloc::raw_vec::RawVec$LT$T$C$A$GT$::grow_one::hcb77b4cc7fe90c59(&v62, 2LL);
      v63[v31] = v30 ^ __ROL2__(v29, 2);
      v24 = v31 + 1;
      v64 = v31 + 1;
      if ( v25 == 20 )
        break;
      v23 = v59;
      ++v25;
      v26 = v59 - 1;
      if ( !v59 )
        goto LABEL_87;
    }
```
- Đoạn code này sẽ có nhiệm vụ khởi tạo 2 array dựa trên hai seed `v0` và `v12` mà mình đã đề cập ở trên bằng các phép `ROL` và `XOR`

```C
       do
        {
          LOWORD(v22) = __ROL2__(v22, 9);
          v22 += v36;
          LOWORD(v22) = *v34++ ^ v22;
          LOWORD(v36) = __ROL2__(v36, 2);
          v36 ^= v22;
          --v35;
        }
        while ( v35 );
      }
      else
      {
        v36 = v54;
      }
      if ( (v31 & 0x7FFFFFFFFFFFFFFFuLL) >= 3 )
      {
        do
        {
          LOWORD(v22) = __ROL2__(v22, 9);
          v37 = v36 + v22;
          LOWORD(v37) = *v34 ^ v37;
          LOWORD(v36) = __ROL2__(v36, 2);
          v38 = v37 ^ v36;
          LOWORD(v37) = __ROL2__(v37, 9);
          v39 = v38 + v37;
          LOWORD(v39) = v34[1] ^ v39;
          LOWORD(v38) = __ROL2__(v38, 2);
          v40 = v39 ^ v38;
          LOWORD(v39) = __ROL2__(v39, 9);
          v41 = v40 + v39;
          LOWORD(v41) = v34[2] ^ v41;
          LOWORD(v40) = __ROL2__(v40, 2);
          v42 = v41 ^ v40;
          LOWORD(v41) = __ROL2__(v41, 9);
          v22 = v42 + v41;
          LOWORD(v22) = v34[3] ^ v22;
          LOWORD(v42) = __ROL2__(v42, 2);
          v36 = v22 ^ v42;
          v34 += 4;
        }
        while ( v34 != (_WORD *)(v33 + 2 * v24) );
      }
    }
    if ( v32 )
      _rust_dealloc();
    v43 = _byteswap_ulong((v55 << 16) | (unsigned __int16)v61);
    v44 = dword_483D0[(unsigned __int8)~(_BYTE)v43] ^ 0xFFFFFF;
    v45 = dword_483D0[(unsigned __int8)(BYTE2(v43) ^ LOBYTE(dword_483D0[(unsigned __int8)(BYTE1(v43) ^ v44)]) ^ BYTE1(v44))] ^ ((dword_483D0[(unsigned __int8)(BYTE1(v43) ^ v44)] ^ (v44 >> 8)) >> 8);
    v46 = dword_483D0[HIBYTE(v43) ^ (unsigned __int8)v45] ^ (v45 >> 8);
    v47 = v68;
    v13 = v73;
    if ( v68 == v66 )
      alloc::raw_vec::RawVec$LT$T$C$A$GT$::grow_one::h15e92b46b579b29e(&v66);
    v0 = ~v46;
    v14 = (__int64)v67;
    v67[2 * v47] = v22;
    *(_WORD *)(v14 + 4 * v47 + 2) = v36;
    v15 = v47 + 1;
    v68 = v15;
    v55 = HIWORD(v0);
    v11 = v72;
  }
  while ( v72 );
```
- Đoạn code này sẽ tiến hành biến đổi 2 block 16 bits input của user bằng các phép `ROR`, `XOR` và `+`, cụ thể thì vòng `do while` đẩu tiên sẽ lặp 2 lần còn vòng `do while` tiếp theo sẽ lặp trong khoảng `length của array được khởi tạo bởi seed - 2 (20 lần)`. Cuối cùng thì khởi tạo seed mới thông qua 1 map `dword_483D0` và tiếp tục vòng lặp cho đến khi duyệt hết input. Sau khi biến đổi xong thì sẽ kiểm tra lần lượt các khối 16 bit một của input với các khối 16 bit được khởi tạo từ `xmmword_48000`, `xmmword_48010`. `0x8FE70E707F8D8AA3` và `0x8F5EE71E`
- Bài này tuy không khó nhưng bởi số lượng các phép biến đổi rất nhiều và đồng thời các datatype được gắn cho các biến cũng khá loằng ngoằng nên ta phải lưu ý. Bên dưới là script bruteforce 2 block 16 bits flag của mình(chạy sẽ khá lâu đó :v)

## Script and Flag
```python
import struct
def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]
def rol(val, bits, bit_size):
    return (val << bits % bit_size) & (2 ** bit_size - 1) | \
           ((val & (2 ** bit_size - 1)) >> (bit_size - (bits % bit_size)))

cyphertext = [0xF34A, 0x3AA8, 0xFC90, 0x415D, 0xC87B, 0xC88A, 0x234C, 0xB629, 0xFE48, 0x8D12,
0xD395, 0x2437, 0x2544, 0x19C2, 0xF1FA, 0x7A41, 0x8AA3, 0x7F8D, 0x0E70, 0x8FE7,
0xE71E, 0x8F5E]
v0 = 0x1110
v12 = 0x1918

map = [0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706aF48F, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bF1d91, 0x1db71064, 0x6ab020F2, 0xF3b97148, 0x84be41de,
0x1adad47d, 0x6ddde4eb, 0xF4d4b551, 0x83d385c7, 0x136c9856, 0x646ba8c0, 0xFd62F97a, 0x8a65c9ec, 0x14015c4F, 0x63066cd9,
0xFa0F3d63, 0x8d080dF5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85Fd, 0xa50ab56b,
0x35b5a8Fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcF940, 0x32d86ce3, 0x45dF5c75, 0xdcd60dcF, 0xabd13d59, 0x26d930ac, 0x51de003a,
0xc8d75180, 0xbFd06116, 0x21b4F4b5, 0x56b3c423, 0xcFba9599, 0xb8bda50F, 0x2802b89e, 0x5F058808, 0xc60cd9b2, 0xb10be924,
0x2F6F7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106, 0x98d220bc, 0xeFd5102a, 0x71b18589, 0x06b6b51F,
0x9FbFe4a5, 0xe8b8d433, 0x7807c9a2, 0x0F00F934, 0x9609a88e, 0xe10e9818, 0x7F6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
0x6b6b51F4, 0x1c6c6162, 0x856530d8, 0xF262004e, 0x6c0695ed, 0x1b01a57b, 0x8208F4c1, 0xF50Fc457, 0x65b0d9c6, 0x12b7e950,
0x8bbeb8ea, 0xFcb9887c, 0x62dd1ddF, 0x15da2d49, 0x8cd37cF3, 0xFbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
0x4adFa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6F4Fb, 0x4369e96a, 0x346ed9Fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
0xaa0a4c5F, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206F85b3, 0xb966d409, 0xce61e49F,
0x5edeF90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abFb3b6,
0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277aF, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
0xe40ecF0b, 0x9309FF9d, 0x0a00ae27, 0x7d079eb1, 0xF00F9344, 0x8708a3d2, 0x1e01F268, 0x6906c2Fe, 0xF762575d, 0x806567cb,
0x196c3671, 0x6e6b06e7, 0xFed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc, 0xF9b9dF6F, 0x8ebeeFF9, 0x17b7be43, 0x60b08ed5,
0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4FdFF252, 0xd1bb67F1, 0xa6bc5767, 0x3Fb506dd, 0x48b2364b, 0xd80d2bda, 0xaF0a1b4c,
0x36034aF6, 0x41047a60, 0xdF60eFc3, 0xa867dF55, 0x316e8eeF, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256Fd2a0, 0x5268e236,
0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262F, 0xc5ba3bbe, 0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7FFa7, 0xb5d0cF31,
0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63F226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363F, 0x72076785, 0x05005713,
0x95bF4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b, 0xe5d5be0d, 0x7cdceFb7, 0x0bdbdF21, 0x86d3d2d4, 0xF1d4e242,
0x68ddb3F8, 0x1Fda836e, 0x81be16cd, 0xF6b9265b, 0x6Fb077e1, 0x18b74777, 0x88085ae6, 0xFF0F6a70, 0x66063bca, 0x11010b5c,
0x8F659eFF, 0xF862ae69, 0x616bFFd3, 0x166ccF45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016F7,
0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40dF0b66, 0x37d83bF0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cF7F, 0x30b5FFe9,
0xbdbdF21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693, 0x54de5729, 0x23d967bF, 0xb3667a2e, 0xc4614ab8,
0x5d681b02, 0x2a6F2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05dF1b, 0x2d02eF8d]


for i in range(0,44,4):
    hex_1 = [v12]
    hex_2 = [v0]
    for j in range(21):
        v30 = (hex_1[j]+((hex_2[j]&0xFFFF0000)| rol(hex_2[j]&0xFFFF,9,16))) ^ j
        hex_2.append(v30&0xFFFF)
        vv = v30 ^ ((hex_1[j]&0xFFFF0000)| rol(hex_1[j]&0xFFFF,2,16))
        hex_1.append(vv&0xFFFF)
    for k in range(0x20,0x7F):
        for m in range(0x20,0x7F):
            for n in range(0x20,0x7F):
                for o in range(0x20,0x7F):
                
                    count = 0
                    v22 = (n<<8) | o   

                    v36 = (k<<8) | m   

                    for j in range(2):
                        v22 =(v22&0xFFFF0000)| rol(v22&0xFFFF,9,16)
                        v22 = (v36 + v22)
                        v22 = (v22&0xFFFF0000)|(hex_1[count]^(v22&0xFFFF))
                        v36 =(v36&0xFFFF0000)| rol(v36,2,16) 
                        v36 ^= v22
                        count +=1
                    while(count < len(hex_1)):
                        v22 =(v22&0xFFFF0000)| rol(v22&0xFFFF,9,16)
                        v37 = v36 + v22
                        v37 =(v37&0xFFFF0000)| (hex_1[count]^(v37&0xFFFF))
                        v36 =(v36&0xFFFF0000)| rol(v36,2,16)
                        v38 = v37 ^ v36 
                        v37 = (v37&0xFFFF0000)| rol(v37&0xFFFF,9,16)
                        v39 = v38 + v37
                        v39 = (v39&0xFFFF0000)| (hex_1[count+1]^(v39&0xFFFF))
                        v38 = (v38&0xFFFF0000)| rol(v38,2,16)
                        v40 = v39 ^ v38
                        v39 = (v39&0xFFFF0000)| rol(v39&0xFFFF,9,16)
                        v41 = v40 + v39
                        v41 = (v41&0xFFFF0000)| (hex_1[count+2]^(v41&0xFFFF))
                        v40 = (v40&0xFFFF0000)| rol(v40,2,16)
                        v42 = v41 ^ v40 
                        v41 = (v41&0xFFFF0000)| rol(v41&0xFFFF,9,16)
                        v22 = v42 + v41
                        v22 = (v22&0xFFFF0000)| (hex_1[count+3]^(v22&0xFFFF))
                        v42 = (v42&0xFFFF0000)| rol(v42,2,16)
                        v36 = v22 ^ v42
                        count += 4

                    v43 = swap32((v12<<16)|(v0&0xFFFF))
                    v44 = map[(~v43)&0xFFFFFFFF&0xFF] ^ 0xFFFFFF
                    v45 = (((map[((v43>>8)^v44)&0xFF])^(v44>>8))>>8) ^ map[(((map[((v43>>8)^v44)&0xFF])^(v44>>8))^(v43>>16))&0xFF]
                    v46 = map[(v43>>24)^(v45&0xFF)] ^ (v45>>8)
                    v0 = ((~v46)&0xFFFFFFFF)
                            
                    if(((v22)&0xFFFF == cyphertext[0]) and ((v36)&0xFFFF == cyphertext[1])): #for each cyphertext replace cyphertext's indices accordingly (22 in total btw) 
                        print(hex(((n<<8) | o)),hex((k<<8) | m))
    v55 = v0 >> 0x10
    v12 = v55
```
# Math 2
## Mics
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/f58adeb7-c4f8-4031-af22-e862df77dec0)

## Detailed Analysis
- Hàm `main`
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // ebx
  char v5; // [rsp+13h] [rbp-107Dh]
  unsigned __int16 v6; // [rsp+14h] [rbp-107Ch]
  unsigned __int16 v7; // [rsp+16h] [rbp-107Ah]
  unsigned __int16 v8; // [rsp+18h] [rbp-1078h]
  int v9; // [rsp+1Ch] [rbp-1074h] BYREF
  unsigned int v10; // [rsp+20h] [rbp-1070h] BYREF
  unsigned int v11; // [rsp+24h] [rbp-106Ch] BYREF
  int i; // [rsp+28h] [rbp-1068h]
  int j; // [rsp+2Ch] [rbp-1064h]
  int v14; // [rsp+30h] [rbp-1060h]
  unsigned int k; // [rsp+34h] [rbp-105Ch]
  int m; // [rsp+38h] [rbp-1058h]
  int n; // [rsp+3Ch] [rbp-1054h]
  int ii; // [rsp+40h] [rbp-1050h]
  unsigned int v19; // [rsp+44h] [rbp-104Ch]
  int v20; // [rsp+48h] [rbp-1048h]
  unsigned int v21; // [rsp+4Ch] [rbp-1044h]
  __int64 v22; // [rsp+50h] [rbp-1040h]
  __int64 v23; // [rsp+58h] [rbp-1038h]
  __int64 v24; // [rsp+60h] [rbp-1030h]
  unsigned __int64 v25; // [rsp+68h] [rbp-1028h]
  char v26[24]; // [rsp+70h] [rbp-1020h]
  unsigned __int64 v27; // [rsp+1078h] [rbp-18h]
  __int64 savedregs; // [rsp+1090h] [rbp+0h] BYREF

  v27 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  for ( i = 0; i <= 511; ++i )
  {
    for ( j = 0; j <= 7; ++j )
      *((_BYTE *)&savedregs + 8 * j + i - 4128) = 0;
  }
  puts("*****************");
  puts("* PWNYMAPS v0.1 *");
  puts("*****************");
  puts("The developer has only tested non-earth planetary systems. Please proceed with caution.");
  printf("%s", "Indicate your directional complexity level: ");
  __isoc99_scanf("%u", &v9);
  getchar();
  if ( (unsigned int)v9 > 0x200 )
    goto LABEL_26;
  v14 = 1;
  for ( k = 0; (int)k < v9; ++k )
  {
    printf("Indicate your 'Earth'-type coordinate %x {{hintText.toUpperCase()}}: ", k);
    __isoc99_scanf("%u%u", &v10, &v11);
    getchar();
    if ( v11 > 0xFFFFFFF )
      goto LABEL_26;
    v19 = v10 >> 8;
    v6 = (16 * v10) & 0xFF0 | (v11 >> 28);
    v7 = HIWORD(v11) & 0xFFF;
    v8 = EncodeMorton_12bit((unsigned __int16)v11 >> 10, (v11 >> 4) & 0x3F);
    v20 = EncodeMorton_24bit(v8, v7);
    v24 = EncodeMorton_48bit(v19, v7);
    v25 = (v24 << 12) | v6;
    v26[8 * k] = Unpad64Bit_8Bit(v25);
    v26[8 * k + 1] = Unpad64Bit_8Bit(v25 >> 1);
    v26[8 * k + 2] = Unpad64Bit_8Bit(v25 >> 2);
    v26[8 * k + 3] = Unpad64Bit_8Bit(v25 >> 3);
    v26[8 * k + 4] = Unpad64Bit_8Bit(v25 >> 4);
    v26[8 * k + 5] = Unpad64Bit_8Bit(v25 >> 5);
    v26[8 * k + 6] = Unpad64Bit_8Bit(v25 >> 6);
    v26[8 * k + 7] = Unpad64Bit_8Bit(v25 >> 7);
    v5 = v26[8 * k + 1];
    v26[8 * k + 1] = v26[8 * k + 5];
    v26[8 * k + 5] = v5;
    v21 = numberOfSetBits((unsigned __int16)((((unsigned __int8)v26[8 * k + 4] << 8) | (unsigned __int8)v26[8 * k + 5]) ^ (((unsigned __int8)v26[8 * k + 2] << 8) | (unsigned __int8)v26[8 * k + 3]) ^ ((unsigned __int8)v26[8 * k + 1] | ((unsigned __int8)v26[8 * k] << 8)) ^ (((unsigned __int8)v26[8 * k + 6] << 8) | (unsigned __int8)v26[8 * k + 7])));
    v3 = correct_checksums[k];
    if ( v3 != (unsigned int)hash(v21) )
      v14 = 0;
  }
  if ( v14 )
  {
    for ( m = 1; m < v9; ++m )
    {
      for ( n = 0; n <= 7; ++n )
      {
        numberOfSetBits(*((unsigned __int8 *)&savedregs + 8 * m + n - 4136));
        *((_BYTE *)&savedregs + 8 * m + n - 4128) = *((_BYTE *)&savedregs + 8 * m + n - 4128);
      }
    }
    for ( ii = 0; ii < v9; ++ii )
    {
      v22 = EncodeMorton_9x7bit(
              v26[8 * ii] & 0x7F,
              v26[8 * (ii % v9) + 1] & 0x7F,
              v26[8 * (ii % v9) + 2] & 0x7F,
              v26[8 * (ii % v9) + 3] & 0x7F,
              v26[8 * (ii % v9) + 4] & 0x7F,
              v26[8 * (ii % v9) + 5] & 0x7F,
              v26[8 * (ii % v9) + 6] & 0x7F,
              v26[8 * (ii % v9) + 7] & 0x7F,
              ((int)(unsigned __int8)v26[8 * ii + 6] >> 6) & 2 | ((int)(unsigned __int8)v26[8 * ii + 5] >> 5) & 4 | ((int)(unsigned __int8)v26[8 * ii + 4] >> 4) & 8 | ((int)(unsigned __int8)v26[8 * ii + 3] >> 3) & 0x10 | ((int)(unsigned __int8)v26[8 * ii + 2] >> 2) & 0x20 | ((int)(unsigned __int8)v26[8 * ii + 1] >> 1) & 0x40u | ((unsigned __int8)v26[8 * ii + 7] >> 7));
      v23 = (unsigned __int8)v26[8 * ii] >> 7;
      v22 |= v23 << 63;
      if ( v22 != correct[ii] )
        goto LABEL_26;
    }
    puts("You have reached your destination. PWNYMAPS does not support route plotting yet.");
    return 0;
  }
  else
  {
LABEL_26:
    puts("Continue straight for 500 meter(s) into Lake Michigan.");
    return 1;
  }
}
```
- Nhìn qua thì có vẻ đây là một bài bắt nhập tọa độ để gen ra một map phụ thuộc vào độ phức tạp của map muốn tạo. Tùy thuộc vào độ phức tạp ta nhập vào bao nhiêu thì ta sẽ phải nhập bấy nhiêu cái tọa độ (tọa độ có dạng x,y). Sau đó tọa độ mà ta nhập vào sẽ được biến đổi thông qua các hàm như `EncodeMorton_12bit`, `Unpad64Bit_8Bit`,... và cuối cùng kiểm tra với `correct`
- Với điều kiện cuối cùng là kiểm tra với `correct` ta có thể trace ngược lại những variables có liên quan là `v22` -> `v23` -> `v26` -> `v25` -> `v11 & v6(x&y)`
- Vậy để giải ta chỉ cần viết script cho những biến để tìm các biến liên quan và build lại các hàm nếu cần thiết. May thay các hàm này không quá phức tạp nên ta chỉ cần chép chúng ra, sửa lại data type và ném vào script(z3). Bởi số lượng data cũng như là các hàm cần phải build lại khá là lớn nên mình sẽ phân script ra làm 3 phase để tiện hơn

![image](https://github.com/user-attachments/assets/336087a3-34de-4721-b65d-cbb5c23a22de)

![image](https://github.com/user-attachments/assets/ac438d6e-f564-4513-b20d-959c794a0748)

## Script and Flag
```python
# find v26 phase
from z3 import *
v9 = 513
def Pad7Bit(a1):
    a1 &= 0xFF
    return a1 & 1 | (((a1&0xFFFFFFFFFFFFFFFF) & 0x7F) << 32) & 0x1000000001 | ((a1 & 0xF | (((a1&0xFFFFFFFFFFFFFFFF) & 0x7F) << 32) & 0x700000000F) << 16) & 0x40001000040001 | ((a1 & 3 | (((a1&0xFFFFFFFFFFFFFFFF) & 0x7F) << 32) & 0x3000000003 | ((a1 & 0xF | (((a1&0xFFFFFFFFFFFFFFFF) & 0x7F) << 32) & 0x700000000F) << 16) & 0x400030000C0003) << 8) & 0x40201008040201
def EncodeMorton_9x7bit(a1,a2,a3,a4,a5,a6,a7,a8,a9):
    a1 &= 0xFF
    a2 &= 0xFF
    a3 &= 0xFF
    a4 &= 0xFF
    a5 &= 0xFF
    a6 &= 0xFF
    a7 &= 0xFF
    a8 &= 0xFF
    a9 &= 0xFF
    v9 = Pad7Bit(a1)
    v10 = (2 * Pad7Bit(a2)) | v9
    v11 = (4 * Pad7Bit(a3)) | v10
    v12 = (8 * Pad7Bit(a4)) | v11
    v13 = (16 * Pad7Bit(a5)) | v12
    v14 = (32 * Pad7Bit(a6)) | v13
    v15 = (Pad7Bit(a7) << 6) | v14
    v16 = (Pad7Bit(a8) << 7) | v15
    return v16 | (Pad7Bit(a9) << 8)
v26 = [BitVec('x[%d]'%i,64) for i in range(8*(336%512))]
s = Solver()
correct = [0x00022640ABA57200, 0x0008004479D42852, 0x000880054948C092, 0x0008A41420193A02, 0x00400541D1E04050, 0x004821117A352810, 0x004A0044C8404A12, 0x004A245518302A90, 0x004A24557B20D892, 0x004A2650E3796050,
0x010A01442864E2D0, 0x0108A505E86D6802, 0x0108A50451E1C880, 0x0108A505F3EC4010, 0x0108A70169E13012, 0x0108A7011AF138D0, 0x0108860412910010, 0x01422700D0B40812, 0x0142865141E590C0, 0x0142A44551DCE092,
0x0148A455682D2000, 0x014A2545A205AA92, 0x0400A0550A055212, 0x0402A1044BEC02C2, 0x0408250471C01280, 0x04088145FB0D1852, 0x0408834010DC50C0, 0x04088211F1A83012, 0x050227401A7400C2, 0x050202007AA948C0,
0x0500835170E80042, 0x044A071423453280, 0x0448A30420E53000, 0x0442A601BA382A52, 0x04422751CA9DDAD0, 0x0442045472A068C0, 0x0442810491C9B012, 0x0448245568915880, 0x044A2044C9FDE000, 0x0500054449210290,
0x0502044461B93242, 0x0548851463309A82, 0x054825446B34E012, 0x05482105BA4CB042, 0x0548230008D5C852, 0x0548230018DCF292, 0x0548261528B93800, 0x054807559B9928D0, 0x0542A4D162197A02, 0x054801913325BA90,
0x0548848189197012, 0x054A8614B1ACB202, 0x1002A31432D18890, 0x1008074499F8B090, 0x054A8304B2D578C0, 0x0540A75590C45A40, 0x054023543B083AD0, 0x050826453AF42010, 0x1048A00422488082, 0x10488015436C0082,
0x1048235023E1B840, 0x104822401ABC48C2, 0x1048071423B4E252, 0x10480714F370E090, 0x104821D022ADEAD2, 0x1048A5D190B072D0, 0x104A81D0D074A850, 0x1102219079E8F2D2, 0x110884C1BB8C0212, 0x1108A61051C988C2,
0x11020650F2100800, 0x104A824071B45812, 0x10420700D1893A50, 0x10402750F19DF080, 0x100A8600D00128C0, 0x14088401FB31D250, 0x14082101FB75B802, 0x114AA544C324F200, 0x140000546A19E842, 0x14000515BA2972C2,
0x1400071099100A42, 0x114AA740731408C0, 0x114A82017160EA10, 0x1142230402F4C850, 0x11408705A135F240, 0x1140A654614C0A80, 0x1148830563BD5A52, 0x114A831519A56080, 0x14002355F03950D2, 0x14008091E8EDD210,
0x1400A08032B172D2, 0x140821852BC00050, 0x144000C449118242, 0x1500001461ED8290, 0x144AA154B288C082, 0x144AA350001CD880, 0x144AA7016BE07840, 0x1500231071E41AD2, 0x150026452BECCAD2, 0x144AA58039586A52,
0x150024C17A053A42, 0x150024C173551A12, 0x150A25150A45F2D0, 0x154005558B45C802, 0x15422005AA558842, 0x154880058B8DD252, 0x800001046854AAC0, 0x80020004E175F2C2, 0x800280544931F000, 0x8008A054C3303A00,
0x80482541A1C5D2D2, 0x8048210038A542C0, 0x80480114AA697840, 0x8042A015B3917A52, 0x804283502048A0C0, 0x8040A310F8D91240, 0x8040A314221110D2, 0x8040A644BA291890, 0x80420615197C2892, 0x804AA254FBF8A8D0,
0x8102A20478A938D2, 0x810A031539F55250, 0x81420701F81D7AD0, 0x814226501230BA12, 0x814003412855CAC0, 0x810801047A995250, 0x8100A105137DEA90, 0x814AA454F1A5D840, 0x814AA21028C50252, 0x814A8351C16C80D0,
0x814A2711F25CD250, 0x814A8245A234BAC2, 0x814A2715F195D090, 0x814A80C189F828C0, 0x840082549B2D7A50, 0x840203459138A0C0, 0x84088644D961AA00, 0x844087047B200A90, 0x8440A65453248A50, 0x8502A14533580092,
0x85020414D0E5AA40, 0x844AA1055BFCA8C2, 0x8448A6009814CA52, 0x8448A60408A56AD0, 0x844A8314B864B210, 0x85020304B2293842, 0x850803143B6DD212, 0x850A0655A1A97092, 0x85088711DAD17A12, 0x8502271050A0B880,
0x844AA30050451AC0, 0x8542A005195DB8C0, 0x8542A310022C9892, 0x8542A310B9C8D850, 0x8548260401907080, 0x854883556288F010, 0x854A05D0088D1A12, 0x854A2180C3C91A52, 0x854A859409A96052, 0x9000219468CDC212,
0x90020584302CB252, 0x900800D5E0AC2090, 0x90402494E9A49AC0, 0x904201C5A829B802, 0x9040A245B2A40280, 0x900A0744D3E8B2C2, 0x900001C029517282, 0x854024D08325CA92, 0x850A208121FC4810, 0x904A0515B26D8812,
0x904800459B3DE810, 0x9040871022A1D0C0, 0x9042A251710D0812, 0x904206516838A290, 0x904222005115C050, 0x90482344A38930C0, 0x904A0715EAE99A42, 0x910202059A1532D0, 0x9108065542FDF042, 0x910A2214A03C58D0,
0x910A221058B4F052, 0x910282503BBC9852, 0x904A82109B2412D2, 0x904A8455B9F8C2D2, 0x9100251598492A42, 0x91088414F0F52052, 0x91482545385998D2, 0x91482545710492C2, 0x91488250C36DE0D2, 0x9148A7013AC000D2,
0x914887150B09F280, 0x9148871568412290, 0x914A231480D42240, 0x94002215299CFA52, 0x9400A30508A91AC2, 0x9408870528981050, 0x940A230589CC5212, 0x940A0445B0703092, 0x9440A405100DC292, 0x94428005B9FCC8D0,
0x944884559A6D0852, 0x944A2404F21142D2, 0x9500241472CD1840, 0x9508A410F32C7AC0, 0x950885558038C840, 0x95088554B3003202, 0x95088445DA497AC2, 0x950887509075E850, 0x9508A301DBC11210, 0x9508A745E999F850,
0x9540260548056000, 0x9542A354CAC4A892, 0x95488610FAA94250, 0x954A0700985032C2, 0x9542860009D18292, 0x950AA4445B513AC2, 0x0020A75423B48880, 0x0020A640F855BA90, 0x0022260042397850, 0x002A045473F45052,
0x002AA05552306240, 0x00608310A93D4A02, 0x00622351C0388850, 0x0062A3105204EA92, 0x0062A31039B98A40, 0x006A044572B89842, 0x006AA2410204D842, 0x012002114AE010C0, 0x012222117A910282, 0x01228315298C82D0,
0x012A24057B4D32D2, 0x016002014BB03090, 0x0160020113C0B0C2, 0x012AA214E2D42082, 0x012AA214B134A812, 0x01602741DA91F0D2, 0x016803552B74DAC2, 0x016A86544B7C5292, 0x042883048301A280, 0x04282641B07D6212,
0x04288610033C4050, 0x04602150A944DA42, 0x0468805071794AD0, 0x046A24415ACC12C0, 0x05200044E35D7A02, 0x05222504F1E19AD0, 0x052A2740E0BCD090, 0x05602751192D18D0, 0x056203517A69D002, 0x0562265501008280,
0x052A8710415D8A90, 0x0528835109159840, 0x05208641A8F070D2, 0x05202211EB05D8C2, 0x046A8300D1DD1A40, 0x04688255A3ACD2C0, 0x0462A6556A442852, 0x04222745A8250AD0, 0x0420A3446BC4FA92, 0x0460814123A1FA82,
0x046205416B91E010, 0x056AA1445A453012, 0x056AA210290C1AD0, 0x056A8700600DEA92, 0x10200200704152C2, 0x10208255A09CB810, 0x102206544290C282, 0x102A865582498242, 0x10602711394CA802, 0x10602710B97190C2,
0x1060A21152D138C0, 0x10620645A3B8F052, 0x10680215A0A9EA10, 0x106A02448B0502C0, 0x106A875139187802, 0x106AA741A8892A82, 0x1120060089C18850, 0x11602455D2F84010, 0x1160875062D1FA82, 0x112AA600D9510A40,
0x112A2314C80C0A82, 0x11228241D9248A10, 0x11222601BAD46A80, 0x1122260109B060C0, 0x1128A2404870F050, 0x11688500516DAA10, 0x116A055429A87AD0, 0x116A25459248A882, 0x116A8405F2AC4AD0, 0x116AA701C8C402D0,
0x1420220153397A00, 0x142023140AB00A92, 0x14202314C1851842, 0x1420275443F1E0C0, 0x14208615EB14EA52, 0x142827054A9C98C2, 0x142A030542544280, 0x142AA65520E958C2, 0x14608710500132C2, 0x142AA651A2003252,
0x1428224002A5D0C2, 0x14202750AB94CA10, 0x1560A64548F04A00, 0x1560071439743A02, 0x1528264419ECF240, 0x15228715E3DC5810, 0x1520A3419294E0D2, 0x152223019A78A852, 0x1528861098889050, 0x152A234061A85292,
0x152A234009C57A00, 0x152824451064E0C0, 0x15200545B970F8C0, 0x15602500D3380042, 0x1560A55423398800, 0x1562A145EB6CA800, 0x15688405335C88D0, 0x156A0015F89C2890, 0x156823018B357092, 0x156226006A3D6040,
0x15680641CBF038D2, 0x156AA7111BF5B212, 0x8022865179FC2A92, 0x8022A31428A11AC0, 0x802082044AC42240, 0x156A2645EACCCA10, 0x15688254B10D5A00, 0x1568871552381810, 0x1568859162609AC0, 0x156821801B78CA50,
0x156281D1706CF892, 0x156081C5218122C0, 0x156000D5ABB11090, 0x152A24D582389002, 0x152A00C461119880, 0x0000000000000000]
for i in range(336):
    v22 = EncodeMorton_9x7bit(
    v26[8 * i] & 0x7F,
    v26[8 * (i % v9) + 1] & 0x7F,
    v26[8 * (i % v9) + 2] & 0x7F,
    v26[8 * (i % v9) + 3] & 0x7F,
    v26[8 * (i % v9) + 4] & 0x7F,
    v26[8 * (i % v9) + 5] & 0x7F,
    v26[8 * (i % v9) + 6] & 0x7F,
    v26[8 * (i % v9) + 7] & 0x7F,
    ((v26[8 * i + 6]&0xFF) >> 6) & 2 | ((v26[8 * i + 5]&0xFF) >> 5) & 4 | ((v26[8 * i + 4]&0xFF) >> 4) & 8 | ((v26[8 * i + 3]&0xFF) >> 3) & 0x10 | ((v26[8 * i + 2]&0xFF) >> 2) & 0x20 | ((v26[8 * i + 1]&0xFF) >> 1) & 0x40 | ((v26[8 * i + 7]&0xFF) >> 7))
    v23 = (v26[8 * i]&0xFF) >> 7
    v22 |= v23 << 63
    s.add(v22 == correct[i])
if(s.check() == sat):
    m = s.model()
    result = [m[v26[i]].as_long() for i in range(len(v26))]
    print(result)
```
```python
# find v25 phase
from z3 import *
def Unpad64Bit_8Bit(a1):
    a1 &= 0xFFFFFFFFFFFFFFFF
    v2 = a1 & 1 | ((a1 & 0x101010101010101) >> 1) & 1 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x2000000001 | ((a1 & 0x100000001 | ((a1 & 0x101010101010101) >> 1) & 0x80000100800001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80402100804021) >> 4) & 0x2000000003 | ((a1 & 1 | ((a1 & 0x101010101010101) >> 1) & 0x80000000000001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80402000000001 | ((a1 & 0x100000001 | ((a1 & 0x101010101010101) >> 1) & 0x80000100800001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80402100804021) >> 4) & 0x80402010080403) >> 8) & 0x6000000007 | ((a1 & 1 | ((a1 & 0x101010101010101) >> 1) & 0x80000000000001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80002000000001 | ((a1 & 0x100000001 | ((a1 & 0x101010101010101) >> 1) & 0x80000100800001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80402100804021) >> 4) & 0x80002000080003 | ((a1 & 1 | ((a1 & 0x101010101010101) >> 1) & 0x80000000000001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80402000000001 | ((a1 & 0x100000001 | ((a1 & 0x101010101010101) >> 1) & 0x80000100800001 | ((a1 & 0x1000100010001 | ((a1 & 0x101010101010101) >> 1) & 0x81008100810081) >> 2) & 0x80402100804021) >> 4) & 0x80402010080403) >> 8) & 0x80006000180007) >> 16) & 0xE00000001F
    return (v2 | (v2>>0x20))&0xFF

v26 = [46, 0, 24, 6, 42, 22, 20, 6, 12, 9, 30, 8, 7, 4, 37, 8, 8, 5, 32, 8, 5, 10, 38, 9, 50, 5, 46, 2, 2, 0, 48, 10, 64, 8, 16, 12, 29, 14, 21, 0, 124, 8, 14, 12, 19, 8, 32, 6, 74, 1, 18, 8, 45, 2, 32, 8, 122, 8, 22, 4, 35, 8, 48, 9, 120, 9, 26, 14, 33, 10, 54, 13, 112, 4, 28, 12, 47, 18, 53, 6, 14, 0, 88, 4, 55, 2, 35, 9, 44, 5, 106, 12, 30, 10, 48, 10, 32, 8, 98, 12, 20, 6, 54, 11, 36, 12, 104, 12, 29, 14, 52, 12, 40, 1, 104, 14, 23, 28, 52, 2, 40, 8, 102, 6, 23, 28, 49, 7, 0, 8, 100, 0, 1, 20, 48, 14, 100, 9, 70, 12, 57, 20, 16, 0, 84, 0, 112, 14, 36, 28, 23, 3, 100, 13, 116, 8, 39, 14, 22, 9, 124, 4, 120, 12, 2, 8, 48, 10, 102, 1, 90, 0, 59, 8, 50, 15, 62, 1, 48, 2, 65, 10, 0, 14, 46, 5, 32, 12, 116, 4, 5, 13, 34, 8, 8, 10, 84, 4, 52, 9, 12, 13, 58, 10, 89, 8, 37, 14, 4, 12, 52, 2, 84, 22, 33, 1, 16, 13, 40, 14, 75, 28, 36, 0, 44, 9, 84, 4, 116, 16, 17, 5, 8, 12, 74, 12, 96, 22, 1, 7, 16, 13, 120, 12, 84, 28, 1, 0, 86, 0, 8, 2, 118, 16, 52, 15, 100, 0, 40, 6, 86, 20, 32, 10, 106, 13, 46, 4, 107, 24, 17, 4, 126, 4, 22, 10, 121, 30, 19, 7, 80, 8, 26, 12, 98, 6, 17, 13, 64, 13, 32, 2, 127, 4, 6, 10, 120, 0, 30, 10, 64, 14, 48, 11, 108, 4, 20, 12, 110, 6, 38, 10, 10, 0, 80, 12, 81, 0, 20, 11, 2, 5, 92, 14, 98, 4, 21, 10, 82, 1, 110, 14, 80, 0, 54, 13, 108, 1, 92, 12, 83, 2, 54, 12, 108, 13, 72, 2, 94, 8, 35, 12, 108, 1, 70, 0, 85, 22, 35, 2, 110, 13, 68, 2, 87, 22, 34, 1, 120, 4, 78, 6, 66, 28, 48, 10, 88, 12, 86, 0, 91, 28, 53, 15, 114, 5, 126, 26, 98, 10, 16, 6, 86, 8, 74, 22, 83, 8, 38, 7, 72, 5, 100, 18, 75, 10, 52, 2, 86, 13, 104, 6, 106, 20, 54, 8, 48, 8, 46, 0, 53, 20, 66, 15, 8, 12, 20, 6, 31, 20, 118, 9, 68, 8, 110, 2, 126, 22, 33, 15, 118, 8, 114, 2, 92, 30, 17, 8, 122, 12, 90, 2, 83, 16, 5, 13, 44, 8, 92, 4, 71, 28, 48, 12, 96, 5, 40, 0, 4, 0, 98, 13, 84, 5, 32, 12, 4, 8, 100, 13, 112, 0, 26, 6, 22, 20, 103, 6, 108, 13, 22, 4, 0, 22, 97, 5, 86, 1, 12, 4, 19, 22, 119, 12, 80, 8, 12, 12, 31, 18, 118, 13, 118, 5, 26, 20, 19, 6, 99, 7, 114, 8, 52, 22, 27, 14, 113, 1, 84, 8, 54, 28, 63, 0, 99, 0, 58, 13, 72, 30, 55, 6, 71, 1, 14, 13, 120, 16, 9, 12, 116, 4, 48, 13, 98, 8, 4, 20, 119, 3, 16, 8, 94, 8, 40, 16, 80, 4, 68, 9, 62, 14, 33, 22, 100, 0, 66, 12, 2, 10, 59, 20, 85, 2, 116, 12, 28, 10, 26, 22, 86, 3, 0, 8, 34, 8, 42, 16, 113, 3, 10, 8, 44, 14, 73, 10, 119, 6, 44, 9, 14, 14, 94, 8, 102, 6, 102, 0, 112, 14, 58, 2, 118, 12, 24, 5, 30, 8, 66, 2, 67, 14, 26, 13, 8, 6, 90, 10, 81, 15, 26, 9, 6, 0, 88, 16, 85, 0, 100, 8, 126, 8, 48, 16, 117, 5, 66, 8, 106, 12, 39, 26, 102, 0, 100, 0, 70, 4, 53, 22, 67, 12, 70, 0, 108, 6, 26, 26, 87, 10, 118, 4, 122, 8, 4, 16, 84, 9, 70, 5, 110, 14, 17, 30, 101, 14, 92, 8, 96, 4, 50, 30, 100, 11, 48, 13, 28, 14, 89, 26, 65, 11, 30, 4, 40, 30, 77, 14, 66, 2, 34, 9, 44, 22, 67, 6, 65, 7, 40, 0, 8, 16, 85, 12, 101, 12, 74, 1, 20, 24, 64, 0, 71, 10, 22, 4, 72, 12, 69, 4, 70, 11, 112, 13, 56, 0, 120, 6, 98, 13, 116, 4, 54, 2, 112, 18, 98, 1, 104, 0, 42, 14, 118, 30, 117, 4, 54, 9, 74, 14, 85, 20, 69, 1, 46, 5, 90, 4, 69, 30, 87, 13, 106, 13, 46, 16, 119, 2, 117, 0, 46, 9, 90, 26, 66, 8, 81, 6, 38, 9, 94, 26, 69, 8, 84, 6, 62, 0, 64, 2, 119, 10, 115, 15, 92, 1, 82, 0, 92, 10, 86, 14, 108, 1, 78, 0, 108, 8, 67, 14, 78, 5, 96, 2, 73, 14, 103, 14, 142, 0, 14, 8, 22, 0, 3, 9, 134, 1, 12, 14, 46, 2, 7, 11, 152, 0, 52, 14, 34, 2, 6, 10, 178, 0, 54, 14, 10, 0, 36, 12, 230, 1, 24, 2, 29, 14, 55, 3, 238, 8, 8, 4, 16, 6, 33, 3, 216, 4, 10, 6, 30, 2, 33, 14, 242, 9, 46, 2, 43, 14, 5, 14, 208, 4, 56, 0, 54, 16, 3, 1, 250, 12, 44, 10, 28, 20, 1, 2, 240, 1, 44, 2, 17, 16, 1, 15, 232, 12, 58, 6, 9, 16, 16, 15, 220, 13, 6, 4, 39, 24, 20, 9, 248, 12, 62, 12, 47, 20, 39, 13, 168, 13, 106, 14, 35, 20, 1, 11, 158, 8, 76, 6, 53, 30, 37, 10, 206, 12, 78, 10, 59, 26, 17, 3, 242, 9, 86, 6, 35, 16, 18, 4, 206, 0, 94, 0, 20, 26, 3, 3, 138, 12, 76, 10, 17, 6, 33, 14, 166, 12, 102, 4, 23, 10, 6, 15, 244, 8, 122, 14, 40, 6, 55, 10, 254, 1, 104, 0, 37, 20, 33, 2, 212, 4, 112, 12, 61, 24, 39, 1, 246, 12, 76, 10, 61, 26, 51, 4, 198, 1, 126, 6, 42, 24, 35, 13, 244, 8, 76, 10, 57, 30, 54, 11, 200, 4, 118, 20, 46, 12, 37, 1, 158, 12, 50, 6, 75, 18, 5, 14, 128, 12, 20, 4, 122, 24, 7, 9, 138, 8, 50, 12, 78, 16, 54, 10, 202, 8, 42, 12, 81, 16, 20, 13, 246, 8, 50, 12, 65, 16, 23, 12, 160, 13, 124, 0, 117, 8, 4, 13, 150, 8, 66, 12, 110, 4, 19, 10, 236, 13, 38, 12, 118, 12, 39, 13, 238, 9, 38, 0, 73, 18, 51, 0, 238, 0, 34, 4, 67, 22, 49, 11, 222, 8, 40, 6, 127, 16, 34, 8, 128, 13, 74, 6, 122, 16, 1, 14, 158, 13, 72, 6, 85, 18, 38, 14, 144, 5, 88, 6, 107, 30, 52, 11, 154, 9, 102, 10, 95, 30, 48, 6, 176, 8, 66, 14, 114, 20, 18, 1, 230, 8, 34, 10, 116, 16, 33, 3, 236, 12, 102, 2, 102, 8, 7, 11, 244, 5, 98, 6, 113, 16, 2, 5, 248, 12, 106, 2, 125, 22, 7, 0, 224, 0, 68, 2, 66, 22, 52, 9, 208, 4, 120, 10, 83, 30, 34, 12, 222, 5, 82, 18, 113, 4, 48, 2, 226, 5, 66, 26, 125, 4, 37, 6, 216, 5, 96, 20, 115, 6, 53, 10, 190, 5, 8, 24, 21, 6, 66, 10, 134, 13, 8, 22, 51, 0, 83, 8, 148, 4, 24, 28, 11, 12, 96, 9, 254, 0, 10, 30, 8, 4, 87, 9, 200, 5, 26, 22, 58, 8, 66, 10, 230, 8, 56, 4, 8, 28, 64, 13, 130, 13, 16, 14, 62, 20, 119, 13, 138, 1, 28, 18, 22, 2, 68, 3, 246, 1, 82, 20, 73, 2, 22, 7, 164, 4, 78, 20, 101, 14, 36, 0, 212, 13, 10, 4, 61, 8, 114, 14, 204, 12, 22, 4, 11, 10, 102, 14, 208, 0, 40, 6, 16, 22, 83, 7, 244, 13, 58, 8, 33, 24, 68, 2, 218, 4, 28, 12, 35, 24, 82, 1, 228, 8, 4, 8, 33, 18, 71, 2, 224, 4, 24, 2, 26, 20, 101, 15, 218, 5, 10, 14, 60, 28, 115, 14, 142, 8, 68, 2, 43, 24, 65, 15, 148, 5, 84, 14, 6, 30, 115, 14, 180, 4, 78, 6, 41, 18, 97, 9, 188, 9, 68, 14, 35, 22, 99, 0, 156, 13, 126, 6, 33, 20, 71, 4, 222, 9, 32, 6, 41, 16, 101, 5, 218, 13, 60, 4, 45, 14, 119, 9, 186, 13, 66, 0, 30, 8, 81, 10, 148, 9, 108, 12, 15, 4, 113, 10, 232, 13, 94, 2, 21, 8, 115, 11, 230, 9, 88, 10, 16, 8, 119, 9, 212, 5, 112, 12, 15, 18, 103, 7, 232, 9, 104, 0, 21, 28, 113, 5, 218, 4, 96, 2, 18, 26, 118, 15, 218, 0, 104, 8, 23, 24, 112, 11, 246, 0, 68, 0, 62, 20, 97, 8, 190, 5, 14, 2, 67, 30, 71, 8, 170, 5, 34, 6, 80, 28, 65, 11, 136, 4, 44, 2, 81, 28, 113, 8, 174, 5, 0, 2, 125, 30, 100, 8, 128, 9, 28, 6, 111, 8, 112, 9, 230, 13, 32, 0, 65, 10, 82, 11, 204, 12, 46, 4, 109, 14, 71, 9, 220, 13, 50, 4, 77, 8, 113, 14, 226, 9, 12, 8, 105, 2, 113, 15, 180, 12, 74, 10, 68, 4, 81, 14, 182, 12, 106, 14, 74, 2, 117, 5, 144, 4, 118, 4, 88, 10, 115, 8, 146, 9, 120, 2, 90, 0, 116, 12, 138, 13, 114, 10, 78, 10, 113, 15, 148, 8, 118, 4, 95, 18, 115, 2, 170, 8, 96, 10, 93, 28, 100, 6, 168, 4, 126, 10, 91, 30, 119, 10, 236, 0, 64, 8, 66, 26, 80, 10, 252, 1, 114, 8, 127, 20, 66, 13, 218, 12, 104, 12, 73, 22, 113, 6, 202, 9, 68, 2, 126, 16, 113, 1, 202, 1, 100, 0, 101, 20, 86, 3, 170, 9, 118, 10, 102, 0, 117, 15, 52, 0, 190, 4, 16, 20, 22, 13, 46, 8, 190, 10, 15, 16, 18, 3, 32, 4, 134, 14, 35, 18, 17, 6, 20, 9, 156, 14, 37, 6, 53, 12, 50, 8, 180, 12, 34, 10, 33, 12, 94, 5, 174, 4, 24, 18, 4, 2, 112, 4, 150, 12, 57, 24, 3, 0, 118, 9, 162, 8, 51, 18, 2, 5, 122, 12, 174, 4, 48, 20, 7, 2, 64, 13, 158, 14, 32, 12, 51, 12, 100, 1, 178, 2, 32, 26, 35, 4, 24, 0, 192, 14, 4, 28, 1, 5, 58, 9, 204, 8, 32, 28, 0, 7, 30, 4, 232, 0, 49, 28, 7, 9, 46, 13, 200, 10, 39, 8, 53, 15, 72, 0, 196, 14, 3, 28, 4, 5, 64, 9, 192, 2, 6, 28, 7, 5, 52, 1, 236, 8, 46, 20, 32, 13, 52, 9, 238, 4, 43, 16, 38, 8, 104, 9, 212, 10, 27, 30, 19, 7, 94, 1, 222, 6, 20, 26, 39, 13, 94, 5, 244, 14, 37, 18, 52, 13, 2, 0, 160, 0, 90, 16, 38, 15, 38, 13, 156, 4, 79, 26, 48, 2, 20, 4, 164, 4, 65, 18, 53, 4, 126, 1, 154, 2, 92, 2, 7, 0, 82, 12, 190, 12, 69, 2, 37, 3, 110, 12, 144, 10, 100, 12, 49, 5, 6, 5, 222, 10, 78, 2, 4, 14, 34, 8, 202, 14, 125, 4, 23, 11, 36, 4, 220, 14, 121, 22, 50, 1, 124, 12, 210, 6, 81, 24, 21, 3, 88, 13, 216, 14, 116, 26, 2, 6, 114, 0, 208, 0, 96, 24, 22, 9, 22, 4, 230, 8, 117, 16, 54, 3, 28, 0, 246, 2, 80, 24, 39, 2, 8, 1, 252, 6, 79, 30, 17, 1, 60, 1, 202, 10, 72, 26, 7, 7, 70, 12, 166, 10, 124, 20, 37, 2, 86, 4, 184, 6, 72, 30, 39, 13, 124, 1, 186, 8, 103, 24, 17, 12, 46, 0, 154, 4, 121, 24, 17, 11, 46, 1, 186, 10, 87, 22, 6, 13, 66, 1, 186, 6, 82, 14, 6, 7, 72, 0, 156, 8, 115, 14, 22, 6, 108, 9, 240, 10, 119, 0, 32, 14, 126, 4, 234, 2, 97, 16, 37, 1, 70, 5, 234, 8, 115, 18, 50, 3, 2, 9, 136, 10, 4, 18, 65, 3, 20, 4, 190, 2, 11, 28, 66, 8, 18, 1, 148, 8, 32, 22, 82, 13, 18, 5, 176, 0, 44, 24, 115, 14, 124, 13, 138, 0, 22, 24, 86, 0, 120, 9, 140, 6, 28, 16, 87, 3, 112, 8, 166, 10, 6, 28, 65, 7, 64, 5, 156, 6, 43, 30, 87, 12, 82, 4, 138, 4, 11, 30, 98, 10, 78, 0, 144, 0, 40, 16, 101, 15, 88, 13, 190, 2, 50, 26, 116, 0, 106, 5, 186, 0, 58, 28, 112, 3, 8, 0, 194, 0, 13, 20, 87, 2, 112, 12, 212, 12, 13, 14, 80, 12, 82, 1, 254, 10, 22, 22, 82, 7, 42, 8, 230, 8, 44, 16, 117, 2, 62, 5, 194, 8, 56, 16, 96, 9, 14, 8, 242, 12, 41, 24, 70, 0, 46, 8, 206, 0, 46, 30, 80, 5, 40, 0, 196, 4, 34, 30, 85, 1, 40, 0, 244, 14, 7, 18, 99, 0, 70, 12, 226, 12, 23, 0, 118, 2, 90, 4, 218, 6, 51, 6, 117, 9, 96, 13, 210, 0, 62, 8, 114, 13, 70, 12, 234, 12, 41, 14, 113, 13, 110, 0, 224, 8, 61, 28, 113, 1, 34, 12, 134, 14, 66, 26, 68, 6, 58, 1, 134, 4, 81, 20, 64, 13, 52, 1, 130, 10, 88, 20, 69, 10, 48, 0, 148, 12, 86, 22, 87, 15, 30, 1, 174, 8, 75, 26, 87, 12, 44, 5, 134, 10, 80, 28, 115, 13, 6, 0, 132, 8, 116, 26, 96, 13, 48, 5, 186, 6, 100, 30, 113, 11, 82, 9, 160, 10, 82, 16, 81, 3, 50, 1, 184, 2, 107, 24, 113, 4, 36, 1, 144, 6, 64, 22, 99, 7, 62, 0, 158, 0, 89, 22, 86, 4, 106, 0, 246, 12, 68, 30, 80, 8, 94, 9, 206, 6, 86, 16, 84, 8, 46, 12, 208, 6, 70, 22, 119, 8, 20, 4, 238, 10, 125, 30, 84, 12, 36, 9, 244, 0, 91, 30, 67, 5, 40, 13, 198, 4, 127, 24, 67, 4, 24, 12, 224, 2, 73, 20, 115, 0, 34, 5, 216, 14, 113, 22, 100, 1, 46, 0, 210, 2, 118, 22, 100, 2, 36, 8, 208, 4, 70, 10, 115, 9, 8, 8, 222, 6, 94, 10, 87, 9, 96, 13, 196, 12, 88, 0, 85, 4, 112, 4, 254, 4, 80, 0, 86, 14, 108, 4, 250, 12, 126, 8, 70, 12, 68, 12, 238, 0, 69, 8, 119, 13, 92, 12, 206, 8, 107, 12, 96, 9, 108, 1, 196, 6, 91, 26, 100, 7, 108, 4, 204, 12, 98, 18, 81, 6, 72, 1, 214, 14, 79, 28, 117, 5, 126, 9, 228, 6, 119, 28, 118, 6, 158, 13, 190, 12, 39, 28, 20, 1, 186, 0, 170, 6, 48, 20, 1, 11, 142, 0, 160, 8, 6, 20, 1, 12, 110, 4, 218, 8, 109, 30, 114, 12, 86, 12, 250, 2, 72, 18, 100, 10, 80, 12, 230, 14, 81, 24, 112, 12, 82, 0, 234, 30, 84, 8, 115, 5, 106, 12, 198, 20, 85, 2, 103, 4, 84, 13, 250, 30, 119, 10, 66, 1, 66, 0, 248, 16, 82, 12, 69, 11, 88, 0, 220, 22, 73, 12, 68, 15, 48, 5, 212, 22, 104, 8, 114, 12, 0, 0, 222, 26, 96, 0, 102, 11, 0, 0, 0, 0, 0, 0, 0, 0]

v25 = [BitVec('x[%d]'%i,64) for i in range(336)]
s = Solver()
for i in range(335):
    v26[i*8+1], v26[i*8+5] = v26[i*8+5], v26[i*8+1]
for i in range(len(v25)):
    s.add(v26[8 * i] == Unpad64Bit_8Bit(v25[i]))
    s.add(v26[8 * i + 1] == Unpad64Bit_8Bit(v25[i] >> 1))
    s.add(v26[8 * i + 2] == Unpad64Bit_8Bit(v25[i] >> 2))
    s.add(v26[8 * i + 3] == Unpad64Bit_8Bit(v25[i] >> 3))
    s.add(v26[8 * i + 4] == Unpad64Bit_8Bit(v25[i] >> 4))
    s.add(v26[8 * i + 5] == Unpad64Bit_8Bit(v25[i] >> 5))
    s.add(v26[8 * i + 6] == Unpad64Bit_8Bit(v25[i] >> 6))
    s.add(v26[8 * i + 7] == Unpad64Bit_8Bit(v25[i] >> 7))

if(s.check()==sat):
    m = s.model()
    result = [m[v25[i]].as_long() for i in range(len(v25))]
    print(result)
```
````python
# find coordinate phase
from z3 import *
def Pad6Bit(a1):
    a1 &= 0xFF
    return (2 * ((4 * (a1 & 0xF)) & 0x33 | (16 * (a1 & 0x3F)) & 0x303 | a1 & 3)) & 0x555 | (4 * (a1 & 0xF)) & 0x11 | (16 * (a1 & 0x3F)) & 0x101 | a1 & 1
def Pad12Bit(a1):
    a1 &= 0xFFFF
    return a1 & 1 | ((a1 & 0xFFF) << 8) & 0x10001 | (16 * (a1&0xFF)) & 0x101 | (4* (a1 & 0xF | ((a1 & 0xFFF) << 8) & 0xF000F | (16 * (a1&0xFF)) & 0xF0F)) & 0x111111 | (2 * (a1 & 3 | ((a1 & 0xFFF) << 8) & 0x30003 | (16 * (a1&0xFF)) & 0x303 | (4 * (a1 & 0xF | ((a1 & 0xFFF) << 8) & 0xF000F | (16 * (a1&0xFF)) & 0xF0F)) & 0x333333)) & 0x555555
def Pad24Bit(a1):
    a1 &= 0xFFFFFFFF
    v2 = a1 & 3 | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0x300000003 | (((a1 & 0xFFFF) | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0xFF0000FFFF) << 8) & 0x300030003 | (16 * ((a1 & 0xFF) | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0xFF000000FF | (((a1 & 0xFFFF) | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0xFF0000FFFF) << 8) & 0xFF00FF00FF)) & 0x30303030303 | (4 * (a1 &0xF | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0xF0000000F | (((a1 & 0xFFFF) | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0xFF0000FFFF) << 8) & 0xF000F000F | (16 * ((a1 & 0xFF) | (((a1 & 0xFFFFFF) & 0xffffffffffffffff) << 16) & 0xFF000000FF | (((a1 & 0xFFFF) | (((a1 & 0xFFFFFF) & 0xFFFFFFFFFFFFFFFF) << 16) & 0xFF0000FFFF) << 8) & 0xFF00FF00FF)) & 0xF0F0F0F0F0F)) & 0x333333333333
    return (v2 | (2 * v2)) & 0x555555555555

def EncodeMorton_12bit(a1,a2):
    a1 &= 0xFF
    a2 &= 0xFF
    v2 = Pad6Bit(a1)
    return v2 | (2 * (Pad6Bit(a2)&0xFFFF))
def EncodeMorton_24bit(a1,a2):
    a1 &= 0xFFFF
    a2 &= 0xFFFF
    v2 = Pad12Bit(a1)
    return v2 | (2 * (Pad12Bit(a2)&0xFFFFFFFF))
def EncodeMorton_48bit(a1,a2):
    a1 &= 0xFFFFFFFF
    a2 &= 0xFFFFFFFF
    v2 = Pad24Bit(a1)
    return v2 | (2 * Pad24Bit(a2))

v25 =[18992711047936, 70388832212080, 74769130078896, 76147692182816, 281836732940880, 353017044767760, 369455654766384, 370834506782096, 370834720444080, 370840847553104, 1213948969440208, 1202112477894176, 1202112631064192, 1202113010663952, 1202118654072880, 1202118994074832, 1200952858542096, 1426419709051952, 1429670232574144, 1430759545459376, 1483539940478976, 1496798627747248, 4509120866650928, 4526760405959136, 4575414371617152, 4578455536634992, 4578461447817920, 4578380350101552, 5648561163010272, 5647101076342464, 5633997140525152, 4873394244917632, 4861020432209920, 4808448750130544, 4804140427890640, 4802966037599936, 4807136516429872, 4856841612201600, 4874154801091072, 5629862614696336, 5647386134092128, 5986091556162976, 5982805923025456, 5982514568058976, 5982520094475888, 5982520633416624, 5982732797516800, 5981719935489232, 5934395213258528, 5981451280047504, 5986050864618032, 6003624277399840, 18037572619388048, 18085139598694544, 6003413826903744, 5916848718810944, 5912175589727696, 5701271249948688, 18371742014652576, 18370646903423136, 18367440607697984, 18367368076920544, 18366600940835696, 18366601881211536, 18367466374420464, 18372140060253136, 18388357958423632, 19159098251172848, 19215392562151728, 19216453160060128, 19158196560331776, 18388258976108080, 18313818805542224, 18297347673414272, 18107041893618880, 22593040875834192, 22589536183639072, 19515595221981952, 22518021988079200, 22518349110483936, 22518355445679456, 19515601999692992, 19514141737244432, 19440544558040656, 19426526148549440, 19427578250069376, 19496619891199856, 19514216713785984, 22519199623318256, 22522435362081552, 22523530668055536, 22589571750559824, 22799526956155232, 23643904695583120, 22893024826770080, 22893030388616832, 22893284055195200, 23645079903866352, 23645300484425712, 22893310187411312, 23645324769860960, 23645324758584624, 23733308585270224, 23925740572624416, 23944067261252704, 24000142292274032, 72057665124390336, 72075188847369184, 72079608048835072, 72133484378594560, 72410898422287344, 72410606611432384, 72409513285164608, 72362166120259440, 72361158101717184, 72344649204140352, 72344650400434416, 72344870268210320, 72356951706375344, 72432560755332304, 73206595184139504, 73271539287427920, 73482914354274256, 73483966107901232, 73465063529629632, 73253934321797968, 73189062956930960, 73558726921670208, 73558440379908464, 73557427126616272, 73554386897685328, 73557356193865184, 73554389037992592, 73557379764851904, 76565624761458512, 76578883334066368, 76636264213304576, 76847421791405456, 76848473974588752, 77710272016679088, 77704968019891520, 76936198735484128, 76918819234596720, 76918820577187792, 76935112261458192, 77704766098545760, 77757546705308464, 77775361968609968, 77762217844842288, 77706142423866496, 76936205112020416, 77991661035445440, 77991739908508848, 77991740794097232, 78040322424576640, 78043436516792848, 78056928930139440, 78057732488465776, 78061311948919408, 90073201802199856, 90089965444749680, 90142419779784848, 90354883207318976, 90371182505286688, 90358993914626432, 90160325948234208, 90072112895925152, 77969999054620592, 77776188482717200, 90441779412321328, 90423856466875920, 90358222129121984, 90376588111217712, 90371364907405712, 90372168487387728, 90425032767084736, 90441787616447840, 91215496242108880, 91268568468937312, 91286968266985168, 91286966469876336, 91219913388018800, 90445840221014512, 90446125932102640, 91199342864536928, 91272941574000752, 91551199269276912, 91551199387535840, 91554164705448688, 91555586584477936, 91554492916489088, 91554493104165264, 91568511894622528, 94576706843008880, 94581169242934752, 94650713420204112, 94664732399831856, 94663848218073264, 94862842307658672, 94879060462618320, 94932133310202992, 94946405634049008, 95702873663573056, 95777638578724800, 95776626396907072, 95776626977020192, 95776554079002592, 95776633341728336, 95777436697004304, 95777730425445968, 95984352369938944, 96006158163334320, 96058022646416208, 96071280999274976, 96005240781193648, 95795245477043680, 288236249600181376, 288236175382404496, 288249351462755920, 288318636334975600, 288323858976215872, 288516331138811680, 288530642049451088, 288535023156549552, 288535023105000768, 288600107047079008, 288605335428615776, 289356289138100416, 289374981438472608, 289378350166917584, 289445614330157552, 289637759823255696, 289637760209410272, 289449750058963104, 289449750456783920, 289639220912773872, 289708220843118560, 289730417269738416, 292808822307737984, 292805745592603440, 292809030348112464, 293016640819384160, 293090239767676880, 293104803988572608, 293859895499136800, 293878914141048272, 293949305967823504, 294142824430537936, 294159042433567264, 294160349488234880, 293952591286879632, 293934741315767360, 293864574767995632, 293860988615249632, 293107887989296448, 293090250143255488, 293038847851304048, 292753039377925584, 292739570205941680, 293019934815608736, 293033403983778320, 294234897895233584, 294234822126144976, 294234062030231472, 306244783990410208, 306249205291637776, 306262674080416672, 306337441041662304, 306527706293556256, 306527706527090912, 306531760795458752, 306544145003862640, 306596633786373904, 306614238783308224, 306618982937665056, 306620077881595296, 307370958326514768, 307653548542132752, 307656921464627104, 307464417486079296, 307459819183343008, 307392691565053200, 307389650666198912, 307389649788998336, 307446566793009744, 307727260611892496, 307740477785513936, 307741573761750176, 307744786598266832, 307745960674656720, 310749483110276864, 310749557578139056, 310749557959134304, 310749849758651072, 310753062778394480, 310820197074685152, 310836414853219200, 310842139971587808, 311034604465199584, 310842138097097072, 310819868323334880, 310749847827728144, 312161549711968000, 312156108428746016, 311946045808139072, 311896623577239056, 311879867090555632, 311893044070470768, 311949329573234768, 311963429334813616, 311963429148794624, 311946037228556992, 311874638048943808, 312157193236119648, 312161614032585728, 312178927499564032, 312230793641805008, 312243717604316304, 312227295069575856, 312174724567110208, 312226419031547120, 312249564744636720, 360310266161730992, 360311143770262976, 360292379134202176, 312245112941004560, 312230549053869824, 312230875308493840, 312230898459758016, 312227321077319504, 312177864734236336, 312160269730222528, 312155807553587344, 311963667810502688, 311962289018555520, 0]
x = [BitVec('x[%d]'%i,64) for i in range(336)]
y = [BitVec('y[%d]'%i,64) for i in range(336)]
s = Solver()
for i in range(len(x)):
    v19 = x[i] >> 8
    v6 = (16 * x[i]) & 0xFF0 | (y[i] >> 28) 
    v7 = (y[i] >> 0x10) & 0xFFF
    v8 = EncodeMorton_12bit((y[i] & 0xFFFF) >> 10,(y[i] >> 4) & 0x3F) 
    v20 = EncodeMorton_24bit(v8, v7) 
    v24 = EncodeMorton_48bit(v19, v7)
    s.add(v25[i] == ((v24 << 12) | v6))
if(s.check() == sat):
    m = s.model()
    result = [m[x[i]].as_long() for i in range(len(x))]
    result1 = [m[y[i]].as_long() for i in range(len(y))]
for i in range(len(result)):
    print(result[i],end='')
    print(",",end='')
    print(result1[i])
````
# Math 3
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/2f781d3f-858b-4544-99b6-10f99ae2c52b)

## Detailed Analysis
- Hàm `main`
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v3; // r12d
  __m128i v5; // [rsp+0h] [rbp-38h] BYREF
  __m128i s2[2]; // [rsp+10h] [rbp-28h] BYREF

  printf("Flag: ");
  __isoc99_scanf("%15s", &v5);
  s2[0] = _mm_xor_si128(
            _mm_add_epi32(_mm_shuffle_epi8(_mm_load_si128(&v5), (__m128i)SHUFFLE), (__m128i)ADD32),
            (__m128i)XOR);
  if ( !strncmp(v5.m128i_i8, s2[0].m128i_i8, 0x10uLL) && (v3 = strncmp(s2[0].m128i_i8, EXPECTED_PREFIX, 4uLL)) == 0 )
  {
    puts("SUCCESS");
  }
  else
  {
    v3 = 1;
    puts("FAILURE");
  }
  return v3;
}
```
- Hàm `main` sẽ có nhiệm vụ nhận input từ user, sau đó biến đổi như sau. Đầu tiên tiến hành `shuffle` các phần tử có trong input với shuffle mask `SHUFFLE`, tiếp đến là tiến hành cộng 4 byte 1 của input (theo kiểu little endian) với các dword có trong `ADD32`, và cuối cùng xor các phần tử có trong inout với `XOR`, nếu input sau khi được biến đổi vẫn giống như trước biến đổi thì đúng
- Với các dữ kiện bên trên thì việc viết script sẽ không quá khó khăn (thậm chí không cần phải debug). Có 1 tips cho bài này nếu như các bạn muốn debug xem input được biến đổi cụ thể như nào thì ta có thể sử dụng cửa sổ `XMM registers` của IDA
## Script and Flag
```python
# z3 my beloved <3 
from z3 import *
SHUFFLE = [  0x02, 0x06, 0x07, 0x01, 0x05, 0x0B, 0x09, 0x0E, 0x03, 0x0F, 0x04, 0x08, 0x0A, 0x0C, 0x0D, 0x00]
ADD32 = [0xDEADBEEF, 0xFEE1DEAD, 0x13371337, 0x67637466]
XOR = [0x76, 0x58, 0xB4, 0x49, 0x8D, 0x1A, 0x5F, 0x38, 0xD4, 0x23, 0xF8, 0x34, 0xEB, 0x86, 0xF9, 0xAA]
flag = [BitVec('x[%d]'%i,8) for i in range(16)]
s = Solver()
temp = [0]*len(flag)
for i in range(len(flag)):
    temp[i] = flag[SHUFFLE[i]]
cond = Concat(temp[3],temp[2],temp[1],temp[0])
cond1 = Concat(temp[7],temp[6],temp[5],temp[4])
cond2= Concat(temp[11],temp[10],temp[9],temp[8])
cond3 = Concat(temp[15],temp[14],temp[13],temp[12])
    
sum= (cond+ADD32[0])&0xFFFFFFFF
sum1= (cond1+ADD32[1])&0xFFFFFFFF
sum2= (cond2+ADD32[2])&0xFFFFFFFF
sum3= (cond3+ADD32[3])&0xFFFFFFFF

temp[0] = Extract(7, 0, sum)
temp[1] = Extract(15, 8, sum)
temp[2] = Extract(23, 16, sum)
temp[3] = Extract(31, 24, sum)
temp[4] = Extract(7, 0, sum1)
temp[5] = Extract(15, 8, sum1)
temp[6] = Extract(23, 16, sum1)
temp[7] = Extract(31, 24, sum1)
temp[8] = Extract(7, 0, sum2)
temp[9] = Extract(15, 8, sum2)
temp[10] = Extract(23, 16, sum2)
temp[11] = Extract(31, 24, sum2)
temp[12] = Extract(7, 0, sum3)
temp[13] = Extract(15, 8, sum3)
temp[14] = Extract(23, 16, sum3)
temp[15] = Extract(31, 24, sum3)

for i in range(len(temp)):
    temp[i] ^= XOR[i]
for i in range(len(flag)):
    s.add(flag[i] == temp[i])
if(s.check()==sat):
    m = s.model()
    result = [m[flag[i]].as_long() for i in range(16)]
for i in result:
    print(chr(i),end='')

```
