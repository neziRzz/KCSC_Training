# Misc
- Đề cho 1 file PE32 và 2 dll kèm theo (trong trường hợp máy không chạy được chương trình)

![image](https://github.com/user-attachments/assets/e2243221-b3f8-496b-9a67-d8fc8a81d046)

# Detailed analysis 
- IDA's Pseudocode
```C
int __cdecl main_0(int argc, const char **argv, const char **envp)
{
  FILE *v3; // eax
  size_t content_length; // eax
  char v6; // [esp+0h] [ebp-14Ch]
  char v7; // [esp+0h] [ebp-14Ch]
  size_t v8; // [esp+10h] [ebp-13Ch]
  size_t j; // [esp+DCh] [ebp-70h]
  unsigned int i; // [esp+E8h] [ebp-64h]
  void (__cdecl *encrypt_flag_content)(const char *, char *, size_t); // [esp+F4h] [ebp-58h]
  char *temp_buffer; // [esp+10Ch] [ebp-40h]
  const char *flag_content; // [esp+118h] [ebp-34h]
  char input[36]; // [esp+124h] [ebp-28h] BYREF

  __CheckForDebuggerJustMyCode(&unk_41C017);
  j_memset(input, 0, 0x20u);
  malloc(0x19u);
  temp_buffer = (char *)malloc(0x19u);
  sub_4110D7("Show your skills. What is the flag?\n", v6);
  v3 = _acrt_iob_func(0);
  fgets(input, 32, v3);
  if ( input[j_strlen(input) - 1] == 0xA )
  {
    v8 = j_strlen(input) - 1;
    if ( v8 >= 32 )
      j____report_rangecheckfailure();
    input[v8] = 0;
  }
  if ( j_strlen(input) == 30
    && (flag_content = j_cmp_header_and_last_then_get_content(input)) != 0
    && j_strlen(flag_content) == 24 )
  {
    encrypt_flag_content = (void (__cdecl *)(const char *, char *, size_t))VirtualAlloc(
                                                                             0,
                                                                             0xA4u,
                                                                             MEM_COMMIT,
                                                                             PAGE_EXECUTE_READWRITE);
    if ( encrypt_flag_content )
    {
      for ( i = 0; i < 0xA4; ++i )
        *((_BYTE *)encrypt_flag_content + i) = encrypted_bytecodes[i] ^ 0x41;
      content_length = j_strlen(flag_content);
      encrypt_flag_content(flag_content, temp_buffer, content_length);
      VirtualFree(encrypt_flag_content, 0xA4u, 0x8000u);
      for ( j = 0; j < j_strlen(flag_content); ++j )
      {
        if ( temp_buffer[j] != byte_417CF4[j] )
          goto LABEL_18;
      }
      sub_4110D7("Not uncorrect ^_^", v7);
      return 0;
    }
    else
    {
      perror("VirtualAlloc failed");
      return 1;
    }
  }
  else
  {
LABEL_18:
    sub_4110D7("Not correct @_@", v7);
    return 0;
  }
}
```

- Ta có thể thấy rằng về cơ bản flow của chương trình sẽ như sau
  + Chương trình tiến hành nhận input của user bằng `fgets` (giới hạn số byte tối đa mà buffer có thể chứa là 32 byte)
  + Tiến hành bỏ newline character có trong buffer input (input[j_strlen(input) - 1] == 0xA với 0xA = "\n")
  + Kiểm tra đồng thời 3 điều kiện sau
    + Độ dài của input (sau khi bỏ newline character) là 30 hay không
    + Giá trị return của hàm `j_cmp_header_and_last_then_get_content(input)` có khác 0 hay không (sẽ phân tích kĩ hơn hàm này sau)
    + Độ dài của `flag_content` là 24 hay không ( giá trị cụ thể của `flag_content` sẽ do `j_cmp_header_and_last_then_get_content(input))` quyết định)
    + Hàm `j_cmp_header_and_last_then_get_content()`
```C
    char *__cdecl sub_411890(char *Str)
{
  char *Destination; // [esp+D0h] [ebp-2Ch]
  char *v3; // [esp+E8h] [ebp-14h]
  char *Source; // [esp+F4h] [ebp-8h]
  char *Sourcea; // [esp+F4h] [ebp-8h]

  __CheckForDebuggerJustMyCode(&unk_41C017);
  Source = j_strstr(Str, "KCSC{");
  if ( Source )
  {
    Sourcea = &Source[j_strlen("KCSC{")];
    v3 = j_strchr(Sourcea, '}');
    if ( v3 )
    {
      Destination = (char *)malloc(v3 - Sourcea + 1);
      if ( !strncpy_s(Destination, v3 - Sourcea + 1, Sourcea, v3 - Sourcea) )
        return Destination;
      free(Destination);
    }
  }
  return 0;
}
```
  + Hàm này sẽ có chức năng là kiểm tra input có bắt đầu bằng `KCSC{` và kết thúc với `}` hay không, nếu có thì sẽ bỏ 2 string vừa kể trên và return string đã bị biến đổi (Ví dụ input có format `KCSC{just_a_made_up_flag}` thì hàm này sẽ trả về string `just_a_made_up_flag`)

----------------------------------------------------------------------------------------------------------------------------------------
  + Nếu không thỏa mãn 1 trong 3 điều kiện trên thì sẽ in ra string `Not correct @_@` và thoát, ngược lại chương trình tiếp tục thực thi như sau
    + Tiến hành cấp phát vùng nhớ cho hàm `encrypt_flag_content` bằng `VirtualAlloc` 
# Script and flag
```python
from z3 import *
key = "reversing_is_pretty_cool"
cyphertext =[
  0x44, 0x93, 0x51, 0x42, 0x24, 0x45, 0x2E, 0x9B, 0x01, 0x99, 
  0x7F, 0x05, 0x4D, 0x47, 0x25, 0x43, 0xA2, 0xE2, 0x3E, 0xAA, 
  0x85, 0x99, 0x18, 0x7E
]
s = Solver()
flag = [BitVec("x[%d]"% i,8) for i in range(24)]
for i in range(len(flag)):
    s.add(flag[i]>0x20)
    s.add(flag[i]<0x7F)
for i in range(len(cyphertext)):
    v5 = 16 * (flag[i] % 16) + flag[i] / 16
    s.add(v5 ^ ord(key[i]) == cyphertext[i])
    
if(s.check() == sat):
    x = ''
    for i in range(len(flag)):
        last = int(str(s.model()[flag[i]]))
        x += chr(last)
else:
print("Failed")
print("KCSC{",end='')
print(x,end='')
print("}")
```
**Flag:** `KCSC{correct_flag!submit_now!}`