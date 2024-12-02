# Datastruct1
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/dd62b04f-6795-49dd-a6c6-14c751344f2a)

## Detailed Analysis
- Hàm `main()`
```C
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[2052]; // [rsp+0h] [rbp-810h] BYREF
  int v5; // [rsp+804h] [rbp-Ch]
  __int64 i; // [rsp+808h] [rbp-8h]

  memset(v4, 0, 0x7F8uLL);
  for ( i = 0LL; ; ++i )
  {
    v5 = getchar();
    if ( v5 == -1 )
      break;
    argv = (const char **)(unsigned __int8)v5;
    add_char_to_map(v4, (unsigned __int8)v5, i);
  }
  serialize_and_output(v4, argv);
  return 0;
}
```
- Hàm `main()` sẽ có nhiệm vụ lấy từng char có trong input của user (tính cả newline character), sau đó đưa vào hàm `add_char_to_map` để xử lí, cuối cùng hàm `serialize_and_output` sẽ có nhiệm vụ serialize và write input sau khi đã được xử lí vào `STDOUT`

- Hàm `add_char_to_map()`
```C
_QWORD *__fastcall add_char_to_map(__int64 a1, unsigned __int8 a2, __int64 a3)
{
  _QWORD *result; // rax
  _QWORD *v5; // [rsp+20h] [rbp-10h]
  _QWORD *v6; // [rsp+28h] [rbp-8h]

  v6 = *(_QWORD **)(8LL * a2 + a1);
  v5 = malloc(0x10uLL);
  *v5 = a3;
  v5[1] = 0LL;
  if ( v6 )
  {
    while ( v6[1] )
      v6 = (_QWORD *)v6[1];
    result = v6;
    v6[1] = v5;
  }
  else
  {
    result = v5;
    *(_QWORD *)(a1 + 8LL * a2) = v5;
  }
  return result;
}
```
- Hàm này sẽ khởi tạo một linked list với các data được đưa vào list như sau
  + Số lần mà kí tự được nhập từ input xuất hiện (giả sử nhập `abcaa` thì sẽ đẩy 3 vào list vì `a` xuất hiện 3 lần)
  + Các index mà có sự xuất hiện của kí tự đó (tiếp tục lấy ví dụ trên thì kí tự `a` xuất hiện tại các index `0`, `3` và `4` thì sẽ lần lượt đẩy `0`, `3` và `4` vào list)

- Hàm `serialize_and_output`
```C
void __fastcall serialize_and_output(__int64 a1)
{
  __int64 ptr; // [rsp+10h] [rbp-20h] BYREF
  void **v2; // [rsp+18h] [rbp-18h]
  void *j; // [rsp+20h] [rbp-10h]
  int i; // [rsp+2Ch] [rbp-4h]

  for ( i = 0; i <= 254; ++i )
  {
    v2 = (void **)(8LL * i + a1);
    ptr = list_len(v2);
    fwrite(&ptr, 8uLL, 1uLL, _bss_start);
    for ( j = *v2; j; j = (void *)*((_QWORD *)j + 1) )
      fwrite(j, 8uLL, 1uLL, _bss_start);
  }
}
```
- Hàm này sẽ tiến hành dùng vòng  `for ( i = 0; i <= 254; ++i )` (tương ứng với việc gắn các byte 0->0xFF) để duyệt qua list, `v2 = (void **)(8LL * i + a1)` ám chỉ rằng linked list được khởi tạo từ hàm `add_char_to_map` sẽ được duyệt 8 byte một để kiểm tra sự hiện diện của các byte từ 0 -> 0xFF ở trong input được user cung cấp. Để phân tích kĩ hơn mình sẽ phân tích file dump `message.txt.cz`

![image](https://github.com/user-attachments/assets/1b784165-6209-4012-8562-979dbf7686cd)

- Ta có thể thấy rằng các byte từ sẽ không có sự xuất hiện của các byte 0 -> 0x9 bởi trong khoảng 0x49 byte đầu đều là các byte null. Nhưng khi đến byte thứ 0x50 (tương đương với 0xA bởi 0x50 // 8 = 0xA  hay là newline character) thì ta có thể thấy số lần xuất hiện của byte này là 0xC (12 lần) và tương ứng với 12 vị trí của nó được append ở ngay sau. Vậy để giải ta sẽ viết script để duyệt qua file `message.txt.cz` để khôi phục lại input ban đầu

## Script and Flag
```python
f = open("path\\to\\message.txt.cz","rb")

data = f.read()
data_len = len(data)
flag = [0]*(len(data))
curr_index = 0
for i in range(256):
    if(curr_index>=data_len):
        break
    count = data[curr_index]
    curr_ascii = i
    curr_index += 8
    if(count != 0):
        iterate = curr_index
        for j in range(count):
            flag[int.from_bytes(data[iterate:iterate+2],"little")]=curr_ascii
            iterate +=8
            curr_index +=8
    
for i in flag:
    print(chr(i),end='')
```

# Datastruct2
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/f088ac51-39a1-4ec0-adea-2240d596f07a)

## Detailed Analysis
## Script and Flag
```python
from z3 import *
flag = [BitVec("x[%d]"%i,8)for i in range(16)]
s = Solver()
cyphertext = [0x69, 0x84, 0x94, 0xA4, 0x53, 0x0F, 0x39, 0x8A, 0xB4, 0x73, 0x37, 0xBC, 0x43, 0xD8, 0x72, 0x4C] # too lazy to write a solve script so i wrote a step by step solver instead (just use 16 bytes of cyphertext for each decrypt routine)
bytecode = [0x02, 0x01, 0x05, 0xAA, 0x02, 0x02, 0x05, 0xED, # stripped 0x04 case at the beginning and 0x02 at the end
  0x02, 0x03, 0x05, 0xEC, 0x02, 0x04, 0x05, 0x5D, 0x02, 0x05, 
  0x05, 0x8E, 0x02, 0x06, 0x05, 0x87, 0x02, 0x07, 0x05, 0x41, 
  . . . . . . . 
  0x01, 0x12, 0x01, 0x25, 0x01, 0x2B, 0x01, 0x6E, 0x03, 0x2B, 
  0x03, 0x55, 0x03, 0x5A, 0x03, 0x36, 0x03, 0x54, 0x03, 0x7A, 
  0x03, 0x34, 0x03, 0x22, 0x03, 0x18, 0x03, 0x43, 0x03, 0x4B, 
  0x03, 0x63, 0x03, 0x13, 0x03, 0x5F, 0x03, 0x2D, 0x04, 0x20
]

queue_state = []
result = []
for i in range(0,len(bytecode),2):
  if(bytecode[i] == 0x02):
    queue_state.append(flag[bytecode[i+1]-1])
  if(bytecode[i] == 0x05):
    queue_state.append(bytecode[i+1])
  if(bytecode[i] == 0x01):
    v9 = queue_state.pop(0)
    v6 = queue_state.pop(0)
    queue_state.append((v6*v9)&0xFF)
  if(bytecode[i] == 0x03):
    v8 = queue_state.pop(0)
    v5 = queue_state.pop(0)
    queue_state.append((v8+v5)&0xFF)
  if(bytecode[i] == 0x04):
    v7 = queue_state.pop(0)
    result.append(v7)

for i in range(16):
  s.add(result[i] == cyphertext[i])
if(s.check()==sat):
  model = s.model()
  flag_string = ''.join([chr(model[flag[i]].as_long()) for i in range(16)])
  print(flag_string)
  
```
