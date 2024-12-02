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
```python
Organizer 1: Hey, did you finalize the password for the next... you know?

Organizer 2: Yeah, I did. It's "HTB{4_v3ry_b4d_compr3ss1on_sch3m3}"

Organizer 1: "HTB{4_v3ry_b4d_compr3ss1on_sch3m3}," got it. Sounds ominous enough to keep things interesting. Where do we spread the word?

Organizer 2: Let's stick to the usual channels: encrypted messages to the leaders and discreetly slip it into the training manuals for the participants.

Organizer 1: Perfect. And let's make sure it's not leaked this time. Last thing we need is an early bird getting the worm.

Organizer 2: Agreed. We can't afford any slip-ups, especially with the stakes so high. The anticipation leading up to it should be palpable.

Organizer 1: Absolutely. The thrill of the unknown is what keeps them coming back for more. "HTB{4_v3ry_b4d_compr3ss1on_sch3m3}" it is then.
```
# Datastruct2
- Đề cho 1 file ELF64

![image](https://github.com/user-attachments/assets/f088ac51-39a1-4ec0-adea-2240d596f07a)

## Detailed Analysis
- Hàm `main()`
```C
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[72]; // [rsp+0h] [rbp-60h] BYREF
  void *ptr; // [rsp+48h] [rbp-18h]
  FILE *stream; // [rsp+50h] [rbp-10h]
  int i; // [rsp+5Ch] [rbp-4h]

  stream = fopen("flag.txt", "r");
  fgets(s, 65, stream);
  fclose(stream);
  ptr = malloc(0x40uLL);
  for ( i = 0; i <= 63; i += 16 )
    sub_1403(&s[i], (char *)ptr + i);
  stream = fopen("output.bin", "w");
  fwrite(ptr, 1uLL, 0x40uLL, stream);
  fclose(stream);
  free(ptr);
  return 0LL;
}
```
- Hàm `main()` sẽ tiến hành mở file `flag.txt` (file này chứa flag ofc) và lấy 65 byte từ file này. Sau đó tiến hành xử lí 16 byte một thông qua hàm `sub_1403()`. Cuối cùng thì write hết các byte được xử lí vào file `output.bin`

- Hàm `sub_1403()`
```C
_BYTE *__fastcall sub_1403(__int64 a1, __int64 a2)
{
  _BYTE *result; // rax
  char v3; // cl
  __int64 v4[4]; // [rsp+10h] [rbp-40h] BYREF
  char v5; // [rsp+30h] [rbp-20h]
  __int64 v6[2]; // [rsp+38h] [rbp-18h] BYREF
  int j; // [rsp+48h] [rbp-8h]
  int i; // [rsp+4Ch] [rbp-4h]

  memset(v4, 0, sizeof(v4));
  v5 = 0;
  v6[0] = 0LL;
  v6[1] = 0LL;
  for ( i = 0; i <= 15; ++i )
    sub_1189(v6, *(unsigned __int8 *)(i + a1));
  result = (_BYTE *)sub_1396(v4, &unk_4060);
  for ( j = 0; j <= 15; ++j )
  {
    v3 = sub_11F7(v6);
    result = (_BYTE *)(j + a2);
    *result = v3;
  }
  return result;
}
```
- Hàm này tiến hành khởi tạo 1 linked list từ 16 byte của input sau đó đưa vào hàm `sub_1396()` để tiếp tục xử lí. Linked list sau khi được xử lí sẽ được free bằng hàm `sub_11F7()` và các phần tử trong list lần lượt được đưa vào `result` để viết vào `output.bin`

- Hàm `sub_1396()`
```C
__int64 __fastcall sub_1396(__int64 a1, __int64 a2)
{
  int v2; // eax
  __int64 result; // rax
  unsigned int v4; // [rsp+18h] [rbp-8h]
  int v5; // [rsp+1Ch] [rbp-4h]

  v5 = 0;
  while ( 1 )
  {
    v4 = *(unsigned __int8 *)(v5 + a2);
    v2 = v5 + 1;
    v5 += 2;
    result = *(unsigned __int8 *)(v2 + a2);
    if ( !v4 )
      break;
    sub_1253(a1, v4, (unsigned __int8)result);
  }
  return result;
}
```
- Hàm này mô phỏng lại cách thức hoạt động của một VM (Virtual Machine) với `v5` là VIP (Virtual Instruction Pointer) với các bytecode được lấy từ `unk_4060`(lấy 2 byte một, với byte đầu tiên là opcode và byte thứ 2 là operand). Sau khi fetch được bytecode thì chương trình sẽ tăng VIP lên 2 byte và tùy thuộc vào opcode thì sẽ được xử lí ở bên trong hàm `sub_1253()`


- Hàm `sub_1253()`
```C
__int64 __fastcall sub_1253(__int64 a1, unsigned int a2, unsigned __int8 a3)
{
  __int64 result; // rax
  char v5; // [rsp+18h] [rbp-8h]
  char v6; // [rsp+18h] [rbp-8h]
  char v7; // [rsp+1Ch] [rbp-4h]
  char v8; // [rsp+1Ch] [rbp-4h]
  char v9; // [rsp+1Ch] [rbp-4h]

  result = a2;
  switch ( a2 )
  {
    case 1u:
      v9 = sub_11F7(a1 + 40);
      v6 = sub_11F7(a1 + 40);
      result = sub_1189(a1 + 40, (unsigned __int8)(v6 * v9));
      break;
    case 2u:
      result = sub_1189(a1 + 40, *(unsigned __int8 *)(a1 + a3));
      break;
    case 3u:
      v8 = sub_11F7(a1 + 40);
      v5 = sub_11F7(a1 + 40);
      result = sub_1189(a1 + 40, (unsigned __int8)(v8 + v5));
      break;
    case 4u:
      v7 = sub_11F7(a1 + 40);
      result = a3;
      *(_BYTE *)(a1 + a3) = v7;
      break;
    case 5u:
      result = sub_1189(a1 + 40, a3);
      break;
    default:
      return result;
  }
  return result;
}
```
- Hàm này sẽ mô phỏng lại queue data structure bằng các opcode (byte đầu) từ `unk_4060`, cụ thể các case sẽ có chức năng như sau
  + `Case 1`: Dequeue 2 phần tử ở đầu queue rồi sau đó nhân chúng lại với nhau rồi đẩy kết quả xuống cuối queue (chỉ lấy LOBYTE của kết quả)
  + `Case 2`: Đẩy phần tử thứ `a3` trong 16 byte input vào cuối queue
  + `Case 3`: Dequeue 2 phần tử ở đầu queue rồi sau đó cộng chúng lại với nhau rồi đẩy kết quả xuống cuối queue (chỉ lấy LOBYTE của kết quả)
  + `Case 4`: Dequeue phần tử ở đầu queue rồi lưu vào 1 buffer
  + `Case 5`: Queue phần tử được chỉ định trong operand (ví dụ nếu như opcode là `0x05 0xDE` thì sẽ append `0xDE`)

- Vậy để giải ta chỉ cần viết script mô phỏng lại và dùng z3 để tìm flag 
## Script and Flag
```python
from z3 import *
flag = [BitVec("x[%d]"%i,8)for i in range(16)]
s = Solver()
cyphertext = [0x69, 0x84, 0x94, 0xA4, 0x53, 0x0F, 0x39, 0x8A, 0xB4, 0x73, 0x37, 0xBC, 0x43, 0xD8, 0x72, 0x4C] # too lazy to write a solve script so i wrote a step by step solver instead (just use 16 bytes of cyphertext for each decryption routine)
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
