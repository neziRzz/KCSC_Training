- Đề cho 1 file PE32 và 2 dll kèm theo (trong trường hợp máy không chạy được chương trình)

![image](https://github.com/user-attachments/assets/e2243221-b3f8-496b-9a67-d8fc8a81d046)

- IDA's Pseudocode
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
