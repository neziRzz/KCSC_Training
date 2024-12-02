# Datastruct1
## Detailed Analysis
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
