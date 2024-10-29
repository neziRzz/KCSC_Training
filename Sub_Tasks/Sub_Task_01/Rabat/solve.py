from z3 import *
flag = [BitVec("x[%d]"% i,8)for i in range(28)]
s = Solver()
cond1 = Concat(flag[23],flag[22],flag[21],flag[20],flag[19],flag[18],flag[17],flag[16])
cond2 = ZeroExt(32,Concat(flag[27],flag[26],flag[25],flag[24]))
cond3 = Concat(flag[7],flag[6],flag[5],flag[4],flag[3],flag[2],flag[1],flag[0])
cond4 = Concat(flag[15],flag[14],flag[13],flag[12],flag[11],flag[10],flag[9],flag[8])

for i in range(len(flag)):
    s.add(flag[i]>0x20)
    s.add(flag[i]<0x7F)
s.add(ZeroExt(64,cond3) * ZeroExt(64,cond4) == BitVecVal(0x239024F9F888D600A1669A478F0F1F10,128))
s.add(flag[7] + flag[6] + flag[5] + flag[4] + flag[3] + flag[2] + flag[1] + flag[0] == 0x2A0 )
s.add(flag[15] + flag[14] + flag[13] + flag[12] + flag[11] + flag[10] + flag[9] + flag[8] == 0x316 )
s.add(cond1 / cond2 == 0x17CC632FA)
s.add(cond1 % cond2 == 0x7DE5C8E)
s.add(flag[23] + flag[22] + flag[21] + flag[20] + flag[19] + flag[18] + flag[17] + flag[16] == 0x293 )
s.add(flag[24] == 0x61)
s.add(flag[25] == 0x62)
s.add(flag[26] == 0x61)
s.add(flag[27] == 0x37)
s.add(cond3+cond4 == 0x0BED4CFAAC5C9C25B)
if(s.check() == sat):
    x = ''
    for i in range(len(flag)):
        last = int(str(s.model()[flag[i]]))
        x += chr(last)
print(x)
