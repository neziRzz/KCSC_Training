from math import *
flag = [0]*21
flag[3] = 0x157000
flag[2] = 0x0011A9F9
flag[1]= 0x6B2C0
flag[0] = 0x13693
flag[7] = 0xDED21
flag[6] = 0x1BB528
flag[5] = 0x1BB528
flag[4] = 0x1CB91
flag[11] = 0x0D151F
flag[10] = 0x169B48
flag[9] = 0xFB89D
flag[8] = 0x144F38
flag[15] = 0x1338C0
flag[14] = 0xDED21
flag[13] = 0x17D140
flag[12] = 0x8B98B
flag[19] = 0x144F38
flag[18] = 0x1B000
flag[17] = 0x11A9F9
flag[16] = 0x1338C0
flag[20] = 0x1734EB
final=''
for i in range(len(flag)):
    final +=chr(ceil((flag[i])**(1./3.)))
print(final)
