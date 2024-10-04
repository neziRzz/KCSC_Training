xormask = bytes.fromhex("9A4680117EB17A4B")
fmsg = bytes.fromhex("D912C67D1BD00825")
hex1 = bytes.fromhex("01BEF3ACB01B14EA")
hex2 = bytes.fromhex("7AF392DFDD7A7FB5")
hex3 = bytes.fromhex("27AD3F9CF348F25B")
hex4 = bytes.fromhex("61C24DE8812D8128")
hex5 = bytes.fromhex("FC7E6342A88E01E7")[:4]
hex6 = bytes.fromhex("A34F5B74")
hex7 = bytes.fromhex("FC7E6342A88E01E7")[4:6]
hex8 = bytes.fromhex("9DF3")
flag = ''
for i in range(len(xormask)):
    flag += chr(xormask[i]^fmsg[i])
for i in range(len(hex1)):
    flag += chr(hex1[i]^hex2[i])
for i in range(len(hex3)):
    flag += chr(hex3[i]^hex4[i])
for i in range(len(hex5)):
    flag += chr(hex5[i]^hex6[i])
for i in range(len(hex7)):
    flag += chr(hex7[i]^hex8[i])
print(flag) #CTFlearn{Masmak_Fortress_1865}
