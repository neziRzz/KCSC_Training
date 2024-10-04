x = "A88E" #25A5275A3FC01912
hex1 = bytes.fromhex(x)
y = "9A4680117EB17A4B"
xormask= bytes.fromhex(y)
z = "9DF3"
v5 = 10
hex2 = bytes.fromhex(z)
flag1='CTFlearn{'
flag2='Masmak_'
flag3='Fortress'
flag4='_186'
flag5= '5}'
print(flag1+flag2+flag3+flag4+flag5) #CTFlearn{Masmak_Fortress_1865}
