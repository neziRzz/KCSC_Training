flag_enc = "W8Hj?1VESL^g4xwcvtW%humtEosd$Fq^dXPvi$#sSEe@o618Zl9.5PFrvC%O_E*LB%Igl8qur9SuLAp4MkK#pRzwJHI*Fn9mUs%mGK^RQKO.G*JFJvV%?VJpCpVF9eJuz5&kB!&_VF5DrF?U?jfm&x^9aC7X2(&cGGzbLbOsSOuBeq*ZT%fpc&9riTDO5X%RuTKI@vCqu#CsTAp$Q9WoXJv96.ySdB2EfMK*$NX?.U*aDrfPQQPhFB9cC6y0hMGvbgjBogSux65gTL#Cm9TQt7nTayu9Vr%thh2GnnikE8JnIwlHfreZep^sZ6IrnXT#qu50Lv.Rd_XPDfgwzWcJ3ISjKM!ftRllVyF$?RE_dcJT5&uKZJ!WsqR853uLzcs!8&VyRuTDsiq#6PdmBNlPI$tPi?wZ5$ACCf9yda!OkP.Dc73Nx.Nt1Rj0O.?P!sZDB^d0LN1qXR31!t?OZ#mm7SfZHPO*4gx1J0nyC^d2EKeq^f4h7mSqaIcMv0ZT@G0M"
print("CTFlearn{",end='')
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF00D % (i * i * i + i * i)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF010 % (i * i + i * i * i + 3)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF013 % (i * i + i * i * i + 6)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF016 % (i * i + i * i * i + 9)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF019 % (i * i + i * i * i + 12)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF01C % (i * i + i * i * i + 15)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF01F % (i * i + i * i * i + 18)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF022 % (i * i + i * i * i + 21)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(i == ord(flag_enc[(0xBAADF025 % (i * i + i * i * i + 24)) & 0x1FF])):
        print(chr(i),end='')
        break
for i in range (0x20,0x7F):
    if(ord(flag_enc[(0xBAADF028 % (i * i + i * i * i + 27)) & 0x1FF]) == i ):
        print(chr(i),end='')
        break
print("}")
