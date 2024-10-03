hex1 = "E8FFEDC7CECAD9C5D0EED2CEF4E79BDDCEF4E2C8CEC7CAC5CFF4D6"
cyphertext = bytes.fromhex(hex1)
for i in range(len(cyphertext)):
    print(chr(cyphertext[i]^0xAB),end='')
