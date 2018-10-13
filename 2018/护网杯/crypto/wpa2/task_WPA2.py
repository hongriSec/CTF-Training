#!/usr/bin/env python

import hmac
from hashlib import pbkdf2_hmac,sha1,md5
from Crypto.Cipher import AES
import string
import random
import struct

def PRF(key,A,B):
	nByte = 48
	i = 0
	R = ''
	
	while ( i <= ((nByte*8 + 159)/160)):
		hmacsha1 = hmac.new(key,A+"\x00" + B + chr(i),sha1)
		R += hmacsha1.digest()
		i += 1
	return R[0:nByte]

def MakeAB(aNonce,sNonce,apMac,cliMac):
	A = "Pairwise key expansion"
	B = min(apMac,cliMac) + max(apMac,cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce)
	return (A,B)

def MakeKeys(pwd,ssid,A,B):
	pmk = pbkdf2_hmac('sha1',pwd,ssid,4096,32)
	
	ptk = PRF(pmk,A,B)
	
	return (ptk,pmk)
def XOR(b1,b2,l):
	if (len(b1)<l or len(b2)<l):
		return None
	res = ''
	for i in range(l):
		res += chr(ord(b1[i]) ^ ord(b2[i]))
	if (len(b1)>l):
		res += b1[l:]
	return res

def EncryptCCMP(indata,TK,PN):
    if len(TK) != 16 or len(PN) != 6:
        return None

    is_a4 = (ord(indata[1]) & 0x03) == 3
    is_qos = (ord(indata[0]) & 0x8c) == 0x88

    z = 24 + 6 * (1 if is_a4 else 0)
    z += 2 * (1 if is_qos else 0)

    h80211 = list(indata)

    h80211[z + 0] = PN[5]
    h80211[z + 1] = PN[4]
    h80211[z + 2] = '\x00'
    h80211[z + 3] = '\x20'
    h80211[z + 4] = PN[3]
    h80211[z + 5] = PN[2]
    h80211[z + 6] = PN[1]
    h80211[z + 7] = PN[0]

    inputpkt = ''.join(h80211)

    data_len = len(inputpkt) - z - 8
    B0 = ''
    B0 += '\x59'
    B0 += '\x00'
    B0 += inputpkt[10:16]
    B0 += PN
    B0 += chr((data_len >> 8) & 0xFF)
    B0 += chr(data_len & 0xFF)

    AAD = '\x00' * 2  # [0] [1]

    AAD += chr(ord(inputpkt[0]) & 0x8F)  # [2]
    AAD += chr(ord(inputpkt[1]) & 0xC7)  # [3]
    AAD += inputpkt[4:4 + 3 * 6]  # [4]..[21]
    AAD += chr(ord(inputpkt[22]) & 0x0F)  # [22]

    AAD += '\x00'  # [23]

    if (is_a4):
        AAD += inputpkt[24:24 + 6]  # [24]..[29]
        if (is_qos):
            AAD += chr(ord(inputpkt[z - 2]) & 0x0F)  # [30]
            AAD += '\x00'  # [31]
            tmp = list(B0)
            tmp[1] = AAD[30]
            B0 = ''.join(tmp)
            tmp = list(AAD)
            tmp[1] = chr(22 + 2 + 6)
            AAD = ''.join(tmp)
        else:
            AAD += '\x00' * 2  # [30]..[31]
            tmp = list(B0)
            tmp[1] = '\x00'
            B0 = ''.join(tmp)
            tmp = list(AAD)
            tmp[1] = chr(22 + 6)
            AAD = ''.join(tmp)
    else:
        if (is_qos):
            AAD += chr(ord(inputpkt[z - 2]) & 0x0F)  # [24]
            AAD += '\x00'  # [25]
            tmp = list(B0)
            tmp[1] = AAD[24]
            B0 = ''.join(tmp)
            tmp = list(AAD)
            tmp[1] = chr(22 + 2)
            AAD = ''.join(tmp)
        else:
            AAD += '\x00' * 2  # [24]..[25]
            tmp = list(B0)
            tmp[1] = '\x00'
            B0 = ''.join(tmp)
            tmp = list(AAD)
            tmp[1] = chr(22)
            AAD = ''.join(tmp)
        AAD += '\x00' * 6

    cipher = AES.new(TK, AES.MODE_ECB)
    MIC = cipher.encrypt(B0)
    MIC = XOR(MIC, AAD, 16)
    MIC = cipher.encrypt(MIC)
    MIC = XOR(MIC, AAD[16:], 16)
    MIC = cipher.encrypt(MIC)

    tmp = list(B0)
    tmp[0] = chr(ord(tmp[0]) & 0x07)
    tmp[14] = '\x00'
    tmp[15] = '\x00'
    B0 = ''.join(tmp)

    B = cipher.encrypt(B0)
    initMIC = B

    blocks = (data_len + 16 - 1) / 16
    last = data_len % 16
    offset = z + 8

    encryptedPacket = ''

    for i in range(1, blocks + 1):
        n = last if (last > 0 and i == blocks) else 16
        MIC = XOR(MIC,inputpkt[offset:offset+n],n)
        MIC = cipher.encrypt(MIC)
        tmp = list(B0)
        tmp[14] = chr((i >> 8) & 0xFF)
        tmp[15] = chr(i & 0xFF)
        B0 = ''.join(tmp)
        B = cipher.encrypt(B0)
        out = XOR(inputpkt[offset:offset + n], B, n)
        encryptedPacket += out


        offset += n

    encryptedPacket = inputpkt[:z+8] + encryptedPacket
    encryptedPacket += XOR(initMIC,MIC,8)[:8]

    return encryptedPacket

if __name__=="__main__":

	print "Welcome to HuWang Bei WPA2 Simulation System.. Initilizing Parameters.."
	print ""
	
	ssid = "HuWang"
	
	psk = ''.join(random.choice(string.ascii_uppercase+ string.ascii_lowercase + string.digits) for _ in range(16))
	rnddev = open("/dev/urandom","rb")
	
	aNonce = rnddev.read(32)
	
	sNonce = rnddev.read(32)
	
	apMac = rnddev.read(6)
	
	staMac = rnddev.read(6)
	
	rnddev.close()
	
	print "SSID = "+ssid
	print ""
	
	print "PSK = "+psk
	print ""
	
	outmac=apMac.encode('hex').upper()
	macaddr = ''
	for i in range(len(outmac)):
		macaddr += outmac[i]
		if (i%2!=0 and i<len(outmac)-1):
			macaddr+=':'
	print "AP_MAC = "+macaddr
	print ""
	
	print "AP_Nonce = "+aNonce.encode('hex')
	print ""
	
	outmac=staMac.encode('hex').upper()
	macaddr = ''
	for i in range(len(outmac)):
		macaddr += outmac[i]
		if (i%2!=0 and i<len(outmac)-1):
			macaddr+=':'
	
	print "STA_MAC = "+macaddr
	print ""
			
	print "STA_Nonce = "+sNonce.encode('hex')
	print ""
	
	A,B = MakeAB(aNonce,sNonce,apMac,staMac)
	
	ptk,pmk = MakeKeys(psk,ssid,A,B)
	
	key = ptk[-16:]
	
	chlvalue = ''.join(random.choice(string.ascii_uppercase+ string.ascii_lowercase + string.digits) for _ in range(16))
	challenge = "Challenge Vlaue: "+chlvalue
	
	
	datapkt = ("88423a01"+staMac.encode('hex')+apMac.encode('hex')+apMac.encode('hex')+"60920000"+"0000002000000000"+challenge.encode('hex')).decode('hex')
	
	packetNumber = struct.pack(">Q",random.randint(1,9999999))[2:]
	
	outtoUser = EncryptCCMP(datapkt,key,packetNumber)
	
	print "CCMP Encrypted Packet = "+outtoUser.encode("hex")
	print ""
	
	userinput = raw_input("Input decrypted challenge value in Packet:")
	print ""
	
	if (userinput == chlvalue):
		f = open("flag","r")
		content = f.read()
		f.close()
		print "Congratulations!Your flag is: "+content
	else:
		print "Wrong!"
	
	
	
	
	
	
	
