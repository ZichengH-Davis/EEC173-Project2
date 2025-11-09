import socket
import os
import time


label = "tmz"
encoded = label.encode("ascii")
print(encoded.hex())
tmz = f"{len(label):02x}" + encoded.hex()

label = "com"
encoded = label.encode("ascii")
print(encoded.hex())
com = f"{len(label):02x}" + encoded.hex()

id_hex  = "2222"
flag   = "0000"
qdcount = "0001"
ancount = "0000"
nscount = "0000"
arcount = "0000"

domain_terminator = "00"
qname_hex = tmz + com + domain_terminator     

qtype_hex  = "0001"   # A type
qclass_hex = "0001"   # Internet

payload_hex = id_hex + flag + qdcount + ancount + nscount + arcount + qname_hex + qtype_hex + qclass_hex
payload = bytes.fromhex(payload_hex) #convert string of hex number to bytes

#print("payload:", payload_hex)
#print("payload byte:", payload)



# specify server host and port to connect to
SERVER_HOST = '170.247.170.2'
SERVER_PORT = 53

# open a new datagram socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:
    client_socket.sendto(payload, (SERVER_HOST, SERVER_PORT))
    data, addr = client_socket.recvfrom(4096)
    #print(f"Reply {len(data)} bytes from {addr}")
    #print(data.hex())
    data_hex = data.hex()

    #print(data_hex[-8:])
    ip_hex = data_hex[-8:]

    ip_first = str(int(ip_hex[0:2], 16))
    #print(ip_first)
    ip_second = str(int(ip_hex[2:4], 16))
    #print(ip_second)
    ip_third = str(int(ip_hex[4:6], 16))
    #print(ip_third)
    ip_fourth = str(int(ip_hex[6:8], 16))
    #print(ip_fourth)

    ip = ip_first + '.' + ip_second + '.' + ip_third + '.' + ip_fourth

    #print(ip)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket2:
        client_socket2.sendto(payload, (ip, SERVER_PORT))
        data2, addr2 = client_socket2.recvfrom(4096)
        print(f"Reply {len(data2)} bytes from {addr2}")
        print(data2.hex())


        data2_hex = data2.hex()

        ip_hex2 = data2_hex[-8:]

        ip_first2 = str(int(ip_hex2[0:2], 16))
        #print(ip_first)
        ip_second2 = str(int(ip_hex2[2:4], 16))
        #print(ip_second)
        ip_third2 = str(int(ip_hex2[4:6], 16))
        #print(ip_third)
        ip_fourth2 = str(int(ip_hex2[6:8], 16))
        #print(ip_fourth)
        ip2 = ip_first2 + '.' + ip_second2 + '.' + ip_third2 + '.' + ip_fourth2
        print(ip2)

        