import socket
import time


label = "tmz"
encoded = label.encode("ascii")
#print(encoded.hex())
tmz = f"{len(label):02x}" + encoded.hex()

label = "com"
encoded = label.encode("ascii")
#print(encoded.hex())
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




def read_2bytes(msg, off):
   high = msg[off]
   low  = msg[off + 1]
   v = (high << 8) | low
   return v, off + 2

   

def read_4bytes(msg, off):
    v = ((msg[off] << 24) |
         (msg[off + 1] << 16) |
         (msg[off + 2] << 8) |
          msg[off + 3])
    return v, off + 4


def skip_name(msg, off):
    while True:
        length = msg[off]
        if length == 0: #end of name
            return off + 1
        if (length & 0xC0) == 0xC0: #if the first 2 bits are 11, its a pointer
            return off + 2
        off += 1 + length 


def parse_data(msg):
    off = 0
    _id,off = read_2bytes(msg, off)
    flags,off = read_2bytes(msg, off)
    qd,off = read_2bytes(msg, off)
    an,off = read_2bytes(msg, off)
    ns,off = read_2bytes(msg, off)
    ar,off = read_2bytes(msg, off)


    for _ in range(qd):
        off = skip_name(msg, off)
        off += 4

    ips = []

    def read_rrs(count, off):
        for _ in range(count):
            off = skip_name(msg, off)
            rtype, off = read_2bytes(msg, off)
            rclass, off = read_2bytes(msg, off)
            _ttl, off = read_4bytes(msg, off)
            rdlen, off = read_2bytes(msg, off)
            rdata = msg[off:off + rdlen]
            off += rdlen

            # if TYPE=1, CLASS=1, length 4 bytes, its an ip address
            if rtype == 1 and rclass == 1 and rdlen == 4: 
                ip1 = rdata[0]
                ip2 = rdata[1]
                ip3 = rdata[2]
                ip4 = rdata[3]


                s0 = str(ip1)
                s1 = str(ip2)
                s2 = str(ip3)
                s3 = str(ip4)


                ip = s0 + "." + s1 + "." + s2 + "." + s3
                ips.append(ip)

        return off

    off = read_rrs(an, off)# answers
    off = read_rrs(ns, off)# authority
    off = read_rrs(ar, off)# additional

    return ips


# specify server host and port to connect to
SERVER_HOST = '170.247.170.2'
SERVER_PORT = 53

# open a new datagram socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket:#root server

    client_socket.sendto(payload, (SERVER_HOST, SERVER_PORT))
    data, addr = client_socket.recvfrom(1024)
    ips = parse_data(data)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket2: #tld

        client_socket2.sendto(payload, (ips[0], SERVER_PORT))
        data2, addr2 = client_socket2.recvfrom(1024)
        ips2 = parse_data(data2)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client_socket3: #authoritative domain

            client_socket3.sendto(payload, (ips2[0], SERVER_PORT))
            data3, addr3 = client_socket3.recvfrom(1024)
            ips3 = parse_data(data3)
            print(parse_data(data3))


http = b"GET / HTTP/1.1\r\nHost: tmz.com\r\nConnection: close\r\n\r\n"

SERVER_HOST_TCP = ips3[0]
SERVER_PORT_TCP = 80


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:

    s.connect((SERVER_HOST_TCP, SERVER_PORT_TCP))

    s.sendall(http)

    data = s.recv(1024)
