import hashlib
import hmac
import struct
import numpy as np

def sha(data):
    return hashlib.sha256(data).digest()

def extract(salt, data):
    return hmac.digest(salt, data, 'sha256')

def expand(key, info, length):
    previous = b''
    result = b''
    for counter in range(1, (length + 31) // 32 + 1):
        previous = extract(key, previous + info + bytes([counter]))
        result += previous
    return result[:length]

def le(value):
    return struct.pack('<Q', value)

def mix(key, data, info):
    return extract(expand(key, le(info), 32), data)

def chacha(key,nonce,data,rounds=8):
    count=(len(data)+63)//64
    initial=np.zeros((16,count),dtype=np.uint32)
    initial[:4]=np.frombuffer(b'expand 32-byte k',dtype='<u4')[:,None]
    initial[4:12]=np.frombuffer(key,dtype='<u4')[:,None]
    initial[12]=np.arange(count,dtype=np.uint32)
    initial[13:]=np.frombuffer(nonce,dtype='<u4')[:,None]
    x=initial.copy()
    def qr(a,b,c,d):
        x[a]+=x[b];x[d]^=x[a];x[d]=(x[d]<<16)|(x[d]>>16)
        x[c]+=x[d];x[b]^=x[c];x[b]=(x[b]<<12)|(x[b]>>20)
        x[a]+=x[b];x[d]^=x[a];x[d]=(x[d]<<8)|(x[d]>>24)
        x[c]+=x[d];x[b]^=x[c];x[b]=(x[b]<<7)|(x[b]>>25)
    for _ in range(rounds//2):
        for t in [(0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)]:qr(*t)
    stream=(x+initial).T.astype('<u4').tobytes()[:len(data)]
    return (np.frombuffer(data,dtype=np.uint8)^np.frombuffer(stream,dtype=np.uint8)).tobytes()
