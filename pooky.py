
from sys import platform as _platform
if _platform == 'darwin':
    import crypto
    sys.modules['Crypto'] = crypto


from Crypto.Cipher import AES
import random,time,os,uuid
def decwithiv(key,data,iv):
    m=AES.new(key,AES.MODE_ECB)
    data=m.decrypt(data)
    data="".join([chr(ord(data[i])^iv[i]) for i in range(0,16)])
    return data

def decrypt(u):
    u=u.decode('hex')
    iv=[ord(u[i]) for i in range(0,16)]
    u=u[16:]
    key='\xf2 \xc2k\x92\xa0!\xaa\xaf\x86(\x0c\xb3\x9d\xeev\x1eu\xef\xa8\xa1\xe2NP\xd3i\xe1\x1d7\xc9\xd1P'
    j=0
    dat=""
    while j<len(u):
        d=decwithiv(key,u[j:(j+16)],iv)
        dat+=d
        iv=[ord(u[j+i]) for i in range(0,16)]
        j+=16
    return dat

# The last 2 functions are for decrypting the hex encoded data from any cookie or the bogus post data.

def aeswithiv(key,data,iv):
    m=AES.new(key,AES.MODE_ECB)
    dat="".join([chr(ord(data[i])^iv[i]) for i in range(0,16)])
    return m.encrypt(dat)

def encrypt(u,iv):
    pad=16-(len(u)%16)
    u+=(chr(pad)*pad)
    key='\xf2 \xc2k\x92\xa0!\xaa\xaf\x86(\x0c\xb3\x9d\xeev\x1eu\xef\xa8\xa1\xe2NP\xd3i\xe1\x1d7\xc9\xd1P'
    j=0
    dat=""
    pref="".join(chr(s) for s in iv)
    while j<len(u):
        d=aeswithiv(key,u[j:(j+16)],iv)
        dat+=d
        j+=16
        iv=[ord(d[i]) for i in range(0,16)]
    return (pref+dat).encode('hex')

def generate_cookies():
    cookies={}
    l=[239, 222, 190, 173]
    random.shuffle(l)
    k="".join(chr(u) for u in l)
    items=[("pooky_telemetry",45),("pooky_recaptcha",87),("pooky_recaptcha_coherence",40),("pooky_data",195),("pooky_settings",200)]
    item=random.choice(items)
    cookies["pooky_electric"]=encrypt(chr(item[1]),[ord(j) for j in os.urandom(16)])
    for p,q in items:
        if p!=item[0]:
            cookies[p]=encrypt("".join(chr(random.randint(1,199)) for i in range(0,16)),[ord(j) for j in os.urandom(16)])
        else:
            cookies[p]=encrypt("".join(chr(s) for s in l),[ord(j) for j in os.urandom(16)])
    x=str(int(time.time()*1000))
    y=""
    for p in x:
        y+=str(random.randint(0,8))
        y+=p
    cookies["pooky_mouse"]=encrypt(y.decode('hex'),[ord(j) for j in os.urandom(16)])
    cookies["pooky"]=str(uuid.uuid4())
    cookies["pooky_performance"]=encrypt(cookies["pooky"].replace("-","")[::-1].decode('hex'), [ord(j) for j in os.urandom(16)])
    return cookies
