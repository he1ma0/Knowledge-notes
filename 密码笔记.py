de≡1mod(φ(N))    即d、e的乘积模φ(N)余数为1，那么d和e互为对方模φ(N)的模逆元/数论倒数
求模逆也可直接利用gmpy2库。如
import gmpy2
print gmpy2.invert(47,30) 可求得47模30的逆为23。
也就是，已知
p = 3487583947589437589237958723892346254777 
q = 8767867843568934765983476584376578389
e = 65537
求 d = 
直接根据 ed≡1(modr)，其中 r=φ(N)=φ(p)φ(q)=(p−1)(q−1)，可得 d。
import gmpy2
p = 3487583947589437589237958723892346254777
q = 8767867843568934765983476584376578389
e = 65537
phin = (p - 1) * (q - 1)
print gmpy2.invert(e, phin)






费马小定理：
如果p是一个质数，而整数a不是p的倍数,则有
a^(p−1)≡1(mod p)
另外上式两边同时乘a，得
a^p≡a(mod ap)

模运算法则：
(a + b) % n ≡ (a % n + b % n) % n

(a - b) % n ≡ (a % n - b % n) % n

(a * b) % n ≡ (a % n * b % n) % n

(a ^ b) % n ≡ ((a % n) ^ b) % n //幂运算

若 a ≡ b(mod n) ,则

1.对于任意正整数c,有a^c ≡ b^c(mod n)

2.对于任意整数c,有ac ≡ bc(mod n),a+c ≡ b+c(mod n),

3.若 c ≡ d(mod n),则a-c ≡ b-d(mod n),a+c ≡ b+d(mod n),ac ≡ bd(mod n)

如果ac≡bc (mod m)，且c和m互质，则a≡b (mod m）。





现代密码常见分类：
流密码：
分组密码：
	常见: AES、DES
		但是根据现代计算机的性能，des密钥长度仅为56位，可以进行爆破攻击，所以现在很少考
		而AES的常见攻击方式是CBC翻转攻击、padding oracle 攻击
非对称密码（公钥密码）：常见RSA
	RSA常见攻击方法：
		套路1： 共模攻击		https://skysec.top  2018/09/13
		套路2： 低指数攻击  （公钥e很小）
		套路3： 大指数攻击  （公钥e很大）
		套路4： 广播攻击
		套路5： dp与dq
		套路6： Coppersmith定理攻击
哈希函数：










RSA基本原理：
  公钥和私钥的产生：
	1、随机选择两个不同的大质数p和q，计算 N=p×q
	2、根据欧拉函数，有r=φ(N)=φ(p)φ(q)=(p−1)(q−1)
	3、选择一个小于r的整数e，使得e和r互质。并求得e关于r的模反元素，命名为d，即ed≡1(modr)
	4、将p和q的记录销毁
	此时，(N,e)是公钥，(N,d)是私钥
  消息加密：
    首先需要将消息m以一个双方约定好的格式转化为一个小于N，且与N互质的整数n，如果消息太长，可以将消息分为几段，
    也就是我们所说的块加密，后对于每一部分利用如下公式进行加密：
    n^e≡c(modN)
  消息解密：
    利用密钥d进行解密。
      c^d≡n(modN)



分解整数的工具：
在kali中安装了factordb
命令行明星  factordb 16



求模反元素：
利用python库 gmpy2
若e、d是关于phi的模反元素，已知e、phi，求d
d=gmpy2.invert(e,phi)

快速幂取模：
利用python库 gmpy2
对于消息解密公式c^d≡n(modN)，已知密文c，密钥d，N=p*q，求明文n
n=gmpy2.powmod(c,d,N)

python中求 c^d(modn)
pow(c,d,n)

RSA攻击方式：
	模数相关攻击：
		1、暴力分解（在N的比特位数小于512时，可以使用大整数分解的策略获取p和q）
			kali命令行下   factordb N值





AES  python用法
from Crypto.Cipher import AES
c=AES.new(b'Hello,World12345')  
#使用cbc方法加密，除了需要指定特定长度的key值外，还需要指定初始向量iv。使用ECB方式加密不需要指定iv
c=AES.new(b'Hello,World12345',mode=AES.MODE_CBC,IV=b'1234567887654321')
test=c.decrypt(b'miwen')



AES加密解密算法的输入是一个128位的分组，其加密轮数有N轮构成，轮数依赖于密钥长度：16字节密钥对应10轮，24字节密钥对应12轮，32字节密钥对应14轮，
AES是一种块加密，所谓块加密就是每次加密一块明文，那么明文的长度可能很长也可能很短，那么就需要借助两个辅助
1、padding，即padding到指定的分组长度
2、分组加密模式，即明文分组加密的方式
其中，明文分组的方式又分为
ECB(电子密码本模式)
CBC(密码分组链接模式)
PCBC(明文密码块链接)
CFB(密文反馈模式)
OFB(输出反馈模式)
CTR(计数器模式)



CBC字节翻转攻击
前提：不知道key，但是可以控制密文和初始向量IV，并可以获得每次解密后的结果
加密过程：明文都是先与混淆数据（第一组是与IV，之后都是与前一组的密文）进行异或，在执行分组加密
解密过程：每组解密时，先进行分组加密算法的解密，然后与前一组的密文进行异或才是最初的明文，对于第一组则是与IV进行异或
原理：假设当前明文块为C，当前经过key解密，但是尚未进行解混淆的字符串为B，前一密文块为A，则有A^B=C,所以有A^B^C=0,
由于我可以控制密文内容，即可以控制A，那么我令A=B^C,那么这样在进行异或之后的明文就变成了0，基于以上原理，我令A=B^C^X，即可控制异或之后的明文变成了X。
以上是通过控制上一块的密文，来指定的输出当前块的明文的内容，但是由于上一块的密文产生了变化，那么上一块的明文也必将产生不可预期的变化，基于这个原因，
在控制输出的明文为自己想要的内容时，只能从最后一组开始修改，每修改完一组，都需要重新获取一次解密后的数据，根据解密后的数据来修改前一组密文的值，一直
到修改到第一组时，同样的方法修改IV的值来控制第一组解密后的结果
代码示例：
#coding:utf-8
from Crypto.Cipher import AES
from binascii import b2a_hex,a2b_hex

def encrypt(iv,plaintext):
    if len(plaintext)%16 != 0:
        print "plaintext length is invalid"
        return
    if len(iv) != 16:
        print "IV length is invalid"
        return
    key="1234567890123456"
    aes_encrypt = AES.new(key,AES.MODE_CBC,IV=iv)
    return b2a_hex(aes_encrypt.encrypt(plaintext))

def decrypt(iv,cipher):
    if len(iv) != 16:
        print "IV length is invalid"
        return
    key="1234567890123456"
    aes_decrypt = AES.new(key,AES.MODE_CBC,IV=iv)
    return b2a_hex(aes_decrypt.decrypt(a2b_hex(cipher)))

def test():
    iv="ABCDEFGH12345678"
    plaintext="0123456789ABCDEFhellocbcflipping"
    cipher=encrypt(iv, plaintext)
    print 'cipher:  '+cipher
    de_cipher = decrypt(iv, cipher)
    print 'de_cipher:  '+de_cipher
    print 'a2b_hex(de_cipher):  '+a2b_hex(de_cipher)

test()

以上代码输出为：
cipher:  4913ceb9d0a80cfe38a0d5f633c63eb27f1c833277f85bc2bf628cb7e0641851
de_cipher:  3031323334353637383941424344454668656c6c6f636263666c697070696e67
a2b_hex(de_cipher):  0123456789ABCDEFhellocbcflipping

现在使用CBC字节翻转攻击使得最后的字母g变为大写的G，CBC模式下，通常将明文分成每16位一组，也有32位的
g是第二组的第16个字节，最后异或的时第一组密文的第16个字节，也就是cipher[15],因此要将该字节修改为
cipher[15]^ord('g')^ord('G')
据此修改test()方法
def test():
    iv="ABCDEFGH12345678"
    plaintext="0123456789ABCDEFhellocbcflipping"
    cipher=encrypt(iv, plaintext)
    print 'cipher:  '+cipher
    de_cipher = decrypt(iv, cipher)
    print 'de_cipher:  '+de_cipher
    print 'a2b_hex(de_cipher):  '+a2b_hex(de_cipher)
#-------------------adding 1 start-----------------------------------
    bin_cipher = bytearray(a2b_hex(cipher))
    bin_cipher[15] = bin_cipher[15] ^ ord('g') ^ ord('G')
    de_cipher = decrypt(iv,b2a_hex(bin_cipher))
    print "de_cipher2:  "+de_cipher
    print 'a2b_hex(de_cipher):  '+a2b_hex(de_cipher)
#-------------------adding 1 end-------------------------------------
修改之后的输出为：
cipher:  4913ceb9d0a80cfe38a0d5f633c63eb27f1c833277f85bc2bf628cb7e0641851
de_cipher:  3031323334353637383941424344454668656c6c6f636263666c697070696e67
a2b_hex(de_cipher):  0123456789ABCDEFhellocbcflipping
de_cipher2:  23ab74aa019b5d520559f09d6e461ef668656c6c6f636263666c697070696e47
a2b_hex(de_cipher):  #�t��]RY�nF�hellocbcflippinG

成功修改最后一位从g变成G,但是由于修改了第一组的密文，所以第一组解密后变成了乱码
所以这时要修改IV的值来控制第一组密文解密后的结果，这里就需要使用到新的密文块，即de_cipher2，
要将前十六个字节恢复为最初的0123456789ABCDEF，那么就需要将IV与de_cipher2相应位置的值进行异或再与
0123456789ABCDEF相应位置的值进行异或，最后的结果就是新的IV的值
再次修改test
def test():
    iv="ABCDEFGH12345678"
    plaintext="0123456789ABCDEFhellocbcflipping"
    cipher=encrypt(iv, plaintext)
    print 'cipher:  '+cipher
    de_cipher = decrypt(iv, cipher)
    print 'de_cipher:  '+de_cipher
    print 'a2b_hex(de_cipher):  '+a2b_hex(de_cipher)
#-------------------adding 1 start-----------------------------------
    bin_cipher = bytearray(a2b_hex(cipher))
    bin_cipher[15] = bin_cipher[15] ^ ord('g') ^ ord('G')
    de_cipher = decrypt(iv,b2a_hex(bin_cipher))
    print "de_cipher2:  "+de_cipher
    print 'a2b_hex(de_cipher):  '+a2b_hex(de_cipher)
#-------------------adding 1 end-------------------------------------
#-------------------adding 2 start-----------------------------------
    bin_decipher = bytearray(a2b_hex(de_cipher))
    bin_iv = bytearray(iv)
    for i in range(0,len(iv)):
        bin_iv[i] = bin_iv[i] ^ bin_decipher[i] ^ ord(plaintext[i])
    de_cipher = decrypt(str(bin_iv),b2a_hex(bin_cipher))
    print "de_cipher3:  "+de_cipher
    print 'a2b_hex(de_cipher):  '+a2b_hex(de_cipher)
#-------------------adding 2 end-------------------------------------
修改之后的输出为：
cipher:  4913ceb9d0a80cfe38a0d5f633c63eb27f1c833277f85bc2bf628cb7e0641851
de_cipher:  3031323334353637383941424344454668656c6c6f636263666c697070696e67
a2b_hex(de_cipher):  0123456789ABCDEFhellocbcflipping
de_cipher2:  23ab74aa019b5d520559f09d6e461ef668656c6c6f636263666c697070696e47
a2b_hex(de_cipher):  #�t��]RY�nF�hellocbcflippinG
de_cipher3:  3031323334353637383941424344454668656c6c6f636263666c697070696e47
a2b_hex(de_cipher):  0123456789ABCDEFhellocbcflippinG

题目示例：
bugku login4
答案脚本：
#coding:utf-8
import base64
import urllib
#用python2写的,python3有问题
iv='OYVYzBQLqtzn3%2FWq%2F7TDWg%3D%3D'
cipher='fmOBcWkW7pmLgXCEbRZo4AzgBuCwzZ4uEUQDCz0wxvYzO5cpzSOKAKjg3DQm3DxchnzxeKHyak3oDlyu71dzvw%3D%3D'
#这里也是要通过题目源码或者其他的，要知道数据解密后的形式，否则无法分段
#该cipher解密后的形式为 a:2:{s:8:"username";s:5:"zdmin";s:5:"zdmin";s......
#以16个为一组，前两组分别为：
#a:2:{s:8:"userna
#me";s:5:"zdmin";
#我要将第二组的第九位z翻转为a,所以对应于第一组的第九位
iv=base64.b64decode(urllib.unquote(iv))  #此处进行了url解码、base64解码，是因为后台对数据进行了这两种处理，要具体情况具体分析
cipher=base64.b64decode(urllib.unquote(cipher))
n_cipher=str(cipher[0:9])+chr(ord(cipher[9])^ord('z')^ord('a'))+str(cipher[10:])
n_cipher=urllib.quote(base64.b64encode(n_cipher))
print n_cipher
#获得了新的n_cipher后，修改包提交这个字符串，然后后台会把这个字符串使用key值进行解密，
#后台提示base64_decode('rn0sljeKbDhGarhUzy6ozW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjU6InpkbWluIjt9')出错,
#然后根据这个字符串再求iv，我在做这个题的时候犯得错误是，误以为编码前的n_cipher和下面的new_cipher是一样的，所以直接依据n_cipher求IV
#但是实际上在CBC翻转攻击的前提里我提过必须要知道每次解密后的结果，即经过盒子处理的结果，要每次获取这个结果，据此来求上一段的
new_cipher=base64.b64decode('rn0sljeKbDhGarhUzy6ozW1lIjtzOjU6ImFkbWluIjtzOjg6InBhc3N3b3JkIjtzOjU6InpkbWluIjt9')
n_iv=''
right = 'a:2:{s:8:"userna'
for i in range(0,16):
	n_iv+=chr(ord(iv[i])^ord(new_cipher[i])^ord(right[i]))
print urllib.quote(base64.b64encode(n_iv))



Padding Oracle Attack
padding oracle attack 是针对CBC链接模式的攻击，和具体的加密算法无关，也就是说这种攻击方式不是对加密算法的攻击，而是针对算法
的使用不当进行的攻击
前提：攻击者能够获得密文，以及附带在密文前面的IV；攻击者能够触发密文的解密过程，且能够知道密文的解密结果
