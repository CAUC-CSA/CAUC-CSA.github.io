### 基础工具介绍

* **IDA Pro 9.0**: 宇宙第一好用的反汇编和反编译工具，能通过二进制文件反汇编出相应的汇编代码，进而反编译出易懂的C语言代码，便于了解ELF文件是如何工作的。

* **vim**: 简单但是强大的文件编辑器，可用于写攻击脚本exp

* **pwntools**: Python中写针对CTF的pwn环境的攻击脚本提供的一个强大的库，具体用法在后面会有简单介绍

* **ROPgadget**: 命令行工具，能轻松从ELF文件中提取代码片段，对构造ROP链形成攻击脚本给予了极大方便。

* **onegadget**: 一种能够**大幅简化漏洞利用过程**的强大技术

* **gdb**：代码调试工具，有各种强大的功能，如查看栈和寄存器的情况，查找函数地址，程序调试等。

* **pwndbg**: gdb的强大插件之一，是gdb的赛博朋克增强版，极大简化了调试流程。

* **Termius**: 强大的SSH工具，功能类似于XShell，支持SFTP文件传输协议

* **UTM**：稍逊色于vmware和Parallels Desktop的另一虚拟机软件，它具有模拟架构功能，是MacBook等ARM架构的设备调试x86架构的ELF文件的必需软件。

### 软件安装

**IDA Pro 9.0**:

使用Windows的师傅直接点击[这里](https://pan.baidu.com/s/1eCmxbP6nNHm5qz41rFbetg?pwd=5hdq "这里")下载

使用Mac的师傅点击[这里](https://macked.app/ida-professional-9-2-250908-for-mac-crack.html "这里")后登录账号下载，没有就注册一个

**UTM**：

Win的师傅可跳过这一步，Mac的师傅点击[这里](https://mac.getutm.app)下载

**Termius**：

如果你喜欢用图形化界面的虚拟机也可以下载，用作后面AWD连接靶机的工具

配置文件/安装包：[点我选择性下载](https://pan.baidu.com/s/1H1UbuxVodjao-5ABrFy2Cg?pwd=cauc)

配置文件：app.asar

Win安装包：Termius.zip

Mac安装包：Termius.dmg

随后在C://Users/你的用户名/AppData/Local/Programs/Termius/resources目录下，把原来的同名配置文件替换为上面刚下载的配置文件

随后在/Applications/Termius.app/Contents/resources目录下将同名文件替换

在虚拟机中输入：

```bash
ifconfig #可看到自己虚拟机的IP地址
sudo service ssh restart #重启ssh服务
```

随后打开Termius新建主机，输入ip地址，虚拟机的用户名和密码，点击链接即可在Termius界面使用虚拟机了

### 虚拟机环境配置

检查虚拟机版本是否为Ubuntu 22.04，若不是请重新下载，否则安装过程会出问题

打开虚拟机，打开终端，输入以下命令换源：

1. **备份原始源列表**：为防止出错时能够恢复，请务必先备份 。

   ```shell
   sudo cp /etc/apt/sources.list /etc/apt/sources.list.bak
   ```

2. **编辑源列表文件**：使用vim打开源列表文件 。

   ```shell
   vim /etc/apt/sources.list
   ```

3. **替换为清华源配置**：将文件里的原有内容全部删除或注释掉，然后粘贴以下配置内容。这里的 `jammy`是 Ubuntu 22.04 的版本代号，请确保使用它 。

   ```shell
   # 清华大学镜像源配置
   deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy main restricted universe multiverse
   # deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy main restricted universe multiverse
   deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse
   # deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-updates main restricted universe multiverse
   deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
   # deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-backports main restricted universe multiverse
   deb https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-security main restricted universe multiverse
   # deb-src https://mirrors.tuna.tsinghua.edu.cn/ubuntu/ jammy-security main restricted universe multiverse
   ```

   完成后，保存并退出编辑器（:wq!）。

更新虚拟机：

```Bash
sudo apt update
sudo apt upgrade -y
```

等待进程结束。

### vim下载

```bash
sudo apt install vim
```

### Pwntools下载

两种方法

1.pip安装

```bash
sudo apt-get install python3-pip
sudo apt install git -y
pip3 install pwntools
```

2.源码安装

```bash
git clone https://github.com/Gallopsled/pwntools
cd pwntools
pip install -e .
```

### ROPgadget下载

1.pip安装

```bash
pip3 install ROPgadget
```

2.源码安装

```bash
git clone https://github.com/JonathanSalwan/ROPgadget.git
cd ROPgadget
python3 setup.py
```

### Onegadget下载

```bash
sudo apt install ruby
sudo gem install one_gadget
```

### gdb下载

```bash
sudo apt install gdb
```

### pwndbg下载

``` bash
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

至此一个相对完整的Pwn虚拟机环境已经配置完毕。

[原文链接](https://www.ghostfoxy.cn/2025/11/08/FTN001/)
