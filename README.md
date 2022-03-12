# 基于PAM的用户权能分配 

## 实验环境

![image-20220309114947470](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E5%AE%9E%E9%AA%8C%E7%8E%AF%E5%A2%83.png)

## 1每个权能对应的系统调用和功能

- 整理自[man capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

```c
权能 (列出43条)                              系统调用以及功能

CAP_CHOWN             /* 系统调用：chown，对文件的UID和GID做任意的修改 */

CAP_DAC_OVERRIDE       /* 绕过文件读取、写入和执行权限检查.（DAC是“discretionary access control”的缩写。） */

CAP_DAC_READ_SEARCH    /* 绕过文件读取权限检查和目录读取并执行权限检查*/

CAP_FOWNER             /* 忽略进程UID与文件UID的匹配检查 */

CAP_FSETID             /* 修改文件时不清除 set-user-ID 和 set-group-ID 模式位；为其 GID 与文件系统或调用进程的任何补充 GID 不匹配的文件设置 set-group-ID 位。 */

CAP_KILL              /* 系统调用：kill，绕过发送信号时的权限检查，允许对不属于自己的进程发送信号 */

CAP_SETGID            /* 系统调用：setgid，设置和管理进程GID */

CAP_SETUID            /* 系统调用：setuid，设置和管理进程UID */

CAP_SETPCAP          /* 系统调用：capset，如果支持文件功能（即，从 Linux2.6.24 开始）：将调用线程边界集中的任何功能添加到其可继承集； 从边界集中删除能力； 更改安全位标志。
    如果不支持文件功能（即 Linux 2.6.24 之前的内核）：将调用者允许的功能集中的任何功能授予或删除任何其他进程。 （当内核配置为支持文件功能时，CAP_SETPCAP 的此属性不可用，因为 CAP_SETPCAP 对于此类内核具有完全不同的语义。）*/
CAP_SETFCAP          

CAP_LINUX_IMMUTABLE  /* 系统调用：chattr，允许设置文件的不可修改位(IMMUTABLE)和只添加(APPEND-ONLY)属性 */

CAP_NET_BIND_SERVICE  /* 允许绑定到小于1024的端口，普通用户不能通过bind函数绑定到小于1024的端口，而CAP_NET_BIND_SERVICE可以让普通用户也可以绑定端口到1024以下 */

CAP_NET_BROADCAST     /* 允许网络广播和多播访问 */

CAP_NET_ADMIN         /* 执行各种网络相关操作：如接口配置、管理 IP 防火墙、修改路由表等 */

CAP_NET_RAW           /* 系统调用：socket，允许使用原始套接字，原始套接字编程可以接收到本机网卡上的数据帧或者数据包，对监控网络流量和分析有很大的作用 */

CAP_IPC_LOCK          /* 系统调用：mlock，允许锁定内存片段
                       * 锁定内存（mlock(2)、mlockall(2)、mmap(2)、shmctl(2)）；
                       * 使用大页分配内存（memfd_create(2)、mmap(2)、shmctl(2)）。*/

CAP_IPC_OWNER         /* 绕过对 System V IPC 对象的操作的权限检查。 */

CAP_SYS_MODULE        /* 系统调用：init_module，允许普通用户插入和删除内核模块 */

CAP_SYS_RAWIO         /* 执行 I/O 端口操作;访问/proc/kcore;执行各种 SCSI 设备命令等*/

CAP_SYS_CHROOT        /* 系统调用：chroot，普通用户无法使用chroot()系统调用更改程序执行时所参考的根目录位置，而CAP_SYS_CHROOT可以给普通用户这个权限 */

CAP_SYS_PTRACE        /* 系统调用：ptrace，允许普通用户跟踪任何进程 */

CAP_SYS_PACCT         /* 系统调用：acct，允许普通用户配置进程记账 */

CAP_SYS_ADMIN         /* 允许执行系统管理任务，如挂载/卸载文件系统，设置磁盘配额，开/关交换设备和文件等 */

CAP_SYS_BOOT          /* 系统调用：reboot，允许普通用户重新启动系统 */

CAP_SYS_NICE          /* 系统调用：nice，允许提升优先级，设置其他进程优先级 */

CAP_SYS_RESOURCE      /* 系统调用：setrlimit，设置资源限制，但是普通用户不能用setrlimit来突破ulimit的限制；在 ext2 文件系统上使用保留空间；覆盖磁盘配额限制；增加资源限制；覆盖键盘映射的最大数量等 */

CAP_SYS_TIME          /* 系统调用：stime，允许改变系统时钟 */

CAP_SYS_TTY_CONFIG    /* 系统调用：vhangup，允许配置TTY设备 */

CAP_MKNOD             /*(since Linux 2.4)系统调用：mknod，允许使用mknod()系统调用来创建特殊文件 */

CAP_LEASE             /*(since Linux 2.4) 系统调用：fcntl，在任意文件上建立租约 */

CAP_AUDIT_READ        /*(since Linux 3.16)允许通过多播网络链接套接字读取审计日志。 */

CAP_AUDIT_WRITE       /*(since Linux 2.6.11) 将记录写入内核审计日志。 */

CAP_AUDIT_CONTROL     /*(since Linux 2.6.11) 启动或禁用内核审计，修改审计过滤器规则；检索审核状态和过滤规则。*/

CAP_SETFCAP           /*(since Linux 2.6.24)设置文件权能 */

CAP_MAC_OVERRIDE      /*(since Linux 2.6.25)覆盖强制访问控制 (MAC)。实施为Smack LSM。 */

CAP_MAC_ADMIN         /*(since Linux 2.6.25)允许 MAC 配置或状态更改。为 Smack Linux 安全模块 (LSM) 实施。 */

CAP_SYSLOG            /*(since Linux 2.6.37) 系统调用：syslog，执行特权syslog(2)操作；当 /proc/sys/kernel/kptr_restrict 的值为 1 时，查看通过 /proc 和其他接口公开的内核地址。（参见 proc(5) 中对 kptr_restrict 的讨论。） */

CAP_WAKE_ALARM        /*(since Linux 3.0) 触发将唤醒系统的东西(设置 CLOCK_REALTIME_ALARM 和 CLOCK_BOOTTIME_ALARM 定时器) */ 

CAP_BLOCK_SUSPEND     /*(since Linux 3.5)系统调用：epoll，可以阻塞系统挂起的特性 */

CAP_AUDIT_READ        /* 允许通过一个多播netlink socket读取审计日志 */
    
CAP_PERFMON           /*(since Linux 5.8)采用各种性能监控机制，包含：
                         * 调用perf_event_open(2)；
                         * 采用具有性能影响的各种 BPF 操作。
                         Linux 5.8 中添加了此功能，以将性能监控功能与重载的 CAP_SYS_ADMIN 功能分开。 另请参阅内核源文件 Documentation/admin-guide/perf-security.rst。*/
CAP_BPF              /*(since Linux 5.8)使用特权 BPF 操作； 参见 bpf(2) 和 bpf-helpers(7)。 Linux 5.8 中添加了此功能，以将 BPF 功能与重载的 CAP_SYS_ADMIN 功能分开。*/  

CAP_CHECKPOINT_RESTORE/*(since Linux 5.9)
*更新 /proc/sys/kernel/ns_last_pid（参见 pid_namespaces(7)）；
*使用 clone3(2) 的 set_tid 特性；
*为其他进程读取 /proc/[pid]/map_files 中符号链接的内容。 Linux 5.9 中添加了此功能，以将检查点/恢复功能与重载的 CAP_SYS_ADMIN 功能分开。*/
```



部分需要的权能如下表：

| 程序            | 需要的权能                              |
| --------------- | --------------------------------------- |
| /bin/ping       | CAP_NET_RAW                             |
| /bin/mount      | CAP_SYS_ADMIN                           |
| /bin/su         | CAP_DAC_OVERRIDE,CAP_SETGID,CAP_SETUID  |
| /bin/fusermount | CAP_SYS_ADMIN                           |
| /bin/umount     | CAP_SYS_ADMIN                           |
| /usr/bin/passwd | CAP_CHOWN ,CAP_DAC_OVERRIDE, CAP_FOWNER |



## 2基于PAM用户权限设置系统

1. 在某用户**登录**时，规定其只具有某几种权能。

2. 例如，用户A登录，其只具有修改网络相关的权能。

3. Hint：比如，按照权能`execve​`变换规则，根据用户名，登陆前设置`cap_net_raw`，然后设置相应的ping**程序**的文件权能。

   

#### **2.1 前置工作**

- 本实验将利用`/bin/ping`以及`/usr/bin/passwd`进行实验验证。
- 添加新用户only_ping、only_passwd

```
adduser only_ping
adduser only_passwd
```

查看用户：

```
cat/etc/passwd
```

![用户](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E7%94%A8%E6%88%B7.png)

- 检查所有具有setuid位的命令

```
find / -perm -4000 –ls 2>    /dev/null
```

下面列出部分文件

![s位2](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/s%E4%BD%8D2.png)

![s位1](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/s%E4%BD%8D1.png)



- 消除`/bin/ping`以及`/usr/bin/passwd`的s位

```
chmod u-s /usr/bin/passwd
chmod u-s /bin/ping
```



- 消除`/bin/ping`以及`/usr/bin/passwd`的权能

```
setcap -r /bin/ping
setcap -r /usr/bin/passwd
```

- 此时登录用户why，only_ping、only_passwd尝试ping操作以及passwd操作均无法成功

ping操作测试：

  ![image-20220309115550934](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E5%8F%96%E6%B6%88S%E4%BD%8D%E5%92%8C%E6%9D%83%E8%83%BD%E5%90%8E%E6%B5%8B%E8%AF%95ping.png)

passwd操作测试：

![取消S位和权能后测试passwd1](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E5%8F%96%E6%B6%88S%E4%BD%8D%E5%92%8C%E6%9D%83%E8%83%BD%E5%90%8E%E6%B5%8B%E8%AF%95passwd1.png)![取消S位和权能后测试passwd2](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E5%8F%96%E6%B6%88S%E4%BD%8D%E5%92%8C%E6%9D%83%E8%83%BD%E5%90%8E%E6%B5%8B%E8%AF%95passwd2.png)

  #### 2.2 使用脚本实现：根据用户名，登陆前赋予该用户相应权能。

- 在`/usr/local/bin/`目录下新建`cap.sh`脚本文件，实现功能：

1. 用户登录前清除`/bin/ping`和`/usr/bin/passwd`的S位
2. 根据登录用户名决定赋予相应的权能，如登录用户是`only_ping`时，赋予CAP_NET_RAW权能，登录用户是`only_passwd`时，赋予`/usr/bin/passwd`CAP_CHOWN ,CAP_DAC_OVERRIDE, CAP_FOWNER权能。
3. 当用户退出时自动执行清除指定的权能，以避免其余用户仍可执行相关命令


  ![image-20220309134614634](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/shell.png)

-   将cap.sh文件设为可执行：

```
chmod u+x /usr/local/bin/cap.sh
```

-   查阅[资料](https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-pam.html#sec-security-pam-whatis)可知登录操作要用到`common-session`，当用户登录和注销时会调用`session` 模块（bundled in the `common-session` file）


  ![image-20220309121202622](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/common-session.png)

  

-   找到 PAM 相关配置文件所在目录`/etc/pam.d`


  ![image-20220309140144634](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/pam.d%E9%85%8D%E7%BD%AE%E6%96%87%E4%BB%B6%E7%9B%AE%E5%BD%95.png)

-   在该目录下的文件common-session中添加如下规则：


  ```shell
  session optional pam_exec.so debug log=/tmp/pam_exec.log seteuid /usr/local/bin/cap.sh
  ```

此模块开启了`debug`模式，用户每次登录会执行`cap.sh`脚本，并将debug信息打印在文件`pam_exec.log`

根据[PAM手册](http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html)，[[Linux 基础篇（鸟哥私房菜）- 第四版]](https://zq99299.github.io/linux-tutorial/tutorial-basis/#%E5%86%85%E5%AE%B9%E5%AF%BC%E8%88%AA)以及[博客1](https://blog.csdn.net/u013648063/article/details/106944141)和[博客2](https://xsyin.github.io/2018/05/01/Linux%E6%9D%83%E8%83%BD%E4%B8%8EPAM%E6%9C%BA%E5%88%B6/)的内容，总结的上述规则内容如下：

  - `pam_exec`： 是PAM的一个可以使用外部命令的模块。
  
  - `session`：session 管理的就是使用者在这次登陆 （或使用这个指令） 期间，PAM 所给予的环境设置。 这个类别通常用在记录使用者登陆与登出时的信息。
  - `optional`：可选的，这个模块控制项目大多是在显示讯息，并不是用在验证方面的。这里是为了防止脚本赋权失败导致用户无法登录。
  - `debug`：打印debug信息。
  - `log=/tmp/pam_exec.log`：命令的打印信息会打印到这个文件。
  - `seteuid: pam_exec.so`会用真实用户ID执行外部命令。
  - `/usr/local/bin/cap.sh`：外部命令。

  

####   2.3 验证基于PAM的用户权能分配

- 查看相应的S位是否取消
![验证S位取消](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E9%AA%8C%E8%AF%81S%E4%BD%8D%E5%8F%96%E6%B6%88.png)
- 登录用户why查看相应权能，并进行`ping`与`passwd`操作

![image-20220312134044026](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E7%94%A8%E6%88%B7why%E6%93%8D%E4%BD%9C.png)

- 登录用户`only_ping`查看`/bin/ping`与`/usr/bin/passwd`权能并进行`ping`与`passwd`操作

![only_ping用户操作](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/only_ping%E7%94%A8%E6%88%B7%E6%93%8D%E4%BD%9C.png)

- 登录用户`only_passwd`查看`/bin/ping`与`/usr/bin/passwd`权能并进行`ping`与`passwd`操作

![only_passwd用户操作](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/only_passwd%E7%94%A8%E6%88%B7%E6%93%8D%E4%BD%9C.png)

-   查看`pam_exec`日志


  ![image-20220309142133678](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E6%97%A5%E5%BF%97%E4%BF%A1%E6%81%AF.png)

  

  

## 3实验总结

​		实验基本实现了基于PAM的用户权能分配，实验选择了对`/bin/ping`与`/usr/bin/passwd`的权能的操作进行验证。当用户why登录时，其不具有相应权能而无法进行`ping`与`passwd`操作，而当登录用户为`only_ping`时赋予`/bin/ping`以相应的CAP_NET_RAW权能，经验证该用户仅被分配指定权能，只可进行`ping`操作;相应的是当登录用户为`only_passwd`时赋予`/usr/bin/passwd`以相应的CAP_CHOWN ,CAP_DAC_OVERRIDE, CAP_FOWNER权能，经验证该用户仅被分配指定权能，只可进行`passwd`操作;实验的debug信息均被打印到临时文件夹`/tmp`的pam.exec.log中，但显示仍有部分报错，此报错不影响相应权能分配功能的实现。

  ## 注意事项

  1、由于ubuntu的默认sh是dash，其与bash不兼容会导致脚本执行出错，需要将Ubuntu解释器修改为默认连接到bash。

  输入命令：

  ```
  sudo dpkg-reconfigure dash
  ```

  弹窗选择否（No）即可。

  

  2、在使用ubuntu20.04时，在取消`/bin/ping`的权能后发现仍可ping通

![image-20220307213612011](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B91.png)

- 此时查看/bin/ping的权限信息，并去掉s位，尝试ping发现仍可ping通

![image-20220307213938946](https://raw.githubusercontent.com/whythebest/UCAS-courseexperiment/master/images/%E6%B3%A8%E6%84%8F%E4%BA%8B%E9%A1%B92.png)

- 这个问题参考了[Linux: Why am I able to use ping if neither SETUID nor Capabilities are set?](https://stackoverflow.com/questions/63177554/linux-why-am-i-able-to-use-ping-if-neither-setuid-nor-capabilities-are-set)

得知Creating (normal) ICMP packets does not require special permissions anymore.

​       So ping in fact doesn't need neither privileges nor capabilites any more.

