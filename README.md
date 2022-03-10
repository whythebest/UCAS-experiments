

# 基于PAM的用户权能分配 

## 实验环境

![image-20220309114947470](C:\Users\dell\learngit\images\image-20220309114947470.png)

## 1每个权能对应的系统调用和功能

- 整理自[man capabilities](https://man7.org/linux/man-pages/man7/capabilities.7.html)

```c
权能                 编号              系统调用以及功能

CAP_CHOWN            0  /* 系统调用：chown，对文件的UID和GID做任意的修改 */

CAP_DAC_OVERRIDE     1  /* 忽略对文件的DAC访问限制 */

CAP_DAC_READ_SEARCH  2  /* 忽略DAC中对文件和目录的读、搜索权限 */

CAP_FOWNER           3  /* 忽略忽略进程UID与文件UID的匹配检查 */

CAP_FSETID           4  /* 文件修改时不清除setuid和setgid位，不匹配时设置setgid位 */

CAP_KILL             5  /* 系统调用：kill，绕过发送信号时的权限检查，允许对不属于自己的进程发送信号 */

CAP_SETGID           6  /* 系统调用：setgid，设置和管理进程GID */

CAP_SETUID           7  /* 系统调用：setuid，设置和管理进程UID */

CAP_SETPCAP          8  /* 系统调用：capset，允许授予或删除其他进程的任何权能，只有init进程具有这种能力 */

CAP_LINUX_IMMUTABLE  9  /* 系统调用：chattr，允许设置文件的不可修改位(IMMUTABLE)和只添加(APPEND-ONLY)属性 */

CAP_NET_BIND_SERVICE 10 /* 允许绑定到小于1024的端口，普通用户不能通过bind函数绑定到小于1024的端口，而CAP_NET_BIND_SERVICE可以让普通用户也可以绑定端口到1024以下 */

CAP_NET_BROADCAST    11 /* 允许网络广播和多播访问 */

CAP_NET_ADMIN        12 /* 允许执行网络管理任务：接口、防火墙和路由等 */

CAP_NET_RAW          13 /* 系统调用：socket，允许使用广元市套接字，原始套接字编程可以接收到本机网卡上的数据帧或者数据包，对监控网络流量和分析有很大的作用 */

CAP_IPC_LOCK         14 /* 系统调用：mlock，允许锁定内存片段 */

CAP_IPC_OWNER        15 /* 忽略IPC所有权检查，对普通用户有作用，可以让普通用户的程序可以读取/更改共享内存 */

CAP_SYS_MODULE       16 /* 系统调用：init_module，允许普通用户插入和删除内核模块 */

CAP_SYS_RAWIO        17 /* 允许对ioperm/iopl的访问 */

CAP_SYS_CHROOT       18 /* 系统调用：chroot，普通用户无法使用chroot()系统调用更改程序执行时所参考的根目录位置，而CAP_SYS_CHROOT可以给普通用户这个权限 */

CAP_SYS_PTRACE       19 /* 系统调用：ptrace，允许普通用户跟踪任何进程 */

CAP_SYS_PACCT        20 /* 系统调用：acct，允许普通用户配置进程记账 */

CAP_SYS_ADMIN        21 /* 允许执行系统管理任务，如挂载/卸载文件系统，设置磁盘配额，开/关交换设备和文件等 */

CAP_SYS_BOOT         22 /* 系统调用：reboot，允许普通用户重新启动系统 */

CAP_SYS_NICE         23 /* 系统调用：nice，允许提升优先级，设置其他进程优先级 */

CAP_SYS_RESOURCE     24 /* 系统调用：setrlimit，设置资源限制，但是普通用户不能用setrlimit来突破ulimit的限制 */

CAP_SYS_TIME         25 /* 系统调用：stime，允许改变系统时钟 */

CAP_SYS_TTY_CONFIG   26 /* 系统调用：vhangup，允许配置TTY设备 */

CAP_MKNOD            27 /* 系统调用：mknod，允许使用mknod()系统调用来创建特殊文件 */

CAP_LEASE            28 /* 系统调用：fcntl，为任意文件建立租约 */

CAP_AUDIT_WRITE      29 /* 允许像内核审计日志写记录 */

CAP_AUDIT_CONTROL    30 /* 启动或禁用内核审计，修改审计过滤器规则 */

CAP_SETFCAP          31 /* 设置文件权能 */

CAP_MAC_OVERRIDE     32 /* 允许MAC配置或状态改变，为smack LSM实现 */

CAP_MAC_ADMIN        33 /* 覆盖强制访问控制 */

CAP_SYSLOG           34 /* 系统调用：syslog，执行特权syslog(2)操作 */

CAP_WAKE_ALARM       35    /* 触发将唤醒系统的东西(设置 CLOCK_REALTIME_ALARM 和 CLOCK_BOOTTIME_ALARM 定时器) */ 

CAP_BLOCK_SUSPEND    36 /* 系统调用：epoll，可以阻塞系统挂起的特性 */

CAP_AUDIT_READ       37  /* 允许通过一个多播netlink socket读取审计日志 */
```

## 2基于PAM用户权限设置系统

1. 在某用户**登录**时，规定其只具有某几种权能。
2. 例如，用户A登录，其只具有修改网络相关的权能。
3. Hint：比如，按照权能execve​变换规则，根据用户名，登陆前设置cap_net_raw，然后设置相应的ping程序的文件权能。

#### **2.1 配置新用户why1，设置CAP_NET_RAW 权能**

- 添加新用户userping

![image-20220309115234418](C:\Users\dell\learngit\images\image-20220309115234418.png)

- 先ping一下得知正常使用

![image-20220309115313885](C:\Users\dell\learngit\images\image-20220309115313885.png)

- 此时查看`/bin/ping`的权能，可知此时具有cap_net_raw权能

![image-20220309115345576](C:\Users\dell\learngit\images\image-20220309115345576.png)

- 以root权限使用命令

  ```
  sudo setcap cap_net_raw-ep /bin/ping 
  chmod u-s /bin/ping
  ```

- 消除ping命令的权能和setuid位，再次尝试ping操作，此时无法成功


  ![image-20220309115506299](C:\Users\dell\learngit\images\image-20220309115506299.png)

  

- 切换用户why1尝试ping操作也无法成功




  ![image-20220309115550934](C:\Users\dell\learngit\images\image-20220309115550934.png)

  

  #### 2.2 使用脚本实现：根据用户名，登陆前设置cap_net_raw，然后设置相应的ping程序的文件权能。

- 在`/usr/local/bin/`目录下新建`ping_cap.sh`脚本文件，实现功能：当why1用户登录时，给/bin/ping添加权能，当用户退出时自动执行清除`/bin/ping`的权能，以避免其余用户仍可执行ping命令


  ![image-20220309134614634](C:\Users\dell\learngit\images\image-20220309134614634.png)

-   通过`chmod u+x /usr/local/bin/ping_cap.sh`设为可执行：


  ![image-20220309120728228](C:\Users\dell\learngit\images\image-20220309120728228.png)

  

-   查阅[资料](https://documentation.suse.com/sles/12-SP4/html/SLES-all/cha-pam.html#sec-security-pam-whatis)可知登录操作要用到`common-session`，当用户登录和注销时会调用`session` 模块（bundled in the `common-session` file）


  ![image-20220309121202622](C:\Users\dell\learngit\images\image-20220309121202622.png)

  

-   于是找到 PAM 相关配置文件所在目录`/etc/pam.d`


  ![image-20220309140144634](C:\Users\dell\learngit\images\image-20220309140144634.png)

-   在该目录下的文件common-session中添加如下规则：


  ```shell
  session optional pam_exec.so debug log=/tmp/pam_exec.log seteuid /usr/local/bin/ping_cap.sh
  ```

此为必须模块，开启了`debug`模式，用户`why1`每次登录会执行`ping_cap.sh`脚本

根据[PAM手册](http://www.linux-pam.org/Linux-PAM-html/Linux-PAM_SAG.html)，[[Linux 基础篇（鸟哥私房菜）- 第四版]](https://zq99299.github.io/linux-tutorial/tutorial-basis/#%E5%86%85%E5%AE%B9%E5%AF%BC%E8%88%AA)以及[博客1](https://blog.csdn.net/u013648063/article/details/106944141)和[博客2](https://xsyin.github.io/2018/05/01/Linux%E6%9D%83%E8%83%BD%E4%B8%8EPAM%E6%9C%BA%E5%88%B6/)的内容，总结的上述规则内容如下：

  - `pam_exec`： 是PAM的一个可以使用外部命令的模块。
  
  - `session`：在用户登陆前把事情给干完，比如挂载目录、记录一些关键信息等
  - `optional`：可选的，一般不会对身份认证起作用。这里是为了防止脚本赋权失败导致用户无法登录。
  - `debug`：打印debug信息
  - `log=/tmp/pam_exec.log`：命令的打印信息会打印到这个文件
  - `seteuid: pam_exec.so`会用真实用户ID执行外部命令。
  - `/usr/local/bin/ping_cap.sh`：外部命令

  

  

-   此时登录用户why测试ping命令发现无法成功，而切换用户why1后发现可以ping通


  ![image-20220309142012519](C:\Users\dell\learngit\images\image-20220309142012519.png)

-   查看`pam_exec`日志，可看出成功打印日志信息


  ![image-20220309142133678](C:\Users\dell\learngit\images\image-20220309142133678.png)

  

  

  

  ## 注意事项

  1、由于ubuntu的默认sh是dash，其与bash不兼容会导致脚本执行出错，需要将Ubuntu解释器修改为默认连接到bash。

  输入命令：

  ```
  sudo dpkg-reconfigure dash
  ```

  弹窗选择否（No）即可。

  

  2、在使用ubuntu20.04时，在取消`/bin/ping`的权能后发现仍可ping通

![image-20220307213612011](C:\Users\dell\learngit\images\image-20220307213612011.png)

- 此时查看/bin/ping的权限信息，并去掉s位，尝试ping发现仍可ping通

![image-20220307213938946](C:\Users\dell\learngit\images\image-20220307213938946.png)

- 这个问题参考了[Linux: Why am I able to use ping if neither SETUID nor Capabilities are set?](https://stackoverflow.com/questions/63177554/linux-why-am-i-able-to-use-ping-if-neither-setuid-nor-capabilities-are-set)

得知Creating (normal) ICMP packets does not require special permissions anymore.

​       So ping in fact doesn't need neither privileges nor capabilites any more.

