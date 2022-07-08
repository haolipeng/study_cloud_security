本人实验环境：Ubuntu 20.04

# 一、AppArmor是什么

AppArmor解决了什么问题，和selinux相比是如何？

相比SELinux，优势在于易用性，实现同样的功能限制，会比使用SELinux的规则代码少很多；从规则代码的可读性上看，apparmor也更容易理解和易读。



# 二、AppArmor的安装和使用

## 2、1 安装AppArmor

ubuntu 20.04及以上版本，默认是自带AppArmor的。



安装 AppArmor 用户空间工具：

- apparmor

- apparmor-utils

- auditd(如果想使用配置文件自动生成工具)


apparmor-utils包含很多实用的工具，



## 2、2 开启AppArmor

Ubuntu 20.04或Debian 10之后版本，AppArmor是默认开启的，跳过此步骤。

```
$ sudo mkdir -p /etc/default/grub.d
$ echo 'GRUB_CMDLINE_LINUX_DEFAULT="$GRUB_CMDLINE_LINUX_DEFAULT apparmor=1 security=apparmor"' \
  | sudo tee /etc/default/grub.d/apparmor.cfg
$ sudo update-grub
$ sudo reboot
```



检测当前状态

AppArmor配置可设置两种模式：

complain模式：只会记录违反策略的行为。

enforce模式：违反策略的操作将被阻止。

请注意，即使在complain模式下，配置文件中的deny规则也会被强制执行/阻止。



假设有一个可执行文件的路径为`/usr/bin/man`，如果要用`Apparmor`对其进行访问控制的话，需要新建一个文件名为`usr.bin.man`的配置文件，并把这个配置文件放到Apparmor专门放置配置文件的目录`/etc/apparmor.d`下。



2、2 规则运行模式

Enforcement模式

Complain模式



# 三、AppArmor 配置文件语法

AppArmor 的语法规则分为以下几类：

Profiles配置

Include Rules

Comments

Capability Rules

Network Rules

File rules

File Globbing 文件通配符

File Globbing

​	r - 读

​	w - 写

 	x - 执行

Execute permissions 执行权限



使用工具来生成和调试apparmor配置文件

​	aa-complain

​	aa-genprof



ubuntu安装audit

安装apparmor-utils

如何使用AppArmor（规则编写）

AppArmor解决什么问题

AppArmor实现原理和源代码分析



停止和删除所有的容器

```
docker container rm -f $(docker container ls -aq)
```



参考链接：

AppArmor 实验（必做）

https://dockerlabs.collabnix.com/advanced/security/apparmor/



AppArmor的基本概念和管理

https://mp.weixin.qq.com/s?src=11&timestamp=1656898746&ver=3899&signature=NWNBHLb*p99jC0ZcXxeT45Ygy8sXnwMY1XFVFZa4ET5coDz0djSWNTMc5FrzdNHxc1sq7xSbQGh7XSOleWhtKYHCUr1QSxHM6ypbVGWzwGkhmXnanbDKTMH1-BFfFDxS&new=1



Apparmor配置文件如何编写

https://gitlab.com/apparmor/apparmor/-/wikis/Profiles



手动编写规则文件

https://gitlab.com/apparmor/apparmor/-/wikis/Profiling_by_hand





官网链接

- [AppArmor/HowToUse](https://wiki.debian.org/AppArmor/HowToUse) - using and troubleshooting AppArmor on Debian



- **[AppArmor wiki](https://gitlab.com/apparmor/apparmor/-/wikis/home)**
- [AppArmor Failures - AppArmor wiki](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Failures)
- [Quick guide to profile Language - AppArmor wiki](https://gitlab.com/apparmor/apparmor/-/wikis/QuickProfileLanguage)
- [Develop your own AppArmor profiles - AppArmor wiki](https://gitlab.com/apparmor/apparmor/-/wikis/Profiles)
- [Profiling with tools - AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/Profiling_with_tools)
- [Profiling by hand - AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/Profiling_by_hand)
- [AppArmor Core Policy Reference - AppArmor Wiki](https://gitlab.com/apparmor/apparmor/-/wikis/AppArmor_Core_Policy_Reference)
- [AppArmor - Ubuntu Community documentation](https://help.ubuntu.com/community/AppArmor)
- **[AppArmor - Ubuntu wiki](https://wiki.ubuntu.com/AppArmor)**
- [DebuggingAppArmor - Ubuntu wiki](https://wiki.ubuntu.com/DebuggingApparmor)
- [AppArmor - openSUSE Security Guide](https://doc.opensuse.org/documentation/leap/security/html/book.security/part.apparmor.html)
- [AppArmor - Ubuntu Server Guide](https://help.ubuntu.com/stable/serverguide/apparmor.html)
- [AppArmor crashcourse (PDF)](http://blog.cboltz.de/uploads/osc12/apparmor-english-2012-v2.pdf) - how to create a profile from scratch
- [AppArmor - The Debian Administrator's Handbook](https://debian-handbook.info/browse/stable/sect.apparmor.html)
- [AppArmor - ArchWiki](https://wiki.archlinux.org/index.php/AppArmor)
- [AppArmor - Wikipedia](https://en.wikipedia.org/wiki/AppArmor)
- [man 8 aa-logprof](https://manpages.debian.org/man/8/aa-logprof)
- [man 8 aa-genprof](https://manpages.debian.org/man/8/aa-genprof)
- [man 5 apparmor.d](https://manpages.debian.org/man/5/apparmor.d)