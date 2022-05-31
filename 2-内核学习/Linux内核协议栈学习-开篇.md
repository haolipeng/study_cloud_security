# 一、内核源码下载和在线阅读地址

[Linux source code (v5.18.1) - Bootlin](https://elixir.bootlin.com/linux/latest/source)

[Index of /pub/linux/kernel/](https://mirrors.edge.kernel.org/pub/linux/kernel/)



# 二、阅读源代码

初次看源代码的同学问的最多的两个问题：

## 2、1 使用什么IDE来阅读源代码？

代码阅读工具是source insight



## 2、2 网络协议栈源代码有哪些？

由于linux内核代码非常的多，我只看网络协议栈相关代码，所以只需要导入以下的目录：

目录结构以后再慢慢的调整，不着急。



**基础部分**

lib

mm

init



**头文件**

include/linux

include/net

include/asm-generic



**网络部分**

net/bridge

net/core

net/ethernet

net/ipv4

net/netfilter

net/netlink

net/packet

net/sched

net/unix

net/xfrm





**内核部分**

kernel



**驱动driver**

drivers/net/ethernet/intel/ixgb



**proc虚拟文件系统**

fs/proc



## 2、3 线上问题排查

每次到线上排查问题，就觉得自己需要学习的知识还有很多，需要努力。

排查问题常用工具

atop

htop

slabinfo

slabtop

pstack