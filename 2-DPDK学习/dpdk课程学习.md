基础概念

DDIO

Data Direct I/O



传统收包采用硬中断

DPDK未采用硬中断，是通过什么来接收数据包呢？PMD收包模式



netstat 分析tcp端口和监听信息

https://paper.seebug.org/934/



Towards Low Latency Interrupt Mode DPDK





Q:dpdk如何从pci地址读取数据包？

![image-20220626204220225](picture/image-20220626204220225.png)



ls /sys/bus/pci/devices/

列出一堆pci的地址。



新版dpdk源代码的编译工作



勇于接受新事物和新技术。

meson

ninja



root@haolipeng-OptiPlex-7090:~# pip3 install meson ninja

Command 'pip3' not found, but can be installed with:

apt install python3-pip



学东西主要是为了解决心中的疑问，

uio比vfio的优点和缺点是什么?
vfio的学习目的是什么？

