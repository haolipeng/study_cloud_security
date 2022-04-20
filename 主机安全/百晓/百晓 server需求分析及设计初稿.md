# 一、需求分析

为了方便描述功能，将功能点区分为server和agent端

## 1、1 agent端亟待解决的问题

迫切需要解决的问题，也是我们需要赶紧做的。

### 1、如何保证客户端的id唯一性呢？

答：采用Txn分布式事务API配合Compare API来确定主机上线的Key唯一性。（写demo进行验证）



### 2、agent上线

### 3、agent正常下线

### 4、agent异常下线

技术上：异常下线，会有1/3的keepalive时间延迟



## 1、2 server端亟待解决的问题

1、server和agent之间通信的数据种类有哪些呢？

server端下发的数据有以下几种：

1、任务

2、配置变更

3、策略（或规则）



2、agent客户端异常下线，server如何感知到呢？

Lease租约机制，过期Key释放，更好的感知主机信息。



# 二、架构设计

## 2、1 总体架构图

<img src="picture/640.webp" alt="图片" style="zoom:67%;" />

数据上报通道

server端和agent端是分为控制面和数据面的

控制面功能

数据面功能

​	数据上报

​	文件上传等等



## 2、2 通信方案

etcd + arpc 的通信方案。

对于实时性要求低的业务，流程如下：

1、agent客户端监听etcd的某些key是否变化

2、server将key对应数据写入etcd数据库中

3、agent会收到数据变更通知，然后读取key对应的数值



对于实时性要求很高的业务，流程如下：

1、server和agent客户端之间建立网络连接的通道

2、server通过arpc通道发下任务、配置变更、策略等数据到agent客户端

3、agent收到数据后，根据数据类型的不同，解析成对应的详情数据



支持加密通信