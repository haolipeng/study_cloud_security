一、agent调试



dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/agent -- -j 192.168.101.97

agent是否可以单独部署，dp是否可以单步部署？其他组件是否可以单独部署呢？


采用国内阿里云的源，文件内容为：

https://mirrors.aliyun.com/alpine/v3.6/main/

https://mirrors.aliyun.com/alpine/v3.6/community/

命令：

sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

安装go语言环境
go install github.com/go-delve/delve/cmd/dlv@v1.7.3


docker cp allinone_5.0.0:/usr/local/bin /root/neuvector/bin


是/bin/sh不是/bin/bash
两者之间的区别是什么？


docker exec -it allinone /bin/sh


https://github.com/vishvananda/netlink 

neuvector单机调试
netlink还是需要好好的熟悉下。



二、dp调试环境搭建

dp和agent在allinone模式下，都是在谷歌的alpine操作系统中进行运行的。