һ��agent����



dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/agent -- -j 192.168.101.97

agent�Ƿ���Ե�������dp�Ƿ���Ե���������������Ƿ���Ե��������أ�


���ù��ڰ����Ƶ�Դ���ļ�����Ϊ��

https://mirrors.aliyun.com/alpine/v3.6/main/

https://mirrors.aliyun.com/alpine/v3.6/community/

���

sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories

��װgo���Ի���
go install github.com/go-delve/delve/cmd/dlv@v1.7.3


docker cp allinone_5.0.0:/usr/local/bin /root/neuvector/bin


��/bin/sh����/bin/bash
����֮���������ʲô��


docker exec -it allinone /bin/sh


https://github.com/vishvananda/netlink 

neuvector��������
netlink������Ҫ�úõ���Ϥ�¡�



����dp���Ի����

dp��agent��allinoneģʽ�£������ڹȸ��alpine����ϵͳ�н������еġ�