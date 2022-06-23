

׼��������

```
docker cp allinone_5.0.0:/usr/local/bin /root/neuvector_5.0.0/bin
```

�������е�

# һ��Զ�̵���agent

Ĭ��ģʽ�£�agent���Ա���ģʽ����dp�Ľ���״̬�����������kill��dp���̣�

Neuvector��enforcer������Ĭ�ϻᴦ��NVProtectģʽ���û���������������һЩ�������Ҳ�ᵼ�½��̱�ɱ����������dlv������agent����������gdb��gdbserver������dp������뱣֤����̲��ᱻNeuvectorɱ����



## 1��1 ���±���agent

��������޸�
go build -gcflags='-N -l'



��agent��������޸ģ�ɾ�����е���syscall.Kill�Ĵ���Ƭ�Ρ�

�漰�����ļ��У�

### 1�� agentɾ������syscall.Kill

![image-20220621104134559](picture/image-20220621104134559.png)

### 2�� agentɾ����dp�Ľ������

��agent��cbKeepAlive������



### 3��monitorɾ����dp���

ɾ��monitor�м��dp�Ĵ��룬��ע�͵�stop_proc(PROC_DP, SIGSEGV, false);����



neuvector/allinone:haolp_5.0.0

|ERRO|AGT|dp.dpSendMsgExSilent: Read error - error=read unixgram /tmp/dp_client.23546->/tmp/dp_listen.sock: i/o timeout



allinone_haolp_5.0.0 | 2022-06-21T10:17:43.917|ERRO|AGT|dp.dpSendMsgExSilent: Data path not connected

�Ǳ�������ͨ�����쳣������



Ϊɶһֱ�ڱ���������أ�#todo



# ����Զ�̵���dp

2��1 ����



������Զ�� GDB/LLDB ���Բ���ļ�Ҫ˵����

1��׼�����е�����Ϣ�Ķ������ļ���

��Զ�� LLDB ������£������������Զ������κε��Է��Ż�ϵͳ�⣬�������Ӧ�ô����ڱ��ػ����ϡ�

���ڴ� macOS �� Linux ��� Linux �� macOS �Ŀ�ƽ̨���ԣ���ʹ��ͨ�� musl����������������еĽ�����룬����������Ŀ�һ���ṩ��

2��ȷ�����������ļ��ŵ�Զ�̻����ϣ����������ļ����ڱ��ػ�����

����Remote Debug���ò���ͬ�������ļ����������Ҫ���ٶ������ļ�������ļ��������и���ʱ**�ֶ�ͬ��**���ǡ�



3����Clion�У�����Remote Debug���á�



4����Զ�̻�����ʹ��gdbserver/lldb-server��������



5������clion����ʼ���ڲ��� 3 �д����ĵ������á�

��/bin/sh����/bin/bash
����֮���������ʲô��

![image-20220620172214365](picture/image-20220620172214365.png)

```
gdbserver --attach localhost:1234 16924
```



# ���������ƻ����ͺͱ���

## 1��go���Ի���

![image-20220621110711299](picture/image-20220621110711299.png)

��������ӳ��go��װ��·���������У���ͨ�����������޸�������**PATH,GOPATH,GO111MODULE,GOPROXY**

golang���õİ汾��go version go1.14.15 linux/amd64

volumes����

```
- /usr/local/go:/usr/local/go
```



## 2����װdlv(����agent)

������������

docker exec -it allinone_hlp_5.0.0 /bin/sh

����allinone_hlp_5.0.0 �����������ơ�



go get github.com/go-delve/delve/cmd/dlv@v1.6.1

������ַ�ʽ��װdlvʧ�ܣ��ɴ�github.com/go-delve/delve����Դ�������go install��װ

֮���Բ���1.6.1�汾��dlv����Ϊ�˸��õĴ���1.14.15�汾��golang��



## 3������alpineϵͳԴΪ����Դ

���ù��ڰ����Ƶ�Դ���ļ�����Ϊ��

https://mirrors.aliyun.com/alpine/v3.6/main/

https://mirrors.aliyun.com/alpine/v3.6/community/

ִ���������£�

```bash
sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/g' /etc/apk/repositories
```



## 4����װvim��gdb, whereis����

**alpineϵͳ��װvim**

```
apk add vim
```



**alpineϵͳ��װgdb(����dp)**

![image-20220616141001775](picture/image-20220616141001775.png)

```
apk add gdb
```



**alpine��װwhereis����**

```bash
apk add --update util-linux
```



## 5�����;���dockerhub

��¼�Լ���dockerhub��#todo

docker tag neuvector/allinone:haolp_5.0.0 haolipeng/neuvector/allinone:debug_5.0.0

docker push haolipeng/neuvector/allinone:debug_5.0.0



agent�Ƿ���Ե�������dp�Ƿ���Ե���������������Ƿ���Ե��������أ�

ע�⣺agent��controller��������ʱ�����ܲ�����ͬһ̨�����ϡ�



# �ġ�����docker-compose�ű�

## 1��׼���������ļ�

**�����������ļ�������������**

��������Neuvector����ļ�����������������Ŀ¼��������õ��ļ��滻��Ӧ���ļ��������滻agent��dp��ִ���ļ���



**�����������ļ�ϵͳ������**

docker cp allinone_5.0.0:/usr/local/bin  /root/neuvector_5.0.0/bin



## 2��dlv��ʽ������agent����

�޸�agent��makefile�б������Ϊ

dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/agent -- -j 192.168.101.97



## 3������Goland IDE

��remote debug configuration������dlv�Ķ˿ڣ�Ȼ��Ϳ��Կ�ʼ�����ˡ�



## 4��gdb��gdbserver��ʽ������dp����

allinone��������Neuvector�ķ�ʽ�ǣ�����supervisor������monitor���̣�

![image-20220621132735757](picture/image-20220621132735757.png)



## 5������clion IDE



https://github.com/vishvananda/netlink
netlink������Ҫ�úõ���Ϥ�¡�linux�Ϻܶ������͹��߶��ǲ���netlink��ʵ�ֵġ�