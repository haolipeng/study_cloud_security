

׼��������

```
docker cp allinone_5.0.0:/usr/local/bin /root/neuvector_5.0.0/bin
```

��allinone����������



```shell
kubectl create clusterrole neuvector-binding-app --verb=get,list,watch,update --resource=nodes,pods,services,namespaces
kubectl create clusterrole neuvector-binding-rbac --verb=get,list,watch --resource=rolebindings.rbac.authorization.k8s.io,roles.rbac.authorization.k8s.io,clusterrolebindings.rbac.authorization.k8s.io,clusterroles.rbac.authorization.k8s.io
kubectl create clusterrolebinding neuvector-binding-app --clusterrole=neuvector-binding-app --serviceaccount=neuvector:default
kubectl create clusterrolebinding neuvector-binding-rbac --clusterrole=neuvector-binding-rbac --serviceaccount=neuvector:default
kubectl create clusterrole neuvector-binding-admission --verb=get,list,watch,create,update,delete --resource=validatingwebhookconfigurations,mutatingwebhookconfigurations
kubectl create clusterrolebinding neuvector-binding-admission --clusterrole=neuvector-binding-admission --serviceaccount=neuvector:default
kubectl create clusterrole neuvector-binding-customresourcedefinition --verb=watch,create,get,update --resource=customresourcedefinitions
kubectl create clusterrolebinding  neuvector-binding-customresourcedefinition --clusterrole=neuvector-binding-customresourcedefinition --serviceaccount=neuvector:default
kubectl create clusterrole neuvector-binding-nvsecurityrules --verb=list,delete --resource=nvsecurityrules,nvclustersecurityrules
kubectl create clusterrolebinding neuvector-binding-nvsecurityrules --clusterrole=neuvector-binding-nvsecurityrules --serviceaccount=neuvector:default
kubectl create clusterrolebinding neuvector-binding-view --clusterrole=view --serviceaccount=neuvector:default
kubectl create rolebinding neuvector-admin --clusterrole=admin --serviceaccount=neuvector:default -n neuvector
kubectl create clusterrole neuvector-binding-nvwafsecurityrules --verb=list,delete --resource=nvwafsecurityrules
kubectl create clusterrolebinding neuvector-binding-nvwafsecurityrules --clusterrole=neuvector-binding-nvwafsecurityrules --serviceaccount=neuvector:default
kubectl create clusterrole neuvector-binding-nvadmissioncontrolsecurityrules --verb=list,delete --resource=nvadmissioncontrolsecurityrules
kubectl create clusterrolebinding neuvector-binding-nvadmissioncontrolsecurityrules --clusterrole=neuvector-binding-nvadmissioncontrolsecurityrules --serviceaccount=neuvector:default
kubectl create clusterrole neuvector-binding-nvdlpsecurityrules --verb=list,delete --resource=nvdlpsecurityrules
kubectl create clusterrolebinding neuvector-binding-nvdlpsecurityrules --clusterrole=neuvector-binding-nvdlpsecurityrules --serviceaccount=neuvector:default
```

ע�����

 neuvector.yaml �ļ���ָ���� nodeport ���񣬽������� kubernetes �ڵ��һ������˿ڣ���Ϊ NeuVector ���� Web ����̨�˿ڡ�



# һ��Զ�̵���agent

Ĭ��ģʽ�£�agent���Ա���ģʽ����dp�Ľ���״̬�����������kill��dp���̣�

Neuvector��enforcer������Ĭ�ϻᴦ��NVProtectģʽ���û���������������һЩ�������Ҳ�ᵼ�½��̱�ɱ����������dlv������agent����������gdb��gdbserver������dp������뱣֤����̲��ᱻNeuvectorɱ����



## 1��1 ���±���agent

��agent��������޸ģ�ɾ�����е���syscall.Kill�Ĵ���Ƭ�Ρ��漰���ļ����£�

### 1�� agentɾ������syscall.Kill

![image-20220621104134559](picture/image-20220621104134559.png)

### 2�� agentɾ����dp�Ľ������

��agent��cbKeepAlive������ֱ���ں����Ŀ�ʼ������true���������һֱ�ǳɹ��ġ�



### 3��monitorɾ����dp���

��PROC_DP�������ڵĴ�����ɾ����

ɾ��monitor�м��dp�Ĵ��룬��ע�͵�stop_proc(PROC_DP, SIGSEGV, false);����



### 4���޸�go������־gcflags

**�޸�agent��makefile�б������Ϊ go build -gcflags='-N -l'**

Ȼ������ִ��make���



## 1��2 dlv����agent

```shell
dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/agent -- -c
```

-c ѡ����Coexist controller and ranger��Ĭ������£�agentҲ����ô�����ġ�



```
dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/agent -- -j 10.240.19.222
```

����ǽ�dlv��������д�뵽supervisor



## 1��3 ����Goland IDE

��remote debug configuration������dlv�Ķ˿ڣ�Ȼ��Ϳ��Կ�ʼ�����ˡ�

![image-20220627175232697](picture/image-20220627175232697.png)



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



## 3��gdb��gdbserver��ʽ������dp����

allinone��������Neuvector�ķ�ʽ�ǣ�����supervisor������monitor���̣�

![image-20220621132735757](../picture/image-20220621132735757.png)



## 4������clion IDE



https://github.com/vishvananda/netlink
netlink������Ҫ�úõ���Ϥ�¡�linux�Ϻܶ������͹��߶��ǲ���netlink��ʵ�ֵġ�



�޸�/etc/profile�����ݣ����ڵ��ԡ�

��������ļ���



�塢������־��ʼ��

main.(*Bench).doDockerHostBench: Running benchmark checks done

main.(*Bench).doDockerContainerBench: Running benchmark checks done

main.(*Bench).doContainerCustomCheck: Running benchmark checks done

���������桢��������Ļ��߼�顣



main.taskAddContainer: - id=42234cc5128b9ff37f9739be63f1bac31c72ca514c9b2c26d20ebd087f082cd2 name=kind_wright

main.taskAddContainer: - id=84e8ee60180561c8883ffd9fc859714d4f38a331827e78bf59bc41966a3bc737 name=amazing_visvesvaraya



