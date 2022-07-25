

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

����Ĵ����޸ģ��μ�git���ύ��¼��

### 2�� agentɾ����dp�Ľ������

��agent��cbKeepAlive������ֱ���ں����Ŀ�ʼ������true���������һֱ�ǳɹ��ġ�



### 3��monitorɾ����dp���

��PROC_DP�������ڵĴ�����ɾ������ɾ�����ж�Ӧ�ĳ���monitor������������

ɾ��monitor�м��dp�Ĵ��룬��ע�͵�stop_proc(PROC_DP, SIGSEGV, false);����



### 4���޸�go������־gcflags

**�޸�agent��makefile�б������Ϊ go build -gcflags='-N -l'**

Ȼ������ִ��make���



## 1��2 dlv����agent��controller

**agent�������в������£�**

```
/usr/local/bin/agent -c
```



**dlv�����������£�**

```shell
dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/agent -- -c
```

-c ѡ����Coexist controller and ranger��Ĭ������£�agentҲ����ô�����ġ�



**dlv attach�������£�**

```
dlv attach 12306 --headless --listen=:2345 --api-version=2 --accept-multiclient
```

����12306��agent�����pid��

��ע���������dlv������ȣ�dlv attach�������������� -c�����в�������Ϊagent����ʱ�Ѿ�����˲�����



## 1��3 ����Goland IDE

��remote debug configuration������dlv�Ķ˿ڣ�Ȼ��Ϳ��Կ�ʼ�����ˡ�

![image-20220627175232697](picture/image-20220627175232697.png)



neuvector/allinone:haolp_5.0.0

|ERRO|AGT|dp.dpSendMsgExSilent: Read error - error=read unixgram /tmp/dp_client.23546->/tmp/dp_listen.sock: i/o timeout



allinone_haolp_5.0.0 | 2022-06-21T10:17:43.917|ERRO|AGT|dp.dpSendMsgExSilent: Data path not connected

�Ǳ�������ͨ�����쳣������



Ϊɶһֱ�ڱ���������أ�#todo



# ����Զ�̵���dp

## 2��1 ����



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

# �塢Զ�̵���controller

**��ubuntu�±����controller������alpineϵͳ�����У�**

**��centos�±����controller������alpineϵͳ�����в�������**



**controller�������в������£�**

```
/ # ps -ef | grep "/usr/local"
root       26003   25951 15 06:35 ?        00:00:07 java -jar /usr/local/bin/admin-assembly-1.0.jar
root       26004   25951  0 06:35 ?        00:00:00 /usr/local/bin/monitor -d
root       26017   26004  2 06:35 ?        00:00:01 /usr/local/bin/controller -j 10.240.19.222
root       26018   26004  4 06:35 ?        00:00:01 /usr/local/bin/dp -n 1
root       26019   26004 12 06:35 ?        00:00:06 /usr/local/bin/agent -c
root       26085   26017  3 06:35 ?        00:00:01 /usr/local/bin/consul agent -datacenter neuvector -data-dir /tmp/neuvector -server -bootstrap -config-file /tmp/consul.json -bind 172.17.0.2 -advertise 10.240.19.222 -node 10.240.19.222 -node-id 805d2ee2-e8d8-eb7a-164d-08c83916a840 -raft-protocol 3
```

�ɻ����һ��consul��������controller�Ƿ��йء�

**dlv�����������£�**

```
dlv --headless=true --listen=:2345 --api-version=2 --accept-multiclient exec /usr/local/bin/controller -- -j 10.240.19.222
```



**���ʵ㣺consul������controller������������**

�������Ƕ���˵������ʱ����dlv���ܸ��õ㡣



# ����Helm����

helm install neuvector --namespace neuvector neuvector/core  --set registry=docker.io  --set tag=5.0.0-preview.1 --set=controller.image.repository=neuvector/controller.preview -- set=enforcer.image.repository=neuvector/enforcer.preview --set  manager.image.repository=neuvector/manager.preview --set  cve.scanner.image.repository=neuvector/scanner.preview --set cve.updater.image.repository=neuvector/updater.preview



```
Get the NeuVector URL by running these commands:
  NODE_PORT=$(kubectl get --namespace neuvector -o jsonpath="{.spec.ports[0].nodePort}" services neuvector-service-webui)
  NODE_IP=$(kubectl get nodes --namespace neuvector -o jsonpath="{.items[0].status.addresses[0].address}")
  echo https://$NODE_IP:$NODE_PORT
```



�ο�����

https://github.com/neuvector/neuvector-helm

# 





