**docker cp文件拷贝命令**

语法格式 ：docker cp 源地址 目的地址

将docker容器的内容拷贝到宿主机

docker cp 7155feee348e:/home/cloudnative-security/src/dpi-agent/build/dpi-agent  .



将宿主机的文件拷贝到容器

scp dpi-agent root@10.254.177.30:/home



**kubectl cp拷贝文件命令**

```
kubectl cp dpi-agent ccs-agent-zcxr4:/home -c dpi-agent -n cnds
```

将dpi-agent文件拷贝到pod ccs-agent-zcxr4的dpi-agent container容器中。

-c 指定拷贝到哪个容器中。



手动添加一条记录

```
iptables -I INPUT 1 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
```



UID 用户ID

GID 组ID

logout命令

nsenter 命令

nsenter -n -t 3433484

进入命名空间，退出命名空间。



**查找Docker容器对应的PID**

docker inspect --format {{.State.Pid}}  <container_name_or_ID>

container_name_or_ID：container的名称或id



**如何更明显的区分出shell是处于容器中，还是在宿主上？**

```
//切换前主机名为cd-xjsq202207130073-ubuntu-zhanglimao-2
root@cd-xjsq202207130073-ubuntu-zhanglimao-2:~#kubectl exec -it -n cnds ccs-agent-sh24f -c dpi-agent -- bash

//切换后主机名换为cd-xjsq202207130073-ubuntu-zhanglimao-3
root@cd-xjsq202207130073-ubuntu-zhanglimao-3:/# 
```



**查看pod中有哪些业务容器**

方法1

kubectl get pods ccs-agent-zcxr4  -n cnds -o jsonpath={.spec.containers[*].name}



方法2

Use 'kubectl describe pod/ccs-agent-zcxr4 -n cnds' to see all of the containers in this pod.

可查看到每个业务容器的信息

ccs-agent

clamav

trivy

dpi-agent

falco



**kubectl exec进入pod的容器中**

kubectl exec -it -n cnds ccs-agent-zcxr4 -c dpi-agent -- bash

-c是进入到pod中的某个container容器中



kubectl命令的补全操作（已完成）

web pod中会curl ccs-service.cnds.svc.cluster.local:8090



