# 场景1：租户隔离

备注：

使用RoleBinding对用户进行角色绑定，不同用户可以绑定到同一个命名空间的同一个角色。

比如gpu用户和disk用户，可以绑定gpu命名空间的同一个角色gpu-reader

用户-命名空间 1对1

命名空间 - 用户 1对多

将用户名字打到命名空间中，是否是个好的做法？感觉不太妥当

如果仅仅是测试，那么给namespace打上标签是可以的。

1-3

2-3



要做到视图上隔离（看不到），也要做到网络访问（准入控制）上的隔离。

前置条件：

1、创建用户或者从集群导入的用户

2、角色绑定，本质：授予用户xx命名空间的yy资源如pod的读写权限

3、用户每次创建的pod都带有指定的标签的话，在DaemonSet和Deployment部署时添加上带有用户名的标签

user: gpu等，我们能保证

4、编写NetworkPolicy策略

5、搞定



**\1)  支持管理员对各租户的用户列表权限配置和管理。**

从实现上看，用户、角色、角色绑定三者是解耦合的，权限配置和管理，就是维护角色和角色绑定的意思。



```bash
#以下命令以gpu用户为例，如需创建其他用户，请把gpu名称替换掉即可

x509 
#创建证书
(umask 077; openssl genrsa -out gpu.key 2048)
openssl req -new -key gpu.key -out gpu.csr -subj "/CN=gpu"
openssl x509 -req -in gpu.csr -CA /etc/kubernetes/pki/ca.crt -CAkey /etc/kubernetes/pki/ca.key -CAcreateserial -out gpu.crt -days 3650
openssl x509 -in gpu.crt -text -noout

#把用户账户信息添加到k8s集群中
kubectl config set-credentials gpu --client-certificate=./gpu.crt --client-key=./gpu.key --embed-certs=true

#创建账户，设置用户访问的集群
kubectl config set-context gpu@kubernetes --cluster=kubernetes --user=gpu

#切换用户
kubectl config use-context gpu@kubernetes
#验证权限
kubectl get pods
#切换成管理员
kubectl config use-context kubernetes-admin@kubernetes
```

获取用户名命令：kubectl config get-contexts



# 场景2：节点隔离（好好思考下）

节点Node隔离实现方案有两种：

## 方案1：使用calico的节点隔离

1、开启自动主机端点

2、给Node节点添加标签

要应用针对所有 Kubernetes 节点的策略，请首先向节点添加标签。标签将同步到其自动主机端点。

3、编写calico网络策略

```
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: some-nodes-policy
spec:
  selector: has(kubernetes-host) && environment == 'dev'
  <rest of the policy>
```



## 方案2：将租户信息打到pod的标签上，并且根据租户信息打上虚拟集群的标签

伪代码如下：

spec:

​	lables：

​		name: A

​	 	virtualCluster:v1



ingress：节点的入口流量

egress：节点的出口流量



# 场景3:  Pod隔离（组）

预期结果：                      

\1)  为cloud-dev创建默认的全部隔离（deny all）网络策略，则dev-tomcat和ops-tomcat-1之间互相不可以访问。--网络策略

\2)  针对dev-tomcat配置外出流量网络策略，可以实现只允许其访问cloud-ops租户下的ops-tomcat-2应用，且不可以访问其它应用

\3)  针对dev-tomcat配置入流量网络策略，可以实现只允许cloud-ops租户下的ops-tomcat-1访问dev-tomcat应用。并验证策略有效性。

创建应用组包含两个应用：ops-tomcat-1、ops-tomcat-2，并配置允许访问cloud-dev下的dev-tomcat-1的出流量策略。为dev-tomcat创建允许访问本应用组的策略。并验证策略有效性和网络连通性。

## 1、拒绝所有

apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: cloud-dev
spec:
  podSelector: {}
  policyTypes:

  - Ingress

  - Egress

    

## 2、外出流量

需求：只允许其访问cloud-ops租户下的ops-tomcat-2应用

egress规则，通过namespace标签识别出租户，通过pod标签识别出ops-tomcat-2

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-same-namespace
  namespace: cloud-dev #目标命名空间
spec:
  podSelector:
    matchLabels:
      name: dev-tomcat   #目标pod标签
  egress:
  - to:
    - podSelector:
        matchLabels:
          name: ops-tomcat-2 #增加podSelector来选择标签
      namespaceSelector:
        matchLabels:
          envirment: cloud-ops #增加namespaceSelector来选择命名空间
```

表明的是符合某个命名空间下，并且符合标签的pod集合，来指定ingress规则



## 3、入流量

针对dev-tomcat配置入流量网络策略，可以实现只允许cloud-ops租户下的ops-tomcat-1访问dev-tomcat应用。并验证策略有效性。

ingress规则，同上，不过要多加一个source和dest字段

```
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-same-namespace
  namespace: cloud-dev
spec:
  podSelector:
    matchLabels:
      name: dev-tomcat
  ingress:
  - from:
    - podSelector:
        matchLabels:
          name: ops-tomcat-1 #增加podSelector来选择标签
      namespaceSelector:
        matchLabels:
          envirment: cloud-ops
    ports:
    - port: 80
```

## 4、针对应用组的隔离

# 场景4：POD与节点网络隔离

在集群中创建应用cloud-dev（具备端口可访问)，在nodeA上有一个副本pod，为cloud-dev配置网络隔离策略（不允许节点与该应用的互相访问）。在nodeB的主机上启动服务监听指定端口，测试pod与节点的网络隔离是否生效。

**预期结果：**                      

1）在cloud-dev的副本pod容器内部，访问节点B上的服务（集群外）端口，查看网络是否可以连通，隔离策略是否生效。

2）为cloud-dev开启NodePort，在nodeB上，访问cloud-dev，验证网络是否可连通，隔离策略是否生效。

网络不可连通视为隔离策略生效，测试通过，否则测试不通过。



**这种方式我理解是NodePort形式的service**，而且在Pdf文件中有明确的服务网络隔离要求（可看时间酌情来实现我）

calico提供了基于服务的隔离方式

ingress/egress + services = service 规则

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-frontend-service-access
  namespace: backend
spec:
  selector: all()
  ingress:
    - action: Allow
      source:
        services:
          name: frontend-service
          namespace: frontend
```

https://docs.projectcalico.org/security/kubernetes-node-ports

https://docs.projectcalico.org/security/service-policy



# 编程时，需要注意的事项

对应到实际编码时，calico网络策略使用calicoctl命令

k8s网络策略使用kubectl命令执行，k8s的不同语言的第三方库也提供了CURD 的api操作接口。

calicoctl不知道是否有类似的东西，如果没有api，就只能执行命令了。



**核心关键字：**

ingress

egress

podSelector

namespaceSelector

此外，我觉得还可以形成云安全产品独有的能力，也是通过calico来实现。



golang

n := namespace{

lable{

}

namespace.create()

apply();

}



create()