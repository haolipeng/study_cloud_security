修改kubernetes节点的ip地址

https://www.qikqiak.com/post/how-to-change-k8s-node-ip/



**利用Kubernetes搭建便携式开发环境之MySQL和Redis**

https://mp.weixin.qq.com/s?__biz=MzUzNTY5MzU2MA==&mid=2247487453&idx=1&sn=4d9ae57ea9079a7cb57d84672b29491a&chksm=fa80de4acdf7575cb9f6ced3a5657c48434d881cbbf694392efe79e4961d353b1f49975b223b&scene=178&cur_album_id=1394839706508148737#rd



# ⚠️ 添加「官方」或「阿里云」的docker仓库
$ wget https://download.docker.com/linux/centos/docker-ce.repo -O /etc/yum.repos.d/docker-ce.repo

$ wget https://mirrors.aliyun.com/docker-ce/linux/centos/docker-ce.repo -O /etc/yum.repos.d/docker-ce.repo



# 查看可用的版本,

# 版本号格式：<year>.<month>.<N>

# 版本号说明：https://docs.docker.com/engine/install/#release-channels

$ yum list docker-ce --showduplicates
  docker-ce.x86_64    	18.06.1.ce-3.el7		docker-ce-stable
  docker-ce.x86_64    	18.06.2.ce-3.el7     	docker-ce-stable
  docker-ce.x86_64    	18.06.3.ce-3.el7     	docker-ce-stable
  docker-ce.x86_64    	3:20.10.11-3.el7     	docker-ce-stable
  docker-ce.x86_64    	3:20.10.12-3.el7     	docker-ce-stable

# ⚠️ 安装「最新版本」或「指定版本」
$ yum -y install docker-ce docker-ce-cli containerd.io
$ yum -y install docker-ce-20.10.12 docker-ce-cli-20.10.12 containerd.io

# 启动Docker服务
$ systemctl start docker
$ systemctl enable docker

# 测试服务
$ docker run hello-world



```shell
kubeadm init \
--apiserver-advertise-address=10.240.19.246 \
--image-repository registry.aliyuncs.com/google_containers \
--kubernetes-version=v1.18.20 


kubeadm init \
--apiserver-advertise-address=10.240.19.246 \
--image-repository registry.aliyuncs.com/google_containers \
--kubernetes-version=v1.18.20 \
--pod-network-cidr=10.244.0.0/16 \
--service-cidr=10.96.0.0/12
```



```
kubeadm join 10.240.19.246:6443 --token 9fm46i.gbgdrm7ov8jl849o \
    --discovery-token-ca-cert-hash sha256:f621188a565d37c1e18ed69c4a4d2c29d1223fd1afe202de771df5b230bae754
```



**kubernetes template** vscode插件

用于写Kubernetes的片段



**kubernetes yaml template**

https://github.com/dennyzhang/kubernetes-yaml-templates



**Kubernetes国内镜像、下载安装包和拉取gcr.io镜像**

https://blog.csdn.net/nklinsirui/article/details/80581286



**快速掌握Service**

https://mp.weixin.qq.com/s?__biz=MzUzNTY5MzU2MA==&mid=2247486082&idx=1&sn=42a9bc8fcfc9da09445e9e2f4cf2fb96&chksm=fa80db15cdf752039494992f71a3bc488cf386841bd1aaaa44115f5e7f155ba55ce468ec89ee&token=2033333242&lang=zh_CN&scene=21#wechat_redirect



kubectl edit 命令，简直就是神器啊。



学习k8s的yaml配置文件的写法

https://learnk8s.io/templating-yaml-with-code



使用kube-install部署后：

docker只在node机器上才有，只有node机器是用来运行容器的；

master机器不运行容器，所以没有docker。

或者把master和node混合部署，这样master和node就都有docker命令了。