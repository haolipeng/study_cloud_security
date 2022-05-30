如何打开所有的debug日志？

在main.c文件中更改log.InfoLevel为DebugLevel

```
type tcPortInfo struct {
   idx  uint // port index in enforcer network namespace
   pref uint
}
```

idx是在enforcer网络命名空间中的端口索引

# 一、现象

## 1、1 enforcer容器接口情况

3: **eth0@if11**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1440 qdisc noqueue state UP group default
    link/ether e6:95:9d:6e:ef:fc brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 minmtu 68 maxmtu 65535
    veth numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    inet 10.42.236.139/32 brd 10.42.236.139 scope global eth0
       valid_lft forever preferred_lft forever
4: **tunl0@NONE**: <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0 promiscuity 0 minmtu 0 maxmtu 0
    ipip any remote any local any ttl inherit nopmtudisc numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
5: **vin362a-eth0@if106**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1440 qdisc noqueue state UP group default qlen 1000
    link/ether 5e:30:b6:b8:72:be brd ff:ff:ff:ff:ff:ff link-netnsid 1 promiscuity 0 minmtu 68 maxmtu 65535
    veth numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
6: **vex362a-eth0@if5**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1440 qdisc noqueue state UP group default qlen 1000
    link/ether 42:c1:b2:cc:20:82 brd ff:ff:ff:ff:ff:ff link-netnsid 0 promiscuity 0 minmtu 68 maxmtu 65535
    veth numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
**10000000: vbr-neuv@vth-neuv**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 2048 qdisc noqueue state UP group default qlen 1000
    link/ether aa:22:59:0b:b5:02 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 68 maxmtu 65535
    veth numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
**10000001: vth-neuv@vbr-neuv**: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 2048 qdisc noqueue state UP group default
    link/ether ce:eb:a0:42:1e:71 brd ff:ff:ff:ff:ff:ff promiscuity 0 minmtu 68 maxm



## 1、2 业务容器接口情况

1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00 promiscuity 0 minmtu 0 maxmtu 0 numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
**4: tunl0@NONE:** <NOARP> mtu 1480 qdisc noop state DOWN group default qlen 1000
    link/ipip 0.0.0.0 brd 0.0.0.0 promiscuity 0 minmtu 0 maxmtu 0
    ipip any remote any local any ttl inherit nopmtudisc numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
**106: eth0@if5:** <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1440 qdisc noqueue state UP group default qlen 1000
    link/ether 5e:d7:54:1f:df:45 brd ff:ff:ff:ff:ff:ff link-netnsid 1 promiscuity 0 minmtu 68 maxmtu 65535
    veth numtxqueues 1 numrxqueues 1 gso_max_size 65536 gso_max_segs 65535
    inet 10.42.236.131/32 brd 10.42.236.131 scope global eth0
       valid_lft forever preferred_lft forever



## 1、3 vin和vex的关系

![image-20220524141400147](picture/image-20220524141400147.png)

vin是一对veth pair，在Neuvector中是vin362a-eth0，vin362a-eth0@if106对应的是业务容器中的106接口索引。

vex362a-eth0@if5代表,vex362a-eth0直连vin362a-eth0接口。



InterceptContainerPorts

初始化并创建vin和vex接口的函数



TapPortPair

很重要。



FwdPortPair

```
func (d *tcPipeDriver) FwdPortPair(pid int, pair *InterceptPair) {
	log.WithFields(log.Fields{"inPort": pair.inPort, "exPort": pair.exPort}).Debug("")
	var cmd string
	var ok bool
	var inInfo, exInfo *tcPortInfo
	//查找vin 接口是否存在
	
	//查找vex 接口是否存在

	一、Ingress方向流量
	1、1 忽略multicast多播数据包
	1、2 将带有 DA 的单播数据包转发到工作负载
	1、3 转发剩余流量，从vex接口转发到vin接口

	二、 Egress方向流量
	2、1 忽略multicast多播数据包
	2、2 转发源自工作负载的带有 SA 的单播数据包
	2、3 转发剩余流量，从vin接口转发到vex接口

	三、 转发来自enforcer的数据包
	3、1 vbr-neuv转发数据包给vin接口
	3、2 vbr-neuv转发数据包给vex接口
}
```



GetPortPairRule:获取PortPair上的规则，也就是vin和vex上的tc规则。



```
// 1. Rename, remove IP and MAC of original port, link
// 1. Create a veth pair, local and peer
// 2. Switch IP and MAC address between link and local port
// 3. Move link and peer to service container
func pullContainerPort(
	link netlink.Link, addrs []netlink.Addr, pid, dstNs int, localPortIndex, inPortIndex int,
) (int, error) {
	var err error
	attrs := link.Attrs()
	exPortName, inPortName := getIntcpPortNames(pid, attrs.Name)

	defer func() {
		if err != nil {
			netlink.LinkSetName(link, attrs.Name)
			netlink.LinkSetHardwareAddr(link, attrs.HardwareAddr)
			netlink.LinkSetUp(link)
		}
	}()

	// Down the link
	if err = netlink.LinkSetDown(link); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return 0, err
	}
	// Change link name to exPortName.
	if err = netlink.LinkSetName(link, exPortName); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing name")
		return 0, err
	}
	// Get link again as name is changed.
	if link1, err := netlink.LinkByName(exPortName); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, err
	} else {
		link = link1
	}
	// Remove IP addresses
	for _, addr := range addrs {
		netlink.AddrDel(link, &addr)
	}
	// Temp. set MAC address
	tmp, _ := net.ParseMAC("00:01:02:03:04:05")
	if err = netlink.LinkSetHardwareAddr(link, tmp); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing MAC")
		return 0, err
	}

	log.WithFields(log.Fields{"inPort": inPortName}).Debug("Create internal pair")

	//创建一个veth pair，一端是原来的端口名，另一端是inPortName
	// Create a new veth pair: one end is the original port name, the other is inPortName
	veth := &linkVeth{
		LinkAttrs: netlink.LinkAttrs{
			Name:   attrs.Name,
			TxQLen: attrs.TxQLen,
			MTU:    attrs.MTU,
			Index:  localPortIndex,
		},
		PeerName:  inPortName,
		PeerIndex: inPortIndex,
	}
	//添加vethAdd
	if err = vethAdd(veth); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in creating veth pair")
		return 0, err
	}
	defer func() {
		if err != nil {
			netlink.LinkDel(veth)
		}
	}()

	log.WithFields(log.Fields{"port": attrs.Name}).Debug("Setting up local port")

	// Get the local link of the veth pair
	var local netlink.Link
	var localMAC net.HardwareAddr
	if local, err = netlink.LinkByName(attrs.Name); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, err
	}
	if err = netlink.LinkSetDown(local); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return 0, err
	}

	if cfg.cnet_type == CNET_MACVLAN {
		// Duplicate the local mac, for Container network  like macvlan, mac in host need persistent, so same mac on vex and container eth0
		localMAC = attrs.HardwareAddr
	} else {
		localMAC = local.Attrs().HardwareAddr
	}

	if err = netlink.LinkSetHardwareAddr(local, attrs.HardwareAddr); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in setting MAC")
		return 0, err
	}
	// TODO: For some reason, there always is an extra IPv6 address that cannot be removed,
	//       the external port _sometimes_ also has an extra IPv6 address left.
	// Get all addresses of the local link
	var localAddrs []netlink.Addr
	if localAddrs, err = netlink.AddrList(local, netlink.FAMILY_ALL); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in getting address")
		return 0, err
	}
	for _, addr := range localAddrs {
		log.WithFields(log.Fields{"addr": addr}).Debug("Delete address")
		netlink.AddrDel(local, &addr)
	}
	for _, addr := range addrs {
		log.WithFields(log.Fields{"addr": addr}).Debug("Add address")
		netlink.AddrAdd(local, &addr)
	}
	// Set local link up
	if err = netlink.LinkSetUp(local); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in enabling port")
		return 0, err
	}
	// Set customer container intf seg/chksum off
	DisableOffload(attrs.Name)
	log.WithFields(log.Fields{"port": inPortName}).Debug("Setting up inPort")

	// Get the peer link
	var peer netlink.Link
	if peer, err = netlink.LinkByName(inPortName); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Cannot find port")
		return 0, err
	}
	if err = netlink.LinkSetDown(peer); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in disabling port")
		return 0, err
	}
	// Move the peer to the service container
	if err = netlink.LinkSetNsFd(peer, dstNs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in moving namespace")
		return 0, err
	}

	log.WithFields(log.Fields{"port": exPortName}).Debug("Setting up exPort")

	// Set the original port MAC to local port MAC
	if err = netlink.LinkSetHardwareAddr(link, localMAC); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in changing MAC")
		return 0, err
	}
	// Move the original port to service container namespace
	if err = netlink.LinkSetNsFd(link, dstNs); err != nil {
		log.WithFields(log.Fields{"error": err}).Error("Error in moving namespace")
		return 0, err
	}

	return local.Attrs().Index, nil
}
```

疑问点：

vbr-neuv和vex是如何建立关系的

vbr-neuv和veth-neuv的关系

main函数中，非tc模式下，先删除veth-neuv再重新创建

```
else if (strcmp(key, "ctrl_del_srvc_port") == 0) {
    ret = dp_ctrl_del_srvc_port(msg);
}
```



对于数据流程的分析

![image-20220524143021751](picture/image-20220524143021751.png)

1、vbr-neuv和vth-neuv是veth pair，向vth-neuv发送数据，vbr-neuv能收到，即vth-neuv是流量入口

上图是FwdPortPair函数的流程

一、Ingress方向流量
	1、1 忽略multicast多播数据包
	1、2 将带有 DA 的单播数据包转发到工作负载
	1、3 转发剩余流量，从vex接口转发到vin接口

二、 Egress方向流量
2、1 忽略multicast多播数据包
2、2 转发源自工作负载的带有 SA 的单播数据包
2、3 转发剩余流量，从vin接口转发到vex接口

三、 转发来自enforcer的数据包
3、1 vbr-neuv转发数据包给vin接口
3、2 vbr-neuv转发数据包给vex接口



```
cmd = fmt.Sprintf("tc filter add dev %v pref %v parent ffff: protocol all "+
   "u32 match u16 0x%02x%02x 0xffff at -14 match u32 0x%02x%02x%02x%02x 0xffffffff at -12 "+
   "action pedit munge offset -14 u16 set 0x%02x%02x munge offset -12 u32 set 0x%02x%02x%02x%02x pipe "+
   "action mirred egress mirror dev %v",
   nvVbrPortName, exInfo.pref,
   pair.UCMAC[0], pair.UCMAC[1], pair.UCMAC[2], pair.UCMAC[3], pair.UCMAC[4], pair.UCMAC[5],
   pair.MAC[0], pair.MAC[1], pair.MAC[2], pair.MAC[3], pair.MAC[4], pair.MAC[5],
   pair.inPort)
```

上述tc的意思是匹配到报文后修改目的mac。



dp.DPCtrlAddMAC(nvSvcPort, pair.MAC, pair.UCMAC, pair.BCMAC, oldMAC, pMAC, nil)



先把这几天的东西好好记录下。

proxymesh的规则如下



```shell
:INPUT ACCEPT [37:3477]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [64:5804]
:NV_INPUT_PROXYMESH - [0:0]
:NV_OUTPUT_PROXYMESH - [0:0]
-A INPUT -j NV_INPUT_PROXYMESH
-A OUTPUT -j NV_OUTPUT_PROXYMESH
-A NV_INPUT_PROXYMESH -p tcp -m tcp --sport 9000 -j NFQUEUE --queue-num 0 --queue-bypass
-A NV_INPUT_PROXYMESH -p tcp -m tcp --sport 15021 -j NFQUEUE --queue-num 0 --queue-bypass
-A NV_INPUT_PROXYMESH -j RETURN
-A NV_OUTPUT_PROXYMESH -p tcp -m tcp --dport 9000 -j NFQUEUE --queue-num 0 --queue-bypass
-A NV_OUTPUT_PROXYMESH -p tcp -m tcp --dport 15021 -j NFQUEUE --queue-num 0 --queue-bypass
-A NV_OUTPUT_PROXYMESH -j RETURN
COMMIT
# Completed on Tue May 24 17:05:13 2022
# Generated by iptables-save v1.8.4 on Tue May 24 17:05:13 2022
*nat
:PREROUTING ACCEPT [13243:794580]
:INPUT ACCEPT [13244:794640]
:OUTPUT ACCEPT [1220:109772]
:POSTROUTING ACCEPT [1220:109772]
:ISTIO_INBOUND - [0:0]
:ISTIO_IN_REDIRECT - [0:0]
:ISTIO_OUTPUT - [0:0]
:ISTIO_REDIRECT - [0:0]
-A PREROUTING -p tcp -j ISTIO_INBOUND
-A OUTPUT -p tcp -j ISTIO_OUTPUT
-A ISTIO_INBOUND -p tcp -m tcp --dport 15008 -j RETURN
-A ISTIO_INBOUND -p tcp -m tcp --dport 22 -j RETURN
-A ISTIO_INBOUND -p tcp -m tcp --dport 15090 -j RETURN
-A ISTIO_INBOUND -p tcp -m tcp --dport 15021 -j RETURN
-A ISTIO_INBOUND -p tcp -m tcp --dport 15020 -j RETURN
-A ISTIO_INBOUND -p tcp -j ISTIO_IN_REDIRECT
-A ISTIO_IN_REDIRECT -p tcp -j REDIRECT --to-ports 15006
-A ISTIO_OUTPUT -s 127.0.0.6/32 -o lo -j RETURN
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -m owner --uid-owner 1337 -j ISTIO_IN_REDIRECT
-A ISTIO_OUTPUT -o lo -m owner ! --uid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -m owner --uid-owner 1337 -j RETURN
-A ISTIO_OUTPUT ! -d 127.0.0.1/32 -o lo -m owner --gid-owner 1337 -j ISTIO_IN_REDIRECT
-A ISTIO_OUTPUT -o lo -m owner ! --gid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -m owner --gid-owner 1337 -j RETURN
-A ISTIO_OUTPUT -d 127.0.0.1/32 -j RETURN
-A ISTIO_OUTPUT -j ISTIO_REDIRECT
-A ISTIO_REDIRECT -p tcp -j REDIRECT --to-ports 15001
COMMIT
```

service mesh服务网格是通过iptables queue实现去进行微隔离的。



所有前端web api的处理都在rest.go文件。

疑问：SA和DA是什么？



在dp目录的ctrl.c文件的dp_ctrl_handler函数中



dp在学习阶段会解析数据包并记录网络规则。



切换成保护模式容器就会调用changeContainerWire方法

流量抓取先优先搞，简单的规则分析。

waf:crd xxxxx custom resource define 规则弄出来。
