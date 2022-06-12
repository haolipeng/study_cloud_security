一、为什么使用PACKET_MMAP

在 Linux 2.4/2.6/3.x 中如果没有启用 PACKET_MMAP，捕获过程非常 效率低下。使用有限的缓冲区并需一次系统调用来捕获每个数据包，



另一方面，PACKET_MMAP提供了一个大小可配置的映射在用户空间的环形缓冲区，可用户发送或接收数据包。这样读取数据包只需要等待，大多数时间无需发起单独的系统调用。

关于传输，通过一次系统调用可以发送多个数据包以获取最大带宽。通过在内核和用户之间使用共享缓冲区，还具有最小化数据包拷贝的好处。



可以使用 PACKET_MMAP 来提高捕获的性能和 传输过程，但不是全部。如果你正在高速抓包，您应该检查您的网卡的设备驱动程序是否支持某种中断负载缓解，或者它是否支持 NAPI，也确保它已启用。

对于传输，检查网络设备所使用的MTU值。



```
----------------------------------------------------
+ How to use mmap() to improve capture process
----------------------------------------------------
```

从用户的角度看，您应该使用更高级别的libpcap库，它是事实的标准。



```
----------------------------------------------------
+ How to use mmap() directly to improve capture process
----------------------------------------------------
```

如何直接使用 mmap() 来改进抓包过程

```
[setup]     socket() -------> creation of the capture socket
            setsockopt() ---> allocation of the circular buffer (ring)
                              option: PACKET_RX_RING
            mmap() ---------> mapping of the allocated buffer to the
                              user process

[capture]   poll() ---------> to wait for incoming packets

[shutdown]  close() --------> destruction of the capture socket and
                              deallocation of all associated 
                              resources.
```



有哪些可用的 TPACKET 版本以及何时使用它们？

```
TPACKET_V1:
	- 未由setsockopt函数指定，则为默认值。
	- RX_RING, TX_RING available

TPACKET_V1 --> TPACKET_V2:
	- Made 64 bit clean due to unsigned long usage in TPACKET_V1
	  structures, thus this also works on 64 bit kernel with 32 bit
	  userspace and the like
	- Timestamp resolution in nanoseconds instead of microseconds
	- RX_RING, TX_RING available
	- VLAN metadata information available for packets
	  (TP_STATUS_VLAN_VALID, TP_STATUS_VLAN_TPID_VALID),
	  in the tpacket2_hdr structure:
		- TP_STATUS_VLAN_VALID bit being set into the tp_status field indicates
		  that the tp_vlan_tci field has valid VLAN TCI value
		- TP_STATUS_VLAN_TPID_VALID bit being set into the tp_status field
		  indicates that the tp_vlan_tpid field has valid VLAN TPID value
	- How to switch to TPACKET_V2:
		1. Replace struct tpacket_hdr by struct tpacket2_hdr
		2. Query header len and save
		3. Set protocol version to 2, set up ring as usual
		4. For getting the sockaddr_ll,
		   use (void *)hdr + TPACKET_ALIGN(hdrlen) instead of
		   (void *)hdr + TPACKET_ALIGN(sizeof(struct tpacket_hdr))

TPACKET_V2 --> TPACKET_V3:
	- Flexible buffer implementation for RX_RING:灵活
		1. Blocks can be configured with non-static frame-size
		2. Read/poll is at a block-level (与数据包级别相反)
		3. Added poll timeout to avoid indefinite user-space wait
		   on idle links(避免无限期等待在空链接上)
		4. Added user-configurable knobs: 添加用户可配置的旋钮
			4.1 block::timeout
			4.2 tpkt_hdr::sk_rxhash
	- RX Hash data available in user space
	- TX_RING semantics are conceptually similar to TPACKET_V2;
	  use tpacket3_hdr instead of tpacket2_hdr, and TPACKET3_HDRLEN
	  instead of TPACKET2_HDRLEN. In the current implementation,
	  the tp_next_offset field in the tpacket3_hdr MUST be set to
	  zero, indicating that the ring does not hold variable sized frames.
	  Packets with non-zero values of tp_next_offset will be dropped.
	  tpacket3_hdr中的tp_next_offset字段必须设置为zero，表明ring不包含可变大小的帧。		         tp_next_offset 值为非零的数据包将被丢弃。
```



参考链接

https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt