**看源代码前心中的疑问**

看代码要有目的的看，才会更有效果。

1、学习模式、监控模式、保护模式三种模式的区别是什么，分别是如何实现的？

子问题：学习模式是如何建立基线的？在三种不同模式之间切换，满满的都是工作量啊。



2、Neuvector支持哪些协议的解析？

NeuVector 深度了解应用程序行为，并将分析有效负载，以确定应用程序协议。协议包括：

HTTP，HTTPS，SSL，SSH，DNS，DNCP，NTP，TFTP，ECHO，RTSP，SIP，MySQL，Redis，Zookeeper，Cassandra，MongoDB，PostgresSQL，Kafka，Couchbase，ActiveMQ，ElasticSearch，RabbitMQ，Radius，VoltDB，Consul，Syslog，Etcd，Spark，Apache，Nginx，Jetty，NodeJS，Oracle，MSSQL 和 GRPC。



3、DDOS防护是如何做到的？

答：tcp flag  + bitmap 位图



4、waf和dlp数据防泄露是如何实现的？

对于tcp/udp负载数据进行持续的正则匹配，使用pcre和hyperscan引擎来匹配。

TODO:对接下waf和dlp的owasp的ruleset规则，可减少运维工作量。



5、协议解析器的注册和使用

构造出协议树，应用层协议->传输层协议，结构体的注册回调机制；

当解析数据包时，遍历指定协议下的所有协议解析器



6、policy策略管理相关的内容

- 关注策略相关结构
- 策略的下发流程



7、Neuvector的会话表是如何进行管理的？分为几种会话表？

​    rcu_map_t ip4frag_map; 			//ipv4分片表
​    rcu_map_t ip6frag_map;			//ipv6分片表
​    rcu_map_t session4_map;			//ipv4会话表
​    rcu_map_t session4_proxymesh_map;
​    rcu_map_t session6_map;			//ipv6会话表
​    rcu_map_t session6_proxymesh_map;//proxy mesh map
​    rcu_map_t unknown_ip_map;		//未知ip的映射表

**会话表类别：**

- ip分片表
- ip会话表
- proxymesh会话表



8、tcp包重组，ip分片重组是如何实现的？

一般来说，将多个数据包重组为完整的payload负载，才能更好的进行模式匹配(waf和dlp检测)。

而Neuvector另辟蹊径，考虑到tcp包重组在云环境中会消耗更多的内存，可能会影响到客户的环境，所以采用类似状态机的机制来进行规则的匹配。



9、还需加强的地方？

微隔离产品 = 数据面 + 控制面，将策略和执行分离是最好的。

控制面统一接口，具体实现可能有几种sdn_controller，netfilter_queue，calico，cilium，xdp，ebpf，等等



这两个开源再好好的过一遍，很久没玩，有点忘记了

snort

suricata



http负载数据一般是压缩的：

gzip

chunk



抓包技术那块，我是好好研究过的，所以交给我没问题。



# 一、基础概念

## 1） 架构解析

NeuVector 本身包含 Controller、Enforcer、Manager、Scanner 和 Updater 模块。 

- Controller ：整个 NeuVector 的控制模块，API 入口，包括配置下发，高可用主要考虑 Controller 的 HA ，通常建议部署 3 个 Controller 模块组成集群。
- Enforcer ：主要用于安全策略部署下发和执行，DaemonSet 类型会在每个节点部署。
- Manager：提供 web-UI(仅HTTPS) 和 CLI 控制台，供用户管理 NeuVector 。
- Scanner ：对节点、容器、Kubernetes 、镜像进行 CVE 漏洞扫描
- Updater ：cronjob ，用于定期更新 CVE 漏洞库



## 2）组 Groups

**1、自动删除未使用的组**

如果组中没有成员（容器），NeuVector 会自动删除学习到的组（不是保留或自定义组）。

**2、主机保护 - “节点”组**

NeuVector 自动创建一个名为“nodes”的组，它代表集群中的每个节点（主机）。

NeuVector 为主机上的可疑进程和提权提供自动监控（例如端口扫描、反向 shell 等）。

此外，NeuVector 将在发现模式下学习每个节点的进程行为，以将这些进程列入白名单，和容器进程的处理方式类似。

**3、自定义组**

可以通过输入组的条件手动添加组。note：自定义组没有保护模式，因为它可能包含很多不同组的容器，每个容器都可能处于不同的模式，从而导致对行为的混淆。

可以通过以下方式创建组：

**Images**

​	按照镜像名称选择容器，Examples: image=wordpress, image@redis

**Nodes**

​	按运行容器的节点选择容器。Examples: node=ip-12-34-56-78.us-west-2

**Individual** **containers**独立容器

​	按实例名称选择容器。Examples: container=nodejs_1, container@nodejs

**Services**

​	按服务来选择容器。如果容器由 Docker Compose 部署，其服务标签值为“project_name:service_name”；如果一个容器是由 Docker swarm模式部署的service，那么它的 service tag 值就是 swarm 服务名。TODO：看来ddocker Compose和Docker swarm还是需要多熟悉下。

**Labels**

​	按标签来选择容器，Examples: com.docker.compose.project=wordpress, location@us-west

**Addresses**

​	按 DNS 名称或 IP 地址范围创建组。Examples: address=www.google.com, address=10.1.0.1, address=10.1.0.0/24, address=10.1.0.1-10.1.0.25.

​	DNS 名称可以是任何可解析的名称。地址条件不接受 != 运算符。



可以使用混合条件类型创建组，但“地址”类型除外，它不能与其他条件一起使用。



## 3） 网络策略

NeuVector 的组支持 3 种模式：学习模式、监控模式和保护模式；各个模式实现作用如下：

- 学习模式（TODO 学习了什么，什么算法）
    学习和记录容器、主机间网络连接情况和进程执行信息。
    自动构建网络规则白名单，保护应用网络正常行为。
    为每个服务的容器中运行的进程设定安全基线，并创建进程配置文件规则白名单。（TODO）
- 监控模式
    NeuVector 监视容器和主机的网络和进程运行情况，遇到非学习模式下记录的行为将在 NeuVector 中进行告警。
- 保护模式
    NeuVector 监视容器和主机的网络和进程运行情况，遇到非学习模式下记录的行为直接拒绝。

新建的容器业务被自动发现默认为学习模式，也可以通过设置将默认模式设置为监控模式或保护模式。



**生产环境最佳实践使用路径可以是：**

- 上新业务时，先学习模式运行一段时间，进行完整的功能测试和调用测试（TODO），得到实际业务环境的网络连接情况和进程执行情况的信息。
- 监控模式运行一段时间，看看有没有额外的特殊情况，进行判断，添加规则。
- 最后全部容器都切换到保护模式，确定最终形态。



# 二、dp项目简介

## 2、1 dp目录结构及文件

**目录结构概览**

![image-20220518155307549](picture/image-20220518155307549.png)

**重点关注的文件列表：**

| 文件名            | 作用                                     | 重要等级 |
| ----------------- | ---------------------------------------- | -------- |
| dpi/dpi_packet.c  | 数据包解析(tcp,udp,icmp)                 | 高       |
| dpi/dpi_parser.c  | 协议解析器                               | 中       |
| dpi/dpi_session.c | 会话管理(创建、销毁、超时、更新)，时间轮 | 中       |
| dpi/dpi_frag.c    | ip分片重组                               | 高       |
| dpi/dpi_meter.c   |                                          |          |
| dpi/dpi_module.h  | dp项目使用的全局变量                     | 高       |
| dpi/dpi_policy.c  | 策略相关（增删改查）                     | 高       |
| ctrl.c            | netfilter_queue，tap，port相关控制代码   | 高       |
| nfq.c             | netfilter_queue方式捕获数据包            | 高       |
| pkt.c             |                                          | 高       |
| ring.c            | SOCK_RAW原始套接字方式捕获数据包         | 高       |
| main.c            | 项目的主文件，入口文件                   | 高       |

meter是仪表盘，用于统计程序运行过程中的数据。

上级目录中的defs.h 很重要，很多宏定义和变量都在此文件中。



**dp项目中引用的第三方库**

| 库名称    | 作用                                |
| --------- | ----------------------------------- |
| hyperscan | 正则表达式匹配库                    |
| jansson   | json数据的序列化和反序列化          |
| jemalloc  | 内存池                              |
| pcre2     | 正则表达式解析                      |
| timeout   | 超时库(时间轮)                      |
| urcu      | 用户态的rcu库，用于替代rwlock读写锁 |



## 2、2 核心数据结构

### 2、2、1 dpi_packet_t数据包结构体

```
typedef struct dpi_packet_ {
    uint8_t *pkt;

    struct ip6_frag *ip6_fragh;

    uint32_t flags;

    struct dpi_session_ *session;
    struct dpi_wing_ *this_wing, *that_wing;

    uint16_t l2;
    uint16_t l3;
    uint16_t l4;
    uint16_t cap_len;
    uint16_t len;
    uint16_t eth_type;
    uint16_t sport, dport;
    uint8_t ip_proto;

    uint8_t tcp_wscale;
    uint16_t tcp_mss;
    uint32_t tcp_ts_value, tcp_ts_echo;

    uint32_t threat_id;
    uint8_t action:   3,
            severity: 3;  // record packet threat severity when session is not located, ex. ping death
    uint8_t pad[3];

    void *frag_trac;
    void *cached_clip;

    uint32_t EOZ;

    uint64_t id;
    struct dpi_parser_ *cur_parser;//当前解析器
    buf_t *pkt_buffer;
    buf_t raw;
    buf_t asm_pkt;
    uint8_t *defrag_data;
    uint32_t asm_seq, parser_asm_seq; // cache asm_seq during protocol parsing

    io_ctx_t *ctx;
    io_ep_t *ep;
    uint8_t *ep_mac;
    io_stats_t *ep_stats;
    io_metry_t *ep_all_metry;
    io_metry_t *ep_app_metry;
    io_stats_t *stats;
    io_metry_t *all_metry;
    io_metry_t *app_metry;

    uint8_t parser_left;
    /*dlp related*/
    uint32_t dlp_match_seq;
    dpi_sig_context_type_t dlp_match_type;
    dpi_sig_context_type_t dlp_pat_context;
    uint8_t dlp_match_flags;
    dpi_dlp_area_t dlp_area[DPI_SIG_CONTEXT_TYPE_MAX];
    buf_t decoded_pkt;

    uint8_t dlp_candidates_overflow;
    uint8_t has_dlp_candidates;

    int dlp_results;
    int dlp_candidates;
    dpi_match_t dlp_match_results[DPI_MAX_MATCH_RESULT];
    dpi_match_candidate_t dlp_match_candidates[DPI_MAX_MATCH_CANDIDATE];
} dpi_packet_t;
```



### 2、2、2 dpi_session_t会话结构体

```go
typedef struct dpi_session_ {
    struct cds_lfht_node node;//Lock-Free RCU Hash Table 无锁哈希表
    timer_entry_t ts_entry; //时间轮
    timer_entry_t tick_entry;//时间轮

    uint32_t id;
    uint32_t created_at; //会话创建的时间
    uint32_t last_report;//最近上报时间

    dpi_wing_t client, server;
    void *parser_data[DPI_PARSER_MAX];

    uint16_t flags;
    uint8_t tick_flags :4,
            meter_flags:4;
    uint8_t only_parser; //唯一的解析器

    uint32_t small_window_tick; // small window size start tick

    BITMASK_DEFINE(parser_bits, DPI_PARSER_MAX);

    uint16_t app, base_app;
    uint8_t ip_proto;
    uint8_t action:      3,
            severity:    3,
            term_reason: 2;
    uint32_t threat_id;
    dpi_policy_desc_t policy_desc;
    dpi_policy_desc_t xff_desc;
    BITOP tags;
    uint32_t xff_client_ip;
    uint16_t xff_app;
    uint16_t xff_port;
} dpi_session_t;
```

dpi_session_t结构体用于描述会话，不仅仅是tcp会话，也可以是ip、udp会话。

1、使用无锁rcu哈希表

2、时间轮

timer_entry_t ts_entry; //时间轮
timer_entry_t tick_entry;//时间轮

这两个时间轮之间的差别是什么？有知道的小伙伴告诉我下吗？

3、会话的client端及server端信息

dpi_wing_t client, server;

```
typedef struct dpi_wing_ {
    uint8_t mac[ETH_ALEN]; //mac地址
    uint16_t port;//端口
    io_ip_t ip;//ip地址
    uint32_t next_seq, init_seq;//init_seq初始化，next_seq下一个序列号
    uint32_t asm_seq;//TODO:asm_seq到底是什么作用？

    union {
        struct {
            uint32_t tcp_acked;
            uint32_t tcp_win;//tcp窗口大小
        };
        struct {
            uint32_t icmp_echo_hash;
            uint16_t icmp_echo_seq;
            uint8_t icmp_times;
        };
    };
    uint16_t tcp_mss;//Maximum Segment Size最大分段大小
    uint8_t tcp_state:  4,
            tcp_wscale: 4;
    uint8_t flags;//标志位
    asm_t asm_cache;
    uint32_t pkts, bytes;//数据包数和字节数
    uint32_t reported_pkts, reported_bytes;//已上报数据包数和已上报字节数
} dpi_wing_t;
```



### 2、2、3 io_callback_ io通信结构体

```
typedef struct io_callback_ {
    int (*debug) (bool print_ts, const char *fmt, va_list args);
    int (*send_packet) (io_ctx_t *ctx, uint8_t *data, int len);
    int (*send_ctrl_json) (json_t *root);
    int (*send_ctrl_binary) (void *buf, int len);
    int (*threat_log) (DPMsgThreatLog *log);
    int (*traffic_log) (DPMsgSession *log);
    int (*connect_report) (DPMsgSession *log, int count_session, int count_violate);
} io_callback_t;
```

threat_log：威胁日志

traffic_log：流量日志

connect_report:连接上报



其赋值处有很多，以standalone模式举例

```
void dpi_setup(io_callback_t *cb, io_config_t *cfg)
{
    g_io_callback = cb;
    g_io_config = cfg;
}
```

只看standalone模式下

```
if (standalone) {
        g_callback.debug = debug_stdout;
        g_callback.send_packet = dp_send_packet;
        g_callback.send_ctrl_json = dp_ctrl_send_json;
        g_callback.send_ctrl_binary = dp_ctrl_send_binary;
        g_callback.threat_log = dp_ctrl_threat_log;
        g_callback.traffic_log = dp_ctrl_traffic_log;
        g_callback.connect_report = dp_ctrl_connect_report;
        dpi_setup(&g_callback, &g_config);

        int ret = net_run(g_in_iface);
    }
```

其中比较重要的是dp_ctrl_send_json和dp_ctrl_send_binary。

dp_ctrl_send_json：将 json 消息作为响应发送到客户端套接字。

dp_ctrl_send_binary:将二进制消息作为响应发送到客户端套接字。

### 2、2、4 策略相关数据结构

#### 1）规则dpi_rule_t

```
typedef struct dpi_rule_ {
    struct cds_lfht_node node;
    dpi_policy_desc_t desc;
    dpi_rule_key_t key;
} dpi_rule_t;
```

key代表查找的key，desc代表的是策略的描述。



#### 2）dpi_policy_desc_t策略描述

```go
typedef struct dpi_policy_desc_ {
    uint32_t id;
    uint8_t action;
    uint8_t flags;
#define POLICY_DESC_CHECK_VER      0x01	//校验版本
#define POLICY_DESC_INTERNAL       0x02 //内部
#define POLICY_DESC_EXTERNAL       0x04	//外部
#define POLICY_DESC_TUNNEL         0x08	//隧道
#define POLICY_DESC_UNKNOWN_IP     0x10	//未知ip
#define POLICY_DESC_SVC_EXTIP      0x20	//service服务ip
#define POLICY_DESC_HOSTIP         0x40	//主机ip
    uint16_t hdl_ver;
    uint32_t order;
} dpi_policy_desc_t;
```



#### 3）dpi_rule_key_t 策略key

规则key详情如下：

```
typedef struct dpi_rule_key_ {
    uint32_t sip;//源ip
    uint32_t dip//目的ip
    uint16_t dport;//目的端口
    uint16_t proto;//协议号
    uint32_t app;//应用
} dpi_rule_key_t;
```



策略的方向分为EGRESS和INGRESS

```
enum {
    POLICY_RULE_DIR_EGRESS,
    POLICY_RULE_DIR_INGRESS,
    POLICY_RULE_DIR_NONE,
};
```



## 2、3 线程模型剖析

多线程并发结构体，如下：

```c
#define th_packet   (g_dpi_thread_data[THREAD_ID].packet)
#define th_snap     (g_dpi_thread_data[THREAD_ID].snap)
#define th_counter  (g_dpi_thread_data[THREAD_ID].counter)
#define th_stats    (g_dpi_thread_data[THREAD_ID].stats)

#define th_ip4frag_map  (g_dpi_thread_data[THREAD_ID].ip4frag_map)
#define th_session4_map (g_dpi_thread_data[THREAD_ID].session4_map)
#define th_session4_proxymesh_map (g_dpi_thread_data[THREAD_ID].session4_proxymesh_map)
```

g_dpi_thread_data[THREAD_ID].xxxxx，其中xxxxx代表每个线程都有属于自己的资源，如会话表、分片表，数据包、状态记录等。



从线程模型来剖析大局的话，整个项目只创建了三个线程：

- 一个定时器线程timer_thr
- 一个dlp线程bld_dlp_thr
- 多个数据接收线程dp_thr

```
static int net_run(const char *in_iface)
{
    pthread_t timer_thr;
    pthread_t bld_dlp_thr;
    pthread_t dp_thr[MAX_DP_THREADS];
    int i, timer_thr_id, bld_dlp_thr_id, thr_id[MAX_DP_THREADS];
    
    ......

    dp_ctrl_init_thread_data();

    pthread_create(&timer_thr, NULL, dp_timer_thr, &timer_thr_id);

    pthread_create(&bld_dlp_thr, NULL, dp_bld_dlp_thr, &bld_dlp_thr_id);

    for (i = 0; i < g_dp_threads; i ++) {
        thr_id[i] = i;
        pthread_create(&dp_thr[i], NULL, dp_data_thr, &thr_id[i]);
    }

    dp_ctrl_loop();

    pthread_join(timer_thr, NULL);
    pthread_join(bld_dlp_thr, NULL);
    for (i = 0; i < g_dp_threads; i ++) {
        pthread_join(dp_thr[i], NULL);
    }

    return 0;
}
```

timer_thr线程：用于更新全局时间g_seconds的线程

bld_dlp_thr线程：用于数据防泄露dlp的线程

dp_thr[i]线程：用于收包的线程，创建了g_dp_threads个dp_thr线程，只有一个线程去更新全局统计计数。

下面重点看下dp_thr线程的线程函数dp_data_thr

```c
void *dp_data_thr(void *args)
{
   	......

    // Create epoll, add ctrl_req event
    if ((th_epoll_fd(thr_id) = epoll_create(MAX_EPOLL_EVENTS)) < 0)

    ctrl_req_ev_ctx = dp_add_ctrl_req_event(thr_id);

#define NO_WAIT    0
#define SHORT_WAIT 2
#define LONG_WAIT  1000
    // Even at packet rate of 1M pps, wait 0.002s means 2K packets. DP queue should
    // be able to accomodate it. Increase wait duration reduce idle CPU usage, but
    // worsen the latency, such as ping latency in protect mode.
    tmo = SHORT_WAIT;
    uint32_t last_seconds = g_seconds;
    while (g_running) {
        // Check if polling context exist, if yes, keep polling it.
        dp_context_t *polling_ctx = th_ctx_inline(thr_id);
        if (likely(polling_ctx != NULL)) {
            if (likely(dp_rx(polling_ctx, g_seconds) == DP_RX_MORE)) {
                // If there are more packets to consume, not to add polling context to epoll,
                // use no-wait time out so we can get back to polling right away.
                tmo = NO_WAIT;
                polling_ctx = NULL;
            } else {
                // If all packets are consumed, add polling context to epoll, so once there is
                // a packet, it can be handled.
                if (dp_epoll_add_ctx(polling_ctx, thr_id) < 0) {
                    tmo = SHORT_WAIT;
                    polling_ctx = NULL;
                } else {
                    tmo = LONG_WAIT;
                }
            }
        }

        int i, evs;
        evs = epoll_wait(th_epoll_fd(thr_id), epoll_evs, MAX_EPOLL_EVENTS, tmo);
        if (evs > 0) {
            for (i = 0; i < evs; i ++) {
                struct epoll_event *ee = &epoll_evs[i];
                dp_context_t *ctx = ee->data.ptr;

                if (ee->events & EPOLLIN) {
                    if (ctx->fd == th_ctrl_req_evfd(thr_id)) {
                        uint64_t cnt;
                        read(ctx->fd, &cnt, sizeof(uint64_t));
                        if (th_ctrl_req(thr_id)) {
                            io_ctx_t context;
                            context.tick = g_seconds;
                            context.tap = ctx->tap;
                            dpi_handle_ctrl_req(th_ctrl_req(thr_id), &context);
                        }
                    } else {
                        dp_rx(ctx, g_seconds);
                    }
                }
            }
        }
		......
    }

    close(th_epoll_fd(thr_id));
    th_epoll_fd(thr_id) = 0;

    return NULL;
}
```

## 2、4 基础组件介绍

### 2、4、1 lock-free rcu hash-table

cds_lsht_node介绍

cds_lfht_node：包含查找和遍历哈希表所需的下一个指针和反向哈希值。cds_lfht_node 应该以8字节内存对齐，低3位用做flag标志。

struct cds_lfht_node 可以作为字段嵌入到结构中。

caa_container_of() 可用于在查找后从 struct cds_lfht_node 获取结构。
嵌入它的结构通常保存对象的key键（或键值对）。调用者代码负责计算 cds_lfht API 的哈希值。



## 2、5 dp源代码编译

编译环境：

Ubuntu 20.04.4 LTS

gcc版本：9.4.0（系统自带）

g++版本：9.4.0（系统自带）

安装下libnetfilter-queue-dev、libpcap-dev库，然后就可以直接编译。

在ubuntu 20.04.4的原生环境下，可以直接编译成功，并进行GDB调试。



# 三、DPI功能

## 3、1 数据捕获

DPI分析的网络流量从何而来？主要有三种方式

![image-20220526162247592](picture/image-20220526162247592.png)



### 3、1、1 standalone模式

standalone模式，是从网络接口进行接收数据。

dp_data_add_tap

“/proc/1/ns/net” 加入到这个网络命名空间，有什么好处？

答：“/proc/1/ns/net”是主机的网络命名空间，进程进入此命名空间后，可看到宿主机上的全部网络信息。

 进入“/proc/1/ns/net”网络命名空间后，使用AF_PACKET raw原始套接字进行抓包。



### 3、1、2 pcap模式

 -p 打开pcap文件或目录下的pcap文件



### 3、1、3 netfilter_queue模式

netfilter_queue netfilter提供的一种机制，可将数据包从内核态拷贝到用户态进行裁决。

dp程序单独启动时，无法指定netfilter_queue模式，需要agent传递dp任务参数。



### 3、1、4 共享内存模式

共享内存模式和standalone模式是差不多的。

```go
{	
		dpi_setup(&g_callback, &g_config);

        g_shm = get_shm(sizeof(dp_mnt_shm_t));
        if (g_shm == NULL) {
            DEBUG_INIT("Unable to get shared memory.\n");
            return -1;
        }

        // Start
        int ret = net_run(g_in_iface);

        munmap(g_shm, sizeof(dp_mnt_shm_t));

        return ret;
}
```

dp_mnt_shm_t结构体如下：

```
typedef struct dp_mnt_shm_ {
    uint32_t dp_hb[MAX_DP_THREADS];
	bool dp_active[MAX_DP_THREADS];
} dp_mnt_shm_t;
```

dp_hb:心跳包，dp和agent之间的心跳包。

dp_active:dp是否存活。



### 3、1、5 原始套接字抓包

新版的libpcap以及suricata都采用的此种抓包方式。

#### 1、创建套接字(AF_PACKET）

```c
int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
```



#### 2、设置套接字属性

```c
// Discard malformed packets 丢弃格式错误的数据包
setsockopt(fd, SOL_PACKET, PACKET_LOSS, &enable, sizeof(enable));

// Packet truncated indication 数据包截断提示
setsockopt(fd, SOL_PACKET, PACKET_COPY_THRESH, &enable, sizeof(enable));
```



#### 3、分配环形缓冲区

包括这两种类型：PACKET_RX_RING和PACKET_TX_RING

```c
setsockopt(fd, SOL_PACKET, PACKET_RX_RING, req, sizeof(*req));//Capture process
if (!tap) {
	setsockopt(fd, SOL_PACKET, PACKET_TX_RING, req, sizeof(*req));//Transmission process
}
```

最重要的参数是req参数，这个参数有以下结构：

```c
struct tpacket_req
    {
        unsigned int    tp_block_size;  /* Minimal size of contiguous block */
        unsigned int    tp_block_nr;    /* Number of blocks */
        unsigned int    tp_frame_size;  /* Size of frame */
        unsigned int    tp_frame_nr;    /* Total number of frames */
    };
```

具体参数含义，查



#### 4、将环形缓冲区映射到用户进程

```c
ring->rx_map = mmap(NULL, ring->map_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, fd, 0);
```

ring->map_size大小代码中设置的是4194304



```c
ring->tx_map = ring->rx_map + ring->size;

ring->rx = dp_rx_v1;
ring->tx = dp_tx_v1;
```

设置其数据包接收函数为dp_rx_v1，数据包发送桉树为dp_tx_v1。

注册的回调函数rx的调用堆栈为：

dp_rx(ring.c)

​	dp_data_thr (pkt.c)

​		net_run (main.c)
​        	main (main.c)



#### 5、将传输套接字与网络接口绑定

bind() 将套接字关联到网络接口，这要归功于 struct sockaddr_ll 结构体的 sll_ifindex 参数。

```
static int dp_ring_bind(int fd, const char *iface)
{
    struct sockaddr_ll ll;
    memset(&ll, 0, sizeof(ll));
    ll.sll_family = PF_PACKET;
    ll.sll_protocol = htons(ETH_P_ALL);
    ll.sll_ifindex = if_nametoindex(iface);
    ll.sll_hatype = 0;
    ll.sll_pkttype = 0;
    ll.sll_halen = 0;

	//绑定操作
    return bind(fd, (struct sockaddr *)&ll, sizeof(ll));
}
```



参考链接

https://www.kernel.org/doc/Documentation/networking/packet_mmap.txt

## 3、2 网络协议解析

dpi_parse_ethernet()

dpi_parse_packet() 解析以太网，判断下一层是否是ip协议

dpi_parse_ipv4() 解析ip协议，判断下一层是否是tcp协议

dpi_parse_tcp()解析tcp协议



ether_aton_r函数

Convert ASCII string S to 48 bit Ethernet address 将字符串转换为48位的以太网地址

**1）以太网协议解析**

```c
static int dpi_parse_packet(dpi_packet_t *p)
{
    struct ethhdr *eth;
    eth = (struct ethhdr *)(p->pkt + p->l2);

    // Start L3 parsing
    p->eth_type = ntohs(eth->h_proto);
    switch (p->eth_type) {
    case ETH_P_IP:
        th_counter.ipv4_pkts ++;
        if (dpi_parse_ipv4(p) < 0) { //解析ip协议数据
            return -1;
        }
        break;
    case ETH_P_IPV6:
     	.....
        break;
    }

    return 0;
}
```

**2）ip协议解析dpi_parse_ipv4函数**

```
static int dpi_parse_ipv4(dpi_packet_t *p)
{
    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);

    // IP fragment分片处理
    p->ip_proto = iph->protocol;
    
    // Start L4 parsing
    switch (p->ip_proto) {
    case IPPROTO_TCP:
        return dpi_parse_tcp(p);
    case IPPROTO_UDP:
        return dpi_parse_udp(p);
    case IPPROTO_ICMP:
        return dpi_parse_icmp(p);
    }

    return 0;
}
```

**3）tcp协议解析dpi_parse_tcp()函数**

```
static int dpi_parse_tcp(dpi_packet_t *p)
{
    struct tcphdr *tcph = (struct tcphdr *)(p->pkt + p->l4);
    uint16_t tcp_len = p->len - p->l4;

	//校验tcp flag标志位 重点，重点，重点
    if (BITMASK_TEST(tcp_bad_flag_mask, tcph->th_flags & TCP_FLAG_MASK)) {
        LOG_BAD_PKT(p, "Bad tcp flags %s", get_tcp_flag_string(tcph, flags));
        return -1;
    }

    // Checksum 校验和
    if (unlikely(g_io_config->enable_cksum)) {
        cksum = get_l4v4_cksum((struct iphdr *)(p->pkt + p->l3), tcph, tcp_len);
    }

	//tcp的option字段解析
    if (tcph_len > sizeof(*tcph)) {
        if (dpi_parse_tcp_options(p) < 0) {
            return -1;
        }
    }

    return 0;
}
```



## 3、3 应用层协议解析

解析器代码都位于dpi/parser目录中

调用栈为：dpi_setup() -> dpi_parser_setup()



### 3、3、1 注册流程

```
void dpi_parser_setup(void)
{
    register_parser(dpi_dhcp_parser());
    ......注册其他协议的解析器
}

static void register_parser(dpi_parser_t *parser)
{
    dpi_parser_t **list = get_parser_list(parser->ip_proto);
    list[parser->type] = parser; 
    //相当于一个二维数组，第一层是proto,第二层是应用层的type类型
}

static dpi_parser_t **get_parser_list(int ip_proto)
{
    switch (ip_proto) {
    case IPPROTO_TCP:
        return g_tcp_parser;
    case IPPROTO_UDP:
        return g_udp_parser;
    default:
        return g_any_parser;
    }
}
```

解析器大致分为三类，全局tcp解析器，全局udp解析器，任意协议的解析器。

解析器的类型parser->type是何时赋值的呢？（在每个应用层协议的结构体初始化中）



再看dpi_dhcp_parser函数

```
dpi_parser_t *dpi_dhcp_parser(void)
{
    return &dpi_parser_dhcp;
}

static dpi_parser_t dpi_parser_dhcp = {
    new_session: dhcp_new_session,
    delete_data: NULL,
    parser:      dhcp_parser,
    name:        "dhcp",
    ip_proto:    IPPROTO_UDP,
    type:        DPI_PARSER_DHCP,
};
```

其中type为DPI_PARSER_DHCP，ip_proto为IPPROTO_UDP



### 3、3、2 调用流程

由于我只关心解析数据包，所以看parser回调函数。

dpi_pkt_proto_parser

​		dpi_proto_parser

​				cp->parser(p);

```
void dpi_proto_parser(dpi_packet_t *p)
{
    dpi_session_t *s = p->session;
    dpi_parser_t **list = get_parser_list(p->ip_proto), *cp;

    //已重组的数据包
    if (p->flags & DPI_PKT_FLAG_ASSEMBLED) {
        p->pkt_buffer = &p->asm_pkt;
    }

    //会话有唯一的解析器
    if (s->flags & DPI_SESS_FLAG_ONLY_PARSER) {
        cp = p->cur_parser = list[s->only_parser];
        if (cp != NULL && cp->parser != NULL) {
            cp->parser(p);//调用解析器

            if (!BITMASK_TEST(s->parser_bits, s->only_parser)) {
                DEBUG_LOG(DBG_SESSION, p, "sess %u: skip parser\n", s->id);
                dpi_delete_parser_data(s, cp);
                s->flags |= DPI_SESS_FLAG_SKIP_PARSER;
                s->flags &= ~DPI_SESS_FLAG_ONLY_PARSER;
                s->flags |= DPI_SESS_FLAG_POLICY_APP_READY;
            }
        }
    } else {
        // Walk through all parsers
        p->parser_left = 0;
        for (t = 0; t < DPI_PARSER_MAX; t ++) {
            cp = p->cur_parser = list[t];
            if (cp != NULL && cp->parser != NULL && BITMASK_TEST(s->parser_bits, t)) {
                cp->parser(p);//调用解析器

                if (BITMASK_TEST(s->parser_bits, t)) {
                    p->parser_left ++;
                    last = t;
                } else {
                    dpi_delete_parser_data(s, cp);//删除解析器数据
                }
            }
        }

        switch (p->parser_left) {
        case 0:
            // Session can still be finalized (protocol recognized) when we reach here - the
            // parser confirms the session type but is not interested in the session any more.
            s->flags |= DPI_SESS_FLAG_SKIP_PARSER; //找不到合适的解析器，则会跳过解析过程
            s->flags |= DPI_SESS_FLAG_POLICY_APP_READY;
            break;
        case 1:
            s->flags |= DPI_SESS_FLAG_LAST_PARSER; //标记最后一个解析器
            s->only_parser = last;
            break;
        }
    }

    //将p->pkt_buffer 置为 &p->raw;
    if (p->flags & DPI_PKT_FLAG_ASSEMBLED) {
        p->pkt_buffer = &p->raw;
    }
}
```



## 3、4 ip分片

ip分片以ipv4版本来进行讲解

数据结构

\#define th_ip4frag_map  (g_dpi_thread_data[THREAD_ID].ip4frag_map)



```
typedef struct dpi_thread_data_ {
    dpi_packet_t packet;
    dpi_snap_t snap;
    io_counter_t counter;
	io_stats_t stats;

    rcu_map_t ip4frag_map; 			//ipv4分片表
    rcu_map_t ip6frag_map;			//ipv6分片表
    rcu_map_t session4_map;			//ipv4会话表
    rcu_map_t session4_proxymesh_map;
    rcu_map_t session6_map;			//ipv6会话表
    rcu_map_t session6_proxymesh_map;//proxy mesh map
    rcu_map_t meter_map;
    rcu_map_t log_map;
    rcu_map_t unknown_ip_map;		//未知ip的映射表
	timer_wheel_t timer;

	io_internal_subnet4_t *subnet4;
	io_spec_internal_subnet4_t *specialipsubnet4;
	io_internal_subnet4_t *policyaddr;

	void *apache_struts_re_data;

    uint8_t dp_msg[DP_MSG_SIZE];
    uint32_t hs_detect_id;
    uint8_t xff_enabled;
} dpi_thread_data_t;
```

分片表的增删改查操作相关的代码

**初始化**

```
void dpi_frag_init(void)
{
    rcu_map_init(&th_ip4frag_map, 1, offsetof(ip4frag_trac_t, node),
                 ip4frag_trac_match, ip4frag_trac_hash);
}
```



**查找和添加**

```
int dpi_ip_defrag(dpi_packet_t *p)
{
    ip4frag_trac_t *trac, key;
    struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
    int ret = -1;

	//构造key
    memset(&key, 0, sizeof(key));
    key.src = iph->saddr;
    key.dst = iph->daddr;
    key.ipid = iph->id;
    key.ingress = !!(p->flags & DPI_PKT_FLAG_INGRESS);

	//以key为依据查找th_ip4frag_map分片表
    trac = rcu_map_lookup(&th_ip4frag_map, &key);
    if (trac == NULL) {
        trac = malloc(sizeof(*trac));
        if (trac == NULL) {
            return -1;
        }

        memcpy(trac, &key, sizeof(key));
        asm_init(&trac->frags);

		//添加到th_ip4frag_map中
        rcu_map_add(&th_ip4frag_map, trac, &key);
        timer_wheel_entry_init(&trac->ts_entry);
        timer_wheel_entry_start(&th_timer, &trac->ts_entry,
                                ipfrag_release, DPI_FRAG_TIMEOUT, th_snap.tick);
    }

    timer_wheel_entry_refresh(&th_timer, &trac->ts_entry, th_snap.tick);

    ipfrag_hold(trac, p);
    if (trac->first && trac->last) {
        ret = ipfrag_construct(trac, p);
    }

    return ret;
}
```

**删除**



## 3、5 会话管理

### 3、5、1 ipv4会话管理

会话管理以ipv4版本来进行讲解

超时机制如何？

**初始化**

```
void dpi_session_init(void)
{
    rcu_map_init(&th_session4_map, 512, offsetof(dpi_session_t, node),
}
```



**查找操作**

```
dpi_session_t *dpi_session_lookup(dpi_packet_t *p)
{
    dpi_session_t *s, key;
    bool ingress = !!(p->flags & DPI_PKT_FLAG_INGRESS);
    bool isproxymesh = cmp_mac_prefix(p->ep_mac, PROXYMESH_MAC_PREFIX);

    memset(&key.client.ip, 0, sizeof(key.client.ip));
    memset(&key.server.ip, 0, sizeof(key.server.ip));

    key.ip_proto = p->ip_proto;

    // Try client side
    if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_FAKE_EP))) {
        // For pcap pcacket, session is always marked as INGRESS
        key.flags = DPI_SESS_FLAG_INGRESS | DPI_SESS_FLAG_FAKE_EP;
    } else {
        key.flags = ingress ? DPI_SESS_FLAG_INGRESS : 0;
    }
    key.client.port = p->sport;
    key.server.port = p->dport;

    if (likely(p->eth_type == ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        key.client.ip.ip4 = iph->saddr;
        key.server.ip.ip4 = iph->daddr;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session4_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session4_map, &key);
        }
    }

    // Try server side
    if (unlikely(FLAGS_TEST(p->flags, DPI_PKT_FLAG_FAKE_EP))) {
        // For pcap pcacket, session is always marked as INGRESS
        key.flags = DPI_SESS_FLAG_INGRESS | DPI_SESS_FLAG_FAKE_EP;
    } else {
        key.flags = !ingress ? DPI_SESS_FLAG_INGRESS : 0;
    }
    key.client.port = p->dport;
    key.server.port = p->sport;

    if (likely(p->eth_type == ETH_P_IP)) {
        struct iphdr *iph = (struct iphdr *)(p->pkt + p->l3);
        key.client.ip.ip4 = iph->daddr;
        key.server.ip.ip4 = iph->saddr;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session4_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session4_map, &key);
        }
    } else {
        struct ip6_hdr *ip6h = (struct ip6_hdr *)(p->pkt + p->l3);
        key.client.ip.ip6 = ip6h->ip6_dst;
        key.server.ip.ip6 = ip6h->ip6_src;
        if (isproxymesh) {
            s = rcu_map_lookup(&th_session6_proxymesh_map, &key);
        } else {
            s = rcu_map_lookup(&th_session6_map, &key);
        }
    }

    return NULL;
}
```

DPI_PKT_FLAG_FAKE_EP是什么时候设置的

对于 pcap 数据包, session会话将被标记为 INGRESS



**删除操作**

dpi_session_release

rcu_map_del(&th_session4_map, s);



### 3、5、2 ipv6 会话管理

### 3、5、3 proxymesh会话管理

TODO： 为什么要有proxymesh会话管理？



## 3、6 meter仪表盘功能

```
typedef struct dpi_meter_ {
    struct cds_lfht_node node;
    timer_entry_t ts_entry;

    io_ip_t peer_ip;
    uint8_t ep_mac[ETH_ALEN];
    uint8_t type;
#define DPI_METER_FLAG_ON   0x01
    uint8_t flags;
    uint32_t count, last_count, log_count;
    uint32_t start_tick, last_log;
    DPMsgThreatLog log;
} dpi_meter_t;
```

meter功能的核心结构体是dpi_meter_t，Neuvector维护了rcu_map_t meter_map;

```
int dpi_meter_packet_inc(uint8_t type, dpi_packet_t *p);
int dpi_meter_synflood_inc(dpi_packet_t *p);
int dpi_meter_session_inc(dpi_packet_t *p, dpi_session_t *s);
void dpi_meter_session_dec(dpi_session_t *s);
bool dpi_meter_session_rate(uint8_t type, dpi_session_t *s);
```

meter仪表盘上，数据统计的维度有以下三种：

1. 数据包情况
2. 会话情况

3. synflood泛洪情况



# 四、DDOS防护实现

只是简单的判断了tcp的标志位。

函数调用栈：dpi_setup -> dpi_packet_setup



定义有问题的tcp标志位合集

```
#define TCP_FLAG_MASK (TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN | TH_RST)
static uint8_t tcp_bad_flag_list[] = {
    0,
    TH_URG,
    TH_FIN,
    TH_PUSH,
    TH_PUSH | TH_FIN,
    TH_PUSH | TH_URG,
    TH_SYN | TH_FIN,
    TH_PUSH | TH_URG | TH_FIN,
    TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN,
    TH_PUSH | TH_URG | TH_FIN | TH_ACK | TH_SYN | TH_RST,
};
BITMASK_DEFINE(tcp_bad_flag_mask, 256);
```

判断流程在tcp数据包的解析函数中，调用BITMASK_TEST(tcp_bad_flag_mask, tcph->th_flags & TCP_FLAG_MASK)来判断tcp数据包的标志位是否合法，从而判断是否是ddos攻击。



# 五、数据防泄露DLP实现

dlp的正则表达式的库，是否好维护？

dpi_dlp_ep_policy_check

采用hyperscan作为匹配引擎，后续需安服来维护正则表达式库。



初始化

何时调用



# 六、应用层防护 WAF 实现

dpi_waf_ep_policy_check

采用hyperscan作为匹配引擎，后续需安服来维护正则表达式库。



# 七、微隔离

微隔离实现的关键函数为

dpi_pkt_policy_reeval()



函数调用栈为：

dpi_recv_packet() -> dpi_inspect_ethernet() -> dpi_pkt_policy_reeval()



```
static void dpi_pkt_policy_reeval(dpi_packet_t *p)
{
    bool to_server = dpi_is_client_pkt(p);
    dpi_session_t *s = p->session;
    int log_violate = 0;

    if (unlikely(dpi_policy_reeval(p, to_server) >= 1)) {
      	//log violate
        if (s->policy_desc.action == DP_POLICY_ACTION_DENY ||
            s->xff_desc.action == DP_POLICY_ACTION_DENY) {
            if (p->ip_proto == IPPROTO_TCP) {
                dpi_inject_reset(p, true);
                dpi_inject_reset(p, false);
            }
            // For mid session deny, keep the session to block
            // traffic coming afterwards
            //dpi_session_delete(s, DPI_SESS_TERM_POLICY);
            //p->session = NULL;
            p->session->action = DPI_ACTION_BLOCK;
            dpi_set_action(p, DPI_ACTION_DROP);
        }
    }
}
```

那微隔离是如何阻断的呢？

dpi_inject_reset(p, true);

dpi_inject_reset(p, false);

上述代码调用dpi_inject_reset是给client和server端都发送reset包。调用reset包是中断链接，而drop数据包后对端还会进行数据包重传，从而可能会加大。



```
void dpi_inject_reset(dpi_packet_t *p, bool to_server)
{
    if (unlikely(p->session == NULL)) return;

    dpi_inject_reset_by_session(p->session, to_server);
}
```

dpi_inject_reset_by_session函数是在构造rst包，并且同时向客户端和服务器都发送reset数据包。



对于上述代码中的第15~20行代码

```
// For mid session deny, keep the session to block
// traffic coming afterwards
//dpi_session_delete(s, DPI_SESS_TERM_POLICY);
//p->session = NULL;
p->session->action = DPI_ACTION_BLOCK;
dpi_set_action(p, DPI_ACTION_DROP);
```

对于中间会话的拒绝，保留会话以阻止之后的流量。

p->action = DPI_ACTION_DROP

p->session->action = DPI_ACTION_BLOCK

分为这两种情况。



在使用tc模式阻断时，dp负责记录微隔离的记录日志。

# 八、agent和dp策略下发及响应



NeuVector 通过组的方式对容器和主机进行管理，对组进行合规性检查、网络规则、进程和文件访问规则、DLP/WAF 的检测配置。

NeuVector 会自动将当前集群主机加入到 nodes 组，对于集群内容器会自动创建以 nv.开头的组(如nv.calico-kube-controller.kube-system)。

![img](picture/1834389-20220407110541018-674713994.png)



函数调用栈如下：

dp_ctrl_loop() -> dp_ctrl_handler() -> dp_ctrl_cfg_policy() ->dpi_policy_cfg()



```
void dp_ctrl_loop(void)
{
    ......
    while (g_running) {
        timeout.tv_sec = 2;
        timeout.tv_usec = 0;

        FD_ZERO(&read_fds);
        FD_SET(g_ctrl_fd, &read_fds);
        ret = select(g_ctrl_fd + 1, &read_fds, NULL, NULL, &timeout);

        if (ret > 0 && FD_ISSET(g_ctrl_fd, &read_fds)) {
            dp_ctrl_handler(g_ctrl_fd);
        }
    }
    ......
}
```

dp_ctrl_loop函数是agent和dp之间通信交互的通道。

创建了g_ctrl_fd和g_ctrl_notify_fd文件描述符。

g_ctrl_fd：agent和dp之间的控制通道。

g_ctrl_notify_fd：agent和dp之间的通知通道。



```
g_ctrl_fd = make_named_socket(DP_SERVER_SOCK);
g_ctrl_notify_fd = make_notify_client(CTRL_NOTIFY_SOCK);
```

```
static int make_named_socket(const char *filename)
{
    struct sockaddr_un name;
    int sock;
    size_t size;

    sock = socket(PF_UNIX, SOCK_DGRAM, 0);
    if (sock < 0) {
        return -1;
    }

    name.sun_family = AF_UNIX;
    strlcpy(name.sun_path, filename, sizeof(name.sun_path));

    size = (offsetof(struct sockaddr_un, sun_path) + strlen(name.sun_path));

    if (bind(sock, (struct sockaddr *)&name, size) < 0) {
        return -1;
    }

    return sock;
}
```

从make_named_socket函数可知，g_ctrl_fd是Unix Domain套接字，路径为DP_SERVER_SOCK 

#define DP_SERVER_SOCK "/tmp/dp_listen.sock"



使用select网络模型监听g_ctrl_fd可读事件，有可读事件时调用dp_ctrl_handler

```
static int dp_ctrl_handler(int fd)
{
    ......
    json_object_foreach(root, key, msg) {
		......
        else if (strcmp(key, "ctrl_cfg_policy") == 0) {
            ret = dp_ctrl_cfg_policy(msg);
        }
        ......
    }

    json_decref(root);

    return ret;
}
```

解析对端传递的json数据，并找到对应的处理函数，如ctrl_cfg_policy的处理函数是dp_ctrl_cfg_policy



基于epoll的事件驱动模型。和libevent的基于事件的驱动模型是几乎一模一样的。



ingress 和 egress是如何来处理的，

\#define DPI_PKT_FLAG_INGRESS    0x00000100宏是如何发挥作用的

这几块的代码也看了，但是文字方面并没有补，因为逻辑上比较复杂，所以考虑绘制下状态图来梳理下思路。



如何判断是tap设备，这块也是我需要好好理解的。

# 参考资料：

proxymesh是对应什么场景？需要补充下proxy mesh的知识TODO：



**How to Enforce Egress Container Security Policies in Kubernetes, OpenShift, and Istio**

https://blog.neuvector.com/article/enforce-egress-control-containers



**iptables netfilter_queue**

https://asphaltt.github.io/post/iptables-nfqueue/



**动态微隔离实验**

https://www.cnblogs.com/rancherlabs/p/16111452.html



**开源软件的产品分析**

https://kubesphere.io/zh/blogs/neuvector-cloud-native-security/