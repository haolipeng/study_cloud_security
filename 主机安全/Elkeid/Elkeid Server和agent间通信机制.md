分析的源代码版本： v1.7-agent

**今日鸡汤：高手和高手之间的差距，就是扣各种细节问题。**



今天的主题是server和agent间通信机制，因为

## **一、proto文件**

agent的proto文件路径：Elkeid/agent/proto/grpc.proto

server的proto文件路径：Elkeid/server/agent_center/grpctrans/proto

agent端核心结构如下所示：

```
message PackagedData {
  repeated EncodedRecord records = 1;   #已编码的记录列表
  string agent_id = 2;
  repeated string intranet_ipv4 = 3;    #内网ipv4地址
  repeated string extranet_ipv4 = 4;    #外网ipv4地址
  repeated string intranet_ipv6 = 5;    #内网ipv6地址
  repeated string extranet_ipv6 = 6;    #外网ipv6地址
  string hostname = 7;                  #主机名
  string version = 8;                   #版本
  string product = 9;                   #产品名
}
```

## **二、agent端源码分析**

## **2、1 调用堆栈**

agent端属于client端，想创建client，必然要调用grpc.pb.go文件中的函数NewTransferClient

```
func NewTransferClient(cc *grpc.ClientConn) TransferClient {
   return &transferClient{cc}
}
```

![img](picture/v2-c5f7bcb5b6bd18b930b719a09b1718eb_720w-16505479717393.png)



编辑切换为居中

调用堆栈

proto.NewTransferClient()函数的调用者为agent/transport目录下，transfer.go文件的startTransfer函数

```
func startTransfer(ctx context.Context, wg *sync.WaitGroup) {
   defer wg.Done()
   retries := 0
   subWg := &sync.WaitGroup{}
   defer subWg.Wait()
   for {
      //判断连接是否存在
      conn := connection.GetConnection(ctx)
      // 获取不到连接，则记录重试次数，当重试次数大于5时，提示无可用连接
      if conn == nil {
         if retries > 5 {
            zap.S().Error("transfer will shutdown because of no avaliable connections")
            return
         }
         //等待5秒中，再去获取下一个连接connection
         zap.S().Warnf("wait to get next connection for 5 seconds,current retry times:%v", retries)
         select {
         case <-ctx.Done():
            return
         case <-time.After(time.Second * 5):
            retries++
            continue
         }
      }
      zap.S().Infof("get connection successfully:idc %v,region %v,netmode %v", connection.IDC, connection.Region, connection.NetMode.Load().(string))
      retries = 0
      var client proto.Transfer_TransferClient
      subCtx, cancel := context.WithCancel(ctx)
      //创建grpc客户端对象，并调用Transfer
      client, err := proto.NewTransferClient(conn).Transfer(subCtx, grpc.UseCompressor("snappy"))
      if err == nil {
         subWg.Add(2)
         //数据发送逻辑
         go handleSend(subCtx, subWg, client)
         go func() {
            //数据接收逻辑
            handleReceive(subCtx, subWg, client)
            // 收到错误后取消服务
            cancel()
         }()
         subWg.Wait()
      } else {
         zap.S().Error(err)
      }
      cancel()
      zap.S().Info("transfer has been canceled,wait next try to transfer for 5 seconds")
      #传输被取消，等待5秒后尝试下一次
      select {
      case <-ctx.Done():
         return
      case <-time.After(time.Second * 5):
      }
   }
}
```

分享一个阅读源代码的小技巧：只看代码的核心逻辑，选择性的暂时不看错误处理的代码，这些代码占总代码的比例很大，其实这些代码仅仅是为了程序的健壮性。

如果忽略错误处理代码的话，我们关心的函数仅仅有三个：

1、connection.GetConnection()

2、处理数据发送逻辑的函数 handleSend()

3、处理数据接收逻辑的函数 handleReceive()

## **2、2 核心函数**

### **2、2、1 connection.GetConnection函数**

```
func GetConnection(ctx context.Context) *grpc.ClientConn {
   c, ok := conn.Load().(*grpc.ClientConn)
   //连接存在
   if ok {
      //判断grpc的连接状态
      switch c.GetState() {
      case connectivity.Ready:      //表示ClientConn 已准备好工作
         //原子增加引用计数retries，当次数大于5时，调用Close()关闭连接
         if atomic.AddInt32(&retries, 1) > 5 {
            c.Close()
         } else {
            return c
         }
      case connectivity.Connecting:  //表示ClientConn 正在连接中
         c.Close()
      case connectivity.Idle:          //表示 ClientConn 空闲
         //原子增加引用计数retries，当次数大于5时，调用Close()关闭连接
         if atomic.AddInt32(&retries, 1) > 5 {
            c.Close()
         } else {
            return c
         }
      case connectivity.TransientFailure:    //表示 ClientConn遇到失败，但期望恢复
         c.Close()
      case connectivity.Shutdown:          //表示 ClientConn已经开始关闭操作
      }
   }
   host, ok := serviceDiscoveryHost[Region]
   if ok {
      addrs, err := resolveService(host, 10)
      if err == nil {
         for _, addr := range addrs {
            context, cancel := context.WithTimeout(ctx, time.Second*3)
            defer cancel()
            c, err := grpc.DialContext(context, addr, dialOptions...)
            if err == nil {
               conn.Store(c)
               NetMode.Store("sd")
               atomic.StoreInt32(&retries, 0)
               return c
            }
         }
      }
   }
   host, ok = privateHost[Region]
   if ok {
      context, cancel := context.WithTimeout(ctx, time.Second*3)
      defer cancel()
      c, err := grpc.DialContext(context, host, dialOptions...)
      if err == nil {
         conn.Store(c)
         NetMode.Store("private")
         atomic.StoreInt32(&retries, 0)
         return c
      }
   }
   host, ok = publicHost[Region]
   if ok {
      context, cancel := context.WithTimeout(ctx, time.Second*3)
      defer cancel()
      c, err := grpc.DialContext(context, host, dialOptions...)
      if err == nil {
         conn.Store(c)
         NetMode.Store("public")
         atomic.StoreInt32(&retries, 0)
         return c
      }
   }
   return nil
}
```

GetConnection函数的核心流程如下：

1、取出原子变量conn的值，如果连接存在，则判断其连接状态；

2、针对五种连接状态（Ready、Connecting、Idle、TransientFailure、Shutdown），有对应的操作

3、serviceDiscoveryHost、privateHost、publicHost处理逻辑都差不多，此处我们只看publicHost的逻辑；

4、从publicHost映射表中查找Region对应的host主机，调用grpc.DialContext去连接host地址，连接成功则保存连接信息到conn原子变量中，并返回连接信息c

### **2、2、2 handleSend()函数**

handleSend()函数中使用的全局变量如下：

```
var (
   Mu                = &sync.Mutex{}        //多个client同时读写Buf，保证其协程安全的互斥锁
   Buf               = [8192]interface{}{}  //数据发送缓冲区
   Offset            = 0                    //发送缓冲区的数据偏移量
   ErrBufferOverflow = errors.New("buffer overflow") //超过发送缓冲区的错误
   hook              func(interface{}) interface{}
   RecordPool        = sync.Pool{           //EncodedRecord类型的对象池
      New: func() interface{} {
         return &proto.EncodedRecord{
            Data: make([]byte, 0, 1024*2),
         }
      },
   }
)
```

**Mu：**多个client同时读写Buf，保证其协程安全的互斥锁

**Buf：**数据发送缓冲区

**Offset：**发送缓冲区的数据偏移量

**ErrBufferOverflow：**超过发送缓冲区容量时，会产生错误

**RecordPool：**EncodedRecord类型的对象池

此处RecordPool采用的对象池sync.Pool，对于频繁创建和销毁的对象使用对象池技术，能大大的提升程序性能。

函数中创建了一个0.1秒的定时器，即每隔0.1秒会触发一次数据发送事件，核心逻辑如下：

```
case <-ticker.C:
   {
      //多个客户端同时操作同一个发送缓冲区core.Offset，所以需加锁
      core.Mu.Lock()
      //发送缓冲区有数据
      if core.Offset != 0 {
         zap.S().Debugf("will send %v recs", core.Offset)
         //创建EncodedRecord切片，用来存储EncodedRecord
         nbuf := make([]*proto.EncodedRecord, 0, core.Offset)
         for _, v := range core.Buf[:core.Offset] {
            //判断元素类型
            //proto.EncodedRecord类型的数据，直接添加到切片中
            //proto.Record类型的数据，转换为proto.EncodedRecord类型的数据再添加到切片中
            switch t := v.(type) {
            case *proto.EncodedRecord:
               nbuf = append(nbuf, t)
            case *proto.Record:
               data, _ := t.Data.Marshal()
               rec := core.RecordPool.Get().(*proto.EncodedRecord)
               rec.DataType = t.DataType
               rec.Timestamp = t.Timestamp
               rec.Data = data
               nbuf = append(nbuf, rec)
            }
         }
         //填充PackagedData结构体并发送出去
         err := client.Send(&proto.PackagedData{
            Records:      nbuf,
            AgentId:      agent.ID,
            IntranetIpv4: host.PrivateIPv4.Load().([]string),
            IntranetIpv6: host.PrivateIPv6.Load().([]string),
            ExtranetIpv4: host.PublicIPv4.Load().([]string),
            ExtranetIpv6: host.PublicIPv6.Load().([]string),
            Hostname:     host.Name.Load().(string),
            Version:      agent.Version,
            Product:      agent.Product,
         })
         //数据发送结束后，将对象归还给对象池core.RecordPool
         for _, v := range nbuf {
            v.Data = v.Data[:0]
            core.RecordPool.Put(v)
         }
         //发送成功则记录发送次数
         if err == nil {
            atomic.AddUint64(&txCnt, uint64(core.Offset))
            core.Offset = 0
         } else {
            core.Mu.Unlock()
            return
         }
      }
      core.Mu.Unlock()
   }
```

1、多个客户端同时操作同一个发送缓冲区core.Offset，所以需加锁Mu；

2、当发送缓冲区有数据时，创建EncodedRecord切片，用来存储EncodedRecord；

3、遍历发送缓冲区中数据并判断类型：

 proto.EncodedRecord类型的数据，直接添加到切片中；

 proto.Record类型的数据，转换为proto.EncodedRecord类型的数据再添加到切片中；

4、填充PackagedData结构体（如agentId，内网ipv4，nbuf记录结果等）并通过grpc接口发送出去

5、 数据发送结束后，将对象归还给对象池core.RecordPool

6、发送成功后，释放锁Mu，并进行统计计数。

Elkeid采用多个grpc连接复用一个发送缓冲区core.Buf，Offset用于指示发送缓冲区中的偏移量，当缓冲区的偏移量大于0时才会触发实际的数据发送操作。

### **2、2、3 handleReceive()函数**

```
func handleReceive(ctx context.Context, wg *sync.WaitGroup, client proto.Transfer_TransferClient) {
   defer wg.Done()
   defer zap.S().Info("receive handler will exit")
   zap.S().Info("receive handler running")
   for {
      cmd, err := client.Recv()
      if err != nil {
         zap.S().Error(err)
         return
      }
      zap.S().Info("received command")
      atomic.AddUint64(&rxCnt, 1) //统计接收数
      if cmd.Task != nil {
         // 给agent的任务
         if cmd.Task.ObjectName == agent.Product {
            switch cmd.Task.DataType {
            case 1060: //1060表示关闭agent
               zap.S().Info("will shutdown agent")
               agent.Cancel()
               zap.S().Info("shutdown agent successfully")
               return
            }

         } else {
            // 给插件的任务
            // 根据插件名称来获取插件对象，成功则向插件发送任务
            // 插件对象为空，则打印错误日志
            plg, ok := plugin.Get(cmd.Task.ObjectName)
            if ok {
               err = plg.SendTask(*cmd.Task)
               if err != nil {
                  plg.Error("send task to plugin failed: ", err)
               }
            } else {
               zap.S().Error("can't find plugin: ", cmd.Task.ObjectName)
            }
         }
         continue
      }
      // 处理配置变更
      cfgs := map[string]*proto.Config{}
      for _, config := range cmd.Configs {
         cfgs[config.Name] = config
      }
      // 配置的版本和agent的版本不同，则更新agent
      if cfg, ok := cfgs[agent.Product]; ok && cfg.Version != agent.Version {
         zap.S().Infof("agent will update:current version %v -> expected version %v", agent.Version, cfg.Version)
         err := agent.Update(*cfg)
         if err == nil {
            zap.S().Info("update successfully")
            agent.Cancel()
            return
         } else {
            zap.S().Error("update failed:", err)
         }
      }
      delete(cfgs, agent.Product)
      // 升级agent成功后同步plugin
      err = plugin.Sync(cfgs)
      if err != nil {
         zap.S().Error(err)
      }
      continue
   }
}
```

**handleReceive()函数的核心流程如下：**

1、调用client.Recv()从server端接收消息

2、判断任务cmd.Task是否为nil，大体分为2种情况

3、给agent的任务，1060表示关闭agent

4、给插件的任务，根据插件名称来获取插件对象，插件对象有效则向插件发送任务

5、处理配置变更，当下发配置的版本和本地的agent版本不同时，更新agent并同步plugin插件信息。

## **三、server端源码分析**

## **3、1 调用堆栈**

调用堆栈如下：

![img](picture/v2-6ae5fa59a9e7730611a306e6f44fe49d_720w.png)



编辑切换为居中

server端调用堆栈

**server服务端的代码位于server/agent_center/grpctrans目录的grpc_server.go文件的runServer函数**

```
func runServer(enableCA bool, port int, crtFile, keyFile, caFile string) {
   // Handling client timeout
   kaep := keepalive.EnforcementPolicy{
      MinTime:             defaultMinPingTime,
      PermitWithoutStream: true,
   }

   kasp := keepalive.ServerParameters{
      MaxConnectionIdle: defaultMaxConnIdle,
      Time:              defaultPingTime,
      Timeout:           defaultPingAckTimeout,
   }

   //设置keepalive参数，
   opts := []grpc.ServerOption{
      grpc.KeepaliveEnforcementPolicy(kaep),
      grpc.KeepaliveParams(kasp),

      grpc.MaxRecvMsgSize(maxMsgSize), //设置服务器可以接收的最大消息大小
      grpc.MaxSendMsgSize(maxMsgSize), //设置服务器可以发送的最大消息大小
   }

   //是否启用ca证书
   if enableCA {
      ct := credential(crtFile, keyFile, caFile)
      if ct == nil {
         ylog.Errorf("RunServer", "####GET_CREDENTIAL_ERROR")
         os.Exit(-1)
      }
      opts = append(opts, grpc.Creds(ct))
   }

   //创建grpc server端
   server := grpc.NewServer(opts...)
   //注册服务到grpc server，后续重点看grpc_handler.TransferHandler
   pb.RegisterTransferServer(server, &grpc_handler.TransferHandler{})
   reflection.Register(server)
    
   //tcp侦听port端口
   lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
   if err != nil {
      ylog.Errorf("RunServer", "####TCP_LISTEN_ERROR: %v", err)
      os.Exit(-1)
   }

   ylog.Infof("RunServer", "####TCP_LISTEN_OK: %v", lis.Addr().String())
   fmt.Printf("####TCP_LISTEN_OK: %v\n", lis.Addr().String())
   if err = server.Serve(lis); err != nil {
      ylog.Errorf("RunServer", "####GRPC_SERVER_ERROR: %v", err)
      os.Exit(-1)
   }
}
```

**转到TransferHandler结构体实现的grpc接口即Transfer函数**

```
func (h *TransferHandler) Transfer(stream pb.Transfer_TransferServer) error {
   //Maximum number of concurrent connections
   //判断并发连接数是否超过最大数量
   if !GlobalGRPCPool.LoadToken() {
      err := errors.New("out of max connection limit")
      ylog.Errorf("Transfer", err.Error())
      return err
   }
   defer func() {
      GlobalGRPCPool.ReleaseToken()
   }()

   //接收第一个包，并获取AgentID值
   //Receive the first packet and get the AgentID
   data, err := stream.Recv()
   if err != nil {
      ylog.Errorf("Transfer", "Transfer error %s", err.Error())
      return err
   }
   agentID := data.AgentID

   //获取客户端的地址
   //Get the client address
   p, ok := peer.FromContext(stream.Context())
   if !ok {
      ylog.Errorf("Transfer", "Transfer error %s", err.Error())
      return err
   }
   addr := p.Addr.String()
   ylog.Infof("Transfer", ">>>>connection addr: %s", addr)

   //构造连接信息Connection，并添加到连接池中
   //add connection info to the GlobalGRPCPool
   ctx, cancelButton := context.WithCancel(context.Background())
   createAt := time.Now().UnixNano() / (1000 * 1000 * 1000)
   connection := pool.Connection{
      AgentID:     agentID,
      SourceAddr:  addr,
      CreateAt:    createAt,
      CommandChan: make(chan *pool.Command),
      Ctx:         ctx,
      CancelFuc:   cancelButton,
   }
   ylog.Infof("Transfer", ">>>>now set %s %v", agentID, connection)
   err = GlobalGRPCPool.Add(agentID, &connection)
   if err != nil {
      ylog.Errorf("Transfer", "Transfer error %s", err.Error())
      return err
   }
   defer func() {
      ylog.Infof("Transfer", "now delete %s ", agentID)
      //从连接池中释放agentID对应的连接
      GlobalGRPCPool.Delete(agentID)
   }()

   //处理第一个数据(重点)
   //Process the first of data
   handleRawData(data, &connection)

   //从agent接收的数据(重点)
   //Receive data from agent
   go recvData(stream, &connection)
    
    //发送命令给agent(重点)
   //Send command to agent
   go sendData(stream, &connection)

   //每次agent连接server时，都将最新配置推送给agent
   //Every time the agent connects to the server
   //it needs to push the latest configuration to agent
   err = GlobalGRPCPool.PostLatestConfig(agentID)
   if err != nil {
      ylog.Errorf("Transfer", "send config error, %s %s", agentID, err.Error())
   }

   //这句是什么作用？
   //stop here
   <-connection.Ctx.Done()
   return nil
}
```

**Transfer函数的逻辑如下：**

1、判断并发连接数是否超过最大数量

2、接收第一个包，并获取AgentID值，获取客户端的地址

3、构造连接信息Connection，并添加到连接池中

4、handleRawData()函数处理处理第一个数据**(重点)**

5、recvData()函数，从agent接收数据**(重点)**

6、sendData()函数，发送命令给agent**(重点)**

7、PostLatestConfig函数，每次agent连接server时，都将最新配置推送给agent

## **3、2 核心函数**

下面来一一剖析下handleRawData、recvData、sendData这三个函数

### **3、2、1 recvData函数**

recvData函数代码如下：

```
func recvData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
   defer conn.CancelFuc()

   for {
      select {
      case <-conn.Ctx.Done():
         ylog.Errorf("recvData", "the send direction of the tcp is closed, now close the recv direction, %s ", conn.AgentID)
         return
      default:
         //从grpc stream中持续不断的接收数据，转而调用handleRawData
         data, err := stream.Recv()
         if err != nil {
            ylog.Errorf("recvData", "Transfer Recv Error %s, now close the recv direction of the tcp, %s ", err.Error(), conn.AgentID)
            return
         }
         handleRawData(data, conn)
      }
   }
}
```

经典的for-select模型编码方式，好熟悉的感jiao。

逻辑很简单，从grpc stream中持续不断的接收数据，转而调用handleRawData，一会好好看下handleRawData函数。

### **3、2、2 sendData函数**

sendData函数代码如下：

```
func sendData(stream pb.Transfer_TransferServer, conn *pool.Connection) {
   defer conn.CancelFuc()

   for {
      select {
      case <-conn.Ctx.Done():
         ylog.Infof("sendData", "the recv direction of the tcp is closed, now close the send direction, %s ", conn.AgentID)
         return
      case cmd := <-conn.CommandChan:
         //if cmd is nil, close the connection
         if cmd == nil {
            ylog.Infof("sendData", "get the close signal , now close the send direction of the tcp, %s ", conn.AgentID)
            return
         }
         err := stream.Send(cmd.Command)
         if err != nil {
            ylog.Errorf("sendData", "Send Task Error %s %s ", conn.AgentID, cmd)
            cmd.Error = err
            close(cmd.Ready)
            return
         }
         ylog.Infof("sendData", "Transfer Send %s %s ", conn.AgentID, cmd)
         cmd.Error = nil
         close(cmd.Ready)
      }
   }
}
```

经典的for-select模型编码方式，好熟悉的感jiao。

1、从conn.CommandChan的管道中读取cmd命令；

2、如cmd为nil则调用的conn.CancelFuc()函数关闭连接；

3、如cmd不为nil，则用stream.Send发送命令，发送后设置状态码和关闭cmd.Ready

### **3、2、3 handleRawData函数**

handleRawData函数代码如下：

```
func handleRawData(req *pb.RawData, conn *pool.Connection) (agentID string) {
   var inIpv4 = strings.Join(req.IntranetIPv4, ",")
   var exIpv4 = strings.Join(req.ExtranetIPv4, ",")
   var inIpv6 = strings.Join(req.IntranetIPv6, ",")
   var exIpv6 = strings.Join(req.ExtranetIPv6, ",")
   var SvrTime = time.Now().Unix()

   for k, v := range req.GetData() {
      ylog.Debugf("handleRawData", "Timestamp:%d, DataType:%d, AgentID:%s, Hostname:%s", k, v.GetTimestamp(), v.GetDataType(), req.AgentID, req.Hostname)

      //Loading from the object pool, which can improve performance
      mqMsg := kafka.MQMsgPool.Get().(*pb.MQData)
      mqMsg.DataType = req.GetData()[k].DataType //消息的DataType字段赋值
      mqMsg.AgentTime = req.GetData()[k].Timestamp
      mqMsg.Body = req.GetData()[k].Body
      mqMsg.AgentID = req.AgentID
      mqMsg.IntranetIPv4 = inIpv4
      mqMsg.ExtranetIPv4 = exIpv4
      mqMsg.IntranetIPv6 = inIpv6
      mqMsg.ExtranetIPv6 = exIpv6
      mqMsg.Hostname = req.Hostname
      mqMsg.Version = req.Version
      mqMsg.Product = req.Product
      mqMsg.SvrTime = SvrTime

      //判断消息的DataType类型
      switch mqMsg.DataType {
      case 1000: //agent心跳包
         //parse the agent heartbeat data
         parseAgentHeartBeat(req.GetData()[k], req, conn)
      case 1001: //agent plugin插件心跳包
         //parse the agent plugins heartbeat data
         parsePluginHeartBeat(req.GetData()[k], req, conn)
      case 2001, 2003, 6003:
         //任务异步推送到远端进行和解
         //Task asynchronously pushed to the remote end for reconciliation.
         item, err := parseRecord(req.GetData()[k])
         if err != nil {
            return
         }

         err = GlobalGRPCPool.PushTask2Manager(item)
         if err != nil {
            ylog.Errorf("handleRawData", "PushTask2Manager error %s", err.Error())
         }
      }

      common.KafkaProducer.SendPBWithKey(req.AgentID, mqMsg)
   }
   return req.AgentID
}
```

handleRawData函数中涉及到几个函数，正好有时间，我们一起喽喽，您瞧好吧！

### **1） RawData.GetData()函数**

RawData结构体的GetData函数，返回*Record类型的切片。

```
func (m *RawData) GetData() []*Record {
   if m != nil {
      return m.Data
   }
   return nil
}
```

### **2） PushTask2Manager()函数**

逻辑：将task任务投递到g.taskChan中

```
func (g *GRPCPool) PushTask2Manager(task map[string]string) error {
   select {
   case g.taskChan <- task:
   default:
      return errors.New("taskChan is full, please try later")
   }
   return nil
}
```

那么g.taskChan管道中的任务是何时发送呢？

```
func (g *GRPCPool) checkTask() {
   timer := time.NewTicker(g.conf.TaskTimeWeight)
   for {
      select {
      case task := <-g.taskChan:
         g.taskList = append(g.taskList, task)
      case <-timer.C:
         if len(g.taskList) < 1 {
            continue
         }

         client.PostTask(g.taskList)
         g.taskList = g.taskList[:0]
         continue
      }

      if len(g.taskList) >= g.conf.TaskCountWeight {
         client.PostTask(g.taskList)
         g.taskList = g.taskList[:0]
      }
   }
}
```

创建定时器，每隔一定时间检测是否有任务，有则调用client.PostTask(g.taskList)发送一批task任务，然后清零任务列表。

由于时间和经历有限，难免有写的不好的地方，还望大家多多提意见。