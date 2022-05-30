Elkeid插件机制剖析

# 零、提出问题和疑惑

按照惯例，先提出问题，带着问题我们再来逐步剖析源代码

1、插件下发后，agent是如何加载插件的？

2、插件和agent之间通信，包括发送任务和数据上报

3、插件的调用栈是什么样的？



# 一、函数调用栈

插件的调用流程如下：

main()  ->  plugin.Startup()   ->  plugin.Load()加载插件



```
func Startup(ctx context.Context, wg *sync.WaitGroup) {
	defer wg.Done()
	defer zap.S().Info("plugin daemon will exit")
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	zap.S().Info("plugin daemon startup")
	for {
		select {
		case cfgs := <-syncCh:
			zap.S().Infof("syncing plugins...")
			// 加载插件
			for _, cfg := range cfgs {
				if cfg.Name != agent.Product {
					plg, err := Load(ctx, *cfg)
					// 同一个插件正在运行，无需操作
					if err == ErrDuplicatePlugin {
						continue
					}
				}
			}
			// 获取当前运行的所有插件
			for _, plg := range GetAll() {
				//对于配置中并没有的插件，进行关闭和移除映射信息
				if _, ok := cfgs[plg.Config.Name]; !ok {
					plg.Infof("when syncing, plugin will be shutdown")
					plg.Shutdown() //插件关闭
					plg.Infof("shutdown successfully")
					m.Delete(plg.Config.Name)
					if err := os.RemoveAll(plg.GetWorkingDirectory()); err != nil {
						plg.Error("delete dir of plugin failed: ", err)
					}
				}
			}
			zap.S().Infof("sync done")
		}
	}
}
```

syncCh的定义在哪里？谁向他投递数据？

定义syncCh的代码：

```
var (
	m      = &sync.Map{}
	syncCh = make(chan map[string]*proto.Config, 1)
)
```

向syncCh投递数据的代码

```
func Sync(cfgs map[string]*proto.Config) (err error) {
	select {
	case syncCh <- cfgs:
	default:
		err = errors.New("plugins are syncing or context has been cancled")
	}
	return
}
```

在之前的《Elkeid Server和agent间通信机制》文章的分析中，我们看到handleReceive中调用了Sync函数。



主要是Load函数，在plugin_linux.go文件中，拆分为以下三个步骤：

```go
//插件加载
func Load(ctx context.Context, config proto.Config) (plg *Plugin, err error) {
	//通过插件名称查找插件对象，m是标准库中的协程安全的map
	loadedPlg, ok := m.Load(config.Name) 
	
	...... 
	
	workingDirectory := path.Join(agent.WorkingDirectory, "plugin", config.Name)
	
	//构造插件的执行路径
	execPath := path.Join(workingDirectory, config.Name) 
	
	cmd := exec.Command(execPath)
	var rx_r, rx_w, tx_r, tx_w *os.File
	
	//插件->agent方向的管道，插件向rx_w写入数据，agent从rx_r中读取数据
	rx_r, rx_w, err = os.Pipe() 
	if err != nil {
		return
	}
	
	//agent->插件方向的管道，agent向tx_w写入数据，插件从tx_r中读取数据
	tx_r, tx_w, err = os.Pipe()	
	if err != nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	//将插件进程的stdin设置为tx_r,stdout设置为rx_w
	cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w) 
	cmd.Dir = workingDirectory
	var errFile *os.File
	errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600)
	if err != nil {
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile //设置stderr为文件
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	logger.Info("plugin's process will start")
	err = cmd.Start()
	tx_r.Close()	//agent进程使用tx_w和rx_r，用不到tx_r和rx_w，所以将这两者关闭
	rx_w.Close()
	if err != nil {
		return
	}
	plg = &Plugin{
		Config:        config,
		mu:            &sync.Mutex{},
		cmd:           cmd,
		rx:            rx_r,
		updateTime:    time.Now(),
		reader:        bufio.NewReaderSize(rx_r, 1024*128),
		tx:            tx_w,
		done:          make(chan struct{}),
		taskCh:        make(chan proto.Task),
		wg:            &sync.WaitGroup{},
		SugaredLogger: logger,
	}
	plg.wg.Add(3)
	
	//等待插件进程退出的协程
    //退出时关闭rx_r和tx_w管道，同时将完成通知投递到plg.done channel中
	go func() {
		defer plg.wg.Done()
		defer plg.Info("gorountine of waiting plugin's process will exit")
		err = cmd.Wait() //等待插件进程退出
		rx_r.Close()	//退出时关闭rx_r和tx_w管道
		tx_w.Close()
		if err != nil {
			plg.Errorf("plugin has exited with error:%v,code:%d", err, cmd.ProcessState.ExitCode())
		} else {
			plg.Infof("plugin has exited with code %d", cmd.ProcessState.ExitCode())
		}
		close(plg.done) //通知完成
	}()
    
    //接收插件数据的go协程
	go func() { 
		defer plg.wg.Done()
		defer plg.Info("gorountine of receiving plugin's data will exit")
		for {
			rec, err := plg.ReceiveData() //细化下说说
			if err != nil {
				if errors.Is(err, bufio.ErrBufferFull) {
					plg.Warn("when receiving data, buffer is full, skip this record")
					continue
				} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
					plg.Error("when receiving data, an error occurred: ", err)
				} else {
					break
				}
			}
			core.Transmission(rec, true) //传输 细化下说说
		}
	}()
	go func() { //向插件发送任务的go协程
		defer plg.wg.Done()
		defer plg.Info("gorountine of sending task to plugin will exit")
		for {
			select {
			case <-plg.done:
				return
			case task := <-plg.taskCh: //任务通道中有任务存在，取出任务
				s := task.Size()
				var dst = make([]byte, 4+s)
				_, err = task.MarshalToSizedBuffer(dst[4:])//将task任务序列化到dst缓冲区(从下标4开始)
				if err != nil {
					plg.Errorf("when marshaling a task, an error occurred: %v, ignored this task: %+v", err, task)
					continue
				}
				binary.LittleEndian.PutUint32(dst[:4], uint32(s))//task任务大小写入到dst的前4个字节中
				var n int
				n, err = plg.tx.Write(dst) //任务写入管道
				if err != nil {
					if !errors.Is(err, os.ErrClosed) {
						plg.Error("when sending task, an error occurred: ", err)
					}
					return
				}
				atomic.AddUint64(&plg.rxCnt, 1)
				atomic.AddUint64(&plg.rxBytes, uint64(n))
			}
		}
	}()
	m.Store(config.Name, plg) //将插件信息保存到sync.Map中
	return
}
```

如果看上面注释版的比较困难，可以看下面拆解版的，嘿嘿（读者：你丫不早说...）





# 二、插件加载与创建

```
func Load(ctx context.Context, config proto.Config) (plg *Plugin, err error) {	
	//通过插件名称查找插件对象，并校验参数，校验失败则返回
	loadedPlg, ok := m.Load(config.Name) 
	
	...... 
	
	workingDirectory := path.Join(agent.WorkingDirectory, "plugin", config.Name)
	
	//构造插件的执行路径
	execPath := path.Join(workingDirectory, config.Name) 
	
	cmd := exec.Command(execPath)
	var rx_r, rx_w, tx_r, tx_w *os.File
	
	//创建插件进程->agent进程方向的管道，插件向rx_w写入数据，agent从rx_r中读取数据
	rx_r, rx_w, err = os.Pipe() 
	if err != nil {
		return
	}
	
	//创建agent进程->插件进程方向的管道，agent向tx_w写入数据，插件从tx_r中读取数据
	tx_r, tx_w, err = os.Pipe()	
	if err != nil {
		return
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	
	//将插件进程的标准输入stdin设置为tx_r
	//将插件进程的标准输出stdout设置为rx_w
	cmd.ExtraFiles = append(cmd.ExtraFiles, tx_r, rx_w) 
	cmd.Dir = workingDirectory
	var errFile *os.File
	errFile, err = os.OpenFile(execPath+".stderr", os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0o0600)
	if err != nil {
		return
	}
	defer errFile.Close()
	cmd.Stderr = errFile //设置stderr为文件
	if config.Detail != "" {
		cmd.Env = append(cmd.Env, "DETAIL="+config.Detail)
	}
	logger.Info("plugin's process will start")
	err = cmd.Start()
	tx_r.Close()	//agent进程使用tx_w和rx_r，用不到tx_r和rx_w，所以将这两者关闭
	rx_w.Close()
	......
}
```



agent.WorkingDirectory的定义

```
var (
	WorkingDirectory, _        = os.Getwd()
)
```

大致流程如下：

1、通过插件名称查找插件对象，并校验参数，校验失败则返回

2、创建插件进程->agent进程方向的管道，然后插件进程向rx_w写入数据，agent进程从rx_r中读取数据（下图中绿色的发送方向）

3、创建agent进程->插件进程方向的管道，然后agent进程向tx_w写入数据，插件进程从tx_r中读取数据（下图中蓝色的接收方向）

4、将插件进程的标准输入stdin设置为tx_r，标准输出stdout设置为rx_w，设置标准错误stderr为指定路径下的文件

5、调用cmd.Start()函数，启动插件进程

6、父进程（即agent进程），用不到tx_r和rx_w，所以将这两者关闭

![image-20220428145956562](https://gitee.com/codergeek/img/raw/master/img/202204281501121.png)



# 三、插件结构体初始化

```go
plg = &Plugin{
		Config:        config,
		mu:            &sync.Mutex{},
		cmd:           cmd,
		rx:            rx_r,
		updateTime:    time.Now(),
		reader:        bufio.NewReaderSize(rx_r, 1024*128),
		tx:            tx_w,
		done:          make(chan struct{}),
		taskCh:        make(chan proto.Task),
		wg:            &sync.WaitGroup{},
		SugaredLogger: logger,
	}
```

Plugin结构体中有几个成员很重要：

done：用于完成通知

taskCh：传递任务的通道

rx：插件进程的读端

tx：插件进程的写端

mu：互斥锁，避免多协程访问的场景



# 四、插件进程和主进程通信

## 4、1 等待插件退出

```
//等待插件进程退出，退出时关闭rx_r和tx_w管道，同时将完成通知投递到plg.done channel中
go func() {
	defer plg.wg.Done()
	defer plg.Info("gorountine of waiting plugin's process will exit")
	err = cmd.Wait()
	rx_r.Close()
	tx_w.Close()
	if err != nil {
		plg.Errorf("plugin has exited with error:%v,code:%d", err, cmd.ProcessState.ExitCode())
	} else {
		plg.Infof("plugin has exited with code %d", cmd.ProcessState.ExitCode())
	}
	close(plg.done) //发送插件完成通知
}()
```

- 协程调用cmd.Wait()函数，以阻塞形式等待插件进程退出；

- 关闭rx_r读通道，tx_w写通道；

- 发送插件完成通知。




## 4、2 插件进程 -> 主进程 (数据上报)

```
go func() { //接收插件数据的go协程，这里展开写下
	defer plg.wg.Done()
	defer plg.Info("gorountine of receiving plugin's data will exit")
	for {
		rec, err := plg.ReceiveData() //展开说说
		if err != nil {
			if errors.Is(err, bufio.ErrBufferFull) {
				plg.Warn("when receiving data, buffer is full, skip this record")
				continue
			} else if !(errors.Is(err, io.EOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, os.ErrClosed)) {
				plg.Error("when receiving data, an error occurred: ", err)
			} else {
				break
			}
		}
		core.Transmission(rec, true) //展开说说
	}
}()
```

主要函数有plg.ReceiveData()和core.Transmission(rec, true)

plg.ReceiveData()：解析出Record的各个字段

```
type EncodedRecord struct {
	DataType  int32  `protobuf:"varint,1,opt,name=data_type,json=dataType,proto3" json:"data_type,omitempty"`
	Timestamp int64  `protobuf:"varint,2,opt,name=timestamp,proto3" json:"timestamp,omitempty"`
	Data      []byte `protobuf:"bytes,3,opt,name=data,proto3" json:"data,omitempty"`
}
```



**核心函数：core.Transmission函数**

```
var (
	Mu                = &sync.Mutex{}
	Buf               = [8192]interface{}{} //interface类型的数组，大小为8192
	Offset            = 0					//上述Buf中数据的偏移量
	ErrBufferOverflow = errors.New("buffer overflow")
	hook              func(interface{}) interface{}
	recordPool        = sync.Pool{			//对象池，用于proto.EncodedRecord类型对象的申请
		New: func() interface{} {
			return &proto.EncodedRecord{
				Data: make([]byte, 0, 1024*2),
			}
		},
	}
)

func Transmission(rec interface{}, tolerate bool) (err error) {
	if hook != nil {
		rec = hook(rec)
	}
	
	//加Mutex锁，线程安全的写Buf
	Mu.Lock()
	defer Mu.Unlock()
	if Offset < len(Buf) {
		Buf[Offset] = rec
		Offset++ //偏移量递增
		return
	}
	if tolerate {
		err = ErrBufferOverflow
	} else {
		Buf[0] = rec
	}
	return
}
```

加Mutex锁，线程安全的写Buf，增加偏移量Offset，当Offset大于等于len(Buf)时，会有两种策略可选：

1、tolerate等于true，则err = ErrBufferOverflow

2、tolerate等于false，则从索引0开始覆盖掉之前存储的数据



## 4、3 主进程 -> 插件进程 (发送任务)

```
go func() { //向插件发送任务的go协程
	defer plg.wg.Done()
	defer plg.Info("gorountine of sending task to plugin will exit")
	for {
		select {
		case <-plg.done:
			return
		case task := <-plg.taskCh: //任务通道中有任务存在，取出任务
			s := task.Size()
			var dst = make([]byte, 4+s)
			_, err = task.MarshalToSizedBuffer(dst[4:])//将task任务序列化到dst缓冲区(从下标4开始)
			if err != nil {
				plg.Errorf("when marshaling a task, an error occurred: %v, ignored this task: %+v", err, task)
				continue
			}
			binary.LittleEndian.PutUint32(dst[:4], uint32(s))//task任务大小写入到dst的前4个字节中
			var n int
			n, err = plg.tx.Write(dst) //任务写入管道
			if err != nil {
				if !errors.Is(err, os.ErrClosed) {
					plg.Error("when sending task, an error occurred: ", err)
				}
				return
			}
			atomic.AddUint64(&plg.rxCnt, 1)
			atomic.AddUint64(&plg.rxBytes, uint64(n))
		}
	}
}()
```



# 四、分析插件代码

插件支持两种语言：rust和go，我这里只分析go语言的。

插件代码分为两部分，lib库和插件功能具体实现，由于具体实现的代码每个插件不同。

plugins/collector/shared.go文件

```
var (
	Scheduler   = cron.New(cron.WithChain(cron.SkipIfStillRunning(zapr.NewLogger(zap.L()))))
	SchedulerMu = &sync.Mutex{}
	Client      = plugins.New() //创建插件对象
	userCache   = cache.New(time.Hour*time.Duration(2), time.Minute*time.Duration(30))
)
```



定位到plugins/lib/go/client_linux.go文件。

```
func New() (c *Client) {
	c = &Client{
		rx: os.Stdin,
		tx: os.Stdout,
		// MAX_SIZE = 1 MB
		reader: bufio.NewReaderSize(os.NewFile(3, "pipe"), 1024*1024),
		writer: bufio.NewWriterSize(os.NewFile(4, "pipe"), 512*1024),
		rmu:    &sync.Mutex{},
		wmu:    &sync.Mutex{},
	}
	go func() {
		ticker := time.NewTicker(time.Millisecond * 200)
		defer ticker.Stop()
		for {
			<-ticker.C
			if err := c.Flush(); err != nil {
				break
			}
		}
	}()
	return
}
```

创建ticker定时器，每0.2秒刷新一次缓存（调用 c.Flush() 函数）



插件刷新的数据是哪里产生的呢？

```
func (c *Client) SendRecord(rec *Record) (err error) {
	c.wmu.Lock()
	defer c.wmu.Unlock()
	size := rec.Size()
	err = binary.Write(c.writer, binary.LittleEndian, uint32(size))
	if err != nil {
		return
	}
	var buf []byte
	buf, err = rec.Marshal()
	if err != nil {
		return
	}
	_, err = c.writer.Write(buf)
	return
}
```

插件进程扫描到需要的数据后，通过SendRecord将数据写入到Client.writer变量中。
