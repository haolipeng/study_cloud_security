# 零、概念及优缺点

LSM是什么？

Linux Security Module



优点：

轻量级

通用性

可集成不同的访问控制机制



# 一、内核初始化

```
DEFINE_LSM(yama) = {
	.name = "yama",
	.init = yama_init,
};


static int __init yama_init(void)
{
	pr_info("Yama: becoming mindful.\n");
	security_add_hooks(yama_hooks, ARRAY_SIZE(yama_hooks), "yama");
	yama_init_sysctl();
	return 0;
}
```

核心函数是security_add_hooks函数，将yama_hooks添加到hook 列表中。

先来看一下yama_hooks

```
static struct security_hook_list yama_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(ptrace_access_check, yama_ptrace_access_check),
	LSM_HOOK_INIT(ptrace_traceme, yama_ptrace_traceme),
	LSM_HOOK_INIT(task_prctl, yama_task_prctl),
	LSM_HOOK_INIT(task_free, yama_task_free),
};
```

**LSM_HOOK_INIT的定义**

```
#define LSM_HOOK_INIT(HEAD, HOOK) \
	{ .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }
```

LSM_HOOK_INIT宏是给security_hook_list结构体中的head和hook成员变量赋值。

看到这如果有点懵逼的话，估计是对核心结构体的掌握不到位。



# 二、核心结构体

需正确理解以下三个核心数据结构，理解一遍，下次妥妥的。

- security_hook_list
- security_hook_heads
- security_list_options

## 2、1 security_hook_list结构体

每一个hook点可以用struct security_hook_list结构来描述：

```
struct security_hook_list {
	struct hlist_node		list;//用于侵入式链表
	struct hlist_head		*head;//指向该hook点的hlist头
	union security_list_options	hook;//hook点函数指针
	char				*lsm;
} __randomize_layout;
```

每个hook点包含一个函数指针声明和指向该hook点的hlist头。

security_list_options以union的方式存在，然后通过侵入式链表连接（成员指向成员），可以有效的节省空间。

关于侵入式链表的信息，可参考https://codeantenna.com/a/4ZsiGAhmQ1



## 2、2 security_list_options结构体

```
union security_list_options {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) RET (*NAME)(__VA_ARGS__);
	#include "lsm_hook_defs.h"
	#undef LSM_HOOK
};
```

定义LSM_HOOK宏，然后包含lsm_hook_defs.h文件。

```
LSM_HOOK(void, LSM_RET_VOID, task_free, struct task_struct *task)
```

以task_free为例，security_list_options结构体转换后变为：

```
union security_list_options {
	void (*task_free)(struct task_struct *task); //函数指针
	//其他hook点的函数指针
};
```

**总结：security_list_options结构体中存放着所有hook点的函数指针声明。**



## 2、3 security_hook_heads结构体

```
#define LSM_HOOK_INIT(HEAD, HOOK) \
	{ .head = &security_hook_heads.HEAD, .hook = { .HEAD = HOOK } }
```

**head变量赋值过程**

head变量赋值为&security_hook_heads.HEAD，HEAD是注册的函数名称（如task_free）。

```c
struct security_hook_heads security_hook_heads;
```

创建security_hook_heads类型变量security_hook_heads。



```c
struct security_hook_heads {
	#define LSM_HOOK(RET, DEFAULT, NAME, ...) struct hlist_head NAME;
	#include "lsm_hook_defs.h"
	#undef LSM_HOOK
} __randomize_layout;
```



lsm_hook_defs.h文件中是所有的hook点，以task_free为例。

```
LSM_HOOK(void, LSM_RET_VOID, task_free, struct task_struct *task)
```

进行变形：

```
//根据lsm_hook_defs.h文件中LSM_HOOK生成security_hook_heads的成员变量
struct security_hook_heads {
	struct hlist_head task_alloc;
	struct hlist_head task_free;
	......//其他函数的struct hlist_head
} __randomize_layout;
```



**hook变量赋值**

.hook = { .HEAD = HOOK }

还以task_free为例，转换后为.hook = { .task_free =  yama_task_free}

在2、2章节中，security_list_options结构体转换为如下形式：

存储所有hook点的函数指针

```
union security_list_options {
	void (*task_free)(struct task_struct *task); //函数指针
	//其他hook点的函数指针
};
```

.hook = { .task_free =  yama_task_free}这句话，就是给函数指针赋值。

实际在调用task_free函数时，实际调用的是yama_task_free函数。



# 三、编程步骤

程序员要做的事情，包括哪些？

1、确定需要hook的函数(如task_alloc)

2、对hook函数进行填充，添加自己的检查逻辑(改造demo_task_alloc)

3、使用LSM_HOOK_INIT添加到security_hook_list数据结构体中，每个hook点对应一个LSM_HOOK_INIT语句

4、内核模块初始化时，调用security_add_hooks，注册写好的security_hook_list结构体。



安装内核头文件

```shell
apt search linux-headers-$(uname -r)
```



参考链接

https://onestraw.github.io/linux/lsm-example/



https://zhangxin00.github.io/2021/11/15/Linux%E5%AE%89%E5%85%A8%E6%A8%A1%E5%9D%97-LSM-%E5%AD%A6%E4%B9%A0-%E7%AE%80%E5%8D%95%E7%9A%84LSM-demo/

https://github.com/zhangxin00/LSM-demo



Linux Security Modules框架源码分析

https://zhuanlan.zhihu.com/p/352103792