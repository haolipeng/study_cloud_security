Elkeid源代码分析进度表

| 事项                           | 状态   | 原因                                                         |
| ------------------------------ | ------ | ------------------------------------------------------------ |
| Elkied单机部署文档             | 已完成 |                                                              |
| Elkeid Server和agent间通信机制 | 已完成 |                                                              |
| Elkeid 插件机制                | 已完成 |                                                              |
| Elkeid 驱动部分学习            | 未开始 | https://github.com/bytedance/Elkeid/blob/main/driver/LKM/src/trace_buffer.c |



有人只需要资产采集不需要HIDS。可以只用agent+资产插件。



规则引擎用这个https://github.com/njcx/RuleCat/

你把消息推到kafak存到es。再输出前端应该就好了。



规则引擎CEP还蛮多开源的，比如esper

其实可以输出到clickhouce，然后用metabase做聚合分析也不是不行。

ck做长期的数仓很合适，长时段的统计分析，甚至可以搞搞ueba啥的



或者直接上ELK

把数据过滤分析之后，直接丢ELK里。



使用flink对记录进行聚合，但是现在看来好像是不太对劲。

https://github.com/njcx/flink_sec

https://dun.163.com/news/p/22fd13c8ebd948029c68d37c3f6abdba

这块自己不是很清楚，所以需要好好看下。



目前没有提供生产环境容器化部署的脚本

现在对我来说，知识是分散到各个不同的技术平台的。