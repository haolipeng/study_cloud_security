有人只需要资产采集不需要HIDS。可以只用agent+资产插件。



规则引擎用这个https://github.com/njcx/RuleCat/

你把消息推到kafak存到es。再输出前端应该就好了。



规则引擎CEP还蛮多开源的，比如esper

其实可以输出到clickhouce，然后用metabase做聚合分析也不是不行。

ck做长期的数仓很合适，长时段的统计分析，甚至可以搞搞ueba啥的



或者直接上ELK

把数据过滤分析之后，直接丢ELK里。



目前没有提供生产环境容器化部署的脚本