The readme doc is only available in Chinese cuz only Chinese users need this script （i think?

这是一个面向中国大陆用户测试CF SNI代理的python脚本，适配Windows&ubuntu。
该项目使用了生成式AI。

## 前言：

众所周知，CF对大陆访问不友好，但某些神奇的服务又将带有优质线路的cf反代暴露在公网，可能又由于某些原因没有配置好，于是被扫了，我们便可以利用这些ip提速访问cf网站时的速度。
该项目会对输入的反代ip进行多方位测试以确保实际场景可用性。

本项目没有针对80、2xxx端口的反代做支持。

本人因为自身原因没法管这个项目，故不接受任何PR。你可以fork这个项目，改完把仓库地址发在issue中。

**⚠本条道路属于见光死类型，如果你想让这条路活得得久一点，就不要滥用本项目和优质反代ip！**

请你把反代ip想象成某种程度上的公共资源：你在用，别人也在用。
人多不光导致拥挤；用得多了服务提供商也可能会注意到异常。
所以不要长时间、大流量滥用单个反代ip，比如拿去开机场。

## 环境要求 
OS: Windows or Ubuntu（未测试）
    With Python & tracepath/tracert/traceroute & curl & ping

测试环境：Windows 11 with Python & tracert & curl & ping，只保证Windows环境下的可用性。

## 工作流程
导入ip csv -> 提取ip并去重 -> 检查可用性 -> 测试延迟、速度 -> 筛选优质ip -> 使用ipinfo查询ip本身对应国家 -> traceroute分析线路 -> 生成 bestips-{date}.csv 以及 ip.txt

## 参数（覆盖config.ini）

**优先级：命令行给予 > config.ini > 脚本内置默认配置**

- -threads “测试延迟、速度”的线程数，默认2，填max时就取config.ini中的max值。
- -i 输入文件，没填默认./ip.csv
- -o csv输出，没填从config.ini中获取。#这里不支持{date}{num}等映射。
    #该工具本为自动化场景而设计，ip.txt输出是不支持关闭的。
- -d 测速文件大小，计数单位：**MB**。
- -skiptr 跳过traceroute测试（针对导入ip为中国内地ip的情况自行开启）
- -config 后面跟配置文件路径，例如config.ini（代表./config.ini）
- -log 输出日志文件
- -debug 调试模式

## 功能实现解析

### 检查可用性
curl -sS -k --connect-timeout {timeout} --max-time {timeout} --resolve {cf-host}:443:{your-ip} https://{cf-host}/cdn-cgi/trace
有正确输出即为可用。当然，存在特殊情况。

### 测试延迟、速度
ping ... {your-ip} 解析返回延迟
curl -w %{speed_download} ... {large-file-url}


### 去程线路分析
**如您需要使用该功能，请在config.ini中填入你的ipinfo token，默认使用lite版进行ip信息的拉取。不填token也有几率匹配到内置规则。**

traceroute/tracert/tracepath {your-ip}

带去程绕路标注(过HK线路也算绕)，但是实测有些路由器的ip没有被拉到对应的位置，这部分用了置信度辅助判断。
该功能不是特别准，仅供参考。

主要分析：163、CN2、Anet、4837、CMI、CMIN2

## csv输入示例
| ip                  | port | protocol | title         | domain | country | city    | link                                               | org                       |
| ------------------- | ---: | -------- | ------------- | ------ | ------- | ------- | -------------------------------------------------- | ------------------------- |
| **167.179.113.223** |  443 | https    | 403 Forbidden |        | JP      | Tokyo   | [https://167.179.113.223](https://167.179.113.223) | The Constant Company, LLC |
| **108.102.223.154** |  443 | https    | 403 Forbidden |        | US      | Seattle | [https://108.102.223.154](https://108.102.223.154) | Amazon.com, Inc.          |
（ip列必须存在，存在其他输入也无所谓。）

## ip.txt 输出结果示例
```text
1.2.3.4#JP (CN2) Tokyo 1 //电信示例1
5.6.7.8#JP (163绕🇭🇰、🇺🇸) Tokyo 2 //电信示例2
```

## csv输出示例
| route | ip          | cfcountry | tour  | country | city      | speed    | latency |
| ----- | ----------- | --------- | ----- | ------- | --------- | -------- | ------- |
| CN2   | 1.2.3.4     | JP        | None  | JP      | Tokyo     | 12.8MB/s | 50ms    |
| 163   | 5.6.7.8     | JP        | HK→JP | JP      | Tokyo     | 9.7MB/s  | 120ms   |
| CN2   | 12.3.4.5    | JP        | HK→JP | JP      | Tokyo     | 8.3MB/s  | 52ms    |
| CN2   | 12.34.56.78 | HK→US     |       | US      | Califonia | 20.0MB/s | 200ms   |
| 163   | 123.4.56.78 | NL→US     |       | US      | Califonia | 2.3MB/s  | 600ms   |

排列优先级：previousCountry对应的国家 -> 速度降序；把cfcountry一致的ip归类到了一块排序

表头字段注释：
- route：判断的线路类型
- ip：ip
- cfcountry：数据中心colo映射出的国家代码。
- tour：绕路情况，没绕填充None，绕路按照上述格式填充，例：HK→JP
country：这个ip本身对应的国家
city：这个ip对应的城市
speed：这个ip的速度
latency：这个ip的延迟
