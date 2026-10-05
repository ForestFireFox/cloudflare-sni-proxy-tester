The readme doc is only available in Chinese cuz only Chinese users need this script （i think?

这是一个面向中国大陆用户，用于优选CF官方IP的python脚本，适配Windows&ubuntu。
该项目使用了生成式AI。

## 前言：

众所周知，CF对大陆访问不友好，但某些不在DNS解析列表内的的Anycast泛播ip又有比较强的连通性，我们便可以利用这些ip提速访问cf网站时的速度。
该项目会对输入的反代ip进行多方位测试以确保实际场景可用性，例如排除Error1034。

本人因为自身原因没法管这个项目，故不接受任何PR。你可以fork这个项目，改完把仓库地址发在issue中。

**⚠请不要滥用这些IP及本工具，否则将导致此方法被封堵！**

## 环境要求 
OS: Windows or Ubuntu（未测试）
    With Python & tracepath/tracert/traceroute & curl & ping

测试环境：Windows 11 with Python & tracert & curl & ping，只保证Windows环境下的可用性。

## 工作流程
获取IP段，提取最小测试单元 -> 检查可用性 -> 测试延迟、速度 -> 筛选优质ip -> 生成 bestips-{date}.csv 以及 ip.txt

## 参数（覆盖config.ini）

**优先级：命令行给予 > config.ini > 脚本内置默认配置**

- -threads “测试延迟、速度”的线程数，默认2，填max时就取config.ini中的max值。
- -o csv输出，没填从config.ini中获取。（这里不支持{date}{num}等映射，ip.txt输出不支持关闭。）
- -d 测速文件大小，计数单位：**MB**。
- -config 后面跟配置文件路径，例如config.ini（代表./config.ini）
- -log 输出日志文件
- -debug 调试模式（关掉会更快）

## 功能实现解析

### 检查可用性
curl -sS -k --connect-timeout {timeout} --max-time {timeout} --resolve {cf-host}:443:{your-ip} https://{cf-host}/cdn-cgi/trace
有正确输出即为可用。当然，存在特殊情况。

### 测试延迟、速度
ping ... {your-ip} 解析返回延迟
curl -w %{speed_download} ... {large-file-url}

## ip.txt 输出结果示例
```text
1.2.3.4#🇯🇵 Tokyo 1
5.6.7.8#🇯🇵 Tokyo 2
```

## csv输出示例

| colo | country | city | speed | latency | ip |
|---|---|---|---|---|---|
| SIN | SG | Singapore | 19.6MB/s | 88.4ms | 1.2.3.4 |
| SIN | SG | Singapore | 22.3MB/s | 69.7ms | 1.2.4.5 |
| SIN | SG | Singapore | 18.9MB/s | 81.2ms | 1.2.6.7 |
| NRT | JP | Tokyo | 21.4MB/s | 149.3ms | 5.6.7.8 |

表头字段注释：
- ip：ip
- country：访问/cdn-cgi/trace对应的国家/地区代码，该字段可以填充HK等。
- country：colo映射的国家
- city：colo映射的城市
- speed：这个ip的速度
- latency：这个ip的延迟
