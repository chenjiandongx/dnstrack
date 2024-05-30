# dnstrack

> 使用 golang 编写的基于 bpf 的 dns 查询追踪工具。 

dnstrack 使用 libpcap 监听机器网卡并过滤 dns 查询，同时提供了多种输出方式（verbose/question/json/yaml）。此工具主要用于发现是否有进程持续高频地访问 dns 服务。

## Installation

### 1) libpcap

***dnstrack*** 依赖于 `libpacp` 库捕获内核网络数据包，所以需要先安装此工具。

**Debian/Ubuntu**
```shell
$ sudo apt-get install libpcap-dev
```

**CentOS/Fedora**
```shell
$ sudo yum install libpcap libpcap-devel
```

**Windows**

Windows 用户则需要安装 [npcap](https://nmap.org/npcap/) 工具。

### 2) dnstrack

```bash
$ go install github.com/chenjiandongx/dnstrack@latest
```

## Usages

> dnstrack 命令需要在特权模式或者 root 用户下运行。

```shell
> dnstrack -h
# A dns-query tracking tool written in go

Usage:
  dnstrack [flags]

Examples:
  # list all the net-devices
  $ dnstrack -l

  # filters google dns server packet attached in lo0 dev and output with json format
  $ dnstrack -s 8.8.8.8 -o j -d '^lo0$'

Flags:
  -a, --all-devices            listen all devices if present (default true)
  -d, --devices string         devices regex pattern filter
  -h, --help                   help for dnstrack
  -l, --list                   list all devices name
  -o, --output-format string   output format [json(j)|yaml(y)|question(q)|verbose(v)] (default "verbose")
  -s, --server string          dns server filter
  -t, --type string            dns query type filter [A/AAAA/CNAME/...]
  -v, --version                version for dnstrack
```

verbose 输出格式。
```shell
> dnstrack -d '^lo$|^ens'
--------------------

; <ens160>@172.16.22.2:53, ID: 49390, OpCpde: Query, Status: Success
;; When: 2024-05-29T00:42:52+08:00
;; Query Time: 57.667µs
;; Msg Size: 292B

;; Question Section:
google.com.	 A

;; Answer Section:
google.com.	 5	 A	 INET	 93.46.8.90

;; Authority Section:
google.com.	 NS	 INET	 ns2.google.com.
google.com.	 NS	 INET	 ns1.google.com.
google.com.	 NS	 INET	 ns4.google.com.
google.com.	 NS	 INET	 ns3.google.com.

;; Additional Section:
ns2.google.com.	 AAAA	 INET	 2001:4860:4802:34::a
ns4.google.com.	 AAAA	 INET	 2001:4860:4802:38::a
ns3.google.com.	 AAAA	 INET	 2001:4860:4802:36::a
ns1.google.com.	 AAAA	 INET	 2001:4860:4802:32::a
ns2.google.com.	 A	 INET	 216.239.34.10
ns4.google.com.	 A	 INET	 216.239.38.10
ns3.google.com.	 A	 INET	 216.239.36.10
ns1.google.com.	 A	 INET	 216.239.32.10
```

question 输出格式。
```shell
> dnstrack -d '^lo$|^ens' -oq
2024-05-30T18:10:31+08:00	ens160	    172.16.22.2:53	   NS	122.278µs	aws.com.
2024-05-30T18:10:31+08:00	    lo	     127.0.0.53:53	   NS	 72.129ms	aws.com.
2024-05-30T18:10:31+08:00	    lo	     127.0.0.53:53	   NS	 72.212ms	aws.com.
2024-05-30T18:10:38+08:00	ens160	    172.16.22.2:53	 AAAA	   4.176s	aws.com.
2024-05-30T18:10:38+08:00	    lo	     127.0.0.53:53	 AAAA	   4.177s	aws.com.
2024-05-30T18:10:38+08:00	    lo	     127.0.0.53:53	 AAAA	   4.177s	aws.com.
2024-05-30T18:10:53+08:00	ens160	    172.16.22.2:53	    A	 74.872µs	google.com.
2024-05-30T18:10:53+08:00	    lo	     127.0.0.53:53	    A	 10.708µs	google.com.
2024-05-30T18:10:53+08:00	    lo	     127.0.0.53:53	    A	 66.998µs	google.com.
2024-05-30T18:10:53+08:00	    lo	     127.0.0.53:53	    A	  5.792µs	twitter.com.
2024-05-30T18:10:53+08:00	    lo	     127.0.0.53:53	    A	 17.708µs	twitter.com.
2024-05-30T18:10:53+08:00	ens160	    172.16.22.2:53	    A	 43.081µs	twitter.com.
2024-05-30T18:10:53+08:00	ens160	    172.16.22.2:53	    A	 17.583µs	facebook.com.
2024-05-30T18:10:53+08:00	    lo	     127.0.0.53:53	    A	 10.208µs	facebook.com.
2024-05-30T18:10:53+08:00	    lo	     127.0.0.53:53	    A	 41.457µs	facebook.com.
2024-05-30T18:11:07+08:00	    lo	     127.0.0.53:53	CNAME	 23.750µs	aws.com.
2024-05-30T18:11:07+08:00	    lo	     127.0.0.53:53	CNAME	107.458µs	aws.com.
2024-05-30T18:11:07+08:00	ens160	    172.16.22.2:53	CNAME	 72.446ms	aws.com.
```

## License

MIT [©chenjiandongx](https://github.com/chenjiandongx)
