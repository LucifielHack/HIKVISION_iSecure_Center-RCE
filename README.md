## HIKVISION iSecure Center RCE 海康威视综合安防管理平台任意文件上传 POC&EXP

HIKVISION iSecure Center综合安防管理平台是一套“集成化”、“智能化”的平台，通过接入视频监控、一卡通、停车场、报警检测等系统的设备，获取边缘节点数据，实现安防信息化集成与联动，以电子地图为载体，融合各系统能力实现丰富的智能应用。HIKVISION iSecure Center平台基于“统一软件技术架构”先进理念设计，采用业务组件化技术，满足平台在业务上的弹性扩展。该平台适用于全行业通用综合安防业务，对各系统资源进行了整合和集中管理，实现统一部署、统一配置、统一管理和统一调度。

**poc采用无害化扫描检测，无文件残留，可批量检测；exp只做单个url攻击，一键shell。**

### 影响范围：

HIKVISION iSecure Center综合安防管理平台 

### poc

```
usage: iSecure-Center-RCE_POC.py [-h] [-u URL] [-f FILE] [-t THREAD] [-T TIMEOUT] [-o OUTPUT] [-p PROXY]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target url(e.g. http://127.0.0.1)
  -f FILE, --file FILE  Target file(e.g. url.txt)
  -t THREAD, --thread THREAD
                        Number of thread (default 5)
  -T TIMEOUT, --timeout TIMEOUT
                        Request timeout (default 3)
  -o OUTPUT, --output OUTPUT
                        Vuln url output file (e.g. result.txt)
  -p PROXY, --proxy PROXY
                        Request Proxy (e.g http://127.0.0.1:8080)
```

```
python '.\iSecure-Center-RCE_POC.py' -f .\url.txt -t 10
```

![image-20230706013446912](D:\tools\GitHub-exp\iSecure-Center RCE 海康综合安防\github\img\image-20230706013446912.png)



### exp

```
usage: iSecure-Center-RCE_EXP.py [-h] [-u URL] [-T TIMEOUT] [-p PROXY]

optional arguments:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target url(e.g. url.txt)
  -T TIMEOUT, --timeout TIMEOUT
                        Request timeout (default 3)
  -p PROXY, --proxy PROXY
                        Request Proxy (e.g http://127.0.0.1:8080)
```

```
python '.\iSecure-Center-RCE_EXP.py' -u http://127.0.0.1
```

![image-20230706013023264](D:\tools\GitHub-exp\iSecure-Center RCE 海康综合安防\github\img\image-20230706013023264.png)

一键上传后通过哥斯拉连接

![image-20230706013208837](D:\tools\GitHub-exp\iSecure-Center RCE 海康综合安防\github\img\image-20230706013208837.png)



## 免责声明

由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，**均由使用者本人负责，作者不为此承担任何责任**。