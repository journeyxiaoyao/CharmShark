# CharmShark

**被动式工控网络安全分析平台。** 导入抓包文件（PCAP/PCAPNG），自动还原资产与通信拓扑、识别工控协议、检出风险行为，并给出每条告警可核验的证据链与一份可交付的中文评估报告。

**全程不向目标网络发送任何数据包** —— 不扫描、不探测、不影响生产。

> **本项目基于开源项目 [MarlinSpike](https://github.com/eris-ot/marlinspike) v3.7 修改而来。**

---

## 界面

### 项目工作台

（截图已移除，避免泄露现场数据）


### 项目详情


`概览 / 发现 / 资产 / 通信 / 流量异常 / 威胁线索 / 评估历史 / 抓包`

### 发现详情（证据链）


按"为什么判定 → 观察到的通信 → 统计特征 → 这条证据不能证明什么"展开，附原始帧号、关联 Flow 与可复制的 Wireshark 过滤器。

### 评估范围与数据质量


### 评估报告（PDF）


---

## 核心能力

| 能力 | 说明 |
|---|---|
| 资产发现 | IP/MAC/厂商/角色，MAC 与 IP 自动关联 |
| 拓扑重建 | 按 Purdue 层级分层，区分读/写边 |
| 协议解析 | Modbus、S7、DNP3、IEC 104、IEC 61850、EtherNet/IP、PROFINET、BACnet、OPC UA、FINS 等 |
| 风险检测 | 暴露面 / 协议安全 / 行为异常 / 二层异常 / 横向移动 |
| 证据链 | 帧号、Flow、统计特征、可见性、局限说明 |
| 评估报告 | 项目级聚合，浏览器打印导出 PDF |
| 标准导出 | STIX 2.1、OCSF、Sigma、ATT&CK Navigator |
| 多语言 | 中文 / English |

### 能力边界

| 能做 | 不能做 |
|---|---|
| 还原已通信资产的清单与关系 | 发现从未通信过的设备 |
| 识别协议、角色、Purdue 层级 | 读取设备配置、补丁级别 |
| 检出行为异常（信标、扫描、欺骗） | 发现 CVE 漏洞、弱口令 |
| 给出风险等级与整改建议 | 验证漏洞可利用性 |

---

## 技术架构

```
Packet → Flow → ConnectionEvent → RiskFinding
```

| 层 | 职责 |
|---|---|
| Packet | 原始报文、帧号、时间戳、协议字段 |
| Flow | 五元组双向流、TCP 状态、可见性 |
| ConnectionEvent | 一次连接尝试（多包归并），信标周期的计算单位 |
| RiskFinding | 严重度、置信度、证据完整性、证据块、局限 |

六阶段流水线：`ingest → dissect → topology → risk → enrich → emit`。每个阶段产物独立落盘，改检测规则无需重新解析抓包。

检测要点：

- **信标**：两阶段判定（候选间隔 ≥ 5s、事件数 ≥ 10 → RVC + 自相关 + 漂移 + 上下文融合）；
- **端口扫描**：看"每端口包数 + SYN 比例 + 握手完成率"，不看端口数量；
- **服务识别**：端口探测 → TCP 可达 → 应用层协议确认，三层证据；
- **可见性**：单向抓包标 `PARTIAL_VISIBILITY`，不武断判定连接失败。

---

## 快速开始

```bash
git clone https://github.com/journeyxiaoyao/CharmShark.git
cd CharmShark
python -m venv venv
venv\Scripts\pip install -e .   # Windows
venv/bin/pip install -e .       # Linux
```

复制 `config.env.example` 为 `config.env` 并修改密钥，然后：

```bash
python -m marlinspike.app
```

打开 http://127.0.0.1:5002 ，默认账号 `admin`。

使用流程：新建项目 → 上传 PCAP → 开始分析 → 查看结论与证据 → 生成 PDF 报告。

---

## 质量保证

| 测试集 | 内容 | 结果 |
|---|---|---|
| 单元测试 | TCP 状态机、事件归并、去重 | 10/10 |
| 合成回归 | 10 个场景（正常 Modbus/DNS/SSDP/mDNS/FTP，攻击信标/抖动信标/扫描/ARP） | 10/10 |
| 真实抓包 | 132MB / 106 万包 | 16 条发现，证据完整率 100% |

---

## 已知限制

1. 被动分析只能看到"发生通信"的资产；
2. 不提供 CVE、补丁级别、弱口令、配置合规检查；
3. Purdue 层级与设备角色为启发式推断；
4. 采集点位置决定可见范围；
5. 默认阈值为通用值，现场应按规模调整。

---

## 许可证

沿用上游许可证，见 [LICENSE](LICENSE)。

## 致谢

- [MarlinSpike](https://github.com/eris-ot/marlinspike) —— 解析引擎与检测算法
- MITRE ATT&CK for ICS
- ISA-95 / IEC 62443
