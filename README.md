# ClashRulePro

自定义 Clash / Mihomo 规则补充集，侧重自定义直连、代理、拦截、Fake-IP、PCDN 与隐私/安全规则。

## 当前规则文件

| 文件 | 用途 | 建议策略 / 用法 |
|---|---|---|
| `DNS.yaml` | DoH/DoT/DoQ 域名与端口源规则；域名生成 MRS，端口保留 text | DNS-Domain / DNS-Port，REJECT |
| `Malware-Provider.yaml` | Phishing Army 动态钓鱼域名订阅配置片段 | domain provider，REJECT |
| `Privacy.yaml` | GeoSite telemetry / tracker 规则片段 | 直接加入 rules；或使用下文 MetaCubeX MRS |
| `Private.yaml` | 局域网域名、RFC1918、回环、链路本地、IPv6 ULA | classical provider，DIRECT |
| `pcdn.yaml` | PCDN / MCDN 域名、IP 与关键词源规则，构建时拆分 | pcdn-domain / pcdn-ip / pcdn-keyword，REJECT |
| `userDirect.yaml` | 自定义直连规则 | DIRECT |
| `userProxy.yaml` | 自定义代理规则 | PROXY |
| `userReject.yaml` | 自定义安全、隐私和广告拦截规则 | REJECT |

## MRS Provider 拆分与构建

广告规则从 Blackmatrix7 的同一份 `Advertising.list` 拆分为三个 Provider：`Advertising-Domain`（domain/MRS）、`Advertising-IP`（ipcidr/MRS）和 `Advertising-Keyword`（classical/text）。PCDN、DNS、Fake-IP 也按规则类型拆分；DNS 端口规则和域名关键词保留 text，不强行塞入 MRS。

`tvbox` 从 Sfssup 的 domain YAML 转为 domain MRS；`GameDownloadCN` 从 Blackmatrix7 的 domain 规则转为 domain MRS。生成文件位于 `rule_providers/`，由 `.github/workflows/build-mrs.yml` 调用官方 Mihomo `convert-ruleset` 命令构建，并自动提交生成结果。TVBox 源中不符合域名语法或无法由 domain MRS 表达的通配条目会在构建时跳过并写入 Actions 日志。

Mihomo 的 MRS 仅支持 `domain` 和 `ipcidr` 行为；`classical` 必须使用 text/yaml，不能定义为 MRS。相关格式以 [Mihomo Rule Providers 文档](https://wiki.metacubex.one/en/config/rule-providers/) 为准。

## 上游规则整合策略

本仓库不复制整份上游规则，而是优先引用上游维护的数据：

- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：`category-doh`、`category-telemetry`、`tracker` 等 MRS 分类。
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)：YouTube 与 Advertising 等应用规则。
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)：使用 `Only.Ads` 变体，将广告规则与 PCDN / telemetry / tracker 策略拆开，降低规则集重复。

## 关于 .com.cn 高风险拦截

`userReject.yaml` 保留 `DOMAIN-SUFFIX,com.cn` 作为**有意设置的整后缀封锁策略**。公开威胁研究已记录 Silver Fox 仿冒软件下载活动大量使用 .com.cn 等域名；该策略采取 fail-closed 取舍，会同时影响合法 .com.cn 网站。若要降低误杀，应改用经核验的具体 IOC 域名列表，而不是误认为后缀中的每个注册域都已被单独证实为恶意。

## DNS 防绕过说明

`DNS.yaml` 仅维护常见公共加密 DNS 域名规则，生成 `DNS-Domain.mrs`；当前不生成独立 `DNS-Port` provider，也不通过 `DNS.yaml` 覆盖 853（DoT）、784 / 8853（DoQ）端口。它与 MetaCubeX `category-doh.mrs` 联合使用，补足域名分类覆盖。

上传的 Mihomo 配置使用两个 DoT 上游：
- `security.cloudflare-dns.com`：通过代理连接。
- `159277.alidns.com`：通过 DIRECT 连接，用于代理节点解析和 direct DNS。

配置中必须在 DNS REJECT 规则前为这两个上游主机名设置明确例外，并将 TLS sniff 端口增加 853；否则 853 端口规则可能拦截 Mihomo 自己的上游 DNS。即使如此，任意自建 DoH（尤其是伪装在 TCP/443 上或直接使用 IP 的服务）仍无法仅靠静态域名规则完全识别。

TUN DNS 劫持 `any:53` 和 `tcp://any:53` 可接管常规明文 DNS；DoT / DoQ / DoH 需要结合路由规则、TLS SNI 和上游例外配置。部署后应检查 DNS 日志，确认两个上游解析器都能正常连接。

## Unity 与 YouTube 规则取舍

- 不再封锁整个 `unity3d.com`。只屏蔽 Unity 官方文档列出的 Analytics / Performance 端点（CDP、perf、perf-events、内部 CDP relay），保留 Unity Editor、Package Registry、下载 CDN。
- 不再封锁整个 `googlevideo.com` 或 `ytimg.com`。Blackmatrix7 的 YouTube 分流集包含这些媒体域名，配置改为让 YouTube 相关流量走代理；原有明确的 Googlevideo 直连正则例外仍排在 YouTube 规则之前。
- BattleEye 使用 Mihomo 支持的 `DOMAIN-WILDCARD,*-s1.battleye.com`。
- 删除过宽的 `DOMAIN-KEYWORD,null` 与单独的 `DOMAIN-KEYWORD,anti`；保留更具体的 `anticheat` 关键词。

## GitHub Actions 自动检查

推送、PR 和手动触发时运行 `scripts/validate_rules.py`，检查规则类型、字段数量、域名 / CIDR / 端口格式、重复域名和 IP、Go RE2 不兼容正则，以及 DIRECT / PROXY / REJECT 之间可静态判断的冲突。

静态检查不能完整判定任意正则之间的语言交集，也不会下载并展开外部 MRS 或实时钓鱼订阅；这些属于外部动态数据的运行期验证范围。
