# ClashRulePro

自定义 Clash / Mihomo 规则补充集，侧重自定义直连、代理、拦截、Fake-IP、PCDN 与隐私/安全规则。

## 当前规则文件

| 文件 | 用途 | 建议策略 / 用法 |
|---|---|---|
| `Malware-Provider.yaml` | Phishing Army 动态钓鱼域名订阅配置片段 | domain provider，REJECT |
| `Privacy.yaml` | GeoSite telemetry / tracker 规则片段 | 直接加入 rules；或使用下文 MetaCubeX MRS |
| `Private.yaml` | 局域网域名、RFC1918、回环、链路本地、IPv6 ULA | classical provider，DIRECT |
| `pcdn.yaml` | PCDN / MCDN 域名、IP 与关键词源规则 | 自动按规则类型拆分 |
| `Fakeip.yaml` | Fake-IP 排除域名与关键词规则 | 自动按规则类型拆分 |
| `NoBanDirect.yaml` | 自定义直连规则 | DIRECT |
| `userDirect.yaml` | 自定义直连规则 | DIRECT |
| `userProxy.yaml` | 自定义代理规则 | PROXY |
| `userReject.yaml` | 自定义安全、隐私和广告拦截规则 | REJECT |

## MRS Provider 自动发现与构建

`scripts/build_mrs.py` 不再依赖 `DNS.yaml`、`pcdn.yaml`、`Fakeip.yaml` 等固定文件名。默认递归扫描仓库根目录下的 `.yaml` / `.yml` 文件，也可以通过 `--source-dir` 指定专门的规则目录。完整 Mihomo 配置、provider 配置和隐藏目录会被忽略；符合规则列表格式的文件会按内容识别和拆分。

本地规则文件按类型生成：
- `DOMAIN` / `DOMAIN-SUFFIX`：生成 `domain` 行为的 MRS 文件。
- `IP-CIDR` / `IP-CIDR6`：生成 `ipcidr` 行为的 MRS 文件。
- `DOMAIN-KEYWORD`：保留为 classical/text 的 `.txt` 文件。

Mihomo 的 MRS 目前只支持 `domain` 和 `ipcidr` 行为；`DOMAIN-REGEX`、`DOMAIN-WILDCARD`、`GEOSITE`、端口和进程类规则不能塞入这两类 MRS。扫描到的文件若同时包含可转换和不可转换规则，只转换支持的部分并在 Actions 日志中报告跳过数量；没有可转换规则的配置文件会被忽略。命名使用源文件名，子目录名会拼入输出文件名前缀；输出位于 `rule_providers/`。

广告规则仍从 Blackmatrix7 的同一份 `Advertising.list` 拆分为 `Advertising-Domain`（domain/MRS）、`Advertising-IP`（ipcidr/MRS）和 `Advertising-Keyword`（classical/text）。`tvbox` 从 Sfssup 的 domain YAML 转为 domain MRS；`GameDownloadCN` 从 Blackmatrix7 的 domain 规则转为 domain MRS。生成文件由 `.github/workflows/build-mrs.yml` 使用固定版本的官方 Mihomo 转换器构建并自动提交。

示例：

```bash
python scripts/build_mrs.py --mihomo /path/to/mihomo --source-dir ./rules
```

## 上游规则整合策略

本仓库不复制整份上游规则，而是优先引用上游维护的数据：

- [MetaCubeX/meta-rules-dat](https://github.com/MetaCubeX/meta-rules-dat)：`category-doh`、`category-telemetry`、`tracker` 等 MRS 分类。
- [blackmatrix7/ios_rule_script](https://github.com/blackmatrix7/ios_rule_script)：YouTube 与 Advertising 等应用规则。
- [TG-Twilight/AWAvenue-Ads-Rule](https://github.com/TG-Twilight/AWAvenue-Ads-Rule)：使用 `Only.Ads` 变体，将广告规则与 PCDN / telemetry / tracker 策略拆开，降低规则集重复。

## DNS 防绕过说明

当前配置仍引用 `rule_providers/DNS-Domain.mrs`。原始 `DNS.yaml` 已不在仓库，因此自动扫描不会刷新这份既有 MRS 文件；将兼容的 DNS 规则列表重新放入扫描目录后，脚本会按文件名自动发现并生成对应 provider。DNS 域名规则与 MetaCubeX `category-doh.mrs` 联合使用，可补充常见公共加密 DNS 域名覆盖。

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
