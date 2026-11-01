# ClashRulePro

自定义 Clash / Mihomo 规则补充集，保留本仓库已有的自定义直连、代理、拦截、Fake-IP 与 PCDN 规则。

## 新增规则

| 文件 | 用途 | 建议策略 |
|---|---|---|
| \`DNS.yaml\` | 已知公共 DoH 域名，以及常见 DoT / DoQ 端口 | REJECT（按需启用） |
| \`Malware-Provider.yaml\` | Phishing Army 动态钓鱼域名订阅配置片段 | REJECT |
| \`Privacy.yaml\` | 广告/遥测/公共 Tracker 的 GeoSite 分类 | REJECT（按需启用） |
| \`Private.yaml\` | 本地域名、RFC1918、回环、链路本地、IPv6 ULA | DIRECT |

\`DNS.yaml\` 和 \`Privacy.yaml\` 使用 \`GEOSITE\`，需要 Mihomo 以及包含对应分类的 geosite 数据库。建议使用 MetaCubeX/meta-rules-dat 或兼容的 v2fly geosite 数据。

### 规则提供者示例

这些文件是 classical 规则内容，可按需加入现有配置的 \`rule-providers\`。以下只展示新增部分：

\`\`\`yaml
rule-providers:
  private-extra:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/High-cla/clashrulepro/main/Private.yaml"
    path: ./ruleset/private-extra.yaml
    interval: 86400

  dns-bypass:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/High-cla/clashrulepro/main/DNS.yaml"
    path: ./ruleset/dns-bypass.yaml
    interval: 86400

  privacy:
    type: http
    behavior: classical
    format: text
    url: "https://raw.githubusercontent.com/High-cla/clashrulepro/main/Privacy.yaml"
    path: ./ruleset/privacy.yaml
    interval: 86400
\`\`\`

在现有 \`rules\` 中，建议将局域网直连放在较前位置，并将 DNS / 威胁情报拦截放在通用代理和 MATCH 之前：

\`\`\`yaml
rules:
  - RULE-SET,private-extra,DIRECT
  - RULE-SET,dns-bypass,REJECT
  - RULE-SET,privacy,REJECT
  # 将其他现有规则接在这里
  # ...
  - MATCH,PROXY
\`\`\`

不要重复创建已有的 \`rule-providers\` 或 \`rules\` 顶层键；应将条目合并到现有配置。

### DNS 防绕过的边界

- 规则覆盖已知公共 DoH 主机，以及常见 DoT / DoQ 端口 853、784、8853。
- 不能仅靠域名规则识别任意伪装在 TCP/443 上的自建 DoH 服务，也不能保证覆盖所有硬编码 IP 的 DNS 客户端。
- 如需强制设备使用 Mihomo DNS，还应正确启用 TUN DNS 劫持（例如 \`any:53\` 和 \`tcp://any:53\`）并检查 DNS 配置。
- 如果上述公共 DNS 服务被配置为 Mihomo 的上游 nameserver，不要启用对应 REJECT 规则，否则可能导致 DNS 解析失败。

### 恶意网站 / 钓鱼域名订阅

\`Malware-Provider.yaml\` 是 Mihomo 配置片段，不是 classical 域名规则文件。将其中的 \`rule-providers.phishing-army\` 合并进现有配置，并把 \`RULE-SET,phishing-army,REJECT\` 合并到现有 \`rules\`。它直接订阅 Phishing Army 的域名 feed，不在本仓库复制第三方威胁情报数据。该 feed 聚焦钓鱼域名，不等于完整恶意软件、C2 或恶意 IP 情报库；商业用途应自行核对其上游数据源的许可条件。

### 隐私追踪规则

\`Privacy.yaml\` 使用 \`category-ads-and-telemetry\`、\`category-telemetry\` 和 \`category-public-tracker\`。这些集合可能拦截统计、崩溃上报和公共 Tracker，建议先在测试配置中启用，确认没有影响需要的应用后再长期使用。

## 自动检查

GitHub Actions 在推送、PR 和手动触发时运行 \`scripts/validate_rules.py\`，检查：

1. 规则类型、字段数量和域名 / CIDR / 端口格式。
2. 重复域名规则和重复 IP 网段。
3. DOMAIN-REGEX 的 Python 语法，以及 Go RE2 不支持的前瞻、后顾和反向引用。
4. DIRECT、PROXY、REJECT 规则集之间可静态判断的域名和 CIDR 重叠。

GeoSite 分类由外部 geosite 数据库定义，远程 Phishing Army feed 在运行时拉取；本地静态检查无法展开这两类动态集合并证明其完整语义无冲突。正则之间的语言交集也不能在一般情况下完全静态判定。
