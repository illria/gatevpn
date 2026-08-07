# Eianun免费聚合落地IP 🌐

基于 VPNGate / VPNBook / IPSpeed / Vpngate-Scraper / PublicVPNList + OpenVPN 的 Linux VPS 出站代理网关二改版。此版本已去除原项目广告入口，新增多来源节点拉取、指定地区拉取、同地区故障转移、IP 类型优先级、非中断检测与自动兜底。

## 主要改动

- 名称统一改为 **Eianun免费聚合落地IP**。
- 移除 Web UI 里的 VPS 推广广告和 README 中的推广徽章/链接。
- 新增多节点来源：默认同时拉取 **VPNGate + VPNBook + IPSpeed + Vpngate-Scraper + PublicVPNList**。PublicVPNList 默认使用官方 API v1；人工快照只作为可选覆盖，也可在面板里切换为任意单一或组合来源。
- VPNBook 来源默认只抓取节点、不参与启动阶段批量 OpenVPN 检测，避免部分 VPS 因 VPNBook 节点握手/路由推送导致 SSH 卡死。
- 新增后端节点地区过滤：可只保留指定国家/地区节点，不再默认把全部地区节点都写入节点池。
- Web 管理后台“管理员设置”新增 **节点来源** 和 **拉取地区过滤** 配置。
- 安装后的主命令改为 `en`，同时保留 `eianun` 兼容别名，安装时会删除旧 `ml`。
- 安装脚本已适配主流 Linux 包管理器：APT、DNF、YUM、Pacman、Zypper、APK、XBPS、Emerge。

## 支持系统

脚本会自动识别 `/etc/os-release` 和系统包管理器，并安装不同发行版对应的依赖包。

已做适配的发行版族：

- Debian / Ubuntu / Linux Mint 等 APT 系。
- CentOS / RHEL / Rocky Linux / AlmaLinux / Oracle Linux 等 YUM 或 DNF 系。
- Fedora 等 DNF 系。
- Arch Linux / Manjaro 等 Pacman 系。
- openSUSE / SUSE 等 Zypper 系。
- Alpine Linux / APK / OpenRC。
- Void Linux / XBPS。
- Gentoo / Emerge。

服务管理器支持：`systemd`、`OpenRC`、`runit`。极简容器或裁剪系统如果没有 TUN、OpenVPN 或服务管理器，脚本会提示缺失项。

## 快速安装

你的仓库地址是：`https://github.com/illria/gatevpn`

上传文件到该仓库后，使用下面命令安装：

```bash
curl -Ls https://raw.githubusercontent.com/illria/gatevpn/main/install.sh -o install.sh
sudo sh install.sh
```

Alpine Linux 也可以直接使用上面的 `sh` 命令；脚本会通过 `apk` 自动安装 OpenVPN、OpenRC、Python 等依赖。

也可以在安装时指定仓库用户和仓库名：

```bash
sh install.sh illria gatevpn
```

## 安装脚本依赖检测

安装脚本会自动执行：

1. 检测 root 权限。
2. 检测 systemd / `systemctl`。
3. 检测包管理器：`apt-get`、`dnf`、`yum`、`pacman`、`zypper`。
4. 根据发行版安装依赖：`openvpn`、`curl`、`git`、`ca-certificates`、`iptables`、`iproute/iproute2`、`procps/procps-ng`、`psmisc`、`python3/python`、`iputils/iputils-ping`。
5. 安装后再次检测必要工具：`openvpn`、`curl`、`git`、`systemctl`、`ip`、`ping`、`iptables`、`pkill`、`Python`。

RHEL / CentOS / Rocky / AlmaLinux 等系统会尝试自动安装 `epel-release`，方便安装 OpenVPN。如果你的镜像源没有 EPEL，需要先手动启用 EPEL。

## 节点来源与指定地区拉取

默认来源为：

```text
vpngate,vpnbook,ipspeed,vpngate_scraper,publicvpnlist
```

可以在 Web 管理后台修改：

```text
管理员 → 面板设置 → 节点来源
```

也可以命令行修改：

```bash
en source
```

或写入 `/etc/default/eianun-vpngate`：

```bash
NODE_SOURCES=vpngate,vpnbook,ipspeed,vpngate_scraper,publicvpnlist
# 可选：vpngate / vpnbook / ipspeed / vpngate_scraper / publicvpnlist / 多个来源用逗号组合
```

VPNBook 当前免费 OpenVPN 页面提供 US、CA、UK、DE、FR 等服务器，并展示通用账号密码；程序会自动抓取页面中的服务器和密码，再下载 `.ovpn` 配置。若 VPNBook 官网下载端点临时变化导致 `.ovpn` 直链失败，程序会使用公开 OpenVPN 模板替换当前服务器与协议后继续生成候选节点，避免 VPNBook 来源直接归零。

安全说明：VPNBook 默认只抓取 `tcp443`，并且在 `VPNGate + VPNBook` 混合来源下不会自动批量检测 VPNBook 节点。你可以在面板里对某个 VPNBook 节点单独点“检测/切换”。如果你确认自己的 VPS 扛得住并且想让 VPNBook 也参与自动批量检测，可以在 `/etc/default/eianun-vpngate` 里显式开启：

```bash
VPNBOOK_AUTO_TEST=1
VPNBOOK_PROTOCOLS=tcp443
```

如需更多 VPNBook 协议，可手动改为 `tcp443,tcp80,udp53,udp25000`，但不建议低配 VPS 开启。

### IPSpeed 来源说明

IPSpeed 来源会定时读取 `https://ipspeed.info/free-openvpn.php` 的免费 OpenVPN 列表，并下载页面中列出的 `.ovpn` 配置文件。该页面会显示更新时间、国家、配置文件、在线时长与 Ping，程序会把这些节点合并到统一节点池，再进行可用性与 IP 风控检测。

### Vpngate-Scraper 来源说明

Vpngate-Scraper 来源会读取 `https://github.com/fdciabdul/Vpngate-Scraper-API` 自动生成的 Markdown 节点表，并下载其中 `configs/*.ovpn` 配置文件。该列表包含 Hostname、IP、Ping、Speed、Country 和配置链接，程序会把这些节点合并到统一节点池，再进行可用性与 IP 风控检测。

### PublicVPNList 来源说明

PublicVPNList 默认已经加入 `NODE_SOURCES`，不需要先配置人工快照。程序使用官方 API v1 元数据入口：

```text
API base: https://publicvpnlist.com/api/v1
GET /servers
GET /servers/{public_id}
GET /dataset
GET /health
```

默认请求 `https://publicvpnlist.com/api/v1/servers`，参数包括 `protocol=openvpn`、`status=online`、`per_page=200`、`sort=last_checked`、`order=desc` 以及固定允许国家。API 的 metadata 数量和最终可连接节点数量分开统计。API 常常不返回可复用的 `config_download_url`；只有 metadata 同时提供了明确的官网数字下载 ID（或官方 `server/download` 页面路径中的数字 ID）时，程序才会按官网公开的 Check & download 流程执行：先请求同源实时检查，再 POST `get_token.php` 获取一次性下载令牌，随后下载并校验 `.ovpn`。API 的 `pvl_...` public ID 不会被猜测或直接当作官网数字 ID。令牌、Cookie 和短期下载 URL 只存在于本次内存流程中，不写入缓存、节点文件或日志。已有有效配置缓存会优先复用；缺少可验证网页 ID、实时检查失败或令牌/配置校验失败的记录不会成为可连接节点。metadata 不能被拼接成伪造的 OpenVPN 配置。

人工快照仍可作为高级覆盖方式，URL 和本地文件二选一，不得同时配置；清除覆盖后恢复 API 模式：

```bash
PUBLICVPNLIST_ENABLED=1
PUBLICVPNLIST_API_BASE_URL=https://publicvpnlist.com/api/v1
PUBLICVPNLIST_API_URL=https://publicvpnlist.com/api/v1/servers
PUBLICVPNLIST_SNAPSHOT_URL=
PUBLICVPNLIST_SNAPSHOT_FILE=
```

配置人工 snapshot 后优先使用 snapshot；清除后恢复 API 模式，而不是停用来源。snapshot 中已有的 `temporary_ovpn_url` 仍按 HTTPS、域名/SSRF、重定向、配置和 endpoint 规则校验；API 模式只在取得明确网页数字 ID 后进入受限的 Check & download 实现，不抓取 HTML 下载按钮、不猜测一次性 token、不自动操作 Export Builder，也不绕过下载保护。`server_page_url` 最多只用于提取明确的官网数字 ID，绝不当作 `.ovpn` 配置或直接交给 OpenVPN。代码中的 PHP 路径和响应字段属于待真实站点冒烟确认的兼容实现，不是 PublicVPNList API v1 的公开契约；在真实流程确认前，缺少映射的记录会安全跳过。

API 支持每个固定国家的分页、请求/页面/记录/响应大小上限、`Content-Type` 校验、429 `Retry-After` 退避，以及 ETag/`If-None-Match`/`Last-Modified`/304 缓存复用。429 不会长时间阻塞抓取，而是保存有界 backoff 状态。API metadata 单独保存到 `publicvpnlist_api_cache.json`（0600），不保存 cookie、凭据、签名 URL、配置 URL 或配置正文。Check & download 的实时检查、token POST 和最终配置请求共享临时 CookieJar，并分别使用 JSON、表单和 OpenVPN 配置的 `Accept`/`Content-Type` 边界；这些私有请求的真实 Cookie/CSRF/字段协议仍需在隔离环境中通过当前官网验证。配置下载仍经过 HTTPS、域名/SSRF、重定向、OpenVPN endpoint 一致性和严格 sanitizer 校验；若令牌响应跳转到第三方主机，该主机必须加入 `PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS`，官方 API/web hostname 可直接作为默认允许域名。下载失败、实时检查失败或缺少明确网页数字 ID 的记录不会把 metadata 计为可连接节点；`live_flow_mapping_missing` 会单独显示。

PublicVPNList 的状态会显示 `mode`、`Metadata records`、`Live checks`、token、profile 下载/校验、`Connectable candidates`、`Metadata-only skipped`、网页 ID 缺失、熔断/预算/deadline、持久化失败 streak、最后 API 更新时间、API 状态和限流退避状态。若当前 API 的实时检查、一次性下载或配置校验没有产生可连接节点，日志会明确区分 metadata 与 connectable candidates；其他来源仍继续工作。快照 URL、query、签名、Cookie 和 token 不写入缓存、节点文件或日志。

升级兼容：旧版本的通用 `en source` 选择器可能曾写入 `PUBLICVPNLIST_ENABLED=0`，这不会再关闭默认 API 来源；服务升级启动时会自动迁移为启用状态。只有 `en publicvpnlist disable` 或管理后台明确停用时，才会写入独立的人工停用标记并保持关闭。之后修改普通节点来源不会意外停用 PublicVPNList。

PublicVPNList 的固定允许国家为 `PH, US, FR, GB, ID, FI, DE, TW, AU, NL`，实际结果还会与“拉取地区过滤”取交集：

- `PH` 接受全部 IP 类型；
- `US` 仅接受现有 `vpn_utils.enrich_ip_info()` 明确分类为 `residential` 的节点，风控接口失败或分类为空时拒绝；
- 其他固定国家接受全部 IP 类型；
- 其他国家无论用户是否选择，均不从 PublicVPNList 进入节点池。

可选环境变量：

```bash
PUBLICVPNLIST_ENABLED=1
PUBLICVPNLIST_API_BASE_URL=https://publicvpnlist.com/api/v1
PUBLICVPNLIST_REFRESH_SECONDS=21600
PUBLICVPNLIST_API_URL=https://publicvpnlist.com/api/v1/servers
PUBLICVPNLIST_SNAPSHOT_URL=
PUBLICVPNLIST_SNAPSHOT_FILE=
PUBLICVPNLIST_MAX_NODES=100
PUBLICVPNLIST_MAX_SCAN_ROWS=500
PUBLICVPNLIST_MAX_RAW_ROWS=5000
PUBLICVPNLIST_STALE_PROFILE_SECONDS=604800
PUBLICVPNLIST_CONFIG_TIMEOUT_SECONDS=45
PUBLICVPNLIST_MAX_REDIRECTS=5
PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS=
PUBLICVPNLIST_LIVE_FLOW_ATTEMPTS_PER_COUNTRY=2
PUBLICVPNLIST_LIVE_FLOW_MAX_ATTEMPTS=20
PUBLICVPNLIST_LIVE_FLOW_DELAY_SECONDS=0.2
PUBLICVPNLIST_LIVE_FLOW_MAX_FAILURES=9
PUBLICVPNLIST_LIVE_FLOW_MAX_SECONDS=180
PUBLICVPNLIST_API_REFRESH_SECONDS=900
PUBLICVPNLIST_API_MAX_STALE_SECONDS=21600
PUBLICVPNLIST_API_TIMEOUT_SECONDS=10
PUBLICVPNLIST_API_MAX_RETRIES=1
PUBLICVPNLIST_API_MAX_PAGES=20
PUBLICVPNLIST_API_MAX_RECORDS=4000
PUBLICVPNLIST_API_PER_PAGE=200
PUBLICVPNLIST_API_MAX_RETRY_AFTER_SECONDS=300
PUBLICVPNLIST_API_MAX_REQUESTS_PER_REFRESH=30
```

`PUBLICVPNLIST_API_REFRESH_SECONDS` 是 API metadata 的刷新尝试间隔，`PUBLICVPNLIST_REFRESH_SECONDS` 仍用于人工快照；它们都不是已验证配置的硬过期时间。缓存按稳定的 `public id + normalized host + port + proto` 保存已清洗配置，并记录 `snapshot_source_hash`、`snapshot_fetched_at`、`last_refresh_attempt_at`、`last_refresh_success_at`、`config_validated_at`、`last_seen_at` 和 `snapshot_checked_at`。API 失败、304、配置链接失效或部分节点失败时，缓存会保留仍在保留期内的旧验证配置；只有超过 `PUBLICVPNLIST_STALE_PROFILE_SECONDS` 的 profile 才会移除。地区过滤只在读取缓存后执行，切换 PH/FR 不会重新下载已经验证的配置。

配置下载 URL 只允许 HTTPS，并且必须通过 `PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS` 或官方 API hostname 的精确域名限制；程序会拒绝用户名密码、localhost、回环/私网/链路本地/云元数据地址，并在每次重定向时重新执行相同检查，超过 `PUBLICVPNLIST_MAX_REDIRECTS` 也会 fail closed。临时 URL、query、签名和 token 不写日志或缓存。`PUBLICVPNLIST_MAX_RAW_ROWS` 是原始记录安全上限，`PUBLICVPNLIST_MAX_SCAN_ROWS` 只计算规范化后属于固定允许国家的记录；美国节点会先按最多 100 条批量风控，非住宅或无法分类的节点不会消耗配置下载和最终配额。

刷新按快照顺序以最多 100 条 eligible 记录为窗口，只对当前窗口的美国元数据执行批量 IP 类型查询；达到 `PUBLICVPNLIST_MAX_NODES` 后停止后续风控和配置请求。前 `PUBLICVPNLIST_MAX_RAW_ROWS` 条原始记录是额外安全上限，不允许国家不会消耗 eligible 扫描配额，也不会消耗配置下载令牌。API live flow 按固定国家交错排序：先完成每个国家质量最佳节点的第一轮，再尝试每个国家的第二节点；每个国家严格最多尝试 2 个候选，不会因为其他国家缺数据而转用第三个候选。默认十国合计 20 次，受 `PUBLICVPNLIST_LIVE_FLOW_MAX_SECONDS` 的 180 秒墙钟上限、请求间隔和连续 9 次失败熔断约束；首轮仍有可用国家未尝试前，连续失败熔断会延后。若显式把总上限调低，第二轮将无法覆盖全部十国；每个 profile 的失败会按 public id/endpoint 保存指数 backoff，并清理已不再出现在完整 API metadata 中的 retry 条目，429 的 `Retry-After` 会被限制在配置上限内。一次性 token 下载不会复用同一个 token 重试，下一次尝试会重新执行完整 Check → token → download 流程。失败 streak 只有在完整 profile 校验并成功加入缓存后才清零。
PH 是固定允许国家之一，元数据映射、候选筛选、实时下载流程和离线测试均保留；如果上游暂时没有 PH metadata、PH 检查失败或下载失败，PublicVPNList 会降级为其他可用国家，只记录脱敏原因，不清空已成功节点，也不阻断其他国家和来源。

API 元数据刷新在采集流程之外的单例后台线程中执行；服务启动前会先恢复仍在保留期内的已验证 PublicVPNList 配置，因此 API 超时、限流或官网实时下载失败不会阻塞主服务，也不会覆盖 VPNGate、VPNBook、IPSpeed 或 Vpngate-Scraper 的结果。后台刷新完成后，后续采集轮次会读取新缓存；API live flow 具有独立的请求次数、profile 尝试次数和整轮墙钟上限。\n\nPublicVPNList 与 VPNGate、IPSpeed 会按规范化的 `host/IP + port + tcp/udp` endpoint 去重；同一 endpoint 的优先级为 VPNGate > IPSpeed > PublicVPNList。VPNBook 和 Vpngate-Scraper 不参与这次跨来源优先级去重。DNS 临时失败仍保留 hostname key，协议或端口不同的 endpoint 不会误去重。`PUBLICVPNLIST_MAX_NODES` 限制最终节点数，`PUBLICVPNLIST_MAX_SCAN_ROWS` 限制扫描记录数；被美国住宅规则拒绝的节点不消耗最终配额。美国风控按最多 100 个节点一批调用现有 `vpn_utils.enrich_ip_info()`。

### PublicVPNList 手动真实快照冒烟测试

该检查不会进入默认 CI，也不会启动 OpenVPN。脚本分两阶段运行：第一次只需要人工快照 URL，读取并解析快照、选择一个 PH/FR 节点、验证 `temporary_ovpn_url` 的 HTTPS 和地址安全性，然后只输出需要加入允许列表的 hostname 并以退出码 2 结束，不会请求配置；加入 hostname 后再次运行，才会下载配置、逐次验证重定向，并检查 OpenVPN 内容、remote/端口/proto 一致性和配置清理。默认 API 抓取不依赖该人工快照脚本。脚本不会打印完整 URL、query、签名或 token：

```bash
export PUBLICVPNLIST_SNAPSHOT_URL='用户自己生成的临时签名快照 URL'
# 第一次运行：从输出中取得 hostname；退出码 2 表示发现阶段完成
python3 tools/publicvpnlist-smoke.py

export PUBLICVPNLIST_ALLOWED_DOWNLOAD_HOSTS='上一步确认的配置下载 hostname'
# 第二次运行：执行真实配置下载和校验
python3 tools/publicvpnlist-smoke.py
```

脚本只输出成功/失败、国家、remote/port/proto、重定向次数、最终下载域名和配置验证结果，不会输出完整 URL、query、签名或 token。fixture 单元测试只验证离线解析和缓存行为，不代表线上 PublicVPNList 当前可用；在用户提供真实临时 URL 并且脚本输出“通过”前，不应声称线上可用。


## 指定地区拉取节点

支持国家简称、英文名、中文名，多个地区用逗号分隔。

示例：

```text
JP,日本
US,美国
KR,韩国
JP,日本,US,美国
```

设置方式：

1. Web 管理后台 → 管理员 → 面板设置 → 节点来源 / 拉取地区过滤。
2. 命令行执行：

```bash
en country
```

3. 环境变量方式，例如 `/etc/default/eianun-vpngate`：

```bash
VPNGATE_TARGET_COUNTRIES=JP,日本
NODE_SOURCES=vpngate,vpnbook
# VPNBook 默认不参与批量自动检测，防止低配 VPS 卡死；需要时再手动开启
VPNBOOK_AUTO_TEST=0
VPNBOOK_PROTOCOLS=tcp443

# 自动连接/故障转移 IP 类型优先级：默认住宅优先
# 可选 residential / mobile / normal / hosting / proxy / all
# 默认不是硬过滤；无首选类型时会按 住宅 -> 移动 -> 普通/未知 -> 机房 -> 代理IP 逐级兜底。
TARGET_IP_TYPES=residential
```

地区留空表示拉取全部地区；IP 类型填 `all` 表示自动切换不限制类型，直接按综合风险/延迟排序。


## 固定地区与故障转移

- 如果你在“拉取地区过滤”里设置了 `GB,英国`，系统只拉取英国节点，自动切换也只在英国节点中进行。
- 如果没有设置拉取地区，但你在面板手动选择了某个英国节点，系统会把该节点国家记录为故障转移地区；后续该节点失效时，会优先在英国节点中自动切换。
- 自动切换现在使用 **IP 类型优先级**，不是死板硬过滤。默认 `residential` 表示住宅 IP 优先。
- 如果当前国家没有住宅 IP，会继续按 `移动 IP -> 普通/未知 -> 机房 IP -> 代理 IP/Tor` 逐级兜底，尽量保持服务运行。
- 如果你把 IP 类型设置成 `residential,mobile`，则会先找住宅，再找移动；仍然没有时继续按后续类型兜底。
- 如果你设置成 `all`，自动切换会直接把全部类型放进综合风险/延迟排序。
- 默认开启严格同地区故障转移；如需在同地区无可用节点时允许跨地区兜底，可在环境变量中设置：

```bash
STRICT_COUNTRY_FAILOVER=0
```

注意：VPNGate 节点由第三方志愿者提供；VPNBook 节点由 VPNBook 官网提供；IPSpeed 节点由 ipspeed.info 的免费 OpenVPN 列表提供；Vpngate-Scraper 节点由 fdciabdul/Vpngate-Scraper-API 提供；PublicVPNList 是第三方聚合来源。住宅/机房/代理类型识别依赖公开 IP 数据源，不能保证 100% 准确，但会作为自动切换的优先级依据。

## 常用命令

```bash
en status      # 查看状态
en start       # 启动服务
en stop        # 停止服务
en restart     # 重启服务
en logs        # 查看日志
en web         # 修改网页绑定地址/安全后缀
en port        # 修改网页端口
en password    # 修改管理账号密码
en source      # 设置节点来源：VPNGate / VPNBook / IPSpeed / Vpngate-Scraper / PublicVPNList（默认 API）
en publicvpnlist status                         # 查看 API/metadata/可连接节点脱敏状态
en publicvpnlist enable                         # 启用默认 API 来源
en publicvpnlist disable                        # 停用 PublicVPNList（不删除缓存）
en publicvpnlist set-url                        # 设置人工临时快照覆盖 API
en publicvpnlist set-file /path/to/snapshot.json # 设置本地快照文件覆盖 API
en publicvpnlist set-hosts download.example     # 设置额外配置下载域名允许列表
en publicvpnlist clear                          # 清除人工覆盖/允许列表，恢复 API，保留缓存
en publicvpnlist restart                        # 重启服务
en country     # 设置节点拉取地区
en iptype      # 设置自动选择/故障转移 IP 类型，例如住宅IP
en update      # 从 GitHub 拉取最新代码并重新安装/重启
en uninstall   # 卸载
```

兼容命令：`eianun` 会指向 `en`；旧 `ml` 会在安装时自动删除。

## 架构

```text
[ 3x-ui / Xray ]
      │ HTTP / SOCKS5
      ▼
[ 本地代理服务器 :7928 ] --绑定 tun0--> [ OpenVPN / VPNGate / VPNBook / IPSpeed / Vpngate-Scraper / PublicVPNList 节点 ]
      │
      └─ SSH / Web UI 仍走物理网卡，避免 VPS 失联
```

## 本地代理与 UDP 出口

代理端口 `7928` 同时提供 HTTP 和 SOCKS5，但两者能力不同：

- HTTP：`http://127.0.0.1:7928`，仅支持 TCP 普通代理和 HTTP CONNECT，不支持 WebRTC/STUN UDP。
- SOCKS5：`socks5://127.0.0.1:7928`，支持 TCP CONNECT 和 RFC 1928 UDP ASSOCIATE。

SOCKS5 UDP ASSOCIATE 会为每个 TCP 控制连接创建独立的临时 UDP relay。接收本地客户端数据的 socket 与访问公网的 socket 分离，公网 UDP socket 强制绑定 `GATEVPN_TUN_INTERFACE` 指定的接口，默认是 `tun0`。`tun0` 不存在、绑定失败、DNS over tun0 失败或 UDP 发送遇到接口/路由错误时，不会回落到 VPS 默认出口；该 association 会停止或丢弃当前数据包。当前域名 UDP 目标只解析 IPv4 A 记录，暂不支持 IPv6 UDP 目标和 UDP fragmentation。

mihomo 示例：

```yaml
proxies:
  - name: gatevpn
    type: socks5
    server: 127.0.0.1
    port: 7928
    udp: true
```

客户端必须选择 SOCKS5；HTTP 出口不能传递 UDP。手动检测 SOCKS5 UDP 出口：

```bash
python3 tools/check_socks5_udp.py \
  --proxy-host 127.0.0.1 \
  --proxy-port 7928 \
  --stun-host stun.l.google.com \
  --stun-port 19302
```

脚本会输出 STUN 检测到的公网 UDP IP，并提示将它与当前 OpenVPN/tun0 出口进行比对。

## 文件说明

- `vpngate_manager.py`：主程序、Web UI、节点拉取/检测/连接逻辑。
- `vpn_utils.py`：IP 信息、延迟检测、OpenVPN 配置解析等工具函数。
- `proxy_server.py`：本地 HTTP/SOCKS5 代理服务；HTTP 仅 TCP，SOCKS5 支持 TCP CONNECT 和 UDP ASSOCIATE。
- `tools/check_socks5_udp.py`：通过 SOCKS5 UDP relay 发送 STUN Binding Request 的手动检测工具。
- `install.sh`：一键安装和 CLI 工具生成脚本。
- `LICENSE`：原始许可证文件。


### ✅ 已适配的 Linux 发行版 / 包管理器

安装脚本会自动识别并安装依赖：

| 系统类型 | 包管理器 | 服务管理器 |
|---|---|---|
| Debian / Ubuntu / Linux Mint | apt | systemd |
| CentOS / RHEL / AlmaLinux / Rocky / Fedora | yum / dnf | systemd |
| Arch / Manjaro | pacman | systemd |
| openSUSE / SUSE | zypper | systemd |
| Alpine Linux | apk | OpenRC |
| Gentoo | emerge | OpenRC / systemd |
| Void Linux | xbps | runit |

说明：脚本尽量覆盖主流 Linux，但“全部 Linux”里存在大量极简镜像、容器镜像、非标准服务管理器或缺少 TUN/OpenVPN 内核能力的环境。遇到这类系统时，脚本会提示缺失项，而不是静默失败。

---

### 🛡️ 多源 IP 风控与干净度评分

新版内置多源 IP 风控评分，节点检测通过 OpenVPN 握手后，会继续对入口 IP 做多维度质量检查，用于自动排序、手动风险提示和故障转移优选。

默认检测维度：

- `ip-api.com`：地区、ASN、ISP、proxy、hosting、mobile 标记。
- `ipwho.is`：ASN/运营主体与 proxy/vpn/tor/hosting 安全标记。
- `proxycheck.io`：代理/VPN 类型与第三方 risk 分数。
- DNSBL 黑名单：默认检查 `zen.spamhaus.org`、`bl.spamcop.net`、`dnsbl.sorbs.net`、`all.s5h.net`。
- ASN/运营主体关键词：自动识别 VPS、云厂商、数据中心、代理、VPN、托管网络等关键词。

面板会显示：

- IP 类型：住宅 IP / 移动网 / 机房 IP / 代理 IP / Tor 出口。
- 网络质量：干净住宅 / 普通 / 数据中心 / 代理 / 移动端 / 高风险。
- 欺诈值：0-100，越低越干净。
- 黑名单：命中数量与具体 DNSBL 来源。

默认策略：

- 自动检测全部节点后，会从 **全部已检测可用节点** 里按固定地区、IP 类型优先级、欺诈值、黑名单、风险等级和延迟主动优选节点。
- 自动故障转移采用 **balanced + IP 类型优先级**：先选择首选类型里 `欺诈值 <= 25` 且无黑名单命中的干净备用节点。
- 默认 IP 类型优先级是 `residential`，即住宅 IP 优先；但如果当前国家没有住宅 IP，不会停摆，会按移动/普通/机房/代理逐级兜底。
- 代理 IP 是最后兜底选项：只有前面类型都没有可用节点时才会参与自动故障转移。
- 如果当前已经连接的是代理/高风险节点，后面检测到同地区住宅 IP / 移动 IP / 更低风险节点，会自动择优切换；有冷却时间避免频繁跳节点。这个功能可在 Web 面板「管理员 → 面板设置 → 检测完成后自动优选节点」里开关。
- 手动切换不会被风控硬拦截：高风险/未检测节点会弹出提示，确认后仍可强制尝试。
- 如果想让自动故障转移绝对严格，可设置 `AUTO_RISK_MODE=strict` 且 `AUTO_MIN_KEEP_RUNNING=0`。
- 如果想完全禁止手动强制切换，可设置 `ALLOW_MANUAL_RISKY_CONNECT=0`。

可选环境变量：

```bash
# 自动优选的干净 IP 欺诈值阈值，默认 25；超过后会降权，但 balanced 模式不会直接停摆
MAX_AUTO_FRAUD_SCORE=25

# 自动故障转移风控模式：balanced / strict / loose，默认 balanced
AUTO_RISK_MODE=balanced

# balanced 模式下没有干净 IP 时是否继续按 IP 类型优先级兜底保持运行，默认 1
AUTO_MIN_KEEP_RUNNING=1

# 自动连接/故障转移 IP 类型优先级，默认 residential。
# 默认不是硬过滤；会按首选类型开始，再逐级兜底到代理IP。
# residential=住宅IP；mobile=移动；normal=普通/未知；hosting=机房；proxy=代理；all=全部
TARGET_IP_TYPES=residential

# 是否全局允许自动/手动连接风险节点，默认关闭；开启后风控仅展示不阻断
ALLOW_RISKY_IP_CONNECT=0

# 是否允许面板手动确认后强制尝试风险节点，默认开启
ALLOW_MANUAL_RISKY_CONNECT=1

# 是否自动检测拉取到的全部节点，默认开启；关闭后只检测前 10 个
AUTO_TEST_ALL_NODES=1

# 自动检测最多检测多少个节点，0 表示不额外限制，最多受 MAX_SCAN_ROWS 限制
AUTO_TEST_MAX_NODES=0

# 自动检测 OpenVPN 握手并发数，默认 8；VPS 配置低建议 3-5
AUTO_TEST_WORKERS=8

# 刚启动且没有活动连接时，先做一轮质量扫描再连接，避免只测前几个就连到代理/高风险 IP
INITIAL_QUALITY_SCAN_BEFORE_CONNECT=1

# 首次质量扫描最多同步检测多少个节点；0 表示本轮可检测节点全部扫完再连接
INITIAL_QUALITY_SCAN_MAX_NODES=80

# 单个节点 OpenVPN 批量检测超时时间，默认 12 秒
OPENVPN_BATCH_TEST_TIMEOUT_SECONDS=12

# 检测完成后是否从所有可用节点中主动选择更优节点，默认开启；也可在 Web 面板设置中开关
AUTO_SELECT_BEST_NODE=1
# 当前连接正常时不主动断开重连；只更新节点质量，失效时才故障转移
AUTO_SELECT_ALLOW_ACTIVE_SWITCH=0

# 主动优选的通道模式：single（默认）或 dual。dual 仅用于健康连接的主动优选。
AUTO_SWITCH_TUNNEL_MODE=single

# 故障自动切换的通道模式：single（默认）或 dual；与主动优选模式独立。
AUTO_FAILOVER_TUNNEL_MODE=single

# dual 模式切换成功后旧隧道保留排空的秒数，默认 45
AUTO_SWITCH_DRAIN_SECONDS=45

# 代理出口连续失败几次才触发故障转移；默认 3，避免瞬时抖动误切走手动选择的住宅 IP
PROXY_FAIL_AUTO_SWITCH_THRESHOLD=3

# 新连接建立后的健康保护期，默认 30 秒，保护期内不会因为代理检测短暂失败而切换
PROXY_FAIL_GRACE_SECONDS=30

# 代理出口健康检测间隔，默认 10 秒；连续 3 次失败后触发故障转移
PROXY_HEALTH_CHECK_INTERVAL_SECONDS=10

# 自动优选切换冷却时间，避免频繁跳节点，默认 600 秒
AUTO_SELECT_COOLDOWN_SECONDS=600

# 欺诈值至少降低多少才触发自动择优切换，默认 20
AUTO_SWITCH_MIN_FRAUD_DELTA=20

# 同风险等级下延迟至少降低多少毫秒才触发自动择优切换，默认 300ms
AUTO_SWITCH_MIN_LATENCY_DELTA_MS=300

# 是否启用 DNSBL 黑名单检测，默认开启
IP_DNSBL_CHECK=1

# 是否启用 ipwho.is 检测，默认开启
IPWHOIS_CHECK=1

# 是否启用 proxycheck.io 检测，默认开启
PROXYCHECK_CHECK=1

# 风控缓存有效期，默认 24 小时
IP_RISK_CACHE_TTL_SECONDS=86400
```

如需修改，在 `/etc/default/eianun-vpngate` 中写入对应变量后重启服务。


### IP 类型优先级说明

默认 `TARGET_IP_TYPES=residential` 的含义是：**住宅优先**，不是“只允许住宅”。自动故障转移会按以下顺序兜底：

```text
住宅 IP -> 移动 IP -> 普通/未知 -> 机房 IP -> 代理 IP/Tor
```

如果你确实想把 IP 类型当成硬过滤，可以额外设置：

```bash
STRICT_IP_TYPE_FILTER=1
```

### 自动检测全部节点 + 自动优选

新版默认会在每次拉取节点后自动检测全部非活动节点，不再只检测前 10 个。为了防止 VPS 被大量 OpenVPN 进程拖死，检测会按 `AUTO_TEST_WORKERS` 控制并发，默认 8 个并发。面板会每 10 秒自动刷新检测进度，不需要手动刷新。

检测完成后会执行自动优选：从全部 `available` 节点中，先按固定地区范围筛选，再按 IP 类型优先级、黑名单、欺诈值、风险等级、延迟排序。也就是说，如果当前连着代理 IP，后面检测到同地区住宅 IP 或移动 IP，程序会把它列为更优候选；如果没有住宅/移动，也会继续按普通、机房、代理逐级兜底，保证服务不会停摆。

为了避免影响使用体验，默认启用“非中断检测”：每轮检测只刷新节点质量和风控信息，当前节点正常时不会为了优选而主动断开重连。你可以在 Web 面板设置里打开「当前连接正常时主动切换更优节点」，或通过 `AUTO_SELECT_ALLOW_ACTIVE_SWITCH=1` 恢复主动跳转。

主动优选默认使用 `AUTO_SWITCH_TUNNEL_MODE=single`，即沿用原有的停旧启新流程。设置为 `dual` 后，健康连接发现明显更优节点时会先在备用 `tun1` 建立并检查新隧道，确认出口可用后再切换策略路由，并让旧隧道短暂排空。故障转移另由 `AUTO_FAILOVER_TUNNEL_MODE` 独立控制，设置为 `dual` 时，代理连续失败达到阈值后也会先建立并验证备用隧道，再切换到新出口；备用隧道失败会回退原有单通道恢复流程。手动连接仍使用单通道。现有 TCP/UDP 会话不能保证迁移到新公网 IP，但新建请求可在切换后使用新隧道。冷却时间仍由 `AUTO_SELECT_COOLDOWN_SECONDS` 控制。


### VPNBook 节点检测安全说明

VPNBook 来源默认采用安全检测模式：面板点击“检测”时只检查 TCP 端口连通性和 IP 风险信息，不直接启动 OpenVPN 握手，避免部分 VPNBook 配置在测试阶段改写系统路由导致 SSH 卡死。点击“切换”时才会真正启动 OpenVPN，并且程序会使用 `route-nopull + route-noexec` 和配置清洗来避免默认路由被劫持。

如确需让 VPNBook 检测也执行完整 OpenVPN 握手，可在 `/etc/default/eianun-vpngate` 设置：

```bash
VPNBOOK_SAFE_TEST_ONLY=0
```

低配 VPS 不建议关闭该安全模式。
