// OpenVPN 诊断助手 - 单文件 WinForms 版
// 编译: csc /nologo /target:winexe /codepage:65001 /out:"OpenVPN诊断助手.exe" OpenVPNDoctor.cs /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using System.Windows.Forms;
using Microsoft.Win32;

namespace OpenVPNDoctor
{
    // ======================= 数据模型 =======================
    class Meta
    {
        public string Server = "";
        public string Port = "";
        public string Proto = "";
        public int Restarts = 0;
        public bool IsConfig = false;
    }

    class Rule
    {
        public string Id, Severity, Title, Why, Config;
        public string[] Causes, Fixes, Patterns;
        public Func<string, Meta, bool> Custom;

        public Rule Clone()
        {
            return new Rule
            {
                Id = Id, Severity = Severity, Title = Title, Why = Why, Config = Config,
                Causes = Causes != null ? (string[])Causes.Clone() : null,
                Fixes = Fixes != null ? (string[])Fixes.Clone() : null,
                Patterns = Patterns, Custom = Custom
            };
        }
    }

    class Issue
    {
        public Rule Rule;
        public string Line;
    }

    class Result
    {
        public Meta Meta;
        public List<Issue> Issues = new List<Issue>();
    }

    // ======================= 规则引擎 =======================
    static class Engine
    {
        const RegexOptions IC = RegexOptions.IgnoreCase;
        const RegexOptions ICM = RegexOptions.IgnoreCase | RegexOptions.Multiline;

        public static readonly List<Rule> Rules = new List<Rule>
        {
            new Rule
            {
                Id = "TLS_HANDSHAKE_FAILED", Severity = "high",
                Title = "TLS 握手失败：60 秒内未完成密钥协商",
                Patterns = new[] { @"TLS key negotiation failed to occur within", @"TLS handshake failed", @"SIGUSR1\[soft,tls-error\]" },
                Why = "客户端在 60 秒内没能与服务器完成 TLS 握手，连接被重置并自动重启重试。本质是握手报文没有正常往返——服务器根本没收到，或它的回应没能到达你。",
                Causes = new[]
                {
                    "UDP 端口被封锁或严重丢包：运营商/防火墙对境外 UDP VPN 端口的干扰非常常见，这是本类日志最高频的原因",
                    "服务器宕机，或 IP/端口已经失效",
                    "协议不匹配：服务器只监听 TCP，而客户端配置成 UDP（或相反）",
                    "tls-auth / tls-crypt 密钥不匹配，或 key-direction 方向错误（HMAC 校验失败的包会被服务器静默丢弃，表现和完全连不上一样）",
                    "本地防火墙、杀毒软件或企业网关拦截了出站报文",
                    "MTU 问题导致握手大报文被分片丢弃（较少见）"
                },
                Fixes = new[]
                {
                    "确认服务器状态：联系服务商确认服务器 IP/端口是否仍在服务",
                    "改用 TCP 模式：把配置里的 proto udp 改为 proto tcp-client，端口改为 443（TCP 443 伪装成 HTTPS 流量，最难被阻断）",
                    "核对密钥文件：ca.crt、client.crt、client.key、ta.key 必须与服务器端配套；tls-auth 的 key-direction 服务器端为 0、客户端为 1",
                    "临时关闭 Windows 防火墙和第三方杀毒软件测一次，确认是否本地拦截",
                    "换网络测试（如手机热点），排除宽带运营商的干扰"
                },
                Config = "proto tcp-client\nremote 服务器地址 443"
            },
            new Rule
            {
                Id = "CERT_VERIFY_MISSING", Severity = "medium",
                Title = "未启用服务器证书验证（存在中间人攻击风险）",
                Patterns = new[] { @"No server certificate verification method has been enabled" },
                Custom = (t, m) => m.IsConfig && !Regex.IsMatch(t,
                    @"^[ \t]*(?:remote-cert-tls[ \t]+server|verify-x509-name[ \t]+\S+)(?=[ \t\r\n]|$)", ICM),
                Why = "客户端配置中没有 remote-cert-tls 或 verify-x509-name 选项，客户端不会验证服务器的身份。任何持有同一 CA 签发证书的人都可能冒充服务器，进行中间人（MITM）攻击，窃取你的 VPN 流量。",
                Causes = new[] { "服务商导出的 .ovpn 配置文件没有包含 remote-cert-tls 选项" },
                Fixes = new[]
                {
                    "用记事本打开 .ovpn 配置文件，在末尾添加一行：remote-cert-tls server，保存后重新导入连接，警告应消失",
                    "若服务商提供了服务器证书的 CN 名称，可进一步加 verify-x509-name \"服务器CN名\" name 做更严格校验",
                    "注意：如果添加后出现 VERIFY ERROR，说明之前连接的可能不是真正的服务器，请立即核对服务器地址和证书"
                },
                Config = "remote-cert-tls server"
            },
            new Rule
            {
                Id = "AUTH_FAILED", Severity = "high",
                Title = "认证失败（AUTH_FAILED）",
                Patterns = new[] { "AUTH_FAILED", @"auth-failure" },
                Why = "服务器拒绝了客户端的用户名/密码认证。",
                Causes = new[]
                {
                    "用户名或密码错误（注意大小写和多余空格）",
                    "账号已过期、欠费或被封禁",
                    "账号同时在线设备数超限"
                },
                Fixes = new[]
                {
                    "重新核对用户名和密码",
                    "登录服务商后台确认账号状态、续费或重置密码",
                    "退出其他设备上的连接后再试"
                }
            },
            new Rule
            {
                Id = "RESOLVE_FAIL", Severity = "high",
                Title = "无法解析服务器域名（DNS 解析失败）",
                Patterns = new[] { @"RESOLVE: Cannot resolve host address", @"Cannot resolve host" },
                Why = "客户端无法把服务器域名解析成 IP 地址，连接无法发起。",
                Causes = new[] { "域名拼写错误", "本机 DNS 服务器故障或被污染", "域名已过期" },
                Fixes = new[]
                {
                    "核对配置中 remote 一行的域名拼写",
                    "把系统 DNS 换成 223.5.5.5（阿里）或 119.29.29.29（腾讯）后重试",
                    "如果知道服务器 IP，直接把 remote 改为 IP 地址绕过 DNS"
                }
            },
            new Rule
            {
                Id = "CONN_TIMEOUT", Severity = "high",
                Title = "连接超时或被重置",
                Patterns = new[] { "Connection timed out", "Server poll timeout", "Connection reset", "WSAETIMEDOUT", "WSAECONNRESET", @"read UDP.*Unknown error" },
                Why = "TCP 连接建立阶段超时，或已建立的连接被远端/中间设备重置。日志中若出现 Connection reset，常见于防火墙主动发送 RST 包阻断连接。",
                Causes = new[]
                {
                    "服务器端口不可达（宕机、防火墙、端口变更）",
                    "运营商或国家级防火墙识别并阻断了 OpenVPN 特征流量",
                    "本地网络出口限制（公司/校园网）"
                },
                Fixes = new[]
                {
                    "确认服务器在线并核对端口",
                    "换用 443 端口（TCP）降低被识别的概率",
                    "公司/校园网环境尝试改走手机热点验证",
                    "长期方案：考虑带混淆的协议（如 WireGuard + 混淆、Shadowsocks、V2Ray），原生 OpenVPN 特征明显容易被封"
                }
            },
            new Rule
            {
                Id = "CERT_EXPIRED", Severity = "high",
                Title = "证书已过期或尚未生效",
                Patterns = new[] { "certificate has expired", "certificate is not yet valid", "CRL has expired" },
                Why = "TLS 校验发现证书超出有效期，或本机系统时间错误导致误判。",
                Causes = new[] { "服务器或客户端证书已过有效期", "本机系统时间/时区设置错误" },
                Fixes = new[]
                {
                    "先校对 Windows 系统日期、时间和时区（右键任务栏时钟 → 调整日期/时间 → 自动设置）",
                    "时间正确仍报错：需要服务器端重新签发证书，联系服务商更新"
                }
            },
            new Rule
            {
                Id = "VERIFY_ERROR", Severity = "high",
                Title = "证书链校验失败（VERIFY ERROR）",
                Patterns = new[] { "VERIFY ERROR", "unable to get local issuer certificate", "certificate signature failure", @"self.signed certificate in certificate chain" },
                Why = "客户端无法信任服务器出示的证书。",
                Causes = new[]
                {
                    "ca.crt 与服务器实际使用的 CA 不一致（常见于证书轮换后未更新客户端配置）",
                    "证书链不完整",
                    "遭遇中间人攻击（证书被替换）"
                },
                Fixes = new[]
                {
                    "重新从服务商处获取配套的 ca.crt，完整替换旧文件",
                    "确认没有连错服务器地址",
                    "核对服务器证书指纹（若服务商提供）"
                }
            },
            new Rule
            {
                Id = "TAP_ADAPTER", Severity = "high",
                Title = "TAP 虚拟网卡故障",
                Patterns = new[] { "There are no TAP-Windows adapters", "All TAP-Windows adapters on this system are currently in use", "CreateFile failed on TAP", @"Cannot open TUN/TAP", "ERROR: Windows TAP", "open tun device failed" },
                Why = "OpenVPN 找不到可用的 TAP-Windows 虚拟网卡，无法建立隧道。",
                Causes = new[]
                {
                    "TAP 驱动未安装或被卸载",
                    "TAP 适配器被禁用，或已被其他 VPN 进程占用",
                    "驱动损坏"
                },
                Fixes = new[]
                {
                    "设备管理器 → 网络适配器 → TAP-Windows Adapter：确认存在且已启用",
                    "以管理员身份运行 OpenVPN 安装目录下 bin\\addtap.bat 新增一个适配器",
                    "退出其他正在运行的 VPN 软件",
                    "重装 OpenVPN（安装时勾选 TAP 驱动组件），安装后重启"
                }
            },
            new Rule
            {
                Id = "ROUTE_ADD_FAIL", Severity = "medium",
                Title = "添加路由失败",
                Patterns = new[] { "ROUTE: route addition failed", "route add command failed", @"add_route.*failed", "ERROR: Windows route add" },
                Why = "OpenVPN 无法向系统路由表写入路由，流量将无法正确分流进隧道。",
                Causes = new[] { "未以管理员身份运行 OpenVPN（最常见）", "路由与本地已有网段冲突", "TAP 接口未就绪" },
                Fixes = new[]
                {
                    "右键 OpenVPN GUI 图标 → 以管理员身份运行",
                    "检查本地网段是否与 VPN 内网冲突（见“局域网网段冲突”条目）"
                }
            },
            new Rule
            {
                Id = "SUBNET_CONFLICT", Severity = "medium",
                Title = "局域网网段冲突",
                Patterns = new[] { "extremely common subnet address", "conflicts with local" },
                Why = "本地局域网网段（家用路由器常见 192.168.0.x / 192.168.1.x）与 VPN 服务端内网网段相同，会导致路由混乱，表现为“连上了但访问不了内网资源”或流量不走 VPN。",
                Causes = new[] { "两端网段相同" },
                Fixes = new[]
                {
                    "修改自家路由器的 LAN 网段为冷门段（如 192.168.123.0/24）",
                    "或让服务商把 VPN 内网网段改成 10.x.x.x 中的冷门段"
                }
            },
            new Rule
            {
                Id = "LZO_COMPRESS", Severity = "medium",
                Title = "压缩设置问题（comp-lzo）",
                Patterns = new[] { "Bad LZO decompression", "comp-lzo", "Compression for receiving enabled" },
                Why = "两端压缩设置不一致会报 Bad LZO decompression 并大量丢包；且压缩功能存在 VORACLE 安全风险，新版 OpenVPN 已默认禁用。",
                Causes = new[] { "一端开启 comp-lzo，另一端未开启或已禁用" },
                Fixes = new[]
                {
                    "推荐：两端都删除 comp-lzo 配置行（更安全也更稳定）",
                    "或确保两端 comp-lzo 设置完全一致"
                }
            },
            new Rule
            {
                Id = "CIPHER_MISMATCH", Severity = "medium",
                Title = "加密算法不匹配 / 使用了过时弱算法",
                Patterns = new[] { "no shared cipher", "cipher negotiation failed", "unsupported cipher", "DEPRECATED OPTION: --cipher" },
                Custom = (t, m) => m.IsConfig && Regex.IsMatch(t, @"^\s*cipher\s+(BF-CBC|DES|RC2)", ICM),
                Why = "OpenVPN 2.4 及以前用 cipher 指令，2.5+ 改用 data-ciphers 协商；版本跨度大或用了已弃用的弱算法（BF-CBC、DES）会导致协商失败或告警。",
                Causes = new[]
                {
                    "客户端与服务器版本差异大，cipher 协商失败",
                    "配置中仍在使用 BF-CBC / DES 等已弃用的弱算法"
                },
                Fixes = new[]
                {
                    "客户端配置中删除旧的 cipher 行，改为：data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
                    "尽量保持客户端与服务器版本一致（推荐都升级到 2.5 以上）"
                },
                Config = "data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305"
            },
            new Rule
            {
                Id = "PING_RESTART", Severity = "medium",
                Title = "长时间无活动被断开（ping-restart）",
                Patterns = new[] { "Inactivity timeout", @"--ping-restart.*restart", "ping timeout" },
                Why = "keepalive 检测发现链路长时间没有报文往返，触发了自动重连。",
                Causes = new[] { "链路质量差、丢包严重", "运营商 NAT 会话超时时间过短", "服务器负载过高" },
                Fixes = new[]
                {
                    "检查本地网络质量（WiFi 信号、丢包率）",
                    "配置中加 keepalive 10 60，让保活更频繁",
                    "UDP 频繁掉线时改试 TCP 模式"
                }
            },
            new Rule
            {
                Id = "HMAC_FAIL", Severity = "medium",
                Title = "tls-auth/HMAC 校验失败或 TLS 密钥不同步",
                Patterns = new[] { "cannot locate HMAC", @"tls-auth.*failed", @"Authenticate/Decrypt packet error", "TLS keys are out of sync" },
                Why = "tls-auth 的 HMAC 校验失败，或双方 TLS 密钥状态错位。",
                Causes = new[]
                {
                    "ta.key 与服务器端不匹配",
                    "key-direction 方向错误（服务器 0 / 客户端 1）",
                    "遭受注入攻击；或长时间运行后状态异常（重连可恢复）"
                },
                Fixes = new[]
                {
                    "重新获取 ta.key，确认与服务器配套且 key-direction 正确",
                    "条件允许时升级为 tls-crypt（比 tls-auth 更安全）"
                }
            },
            new Rule
            {
                Id = "MTU_ISSUE", Severity = "low",
                Title = "MTU 设置不一致或分片问题",
                Patterns = new[] { @"tun-mtu.*inconsistent", @"link-mtu.*inconsistent", @"WARNING: 'tun-mtu'", @"WARNING: 'link-mtu'", "oversized packet" },
                Why = "两端 MTU 参数不一致，或链路中间节点 MTU 偏小导致大包被丢弃。表现为“能连上但部分网站打不开/大文件传不动”。",
                Causes = new[] { "两端 tun-mtu / link-mtu 配置不一致", "链路 MTU 小于默认 1500（PPPoE、校园网常见）" },
                Fixes = new[]
                {
                    "删除自定义的 tun-mtu / link-mtu，保持两端默认一致",
                    "链路质量差时客户端加 mssfix 1400 试试"
                }
            },
            new Rule
            {
                Id = "FILE_MISSING", Severity = "high",
                Title = "证书/密钥文件找不到",
                Patterns = new[] { @"Cannot open [^\s]*\.(crt|key|pem|ta)", @"Cannot open .*(ca|cert|key|tls-auth)" },
                Why = "配置中引用的证书或密钥文件在指定路径下不存在。",
                Causes = new[]
                {
                    "ca/cert/key/ta 文件的路径写错",
                    "文件缺失（导入配置时没把证书一起拷贝）",
                    "使用了相对路径，但工作目录不对"
                },
                Fixes = new[]
                {
                    "把所有证书文件与 .ovpn 放在同一目录，配置里直接写文件名（如 ca ca.crt）",
                    "或改为绝对路径（注意路径中的反斜杠要写双份或用引号包住）"
                }
            },
            new Rule
            {
                Id = "OPTIONS_ERROR", Severity = "high",
                Title = "配置文件语法错误",
                Patterns = new[] { "Options error", "Unrecognized option or missing", @"Bad --option" },
                Why = "OpenVPN 启动时解析配置失败，日志中一般会指出出错的行号。",
                Causes = new[] { "配置行拼写错误或参数缺失", "从网页复制配置时混入全角字符/多余空格" },
                Fixes = new[]
                {
                    "按日志提示的行号检查 .ovpn 文件",
                    "注意指令大小写、参数个数，以及不要混入全角空格"
                }
            },
            new Rule
            {
                Id = "DEPRECATED_OPTION", Severity = "low",
                Title = "配置包含已过时的选项",
                Patterns = new[] { "DEPRECATED OPTION" },
                Why = "配置中有被官方标记为弃用的指令，当前版本仍兼容，但未来版本可能移除。",
                Causes = new[] { "旧版配置沿用至今" },
                Fixes = new[] { "按日志提示替换为新指令（最常见的是 ns-cert-type server → remote-cert-tls server）" }
            },
            new Rule
            {
                Id = "REPLAY_BACKTRACK", Severity = "low",
                Title = "乱序包过多（Replay-window backtrack）",
                Patterns = new[] { "Replay-window backtrack occurred" },
                Why = "网络质量差导致大量报文乱序到达。偶尔出现可忽略，频繁出现说明链路抖动严重。",
                Causes = new[] { "链路抖动、双链路负载均衡导致乱序" },
                Fixes = new[] { "偶发：无需处理", "频繁出现：换更稳定的网络，或改 TCP 模式" }
            }
        };

        static int SevRank(string s)
        {
            if (s == "high") return 0;
            if (s == "medium") return 1;
            if (s == "low") return 2;
            return 3;
        }

        public static Meta GetMeta(string text)
        {
            var meta = new Meta();
            const string endpoint = @"\[AF_INET6?\]\[?([\d.a-fA-F:]+)\]?:(\d+)";
            var m = Regex.Match(text, @"(?:UDP|TCP)(?:v[46])? link remote:[ \t]*" + endpoint, IC);
            if (!m.Success) m = Regex.Match(text, @"remote address:[ \t]*" + endpoint, IC);
            if (m.Success) { meta.Server = m.Groups[1].Value; meta.Port = m.Groups[2].Value; }

            if (Regex.IsMatch(text, @"UDP(?:v[46])? link remote", IC)) meta.Proto = "UDP";
            else if (Regex.IsMatch(text, @"TCP(?:v[46])? link remote|Attempting to establish TCP connection", IC)) meta.Proto = "TCP";
            else
            {
                var proto = Regex.Match(text, @"^[ \t]*proto[ \t]+(udp[46]?|tcp[46]?(?:-client|-server)?)(?=[ \t\r\n]|$)", ICM);
                if (proto.Success) meta.Proto = proto.Groups[1].Value.StartsWith("udp", StringComparison.OrdinalIgnoreCase) ? "UDP" : "TCP";
            }

            meta.Restarts = Regex.Matches(text, "process restarting").Count;

            meta.IsConfig = Regex.IsMatch(text, @"^[ \t]*client[ \t]*(?:[#;][^\r\n]*)?\r?$", ICM)
                || (Regex.IsMatch(text, @"^[ \t]*remote[ \t]+\S+[ \t]+\d+", ICM)
                    && Regex.IsMatch(text, @"^[ \t]*(ca|cert|key)[ \t]+\S+", ICM));
            if (meta.IsConfig && meta.Server.Length == 0)
            {
                // 参数间只接受横向空白，不能把下一行 ca/cert/key 当作协议。
                var cm = Regex.Match(text, @"^[ \t]*remote[ \t]+(\S+)[ \t]+(\d+)(?:[ \t]+(udp[46]?|tcp[46]?(?:-client|-server)?))?(?=[ \t\r\n]|$)", ICM);
                if (cm.Success)
                {
                    meta.Server = cm.Groups[1].Value;
                    meta.Port = cm.Groups[2].Value;
                    // remote 的显式协议覆盖全局 proto；统一为主动检测使用的 TCP/UDP。
                    if (cm.Groups[3].Success)
                        meta.Proto = cm.Groups[3].Value.StartsWith("udp", StringComparison.OrdinalIgnoreCase) ? "UDP" : "TCP";
                }
            }
            return meta;
        }

        static string MatchLine(string text, string[] patterns)
        {
            var lines = Regex.Split(text, "\r?\n");
            foreach (var line in lines)
            {
                foreach (var p in patterns)
                {
                    if (Regex.IsMatch(line, p, IC))
                    {
                        var t = line.Trim();
                        return t.Length > 220 ? t.Substring(0, 220) + " …" : t;
                    }
                }
            }
            return "";
        }

        public static Result Analyze(string text) { return Analyze(text, Rules); }

        public static Result Analyze(string text, IList<Rule> rules)
        {
            var meta = GetMeta(text);
            var res = new Result { Meta = meta };

            foreach (var r in rules)
            {
                bool hit = false;
                if (r.Patterns != null)
                {
                    foreach (var p in r.Patterns)
                    {
                        if (Regex.IsMatch(text, p, ICM)) { hit = true; break; }
                    }
                }
                if (!hit && r.Custom != null && r.Custom(text, meta)) hit = true;
                if (hit)
                    res.Issues.Add(new Issue { Rule = r, Line = r.Patterns != null ? MatchLine(text, r.Patterns) : "" });
            }

            // 针对 UDP + TLS 握手失败的定向建议
            foreach (var it in res.Issues)
            {
                if (it.Rule.Id == "TLS_HANDSHAKE_FAILED" && meta.Proto == "UDP")
                {
                    var r2 = it.Rule.Clone();
                    string target = meta.Server.Length > 0 ? meta.Server + (meta.Port.Length > 0 ? ":" + meta.Port : "") : "目标服务器";
                    var fixes = new List<string> { "【针对您的日志】您正在使用 UDP 协议连接 " + target + "。UDP 是最容易被干扰/丢包的方式，强烈建议先把 proto 改为 tcp-client、端口改为 443 再试。" };
                    fixes.AddRange(r2.Fixes);
                    r2.Fixes = fixes.ToArray();
                    it.Rule = r2;
                }
            }

            res.Issues.Sort((a, b) => SevRank(a.Rule.Severity).CompareTo(SevRank(b.Rule.Severity)));
            return res;
        }
    }

    // ======================= VPN 识别与各软件特征库 =======================
    class VpnProfile
    {
        public string Id;
        public string Name;
        public string[] ExeNames = new string[0];        // 可识别的 exe 文件名
        public string[] ProductKeywords = new string[0]; // exe 元数据关键词
        public string[] LogDirs = new string[0];         // 支持 {USER} {PF} {PF86} {APPDATA} {LOCALAPPDATA} {EXEDIR}
        public string ExeDir;                            // 用户选择 exe 后填充
        public List<Rule> Rules = new List<Rule>();
    }

    static class Profiles
    {
        public static List<VpnProfile> All;
        public static List<Rule> WinVpnRules;     // Windows 自带 VPN 错误码（追加到所有库）
        public static List<Rule> GenericRules;    // 未识别软件的通用兜底
        public static VpnProfile OpenVpn;

        static Rule R(string sev, string title, string[] patterns, string why, string[] causes, string[] fixes)
        {
            return new Rule { Id = title, Severity = sev, Title = title, Patterns = patterns, Why = why, Causes = causes, Fixes = fixes };
        }

        static Profiles()
        {
            WinVpnRules = new List<Rule>
            {
                R("high", "Windows 错误 809：IKEv2 服务器无响应", new[] { @"错误\s*809", @"error\s*809" },
                    "建立 IKEv2 连接时服务器没有任何回应，报文在中途被丢弃。",
                    new[] { "防火墙/运营商阻断了 UDP 500、4500 或 ESP 协议", "服务器 IKEv2 服务未运行", "服务器地址错误或已下线" },
                    new[] { "换网络环境再试（如手机热点），判断是否本地防火墙问题", "改用 SSTP（走 TCP 443）或 OpenVPN TCP 443 模式", "联系 VPN 提供方确认服务器状态" }),
                R("high", "Windows 错误 789：L2TP/IPSec 协商失败", new[] { @"错误\s*789", @"error\s*789" },
                    "L2TP/IPSec 在安全层协商阶段失败。",
                    new[] { "预共享密钥（PSK）错误", "本地 IPSec 服务未启动", "NAT 环境缺少注册表项 AssumeUDPEncapsulationContextOnSendRule" },
                    new[] { "核对预共享密钥", "services.msc 中确认 IKEEXT、PolicyAgent 服务已启动", "NAT 后连接需在注册表 HKLM\\SYSTEM\\CurrentControlSet\\Services\\PolicyAgent 新建 DWORD AssumeUDPEncapsulationContextOnSendRule = 2，然后重启" }),
                R("medium", "Windows 错误 691：用户名或密码被拒绝", new[] { @"错误\s*691", @"error\s*691" },
                    "服务器拒绝了登录凭据。",
                    new[] { "用户名/密码错误", "账号过期或被停用", "域（Domain）前缀多余" },
                    new[] { "重新输入凭据，注意大小写", "到服务商后台确认账号状态", "域一栏留空重试" }),
                R("medium", "Windows 错误 619/629：端口被断开", new[] { @"错误\s*(619|629)", @"error\s*(619|629)" },
                    "PPTP 连接被中途断开。",
                    new[] { "防火墙阻断 TCP 1723 或 GRE 协议", "路由器不支持 VPN Passthrough" },
                    new[] { "路由器开启 PPTP Passthrough", "PPTP 安全性差且极易被阻断，建议改用其他协议" }),
                R("medium", "Windows 错误 720：PPP 协议故障", new[] { @"错误\s*720", @"error\s*720" },
                    "本机 PPP/WAN 微型端口驱动损坏。",
                    new[] { "WAN 微型端口驱动损坏", "TCP/IP 协议栈异常" },
                    new[] { "管理员命令行执行 netsh int ip reset 后重启", "设备管理器卸载所有“WAN 微型端口”设备后重启自动重装" })
            };

            GenericRules = new List<Rule>
            {
                R("medium", "连接超时", new[] { @"timed? ?out", @"超时" },
                    "日志中出现超时，说明对端无响应。",
                    new[] { "服务器宕机或端口被封", "本地网络质量差", "中间防火墙丢包" },
                    new[] { "换节点/换端口重试", "用手机热点交叉验证是否本地网络问题", "确认服务器地址端口正确" }),
                R("medium", "连接被拒绝", new[] { @"connection refused", @"拒绝连接", @"actively refused" },
                    "目标主机明确拒绝了连接——报文到达了，但端口没有服务在监听。",
                    new[] { "VPN 服务未运行", "端口配置错误", "服务器防火墙未放行该端口" },
                    new[] { "确认端口与服务商给出的一致", "联系服务商确认服务状态" }),
                R("medium", "认证失败", new[] { @"auth\w*\s*fail", @"authentication failed", @"密码错误", @"认证失败", @"unauthorized" },
                    "账号验证未通过。",
                    new[] { "用户名/密码/密钥错误", "订阅或账号已过期" },
                    new[] { "重新填写凭据", "检查订阅/账号是否过期" }),
                R("medium", "证书问题", new[] { @"certificate", @"证书", @"x509" },
                    "TLS 证书验证相关错误。",
                    new[] { "系统时间不准", "证书过期或被替换（中间人）", "客户端跳过证书校验配置不当" },
                    new[] { "校准系统时间", "重新导入/更新证书", "不要在不明网络下关闭证书校验" }),
                R("low", "权限不足", new[] { @"permission denied", @"access is denied", @"权限不足", @"拒绝访问", @"requires elevation" },
                    "程序权限不足以完成操作。",
                    new[] { "未以管理员身份运行" },
                    new[] { "右键 → 以管理员身份运行" })
            };

            var wgRules = new List<Rule>
            {
                R("high", "WireGuard 握手失败", new[] { @"Handshake for peer.*did not complete", @"handshake.*did not complete" },
                    "与对端的握手每 5 秒重试一次均未完成，隧道无法建立。",
                    new[] { "Endpoint 地址/端口错误或服务器已下线", "UDP 端口被运营商/防火墙干扰（WireGuard 只有 UDP）", "双方 PublicKey 不匹配", "PreSharedKey 填错" },
                    new[] { "核对 Endpoint 和双方公钥", "换网络（手机热点）交叉验证", "让服务方更换 UDP 端口", "网络受限严重时换 OpenVPN TCP 443 等抗干扰方案" }),
                R("medium", "密钥格式错误", new[] { @"key is not the correct length", @"invalid key", @"Failed to parse.*key" },
                    "配置中的密钥不是合法的 44 位 Base64 格式。",
                    new[] { "复制时混入空格/换行", "公钥私钥位置填反" },
                    new[] { "重新生成密钥对并完整复制", "确认 PrivateKey 填私钥、PublicKey 填对端公钥" }),
                R("high", "本地端口绑定失败", new[] { @"unable to bind", @"bind.*failed", @"address already in use", @"Failed to create.*socket" },
                    "本地 UDP 端口被占用或无法创建套接字。",
                    new[] { "残留的 WireGuard 进程占用端口", "其他程序占用了 ListenPort" },
                    new[] { "任务管理器结束残留 wireguard 进程", "删除配置中的 ListenPort 行（客户端无需监听）" }),
                R("medium", "DNS 解析失败", new[] { @"unable to resolve", @"failed to resolve", @"no such host", @"DNS resolution failure" },
                    "Endpoint 域名无法解析。",
                    new[] { "DNS 服务器故障或被劫持", "域名已失效" },
                    new[] { "把 DNS 改为 223.5.5.5 / 119.29.29.29", "Endpoint 直接填 IP" }),
                R("medium", "权限不足", new[] { @"access is denied", @"requires administrator", @"not privileged", @"Unable to persist configuration" },
                    "WireGuard 需要管理员权限创建虚拟网卡。",
                    new[] { "未以管理员身份运行", "WireGuard 服务未安装" },
                    new[] { "以管理员身份运行 WireGuard", "重新安装 WireGuard 客户端" })
            };
            foreach (var r in WinVpnRules) wgRules.Add(r);

            var clashRules = new List<Rule>
            {
                R("high", "节点连接被拒绝", new[] { @"connection refused" },
                    "代理节点明确拒绝连接，节点本身有问题。",
                    new[] { "节点已下线或被墙", "订阅过期节点失效", "端口被封锁" },
                    new[] { "更新订阅", "切换其他节点", "到服务商面板确认节点状态" }),
                R("medium", "节点连接超时", new[] { @"i/o timeout", @"deadline exceeded", @"timeout" },
                    "连接节点超时，链路不通或严重拥堵。",
                    new[] { "节点线路拥堵/被 QoS 限速", "本地网络质量差", "节点 IP 被封锁" },
                    new[] { "切换节点", "切换规则/全局模式重试", "用本工具主动检测验证本地网络" }),
                R("medium", "证书校验失败", new[] { @"x509", @"certificate", @"tls: " },
                    "节点 TLS 证书验证出错。",
                    new[] { "系统时间不准", "节点使用自签证书", "遭遇中间人攻击" },
                    new[] { "校准系统时间", "确认节点来源可信后，在配置中加 skip-cert-verify: true（有安全风险）" }),
                R("medium", "本地代理端口被占用", new[] { @"bind: address already in use", @"listen tcp.*bind", @"address already in use" },
                    "Clash 本地混合端口（默认 7890）被其他进程占用。",
                    new[] { "残留 Clash 进程", "其他代理软件占用同端口" },
                    new[] { "结束残留 clash 进程", "设置中更换混合端口（如 7897）" }),
                R("medium", "DNS 解析异常", new[] { @"dns.*(fail|error)", @"resolve.*fail", @"no such host" },
                    "域名解析失败，可能是 DNS 配置或污染问题。",
                    new[] { "DNS 被污染", "Clash DNS 配置错误", "节点域名失效" },
                    new[] { "启用 Clash 内置 DNS（fake-ip 模式）", "更换节点" })
            };
            foreach (var r in WinVpnRules) clashRules.Add(r);

            var ssRules = new List<Rule>
            {
                R("high", "服务器连接超时", new[] { @"timed out", @"timeout" },
                    "连接 Shadowsocks 服务器超时。",
                    new[] { "服务器宕机或 IP 被封锁", "密码/加密方式错误导致无法解密（表现为超时）", "端口被封锁" },
                    new[] { "核对密码与加密方式（如 aes-256-gcm）是否与服务器一致", "更换服务器或端口" }),
                R("high", "解密/认证失败（密码或加密方式不匹配）", new[] { @"decrypt", @"authentication failed", @"invalid address", @"bad decrypt", @"unsupported cipher" },
                    "数据无法正确解密——两端密码或加密方式不一致。",
                    new[] { "密码错误", "加密方式两端不一致", "服务端已更换加密算法" },
                    new[] { "逐项核对服务器地址、端口、密码、加密方式", "向服务商获取最新配置" }),
                R("medium", "连接被拒绝", new[] { @"connection refused" },
                    "服务器端口无服务监听。",
                    new[] { "服务端 shadowsocks 未运行", "端口填错" },
                    new[] { "联系服务商确认服务状态" }),
                R("medium", "配置文件错误", new[] { @"failed to parse", @"invalid config", @"json", @"gui-config" },
                    "配置文件解析失败。",
                    new[] { "gui-config.json 损坏", "手动编辑配置引入语法错误" },
                    new[] { "删除配置目录下 gui-config.json 让程序重建", "重新添加服务器" })
            };
            foreach (var r in WinVpnRules) ssRules.Add(r);

            var v2Rules = new List<Rule>
            {
                R("high", "无法连接服务器", new[] { @"failed to dial", @"dial tcp", @"connection refused" },
                    "V2Ray 核心无法连到服务器。",
                    new[] { "服务器宕机/IP 被封", "端口错误", "传输层配置（ws/grpc 路径等）与服务器不一致" },
                    new[] { "核对地址端口", "核对传输协议、路径、Host 等参数与服务商提供的一致", "更换节点" }),
                R("high", "用户验证失败（UUID 错误）", new[] { @"invalid user", @"user not found", @"unauthorized", @"invalid id" },
                    "服务器拒绝了客户端的身份标识。",
                    new[] { "UUID 复制错误", "alterId 不一致（VMess 旧协议）", "订阅过期" },
                    new[] { "重新从服务商处复制完整配置/订阅", "更新订阅" }),
                R("medium", "TLS/证书问题", new[] { @"x509", @"tls: ", @"handshake failure" },
                    "TLS 层握手失败。",
                    new[] { "系统时间不准", "SNI/Host 配置错误", "证书域名不匹配" },
                    new[] { "校准系统时间", "核对 SNI（serverName）与证书域名一致" }),
                R("medium", "配置文件错误", new[] { @"failed to start", @"failed to parse", @"invalid.*json", @"config.*error" },
                    "V2Ray 核心启动失败，配置有误。",
                    new[] { "config.json 语法错误", "核心版本与配置不兼容" },
                    new[] { "用订阅链接重新导入而非手改 config.json", "更新 v2rayN 及核心" })
            };
            foreach (var r in WinVpnRules) v2Rules.Add(r);

            OpenVpn = new VpnProfile
            {
                Id = "openvpn", Name = "OpenVPN",
                ExeNames = new[] { "openvpn.exe", "openvpn-gui.exe", "openvpnconnect.exe", "openvpn-connect.exe" },
                ProductKeywords = new[] { "openvpn" },
                LogDirs = new[]
                {
                    "{USER}\\OpenVPN\\log", "{PF}\\OpenVPN\\log", "{PF}\\OpenVPN\\log-auto",
                    "{PF86}\\OpenVPN\\log", "{APPDATA}\\OpenVPN Connect\\logs", "{LOCALAPPDATA}\\OpenVPN Connect\\logs"
                },
                Rules = new List<Rule>(Engine.Rules)
            };
            foreach (var r in WinVpnRules) OpenVpn.Rules.Add(r);

            All = new List<VpnProfile>
            {
                OpenVpn,
                new VpnProfile
                {
                    Id = "wireguard", Name = "WireGuard",
                    ExeNames = new[] { "wireguard.exe" },
                    ProductKeywords = new[] { "wireguard" },
                    LogDirs = new[] { "{PF}\\WireGuard\\Data\\log", "{EXEDIR}\\log", "{EXEDIR}" },
                    Rules = wgRules
                },
                new VpnProfile
                {
                    Id = "clash", Name = "Clash 系（Clash/CFW/Verge）",
                    ExeNames = new[] { "clash.exe", "clash-windows.exe", "clash for windows.exe", "clash-verge.exe", "clash-verge-service.exe", "verge.exe" },
                    ProductKeywords = new[] { "clash" },
                    LogDirs = new[] { "{EXEDIR}\\logs", "{EXEDIR}\\log", "{APPDATA}\\clash", "{APPDATA}\\clash-verge", "{APPDATA}\\io.github.clash-verge-rev.clash-verge-rev\\logs", "{LOCALAPPDATA}\\Clash for Windows", "{APPDATA}\\clash_win\\logs" },
                    Rules = clashRules
                },
                new VpnProfile
                {
                    Id = "shadowsocks", Name = "Shadowsocks",
                    ExeNames = new[] { "shadowsocks.exe" },
                    ProductKeywords = new[] { "shadowsocks" },
                    LogDirs = new[] { "{EXEDIR}", "{EXEDIR}\\logs", "{APPDATA}\\Shadowsocks" },
                    Rules = ssRules
                },
                new VpnProfile
                {
                    Id = "v2ray", Name = "V2Ray / v2rayN",
                    ExeNames = new[] { "v2ray.exe", "v2rayn.exe", "xray.exe" },
                    ProductKeywords = new[] { "v2ray", "xray" },
                    LogDirs = new[] { "{EXEDIR}", "{EXEDIR}\\logs", "{EXEDIR}\\guiLogs" },
                    Rules = v2Rules
                }
            };
        }

        // 按 exe 文件名 + 文件元数据识别 VPN 类型
        public static VpnProfile Detect(string exePath)
        {
            string fn = Path.GetFileName(exePath).ToLowerInvariant();
            string meta = fn;
            try
            {
                var fvi = FileVersionInfo.GetVersionInfo(exePath);
                meta = (fn + " " + (fvi.ProductName ?? "") + " " + (fvi.CompanyName ?? "") + " "
                    + (fvi.FileDescription ?? "") + " " + (fvi.OriginalFilename ?? "")).ToLowerInvariant();
            }
            catch { }
            foreach (var p in All)
            {
                foreach (var n in p.ExeNames)
                    if (fn == n) { p.ExeDir = Path.GetDirectoryName(exePath); return p; }
                foreach (var k in p.ProductKeywords)
                    if (meta.Contains(k)) { p.ExeDir = Path.GetDirectoryName(exePath); return p; }
            }
            return null;
        }

        // 未识别软件的通用兜底：扫描程序目录与 AppData 同名目录，只用通用规则
        public static VpnProfile MakeGeneric(string exePath)
        {
            string baseName = Path.GetFileNameWithoutExtension(exePath);
            var rules = new List<Rule>(GenericRules);
            rules.AddRange(WinVpnRules);
            return new VpnProfile
            {
                Id = "generic",
                Name = "通用模式（" + baseName + "）",
                ExeDir = Path.GetDirectoryName(exePath),
                LogDirs = new[] { "{EXEDIR}", "{EXEDIR}\\logs", "{EXEDIR}\\log", "{APPDATA}\\" + baseName, "{LOCALAPPDATA}\\" + baseName },
                Rules = rules
            };
        }

        public static List<string> ExpandDirs(VpnProfile p)
        {
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "{USER}", Environment.GetFolderPath(Environment.SpecialFolder.UserProfile) },
                { "{PF}", Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles) },
                { "{PF86}", Environment.GetEnvironmentVariable("ProgramFiles(x86)") ?? "" },
                { "{APPDATA}", Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) },
                { "{LOCALAPPDATA}", Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData) },
                { "{EXEDIR}", p.ExeDir ?? "" }
            };
            var dirs = new List<string>();
            foreach (var d in p.LogDirs)
            {
                string x = d;
                foreach (var kv in map) x = x.Replace(kv.Key, kv.Value);
                // 占位符未展开（如无 EXEDIR）或展开后非法的路径跳过
                if (string.IsNullOrEmpty(x) || x.IndexOf('{') >= 0 || x.StartsWith("\\")) continue;
                dirs.Add(x);
            }
            return dirs;
        }
    }

    // ======================= 主动检测 =======================
    class CheckResult
    {
        public string Name;
        public string Status;  // ok / warn / fail / info
        public string Detail;
        public string Advice;
    }

    static class ActiveChecks
    {
        public static List<CheckResult> Run(Meta meta)
        {
            var list = new List<CheckResult>();

            // 1. 本地网络可用性
            bool netOk = false;
            try { netOk = NetworkInterface.GetIsNetworkAvailable(); } catch { }
            list.Add(new CheckResult
            {
                Name = "本地网络连接",
                Status = netOk ? "ok" : "fail",
                Detail = netOk ? "本机网络接口正常" : "本机当前无可用网络连接",
                Advice = netOk ? "" : "检查 WiFi/网线连接，确认能正常上网后再连 VPN"
            });

            // 2. TAP/Wintun 虚拟网卡
            try
            {
                var taps = new List<NetworkInterface>();
                foreach (var ni in NetworkInterface.GetAllNetworkInterfaces())
                {
                    string d = (ni.Description ?? "") + " " + (ni.Name ?? "");
                    if (d.IndexOf("TAP", StringComparison.OrdinalIgnoreCase) >= 0
                        || d.IndexOf("Wintun", StringComparison.OrdinalIgnoreCase) >= 0
                        || d.IndexOf("OpenVPN", StringComparison.OrdinalIgnoreCase) >= 0)
                        taps.Add(ni);
                }
                if (taps.Count == 0)
                {
                    list.Add(new CheckResult { Name = "TAP/Wintun 虚拟网卡", Status = "fail", Detail = "未找到 TAP-Windows 或 Wintun 虚拟网卡", Advice = "安装/重装 OpenVPN 时勾选 TAP 驱动；或在设备管理器中确认适配器存在且已启用" });
                }
                else
                {
                    bool anyUp = false;
                    foreach (var t in taps) if (t.OperationalStatus == OperationalStatus.Up) anyUp = true;
                    list.Add(new CheckResult
                    {
                        Name = "TAP/Wintun 虚拟网卡",
                        Status = anyUp ? "ok" : "warn",
                        Detail = "找到 " + taps.Count + " 个虚拟网卡" + (anyUp ? "，状态正常" : "，但均未启用（VPN 未连接时属正常）"),
                        Advice = anyUp ? "" : "若连接时报 TAP 错误：设备管理器中启用适配器，或以管理员身份运行 OpenVPN 安装目录 bin\\addtap.bat"
                    });
                }
            }
            catch (Exception ex)
            {
                list.Add(new CheckResult { Name = "TAP/Wintun 虚拟网卡", Status = "info", Detail = "检测失败：" + ex.Message, Advice = "" });
            }

            // 3. OpenVPN 客户端进程
            try
            {
                int n = 0;
                foreach (var name in new[] { "openvpn", "openvpn-gui", "openvpnconnect", "openvpn-connect" })
                    n += Process.GetProcessesByName(name).Length;
                list.Add(new CheckResult
                {
                    Name = "OpenVPN 客户端进程",
                    Status = n > 0 ? "info" : "warn",
                    Detail = n > 0 ? ("检测到 " + n + " 个 OpenVPN 相关进程正在运行") : "未检测到运行中的 OpenVPN 客户端",
                    Advice = n > 0 ? "" : "先启动 OpenVPN 客户端并尝试连接一次，再点「重新扫描」加载最新日志"
                });
            }
            catch { }

            // 4. 系统时间校准（证书校验依赖正确时间）
            try
            {
                var req = (HttpWebRequest)WebRequest.Create("http://www.baidu.com");
                req.Method = "HEAD";
                req.Timeout = 5000;
                using (var resp = (HttpWebResponse)req.GetResponse())
                {
                    var dt = DateTime.Parse(resp.Headers["Date"]).ToUniversalTime();
                    var diff = Math.Abs((DateTime.UtcNow - dt).TotalSeconds);
                    list.Add(new CheckResult
                    {
                        Name = "系统时间校准",
                        Status = diff <= 120 ? "ok" : "fail",
                        Detail = diff <= 120 ? "系统时间准确（偏差 " + (int)diff + " 秒）" : "系统时间偏差约 " + (int)(diff / 60) + " 分钟，会导致证书校验失败",
                        Advice = diff <= 120 ? "" : "右键任务栏时钟 → 调整日期/时间 → 开启“自动设置时间”"
                    });
                }
            }
            catch
            {
                list.Add(new CheckResult { Name = "系统时间校准", Status = "info", Detail = "无法访问校时服务器，跳过（离线环境请自行确认系统时间正确）", Advice = "" });
            }

            // 5. 服务器域名解析（仅当服务器是域名时）
            if (!string.IsNullOrEmpty(meta.Server) && !Regex.IsMatch(meta.Server, @"^[\d.]+$|^[0-9a-fA-F:]+$"))
            {
                try
                {
                    var addrs = Dns.GetHostAddresses(meta.Server);
                    list.Add(new CheckResult
                    {
                        Name = "服务器域名解析",
                        Status = addrs.Length > 0 ? "ok" : "fail",
                        Detail = addrs.Length > 0 ? (meta.Server + " → " + addrs[0]) : "解析结果为空",
                        Advice = addrs.Length > 0 ? "" : "更换 DNS 为 223.5.5.5 / 119.29.29.29，或在配置中改用 IP 直连"
                    });
                }
                catch (Exception ex)
                {
                    list.Add(new CheckResult { Name = "服务器域名解析", Status = "fail", Detail = meta.Server + " 解析失败：" + ex.Message, Advice = "更换 DNS 为 223.5.5.5 / 119.29.29.29，或在配置中改用 IP 直连" });
                }
            }

            // 6. 服务器 TCP 端口连通性
            int port;
            if (!string.IsNullOrEmpty(meta.Server) && int.TryParse(meta.Port, out port))
            {
                bool udpNote = meta.Proto == "UDP";
                try
                {
                    var sw = Stopwatch.StartNew();
                    using (var tc = new TcpClient())
                    {
                        var ar = tc.BeginConnect(meta.Server, port, null, null);
                        bool ok = ar.AsyncWaitHandle.WaitOne(4000);
                        sw.Stop();
                        if (ok && tc.Client != null && tc.Client.Connected)
                        {
                            list.Add(new CheckResult { Name = "服务器端口连通性", Status = "ok", Detail = meta.Server + ":" + port + " TCP 可连通（" + sw.ElapsedMilliseconds + " ms）", Advice = "" });
                        }
                        else
                        {
                            list.Add(new CheckResult
                            {
                                Name = "服务器端口连通性",
                                Status = udpNote ? "warn" : "fail",
                                Detail = meta.Server + ":" + port + " TCP 连接超时/被拒" + (udpNote ? "（日志显示走 UDP，此端口无 TCP 服务属正常现象，不代表 UDP 一定不通）" : ""),
                                Advice = udpNote ? "UDP 无法从外部直接探测；若 UDP 持续握手失败，大概率被干扰，建议改 TCP 443" : "确认服务器在线、端口正确；或改试 TCP 443 端口"
                            });
                        }
                    }
                }
                catch (Exception ex)
                {
                    list.Add(new CheckResult { Name = "服务器端口连通性", Status = "warn", Detail = "测试 " + meta.Server + ":" + port + " 时出错：" + ex.Message, Advice = "" });
                }
            }

            return list;
        }
    }

    // ======================= HTML 报告渲染 =======================
    static class HtmlReport
    {
        static string Esc(string s)
        {
            return s.Replace("&", "&amp;").Replace("<", "&lt;").Replace(">", "&gt;").Replace("\"", "&quot;");
        }

        static string Li(string[] arr)
        {
            var sb = new StringBuilder("<ul>");
            foreach (var s in arr) sb.Append("<li>").Append(Esc(s)).Append("</li>");
            return sb.Append("</ul>").ToString();
        }

        public static string Head()
        {
            return @"<!DOCTYPE html><html lang='zh-CN'><head><meta http-equiv='X-UA-Compatible' content='IE=edge'><meta charset='utf-8'><style>
*{box-sizing:border-box}body{margin:0;padding:2px 6px 12px 0;font:14px/1.7 'Microsoft YaHei UI','Microsoft YaHei',sans-serif;color:#192f40;background:#edf2f5;word-wrap:break-word}
.summary,.card,.hint{background:#fff;border:1px solid #c5d4dc;border-radius:6px;margin:0 0 12px}
.summary{background:#173447;color:#f5fafb;padding:16px 20px}.summary h2,.hint h2{font-size:20px;line-height:1.4;margin:0 0 8px}
.counts{font-size:13px;color:#c6e2e8}.meta{border-top:1px solid #456170;padding-top:8px;margin-top:10px;color:#d4e7ec}
.head{padding:10px 16px;font-weight:bold;font-size:15px;border-bottom:1px solid #dce5ea}
.body{padding:12px 16px}.badge{display:inline-block;vertical-align:middle;font-size:12px;line-height:20px;padding:0 7px;border-radius:3px;margin-right:8px}
.sev-high .badge,.fail{background:#f9deda;color:#832d2a}.sev-medium .badge,.warn{background:#faebcc;color:#744a11}
.sev-low .badge,.info{background:#e0ebf7;color:#254e73}.sev-info .badge,.ok{background:#d8eee6;color:#205b4a}
h4{font-size:14px;margin:15px 0 3px;color:#254f62}ul{margin:4px 0;padding-left:21px}li{margin:3px 0}
pre,.logline{white-space:pre-wrap;word-wrap:break-word;background:#f2f6f8;border-left:3px solid #75919e;padding:8px 12px;font:13px/1.6 Consolas,monospace}
.hint{padding:26px 20px;border-top:3px solid #247687;color:#435e6b}.hint h2{color:#173447}.hint p{margin:4px 0}kbd{font:12px Consolas,monospace;background:#edf2f5;padding:3px 5px}
table{border-collapse:collapse;width:100%}td{vertical-align:top;border-bottom:1px solid #dce5ea;padding:8px 4px}td:first-child{width:36%}.advice{color:#755015}
</style></head><body>";
        }

        public static string Hint()
        {
            return Head() + "<div class=\"hint\"><h2>等待诊断</h2><p>粘贴或导入日志后，点击「开始诊断」或按 <kbd>Ctrl + Enter</kbd>。</p></div></body></html>";
        }

        public static string Render(Result res, List<CheckResult> checks, bool checking)
        {
            var sb = new StringBuilder(Head());
            var meta = res.Meta;
            var issues = res.Issues;
            int nh = 0, nm = 0, nl = 0;
            foreach (var it in issues)
            {
                if (it.Rule.Severity == "high") nh++;
                else if (it.Rule.Severity == "medium") nm++;
                else nl++;
            }

            sb.Append("<div class='summary'><h2>").Append(issues.Count == 0 ? "未发现已知故障" : "发现 " + issues.Count + " 类问题")
              .Append("</h2><div class='counts'>严重 ").Append(nh).Append(" &nbsp; / &nbsp; 警告 ").Append(nm)
              .Append(" &nbsp; / &nbsp; 提示 ").Append(nl).Append("</div>");
            var bits = new List<string>();
            if (meta.Proto.Length > 0) bits.Add("协议：" + meta.Proto);
            if (meta.Server.Length > 0) bits.Add("服务器：" + meta.Server + (meta.Port.Length > 0 ? ":" + meta.Port : ""));
            if (meta.Restarts > 0) bits.Add("自动重启重试：" + meta.Restarts + " 次（持续性故障，非偶发抖动）");
            if (meta.IsConfig) bits.Add("检测到配置内容，已做交叉检查");
            if (bits.Count > 0) sb.Append("<div class='meta'>").Append(Esc(string.Join("　·　", bits.ToArray()))).Append("</div>");
            sb.Append("</div>");

            // 主动检测结果卡片
            if (checking)
            {
                sb.Append("<div class=\"card\"><div class=\"head\">主动检测</div>")
                  .Append("<div class=\"body\"><span>正在进行本机与网络探测（网卡 / 进程 / 系统时间 / DNS / 端口连通性）…</span></div></div>");
            }
            else if (checks != null && checks.Count > 0)
            {
                sb.Append("<div class=\"card\"><div class=\"head\">主动检测结果</div>")
                  .Append("<div class=\"body\"><table>");
                foreach (var c in checks)
                {
                    string label = c.Status == "ok" ? "正常" : c.Status == "warn" ? "注意" : c.Status == "fail" ? "异常" : "信息";
                    sb.Append("<tr><td><span class='badge ").Append(Esc(c.Status)).Append("'>").Append(label)
                      .Append("</span>").Append(Esc(c.Name)).Append("</td><td>").Append(Esc(c.Detail));
                    if (!string.IsNullOrEmpty(c.Advice))
                        sb.Append("<br><span class='advice'>建议：").Append(Esc(c.Advice)).Append("</span>");
                    sb.Append("</td></tr>");
                }
                sb.Append("</table></div></div>");
            }

            if (issues.Count == 0)
            {
                sb.Append("<div class=\"card sev-info\"><div class=\"head\"><span class=\"badge\">说明</span>未匹配到已知故障模式</div>")
                  .Append("<div class=\"body\">日志中没有命中规则库中的故障特征。建议把 OpenVPN 配置中的 verb 调为 4 复现一次以获取更详细日志，再粘贴分析。</div></div>");
            }

            var sevLabel = new Dictionary<string, string> { { "high", "严重" }, { "medium", "警告" }, { "low", "提示" }, { "info", "说明" } };
            foreach (var it in issues)
            {
                var r = it.Rule;
                sb.Append("<div class=\"card sev-").Append(r.Severity).Append("\">");
                sb.Append("<div class=\"head\"><span class=\"badge\">").Append(sevLabel[r.Severity]).Append("</span>").Append(Esc(r.Title)).Append("</div>");
                sb.Append("<div class=\"body\">");
                if (it.Line.Length > 0) sb.Append("<div class=\"logline\">命中日志：").Append(Esc(it.Line)).Append("</div>");
                sb.Append("<h4>问题说明</h4><div>").Append(Esc(r.Why)).Append("</div>");
                if (r.Causes != null && r.Causes.Length > 0) sb.Append("<h4>可能原因</h4>").Append(Li(r.Causes));
                if (r.Fixes != null && r.Fixes.Length > 0) sb.Append("<h4>解决方案</h4>").Append(Li(r.Fixes));
                if (!string.IsNullOrEmpty(r.Config)) sb.Append("<h4>配置示例</h4><pre>").Append(Esc(r.Config)).Append("</pre>");
                sb.Append("</div></div>");
            }

            // 通用排查清单
            sb.Append("<div class=\"card sev-info\"><div class=\"head\"><span class=\"badge\">说明</span>通用排查清单</div><div class=\"body\">")
              .Append(Li(new[]
              {
                  "始终以管理员身份运行 OpenVPN",
                  "连接优先尝试 TCP 443 端口，被封锁的概率最低",
                  "确保系统日期时间正确，否则证书校验会误报",
                  "把 OpenVPN 客户端升级到最新版",
                  "排查时把配置里的 verb 调到 4，获取更详细日志"
              }))
              .Append("</div></div>");

            return sb.Append("</body></html>").ToString();
        }
    }

    // ======================= 日志来源 =======================
    class LogSource
    {
        public string Path;
        public DateTime Modified;
        public VpnProfile Profile;
        public override string ToString()
        {
            string tag = Profile != null ? "[" + Profile.Name + "] " : "";
            return tag + System.IO.Path.GetFileName(Path) + "  (" + Modified.ToString("MM-dd HH:mm") + ")";
        }
    }

    // ======================= 主窗口 =======================
    class MainForm : Form
    {
        TextBox logInput;
        WebBrowser report;
        Button btnAnalyze, btnImport, btnSample, btnClear, btnRescan, btnSelectVpn;
        ComboBox comboLogs;
        ToolStripStatusLabel statusLabel;
        List<LogSource> logSources = new List<LogSource>();
        VpnProfile currentProfile = Profiles.OpenVpn;

        static readonly string SAMPLE_LOG =
            "Wed Sep 16 17:01:25 2026 WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm for more info.\n" +
            "Wed Sep 16 17:01:25 2026 TCP/UDP: Preserving recently used remote address: [AF_INET]39.175.58.175:1341\n" +
            "Wed Sep 16 17:01:25 2026 UDP link local (bound): [AF_INET][undef]:1194\n" +
            "Wed Sep 16 17:01:25 2026 UDP link remote: [AF_INET]39.175.58.175:1341\n" +
            "Wed Sep 16 17:02:25 2026 TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)\n" +
            "Wed Sep 16 17:02:25 2026 TLS Error: TLS handshake failed\n" +
            "Wed Sep 16 17:02:25 2026 SIGUSR1[soft,tls-error] received, process restarting\n" +
            "Wed Sep 16 17:02:35 2026 WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm for more info.\n" +
            "Wed Sep 16 17:02:35 2026 TCP/UDP: Preserving recently used remote address: [AF_INET]39.175.58.175:1341\n" +
            "Wed Sep 16 17:02:35 2026 UDP link local (bound): [AF_INET][undef]:1194\n" +
            "Wed Sep 16 17:02:35 2026 UDP link remote: [AF_INET]39.175.58.175:1341";

        public MainForm()
        {
            Text = "VPN Doctor · 连接诊断助手";
            ClientSize = new Size(1180, 750);
            MinimumSize = new Size(900, 600);
            StartPosition = FormStartPosition.CenterScreen;
            Font = new Font("Microsoft YaHei UI", 9f);
            BackColor = Canvas;

            var root = new TableLayoutPanel { Dock = DockStyle.Fill, RowCount = 3, ColumnCount = 1 };
            root.RowStyles.Add(new RowStyle(SizeType.Absolute, 72));
            root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            Controls.Add(root);

            var header = new FlowLayoutPanel { Dock = DockStyle.Fill, BackColor = Ink, Margin = Padding.Empty,
                Padding = new Padding(20, 16, 16, 10), WrapContents = false };
            header.Controls.Add(new Label { Text = "VPN Doctor", AutoSize = true, ForeColor = Color.White,
                Font = new Font("Segoe UI", 19f, FontStyle.Bold), Margin = new Padding(0, 0, 16, 0) });
            header.Controls.Add(new Label { Text = "连接诊断助手", AutoSize = true, ForeColor = Color.FromArgb(187, 221, 226),
                Font = new Font(Font.FontFamily, 11f), Margin = new Padding(0, 10, 0, 0) });
            root.Controls.Add(header, 0, 0);

            var workspace = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 2, RowCount = 1,
                Padding = new Padding(12), Margin = Padding.Empty };
            workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 40));
            workspace.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 60));
            workspace.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            root.Controls.Add(workspace, 0, 1);

            var input = new TableLayoutPanel { Dock = DockStyle.Fill, BackColor = Color.White, ColumnCount = 1, RowCount = 7,
                Margin = new Padding(0, 0, 6, 0), Padding = new Padding(14) };
            input.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
            for (int i = 0; i < 7; i++)
                input.RowStyles.Add(i == 5 ? new RowStyle(SizeType.Percent, 100) : new RowStyle(SizeType.AutoSize));
            workspace.Controls.Add(input, 0, 0);

            input.Controls.Add(SectionTitle("日志来源"), 0, 0);
            comboLogs = new ComboBox { Dock = DockStyle.Fill, AccessibleName = "日志来源", DropDownStyle = ComboBoxStyle.DropDownList };
            input.Controls.Add(comboLogs, 0, 1);
            btnRescan = MakeButton("重新扫描", false);
            btnSelectVpn = MakeButton("选择 VPN 程序…", false);
            input.Controls.Add(ActionRow(btnRescan, btnSelectVpn), 0, 2);
            input.Controls.Add(SectionTitle("日志内容"), 0, 3);
            btnImport = MakeButton("导入文件…", false);
            btnSample = MakeButton("载入示例", false);
            btnClear = MakeButton("清空", false);
            input.Controls.Add(ActionRow(btnImport, btnSample, btnClear), 0, 4);
            logInput = new TextBox { Dock = DockStyle.Fill, Multiline = true, ScrollBars = ScrollBars.Vertical,
                AccessibleName = "日志内容", AcceptsReturn = true, Font = new Font("Consolas", 10f),
                BackColor = Ink, ForeColor = Color.FromArgb(224, 239, 241), BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(3, 4, 3, 10) };
            input.Controls.Add(logInput, 0, 5);
            btnAnalyze = MakeButton("开始诊断", true);
            btnAnalyze.Dock = DockStyle.Fill;
            input.Controls.Add(btnAnalyze, 0, 6);

            var results = new TableLayoutPanel { Dock = DockStyle.Fill, ColumnCount = 1, RowCount = 2,
                Margin = new Padding(6, 0, 0, 0) };
            results.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            results.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
            results.Controls.Add(SectionTitle("诊断报告"), 0, 0);
            report = new WebBrowser { Dock = DockStyle.Fill, AccessibleName = "诊断报告",
                Margin = Padding.Empty, ScriptErrorsSuppressed = true, IsWebBrowserContextMenuEnabled = false, AllowWebBrowserDrop = false };
            results.Controls.Add(report, 0, 1);
            workspace.Controls.Add(results, 1, 0);

            var status = new StatusStrip { Dock = DockStyle.Fill, BackColor = Color.White, ForeColor = Ink };
            statusLabel = new ToolStripStatusLabel("就绪") { Spring = true, TextAlign = ContentAlignment.MiddleLeft };
            status.Items.Add(statusLabel);
            root.Controls.Add(status, 0, 2);

            // 事件
            btnAnalyze.Click += (s, e) => DoAnalyze();
            btnSample.Click += (s, e) => { logInput.Text = SAMPLE_LOG; statusLabel.Text = "示例日志"; DoAnalyze(); };
            btnClear.Click += (s, e) => { logInput.Clear(); statusLabel.Text = "就绪"; report.DocumentText = HtmlReport.Hint(); };
            btnImport.Click += (s, e) => ImportFile();
            btnRescan.Click += (s, e) => AutoScan(true);
            btnSelectVpn.Click += (s, e) => SelectVpnExe();
            comboLogs.SelectedIndexChanged += (s, e) =>
            {
                var src = comboLogs.SelectedItem as LogSource;
                if (src != null) LoadSource(src);
            };
            logInput.KeyDown += (s, e) => { if (e.Control && e.KeyCode == Keys.Enter) { DoAnalyze(); e.SuppressKeyPress = true; } };

            Shown += (s, e) => { report.DocumentText = HtmlReport.Hint(); AutoScan(false); };
        }

        static readonly Color Ink = Color.FromArgb(23, 52, 71);
        static readonly Color Canvas = Color.FromArgb(237, 242, 245);
        static readonly Color Accent = Color.FromArgb(19, 99, 111);

        Label SectionTitle(string title)
        {
            return new Label { Text = title, AutoSize = true, ForeColor = Ink, Font = new Font(Font.FontFamily, 12f, FontStyle.Bold),
                Margin = new Padding(2, 5, 2, 8) };
        }

        FlowLayoutPanel ActionRow(params Button[] buttons)
        {
            var row = new FlowLayoutPanel { Dock = DockStyle.Fill, AutoSize = true, Margin = Padding.Empty, WrapContents = true };
            row.Controls.AddRange(buttons);
            return row;
        }

        Button MakeButton(string text, bool primary)
        {
            var b = new Button { Text = text, AutoSize = true, MinimumSize = new Size(0, 33), Padding = new Padding(8, 3, 8, 3),
                FlatStyle = FlatStyle.Flat, BackColor = primary ? Accent : Color.White, ForeColor = primary ? Color.White : Ink,
                Margin = new Padding(3, 3, 4, 5), UseVisualStyleBackColor = false };
            b.FlatAppearance.BorderColor = primary ? Accent : Color.FromArgb(166, 188, 199);
            b.FlatAppearance.MouseOverBackColor = primary ? Color.FromArgb(15, 80, 90) : Canvas;
            return b;
        }

        void DoAnalyze()
        {
            var text = logInput.Text;
            if (string.IsNullOrWhiteSpace(text))
            {
                report.DocumentText = HtmlReport.Head() + "<div class=\"hint\">请先粘贴日志内容，或点击「导入日志文件…」/「载入示例日志」。</div></body></html>";
                return;
            }
            var res = Engine.Analyze(text, currentProfile.Rules);
            // 先展示日志诊断结果，再后台执行主动检测，避免界面卡死
            report.DocumentText = HtmlReport.Render(res, null, true);
            btnAnalyze.Enabled = false;
            var meta = res.Meta;
            var th = new System.Threading.Thread(delegate()
            {
                var checks = ActiveChecks.Run(meta);
                try
                {
                    Invoke(new Action(delegate()
                    {
                        report.DocumentText = HtmlReport.Render(res, checks, false);
                        btnAnalyze.Enabled = true;
                    }));
                }
                catch { }
            });
            th.IsBackground = true;
            th.Start();
        }

        void ImportFile()
        {
            using (var dlg = new OpenFileDialog())
            {
                dlg.Title = "选择 OpenVPN 日志或配置文件";
                dlg.Filter = "日志/配置文件|*.log;*.txt;*.ovpn;*.conf|所有文件|*.*";
                if (dlg.ShowDialog() == DialogResult.OK)
                {
                    try
                    {
                        using (var sr = new StreamReader(dlg.FileName, Encoding.UTF8, true))
                            logInput.Text = sr.ReadToEnd();
                        statusLabel.Text = "已导入 " + dlg.FileName;
                        DoAnalyze();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show("读取文件失败：" + ex.Message, "错误", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        // ======================= 自动扫描本机日志 =======================
        void ShowSources(List<LogSource> sources)
        {
            logSources = sources;
            comboLogs.Items.Clear();
            comboLogs.Enabled = sources.Count > 0;
            foreach (var source in sources) comboLogs.Items.Add(source);
            if (sources.Count == 0) comboLogs.Items.Add("未找到本机日志");
            comboLogs.SelectedIndex = 0;
        }

        void AutoScan(bool manual)
        {
            var list = new List<LogSource>();
            foreach (var p in Profiles.All) ScanInto(p, list);
            list.Sort((a, b) => b.Modified.CompareTo(a.Modified));
            ShowSources(list);
            if (logSources.Count > 0)
            {
                statusLabel.Text = "已自动加载最新日志（共找到 " + logSources.Count + " 个日志文件）";
            }
            else
            {
                statusLabel.Text = "未找到本机 VPN 日志，可点「选择VPN程序…」指定客户端位置，或手动粘贴日志";
                if (manual)
                    report.DocumentText = HtmlReport.Head() + "<div class=\"hint\">未找到本机 VPN 日志。已扫描 OpenVPN / WireGuard / Clash / Shadowsocks / V2Ray 的常见日志位置。<br>如果日志不在默认位置，点「选择VPN程序…」指定客户端 exe 后自动定位；或手动粘贴日志后点击「开始诊断」。</div></body></html>";
            }
        }

        // 按资料库的日志目录扫描（log 目录同时收 *.log 与 *.txt）
        void ScanInto(VpnProfile p, List<LogSource> into)
        {
            foreach (var d in Profiles.ExpandDirs(p))
            {
                try
                {
                    if (!Directory.Exists(d)) continue;
                    bool isLogDir = d.IndexOf("log", StringComparison.OrdinalIgnoreCase) >= 0;
                    var patterns = isLogDir ? new[] { "*.log", "*.txt" } : new[] { "*.log" };
                    foreach (var pat in patterns)
                    {
                        foreach (var f in Directory.GetFiles(d, pat))
                        {
                            var fi = new FileInfo(f);
                            into.Add(new LogSource { Path = f, Modified = fi.LastWriteTime, Profile = p });
                        }
                    }
                }
                catch { }
            }
        }

        // 用户手动选择 VPN 客户端 exe → 识别类型 → 按其资料库扫描日志
        void SelectVpnExe()
        {
            using (var ofd = new OpenFileDialog { Filter = "VPN 客户端程序 (*.exe)|*.exe", Title = "选择 VPN 客户端程序" })
            {
                if (ofd.ShowDialog() != DialogResult.OK) return;
                var prof = Profiles.Detect(ofd.FileName);
                if (prof == null)
                {
                    prof = Profiles.MakeGeneric(ofd.FileName);
                    statusLabel.Text = "未识别的 VPN 程序，已按通用模式扫描其安装目录与 AppData";
                }
                else
                {
                    statusLabel.Text = "已识别：" + prof.Name;
                }
                currentProfile = prof;
                var found = new List<LogSource>();
                ScanInto(prof, found);
                found.Sort((a, b) => b.Modified.CompareTo(a.Modified));
                ShowSources(found);
                if (logSources.Count > 0)
                {
                    statusLabel.Text += "，已加载最新日志";
                }
                else
                {
                    statusLabel.Text += "，但未找到日志——请先运行一次该 VPN 产生日志，或手动粘贴日志后点「开始诊断」";
                }
            }
        }

        void LoadSource(LogSource src)
        {
            try
            {
                if (src.Profile != null) currentProfile = src.Profile;
                string log = ReadFileSafe(src.Path);
                string text = log;
                string cfg = null;
                // 仅 OpenVPN 做 .ovpn 配置交叉检查
                if (src.Profile != null && src.Profile.Id == "openvpn")
                {
                    string cfgPath;
                    cfg = FindConfig(Path.GetFileNameWithoutExtension(src.Path), out cfgPath);
                    if (cfg != null)
                        text += "\n\n# ===== 关联配置 " + cfgPath + " =====\n" + cfg;
                }
                logInput.Text = text;
                statusLabel.Text = "已加载: " + src.Path + "（" + src.Modified.ToString("yyyy-MM-dd HH:mm") + "）"
                    + "　特征库: " + currentProfile.Name
                    + (cfg != null ? "　+ 已关联配置交叉检查" : "");
                DoAnalyze();
            }
            catch (Exception ex)
            {
                statusLabel.Text = "读取日志失败：" + ex.Message;
            }
        }

        string ReadFileSafe(string path)
        {
            // OpenVPN 运行时日志可能被占用，需以共享方式打开
            using (var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete))
            using (var sr = new StreamReader(fs, Encoding.UTF8, true))
                return sr.ReadToEnd();
        }

        // 优先匹配同名配置（日志名与配置名一致），否则取最新修改的配置
        string FindConfig(string baseName, out string foundPath)
        {
            foundPath = null;
            string up = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            string pf = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string pfx86 = Environment.GetEnvironmentVariable("ProgramFiles(x86)");
            var dirs = new List<string>
            {
                Path.Combine(up, "OpenVPN", "config"),
                Path.Combine(pf, "OpenVPN", "config"),
                Path.Combine(pf, "OpenVPN", "config-auto")
            };
            if (!string.IsNullOrEmpty(pfx86)) dirs.Add(Path.Combine(pfx86, "OpenVPN", "config"));
            var all = new List<string>();
            foreach (var d in dirs)
            {
                try
                {
                    if (!Directory.Exists(d)) continue;
                    all.AddRange(Directory.GetFiles(d, "*.ovpn", SearchOption.AllDirectories));
                }
                catch { }
            }
            if (all.Count == 0) return null;
            string match = null;
            foreach (var f in all)
            {
                if (string.Equals(Path.GetFileNameWithoutExtension(f), baseName, StringComparison.OrdinalIgnoreCase)) { match = f; break; }
            }
            if (match == null)
            {
                all.Sort((a, b) => File.GetLastWriteTime(b).CompareTo(File.GetLastWriteTime(a)));
                match = all[0];
            }
            foundPath = match;
            try { return ReadFileSafe(match); } catch { return null; }
        }
    }

    // ======================= 自检（--selftest） =======================
    static class SelfTest
    {
        static int fails = 0;
        static StringBuilder sb = new StringBuilder();

        static void Assert(bool cond, string msg)
        {
            sb.AppendLine((cond ? "PASS: " : "FAIL: ") + msg);
            if (!cond) fails++;
        }

        public static int Run()
        {
            string sample = string.Join("\n", new[]
            {
                "Wed Sep 16 17:01:25 2026 WARNING: No server certificate verification method has been enabled.  See http://openvpn.net/howto.html#mitm for more info.",
                "Wed Sep 16 17:01:25 2026 TCP/UDP: Preserving recently used remote address: [AF_INET]39.175.58.175:1341",
                "Wed Sep 16 17:01:25 2026 UDP link local (bound): [AF_INET][undef]:1194",
                "Wed Sep 16 17:01:25 2026 UDP link remote: [AF_INET]39.175.58.175:1341",
                "Wed Sep 16 17:02:25 2026 TLS Error: TLS key negotiation failed to occur within 60 seconds (check your network connectivity)",
                "Wed Sep 16 17:02:25 2026 TLS Error: TLS handshake failed",
                "Wed Sep 16 17:02:25 2026 SIGUSR1[soft,tls-error] received, process restarting",
                "Wed Sep 16 17:02:35 2026 UDP link remote: [AF_INET]39.175.58.175:1341"
            });

            var r = Engine.Analyze(sample);
            sb.AppendLine("META: server=" + r.Meta.Server + " port=" + r.Meta.Port + " proto=" + r.Meta.Proto + " restarts=" + r.Meta.Restarts);
            foreach (var i in r.Issues) sb.AppendLine("[" + i.Rule.Severity + "] " + i.Rule.Id);

            bool hasTls = false, hasCert = false;
            Rule tlsRule = null;
            foreach (var i in r.Issues)
            {
                if (i.Rule.Id == "TLS_HANDSHAKE_FAILED") { hasTls = true; tlsRule = i.Rule; }
                if (i.Rule.Id == "CERT_VERIFY_MISSING") hasCert = true;
            }
            Assert(hasTls, "检出 TLS 握手失败");
            Assert(hasCert, "检出缺少证书验证");
            Assert(r.Meta.Proto == "UDP", "协议识别为 UDP (实际:" + r.Meta.Proto + ")");
            Assert(r.Meta.Server == "39.175.58.175", "服务器 IP 识别 (实际:" + r.Meta.Server + ")");
            Assert(r.Meta.Port == "1341", "端口识别为 1341 (实际:" + r.Meta.Port + ")");
            Assert(r.Meta.Restarts == 1, "重启次数为 1 (实际:" + r.Meta.Restarts + ")");
            Assert(tlsRule != null && tlsRule.Fixes[0].Contains("针对您的日志"), "UDP 定向建议已注入");
            Assert(r.Issues.Count > 0 && r.Issues[0].Rule.Severity == "high", "严重级别排在最前");

            string cfg = string.Join("\n", new[] { "client", "dev tun", "proto udp", "remote vpn.example.com 1194", "ca ca.crt", "cert c.crt", "key c.key", "cipher BF-CBC" });
            var r2 = Engine.Analyze(cfg);
            bool hasCert2 = false, hasCipher = false;
            foreach (var i in r2.Issues)
            {
                if (i.Rule.Id == "CERT_VERIFY_MISSING") hasCert2 = true;
                if (i.Rule.Id == "CIPHER_MISMATCH") hasCipher = true;
            }
            Assert(hasCert2, "配置缺 remote-cert-tls 应告警");
            Assert(hasCipher, "BF-CBC 弱算法应告警");
            Assert(r2.Meta.IsConfig, "识别为配置内容");

            var noProto = Engine.GetMeta("client\r\nremote vpn.example.com 1194\r\nca ca.crt\r\n");
            Assert(noProto.IsConfig && noProto.Server == "vpn.example.com" && noProto.Port == "1194", "CRLF 配置正确识别服务器");
            Assert(noProto.Proto == "", "remote 未指定协议时不能吞入下一行 ca");
            var remoteOverride = Engine.GetMeta("client\nproto udp\nremote vpn.example.com 443 tcp6\nca ca.crt\n");
            Assert(remoteOverride.Proto == "TCP", "remote 的 tcp6 覆盖全局 udp 并归一化为 TCP");
            var udp6 = Engine.GetMeta("client\nproto udp6\nremote vpn.example.com 1194\n");
            Assert(udp6.Proto == "UDP", "全局 udp6 归一化为 UDP");
            var ipv6 = Engine.GetMeta("UDPv6 link remote: [AF_INET6][2001:db8::1]:1194");
            Assert(ipv6.Server == "2001:db8::1" && ipv6.Port == "1194" && ipv6.Proto == "UDP", "IPv6 日志识别地址、端口及协议");
            var commented = Engine.Analyze("client\nremote vpn.example.com 443\n# remote-cert-tls server\n; verify-x509-name vpn.example.com name\n");
            Assert(commented.Issues.Exists(i => i.Rule.Id == "CERT_VERIFY_MISSING"), "注释里的证书验证指令不能抑制告警");
            var verified = Engine.Analyze("client\nremote vpn.example.com 443\nremote-cert-tls server\n");
            Assert(!verified.Issues.Exists(i => i.Rule.Id == "CERT_VERIFY_MISSING"), "启用服务器证书验证后不误报");
            var named = Engine.Analyze("client\nremote vpn.example.com 443\nverify-x509-name vpn.example.com name\n");
            Assert(!named.Issues.Exists(i => i.Rule.Id == "CERT_VERIFY_MISSING"), "启用证书名称验证后不误报");

            var ok = Engine.Analyze("Wed Sep 16 17:01:25 2026 Initialization Sequence Completed");
            Assert(ok.Issues.Count == 0, "正常日志不应命中 (实际:" + ok.Issues.Count + ")");

            // 主动检测模块冒烟（不应抛异常，且至少包含基础检查项）
            try
            {
                var checks = ActiveChecks.Run(new Meta { Server = "127.0.0.1", Port = "9", Proto = "UDP" });
                Assert(checks.Count >= 4, "主动检测返回 " + checks.Count + " 项（应≥4）");
                bool hasNet = false, hasTime = false, hasTcp = false;
                foreach (var c in checks)
                {
                    if (c.Name == "本地网络连接") hasNet = true;
                    if (c.Name == "系统时间校准") hasTime = true;
                    if (c.Name == "服务器端口连通性") hasTcp = true;
                }
                Assert(hasNet && hasTime && hasTcp, "主动检测包含 网络/时间/端口 检查项");
            }
            catch (Exception ex)
            {
                Assert(false, "主动检测抛异常：" + ex.Message);
            }

            // 多 VPN 识别与各特征库
            Assert(Profiles.Detect(@"C:\x\wireguard.exe") != null && Profiles.Detect(@"C:\x\wireguard.exe").Id == "wireguard", "按文件名识别 WireGuard");
            Assert(Profiles.Detect(@"C:\x\openvpn-gui.exe") != null && Profiles.Detect(@"C:\x\openvpn-gui.exe").Id == "openvpn", "按文件名识别 OpenVPN");
            Assert(Profiles.Detect(@"C:\x\clash-verge.exe") != null && Profiles.Detect(@"C:\x\clash-verge.exe").Id == "clash", "按文件名识别 Clash Verge");
            Assert(Profiles.Detect(@"C:\x\whatever.exe") == null, "未知程序应返回 null 进入通用模式");
            var wg = Profiles.All.Find(p => p.Id == "wireguard");
            var wr = Engine.Analyze("[TUN] Handshake for peer 1 (1.2.3.4:51820) did not complete after 5 seconds, retrying", wg.Rules);
            Assert(wr.Issues.Count >= 1, "WireGuard 握手失败应命中 (实际:" + wr.Issues.Count + ")");
            var cr = Engine.Analyze("time=\"2026-09-16\" level=warning msg=\"[TCP] dial proxy: connect: connection refused\"", Profiles.All.Find(p => p.Id == "clash").Rules);
            Assert(cr.Issues.Count >= 1, "Clash 连接拒绝应命中");
            var gr = Engine.Analyze("连接 VPN 时远程计算机没有响应，错误 809", Profiles.MakeGeneric(@"C:\x\foo.exe").Rules);
            Assert(gr.Issues.Count >= 1, "Windows 错误 809 应命中通用库 (实际:" + gr.Issues.Count + ")");

            sb.AppendLine(fails == 0 ? "=== 全部通过 ===" : ("=== 失败 " + fails + " 项 ==="));
            string outPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "selftest_result.txt");
            File.WriteAllText(outPath, sb.ToString(), Encoding.UTF8);
            return fails == 0 ? 0 : 1;
        }
    }

    static class Program
    {
        [STAThread]
        static int Main(string[] args)
        {
            if (args.Length > 0 && args[0] == "--selftest")
                return SelfTest.Run();

            // 让 WebBrowser 控件以 IE11 模式渲染（仅影响本程序）
            try
            {
                Registry.SetValue(
                    @"HKEY_CURRENT_USER\Software\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_BROWSER_EMULATION",
                    Process.GetCurrentProcess().ProcessName + ".exe", 11001, RegistryValueKind.DWord);
            }
            catch { }

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new MainForm());
            return 0;
        }
    }
}
