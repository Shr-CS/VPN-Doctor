# VPN-Doctor

Windows VPN 日志诊断助手，使用 C# 和 WinForms 编写。支持粘贴或导入日志、识别常见 VPN 客户端，并生成诊断建议与主动网络检查结果。

## 从源码构建

在安装了 .NET Framework 4.x 的 Windows 上，打开 PowerShell：

```powershell
.\build.ps1
.\build\VPNDoctor.exe
```

运行内置回归测试：

```powershell
.\build.ps1 -Test
```

测试结果写入 `build/selftest_result.txt`。测试包含规则命中、配置解析、IPv6 地址识别与证书验证设置检查；主动检测会访问校时服务并检查本机网络。GitHub Actions 在 Windows 上自动编译并运行同一组测试，构建产物可在对应 Actions 运行的 Artifacts 中下载。

仓库根目录的 `VPN诊断助手.exe` 是原有预编译版本。源码修改后请使用 `build/` 中新生成的程序或下载对应提交的 Actions 构建产物。

## OpenVPN 配置解析

`remote` 参数仅在同一行内解析，支持 `tcp4/tcp6/udp4/udp6`，显式的 `remote` 协议优先于全局 `proto`。IPv6 日志可识别 `[AF_INET6][地址]:端口`。注释里的证书验证设置不会被当成已启用。

协议选项参考 [OpenVPN 官方手册](https://openvpn.net/community-docs/community-articles/openvpn-2-6-manual/)。
