# Linux.do Accelerator — iOS

iPhone 版加速器。**0.2.0 起改为本地 TLS 终止 + ECH 代理架构**（与桌面版一致），所有浏览器都可用，
不再只有 Safari：

- 接管域名（`linux.do` / `idcflare.com`）通过隧道 DNS 解析到 `127.0.0.1`
- 浏览器连 `127.0.0.1:443`（iOS 回环全设备共享）→ 命中扩展内的 **Rust ECH 代理**
- 代理用本地根证书终止 TLS，再用私人 DoH 取 ECH 记录、以 **ECH** 直连 Cloudflare
- 只有 DNS 走隧道；真实流量（含代理到 Cloudflare 的上游）全部直连
- **需安装并信任本地根证书**（App 内一键安装 + 按提示开启信任）

> 0.1.x 是纯 DNS 方案，依赖浏览器自己做 ECH，只有 Safari 稳定且几天后会因 ECH key 轮换失效。
> 0.2.0 把 ECH 交给内置 Rust 核心处理，彻底解决这两个问题。

## 为什么是"未签名 + TrollStore"

iOS 上要实现"选择性接管 DNS"，唯一路径是 Network Extension，它需要
`com.apple.developer.networking.networkextension` 授权。这个授权免费开发者账号拿不到、普通侧载
也无法注入，因此本工程按**未签名 IPA**打包，交给 **TrollStore**（可给未签名 IPA 注入任意
entitlement）或自签环境安装。

> 需要 TrollStore 兼容的机型 / iOS 版本。非兼容设备无法安装带该 entitlement 的未签名包。

## 工程结构

```
ios/
  project.yml            # XcodeGen 工程定义（App + PacketTunnel 扩展两个 target）
  App/                   # SwiftUI 主界面 + NETunnelProviderManager 控制
  PacketTunnel/          # NEPacketTunnelProvider 扩展（DNS-only 隧道）
  Shared/                # 两端共用：配置、TOML 解析、DNS/TUN 编解码、DoH 解析器
  Resources/             # Assets.xcassets
```

`Shared/` 里的 `DnsPacketCodec` / `DnsWireParser` / `TunPacketCodec` / `DohResolver` 是从
Android 版 Kotlin（`LinuxdoDns.kt`）逐一移植过来的，行为一致。

## 本地构建

需要 macOS + Xcode。

```bash
brew install xcodegen
cd ios
xcodegen generate            # 生成 LinuxdoAccelerator.xcodeproj
xcodebuild \
  -project LinuxdoAccelerator.xcodeproj \
  -scheme LinuxdoAccelerator \
  -configuration Release -sdk iphoneos \
  -archivePath build/LinuxdoAccelerator.xcarchive \
  CODE_SIGNING_ALLOWED=NO CODE_SIGNING_REQUIRED=NO CODE_SIGN_IDENTITY="" \
  clean archive

# 打包未签名 IPA
APP=build/LinuxdoAccelerator.xcarchive/Products/Applications/LinuxdoAccelerator.app
rm -rf Payload && mkdir Payload && cp -R "$APP" Payload/
zip -qry LinuxdoAccelerator-unsigned.ipa Payload
```

## CI 构建

推 `ios-v*` tag 或手动触发 `.github/workflows/build-ios.yml`，产物是
`LinuxdoAccelerator-unsigned.ipa`（Actions artifact，tag 触发时同时挂到 Release）。

## 安装（TrollStore）

1. 下载 `LinuxdoAccelerator-unsigned.ipa`。
2. 用 TrollStore 打开安装（TrollStore 会补齐签名并保留 entitlement）。
3. 打开 App → "开始加速" → 系统弹出 VPN 配置授权，允许即可。
4. 首次会在"设置 → 通用 → VPN 与设备管理"里出现一条 VPN 配置。

## 配置

App 内"配置"页可编辑 DoH 端点和接管域名，保存后写入 App Group 容器
（`group.io.linuxdo.accelerator`），扩展下次启动时读取。默认值与
`assets/defaults/linuxdo-accelerator.toml` 保持一致。

## 已知限制

- 仅在 TrollStore 兼容设备上可安装。
- ECH 依赖 iOS 17+；更低版本 Safari 不一定支持 ECH，可能仍超时。
- 目前只处理 IPv4/UDP 的 DNS 查询（与 Android 版一致）。
