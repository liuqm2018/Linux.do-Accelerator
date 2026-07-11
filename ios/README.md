# Linux.do Accelerator — iOS

iPhone 版加速器。原理与 Android 版一致：本地起一个 **仅接管 `linux.do` / `idcflare.com` DNS** 的
Network Extension 隧道，把这些域名的 DNS 查询走私人 DoH，取回带 **ECH** 的 `HTTPS/SVCB` 记录，
让支持 ECH 的浏览器（iOS 17+ Safari 原生支持）加密 SNI，绕过运营商的 SNI 阻断。其它域名和所有真实
流量都不进隧道，直连。

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
