# 零码密码与证书工具箱 Tauri 桌面版

该桌面版本直接复用项目根目录的 Vue 工具界面，因此视觉和浏览器版一致；Tauri 仅提供 Windows 窗口和安装包。

## 打包

```powershell
npm run desktop:build
```

成功后，NSIS 安装程序位于：

```text
src-tauri\target\release\bundle\nsis\
```

Windows 首次打包前需要安装 Rust MSVC 工具链和 Visual Studio C++ Build Tools。
