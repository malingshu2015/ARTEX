---
name: oneforall
description: "Use when performing authorized subdomain discovery with the pinned OneForAll tool in the ARTEX container."
version: 1.0.0
author: ARTEX contributors
license: MIT
platforms: [linux]
metadata:
  tags: [security, recon, subdomain, osint, pentest, oneforall, dns]
  homepage: https://github.com/shmilylty/OneForAll
  upstream_version: "0.4.5"
---

# OneForAll · 子域名发现

本 Skill 在 ARTEX Linux 容器中使用固定版本的 OneForAll。安装位置为持久数据卷 `/app/data/tools/OneForAll`，运行结果保存在其 `results/` 子目录。安装脚本和依赖清单随 Skill 一起提供；导入 Skill 时不会自动下载或运行脚本。

## 使用前

1. 确认目标域名属于用户自有资产，或有覆盖该目标和测试时间窗的书面授权。
2. 先检查程序是否可用；仅在缺失时安装。安装脚本会从上游固定提交下载源码、应用一项兼容补丁并创建隔离 Python 环境；若安装目录已存在但检查失败，脚本会停止且不覆盖原文件。

```bash
OFALL=/app/data/tools/OneForAll
if ! bash "$OFALL/ofall.sh" version >/dev/null 2>&1; then
  bash /app/skills/oneforall/scripts/install-container.sh
fi
```

## 默认被动收集

授权范围明确后，对单个目标执行被动收集；此模式不做字典爆破、DNS 解析或 HTTP 探活：

```bash
OFALL=/app/data/tools/OneForAll
bash "$OFALL/ofall.sh" --target example.com --brute False --dns False --req False --fmt json run
```

结果位于 `/app/data/tools/OneForAll/results/`。采集到的被动候选未经 DNS 验证，报告中应明确这一限制。

## 主动探测

只有授权明确覆盖相应行为时，才启用 DNS 解析、HTTP 探活或字典爆破。先确认目标、范围、时间窗、速率和允许的探测类型，再按授权配置运行；不要默认启用爆破。爆破会产生大量并发 DNS 请求，HTTP 探活会向目标主机发送请求。只要授权边界不清楚，就停留在默认被动模式并向用户说明所需信息。

## 依赖与输出

兼容依赖固定在 `assets/requirements-artex.txt`。如需 DNS 爆破，先单独安装并验证 massdns；不要假设它已存在。不要覆盖安装目录中的本地配置。执行结束后总结工具状态、命令模式、输出文件位置、未验证内容与错误；不要将输出误表述为已验证的存活资产。
