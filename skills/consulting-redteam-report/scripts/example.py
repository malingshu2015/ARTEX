#!/usr/bin/env python3
"""Lightweight preflight for an ARTEX Markdown security report."""

import argparse
from pathlib import Path

REQUIRED = {
    "full": [
        "执行摘要", "测试范围与方法", "攻击链复盘", "网络拓扑与资产分布",
        "风险矩阵", "漏洞统计", "漏洞详细发现", "验证与复测",
        "整改方案与路线图", "附录",
    ],
    "finding": ["影响", "证据", "修复", "复测"],
}
PLACEHOLDERS = ("[待填写]", "[待补充]", "TODO", "TBD", "示例客户", "Acme Corp")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="Markdown report to inspect")
    parser.add_argument("--profile", choices=REQUIRED, default="full")
    args = parser.parse_args()
    try:
        text = args.report.read_text(encoding="utf-8")
    except OSError as exc:
        parser.error(f"无法读取报告：{exc}")

    missing = [heading for heading in REQUIRED[args.profile] if heading not in text]
    placeholders = [token for token in PLACEHOLDERS if token.casefold() in text.casefold()]
    if missing:
        print("缺少建议章节：" + "、".join(missing))
    if placeholders:
        print("发现可能未替换的模板占位文本：" + "、".join(placeholders))
    if not missing and not placeholders:
        print("结构与常见占位文本检查通过；仍需人工核验事实、证据、统计和脱敏。")
        return 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
