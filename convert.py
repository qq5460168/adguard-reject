#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
convert.py — 从 rules.txt（支持本地行和远程 URL）拉取 QuantumultX/文本规则并转换为 AdGuard 可用的规则文件 adguard-rules.txt
主要改进点：
- 对正则编译使用安全封装，遇到非法正则不崩溃而记录并跳过
- 支持在 rules.txt 中列出远程规则 URL（以 http/https 开头），会自动拉取内容
- 更完善的日志，便于在 GitHub Actions 日志中定位问题
- 原子写入输出文件，避免部分写入
- 提供可配置超时与调试（--dry-run）
"""
from __future__ import annotations

import argparse
import logging
import re
import sys
from pathlib import Path
from typing import Iterable, List, Optional

import requests

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s: %(message)s",
)
logger = logging.getLogger("convert")

# 常量
DEFAULT_RULES_FILE = "rules.txt"
DEFAULT_OUTPUT_FILE = "adguard-rules.txt"
USER_AGENT = "convert.py (github.com/qq5460168/adguard-reject) +https://github.com/qq5460168/adguard-reject"

def safe_compile(pattern: str, flags: int = 0) -> Optional[re.Pattern]:
    """
    尝试编译 pattern：
    - 编译成功返回 re.Pattern
    - 若直接编译失败，尝试把 pattern 当字面文本用 re.escape 再编译（并记录警告）
    - 若仍失败，返回 None（调用者应跳过该规则）
    """
    try:
        return re.compile(pattern, flags)
    except re.error as e:
        logger.warning("re.compile failed for raw pattern %r: %s", pattern, e)
        try:
            escaped = re.escape(pattern)
            logger.info("fallback: try re.escape for pattern %r -> %r", pattern, escaped)
            return re.compile(escaped, flags)
        except re.error as e2:
            logger.error("re.compile failed after escape for pattern %r: %s", pattern, e2)
            return None


def fetch_text_from_url(url: str, timeout: int = 20) -> Optional[str]:
    """拉取远程文本，遇到网络或 HTTP 错误返回 None（并记录）"""
    headers = {"User-Agent": USER_AGENT}
    try:
        logger.info("fetch remote rules: %s", url)
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
        # 尝试自动检测编码并返回文本
        r.encoding = r.encoding or "utf-8"
        return r.text
    except Exception as e:
        logger.error("failed to fetch %s: %s", url, e)
        return None


def load_sources_from_rules_file(path: Path) -> List[str]:
    """
    读取 rules.txt，返回每一非空、非注释的源行。
    支持在 rules.txt 中直接列出远程 URL（http/https），也支持本地文件路径。
    注：以 '#' 开头视为注释。
    """
    if not path.exists():
        logger.error("rules file not found: %s", path)
        return []

    txt = path.read_text(encoding="utf-8")
    lines = []
    for raw in txt.splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith("#"):
            continue
        lines.append(line)
    logger.info("loaded %d non-empty source lines from %s", len(lines), path)
    return lines


def expand_sources(sources: Iterable[str], timeout: int = 20) -> List[str]:
    """
    将 sources 展开为规则行（支持远程 URL：Fetch 并取其每行）
    返回所有规则行的列表（去除空行与注释）。
    """
    out_lines: List[str] = []
    for src in sources:
        if src.lower().startswith("http://") or src.lower().startswith("https://"):
            text = fetch_text_from_url(src, timeout=timeout)
            if not text:
                logger.warning("skip remote source due to fetch error: %s", src)
                continue
            for raw in text.splitlines():
                line = raw.strip()
                if not line or line.startswith("#"):
                    continue
                out_lines.append(line)
        else:
            # 当作本地文件（相对或绝对）或单条规则
            p = Path(src)
            if p.exists() and p.is_file():
                logger.info("load local rules file: %s", p)
                txt = p.read_text(encoding="utf-8")
                for raw in txt.splitlines():
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    out_lines.append(line)
            else:
                # 直接把 src 当成一条规则（例如 convert.py 中允许直接写规则行）
                out_lines.append(src)
    logger.info("expanded to %d total rule lines", len(out_lines))
    return out_lines


def convert_rule_to_adguard(line: str) -> Optional[str]:
    """
    将单条规则 line 转换为 AdGuard 可接受的规则字符串。
    处理策略（尽量保留语义并避免抛出 re.error）：
    - 若 line 被 /.../ 包裹，视为正则：尝试编译 inner pattern（若失败，尝试 escape 后使用；若仍失败则跳过）
    - 否则，将当作文本匹配，使用 re.escape 转为安全正则，并用 /escaped/ 的形式输出（AdGuard 支持 /pattern/ 形式的 regex 规则）
    - 如果有更多明确的 QuantumultX 语法（如 host、domain、ip-cidr 等），可在此处扩展解析逻辑
    返回值：字符串或 None（表示 skip）
    """
    s = line.strip()
    if not s:
        return None

    # 常见注释或元数据跳过
    if s.startswith("@") or s.lower().startswith("tag:"):
        logger.debug("skip metadata/unsupported line: %r", s)
        return None

    # 如果本身已经像 AdGuard 正则（以 / 开头并以 / 结尾），直接验证合法性
    if s.startswith("/") and s.endswith("/") and len(s) >= 2:
        inner = s[1:-1]
        if safe_compile(inner) is None:
            logger.warning("invalid regex rule skipped: %r", s)
            return None
        # 保持 /pattern/ 形式输出
        return f"/{inner}/"

    # 其他：当作文本匹配，转为安全的 regex（用 /.../ 表示）
    escaped = re.escape(s)
    # 编译验证（虽然 escape 一般可用，但仍然双重保险）
    if safe_compile(escaped) is None:
        logger.warning("escaped pattern still invalid, skip: %r (escaped %r)", s, escaped)
        return None
    return f"/{escaped}/"


def write_atomic(path: Path, lines: Iterable[str]) -> None:
    """原子方式写入文件：先写临时文件，再替换目标"""
    tmp = path.with_suffix(path.suffix + ".tmp")
    content = "\n".join(lines) + ("\n" if lines else "")
    tmp.write_text(content, encoding="utf-8")
    tmp.replace(path)
    logger.info("wrote %d bytes to %s", tmp.stat().st_size, path)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Convert QuantumultX/text rules -> AdGuard rules")
    parser.add_argument("--rules-file", "-r", default=DEFAULT_RULES_FILE, help="local rules list (default: rules.txt)")
    parser.add_argument("--output", "-o", default=DEFAULT_OUTPUT_FILE, help="output file (default: adguard-rules.txt)")
    parser.add_argument("--timeout", "-t", type=int, default=20, help="network timeout seconds")
    parser.add_argument("--dry-run", action="store_true", help="do not write output file, only print summary")
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    args = parser.parse_args(argv or None)

    if args.debug:
        logger.setLevel(logging.DEBUG)

    rules_path = Path(args.rules_file)
    sources = load_sources_from_rules_file(rules_path)
    if not sources:
        logger.error("no sources to process, exiting")
        return 1

    raw_rules = expand_sources(sources, timeout=args.timeout)
    if not raw_rules:
        logger.error("no rules found after expanding sources, exiting")
        return 1

    out_rules: List[str] = []
    skipped = 0
    for idx, line in enumerate(raw_rules, start=1):
        try:
            converted = convert_rule_to_adguard(line)
            if converted:
                out_rules.append(converted)
            else:
                skipped += 1
                logger.debug("skipped rule #%d: %r", idx, line)
        except Exception:
            # 捕获任何不可预期的异常，记录并继续
            logger.exception("unexpected error processing rule #%d: %r", idx, line)
            skipped += 1
            continue

    logger.info("conversion finished: %d => %d, skipped %d", len(raw_rules), len(out_rules), skipped)

    if args.dry_run:
        # 打印摘要并退出，不写入文件
        logger.info("dry-run enabled; not writing output. First 20 converted lines:")
        for i, r in enumerate(out_rules[:20], start=1):
            logger.info("%3d: %s", i, r)
        return 0

    out_path = Path(args.output)
    try:
        write_atomic(out_path, out_rules)
    except Exception as e:
        logger.exception("failed to write output file %s: %s", out_path, e)
        return 1

    logger.info("successfully wrote %d rules to %s", len(out_rules), out_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        logger.warning("Interrupted by user")
        raise