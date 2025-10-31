#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
功能：读取 rules.txt 中的 QuantumultX 在线规则 URL → 批量拉取规则 → 合并并转换为 AdGuard / hosts 规则
改进点：
- 按用户要求：
  - host, 域名, reject  -> 转为 hosts 格式: "0.0.0.0 域名"
  - host-suffix, 域名, reject -> 转为 AdGuard URL 格式: "||域名^"
  - host-keyword, 关键词, reject -> 转为 AdGuard URL 格式: "||关键词^"
- 更健壮的正则，支持更宽松的域名/keyword 捕获（包括点和 Unicode）
- 去除重复，保留注释行并在输出中标注未识别规则
- 更友好的错误处理与统计信息
"""
from typing import List
import re
import requests
import sys
import os

# 配置
URL_CONFIG_FILE = "rules.txt"
ADGUARD_OUTPUT_FILE = "adguard-rules.txt"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
REQUEST_TIMEOUT = 30

# 通用用于捕获域名 / 关键词的模式：尽量宽松，捕获非逗号非空白串（包括带点的域名或关键词）
TOKEN_RE = r'([^\s,]+)'


def read_rule_urls(config_file: str) -> List[str]:
    """读取 rules.txt 中的所有 URL，返回去重后的 URL 列表（忽略空行和 # 注释）"""
    if not os.path.exists(config_file):
        print(f"❌ 错误：未找到配置文件 {config_file}")
        sys.exit(1)

    with open(config_file, 'r', encoding='utf-8') as f:
        lines = [line.rstrip('\n') for line in f]

    urls = []
    seen = set()
    for line in lines:
        s = line.strip()
        if not s or s.startswith('#'):
            continue
        if s not in seen:
            seen.add(s)
            urls.append(s)

    if not urls:
        print(f"❌ 错误：{config_file} 中未找到任何有效 URL")
        sys.exit(1)

    print(f"📋 从 {config_file} 读取到 {len(urls)} 条规则源：")
    for i, u in enumerate(urls, 1):
        print(f"  {i}. {u}")
    return urls


def fetch_single_url_rules(url: str) -> List[str]:
    """拉取单个 URL 的规则文本并按行返回（过滤空行）"""
    try:
        print(f"\n📥 正在拉取：{url}")
        r = requests.get(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        r.raise_for_status()
        text = r.content.decode('utf-8-sig', errors='ignore')
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        print(f"✅ 拉取成功：{len(lines)} 行有效规则")
        return lines
    except requests.exceptions.RequestException as e:
        print(f"⚠️  拉取失败：{url} -> {e}")
        return []


def convert_rule_line(line: str):
    """
    将单行 QuantumultX 规则转换为目标规则。
    返回一个字符串（转换后的规则）或 None（未识别或不需要转换）。
    转换规则（按用户要求）：
      - host, 域名, reject -> "0.0.0.0 域名"
      - host-suffix, 域名后缀, reject -> "||域名^"
      - host-keyword, 关键词, reject -> "||关键词^"
      - url, 协议://域名/路径, reject -> "||域名/路径^"（保留路径以提高精确度）
    其它：注释行由调用者直接保留，未识别则返回 None。
    """
    s = line.strip()

    # host,domain,reject  -> hosts
    m = re.match(rf'host\s*,\s*{TOKEN_RE}\s*,\s*reject\s*$', s, re.I)
    if m:
        domain = m.group(1)
        # 避免把通配符等奇怪字符串写入 hosts
        if domain in ('*', ''):
            return None
        return f"0.0.0.0 {domain}"

    # host-suffix,domain, reject -> ||domain^
    m = re.match(rf'host-suffix\s*,\s*{TOKEN_RE}\s*,\s*reject\s*$', s, re.I)
    if m:
        suffix = m.group(1)
        # 当后缀以点开头或包含通配符时，仍按 ||suffix^ 处理（AdGuard 可以处理常见后缀）
        return f"||{suffix}^"

    # host-keyword,keyword, reject -> ||keyword^
    m = re.match(rf'host-keyword\s*,\s*{TOKEN_RE}\s*,\s*reject\s*$', s, re.I)
    if m:
        keyword = m.group(1)
        # 将关键词直接转换为包含前缀匹配的 AdGuard 形式
        # 注意：host-keyword 有时为域名的部分，转换为 ||keyword^ 能匹配以该关键词开头的主机或域名
        return f"||{keyword}^"

    # url,protocol://domain/... , reject  -> ||domain/path^  （保留路径）
    # 同时支持没有协议的 url,domain/path 的情形
    m = re.match(rf'url\s*,\s*(?:((?:https?|wss?)://)?)([^\s\/,]+)(/[^\s,]*)?\s*,\s*reject\s*$', s, re.I)
    if m:
        domain = m.group(2)
        path = m.group(3) or ""
        # 对路径进行保护：AdGuard 的 ^ 表示分界符，可以直接拼接
        return f"||{domain}{path}^"

    # 其他 reject 形式：比如 plain 'reject' 或 regex 等，暂不处理
    return None


def merge_and_convert(all_rules: List[str], output_file: str) -> None:
    """合并所有规则并转换写入输出文件"""
    header = [
        "# ===============================",
        "# 自动拉取+合并+转换自 QuantumultX 在线规则",
        f"# 规则来源配置：{URL_CONFIG_FILE}",
        "# 支持规则类型（已实现转换）：",
        "#  - host, 域名, reject  -> hosts: 0.0.0.0 域名",
        "#  - host-suffix, 域名后缀, reject -> AdGuard: ||域名^",
        "#  - host-keyword, 关键词, reject -> AdGuard: ||关键词^",
        "#  - url, 协议://域名/路径, reject -> AdGuard: ||域名/路径^",
        "# 注：保留原注释行；未识别的规则会以注释形式写出以便人工检查",
        "# ===============================\n"
    ]

    out_lines = []
    out_lines.extend(header)
    converted = set()
    converted_count = 0
    unrecognized_count = 0
    raw_count = len(all_rules)

    for line in all_rules:
        if not line:
            continue
        stripped = line.strip()

        # 保留注释行原样（但不计入去重）
        if stripped.startswith('#'):
            out_lines.append(stripped)
            continue

        # 只处理包含 reject 的规则（QuantumultX 里通常是 ... ,reject）
        # 如果有 reject 出现在行中才尝试转换
        if 'reject' not in stripped.lower():
            # 跳过不含 reject 的规则（也可按需求保留）
            out_lines.append(f"# 跳过非 reject 规则：{stripped}")
            continue

        converted_rule = convert_rule_line(stripped)
        if converted_rule:
            if converted_rule not in converted:
                out_lines.append(converted_rule)
                converted.add(converted_rule)
                converted_count += 1
            else:
                # 已存在则跳过（去重）
                continue
        else:
            # 未识别，写为注释以便后续人工检查
            out_lines.append(f"# 未识别规则：{stripped}")
            unrecognized_count += 1

    # 写入文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write("\n".join(out_lines))
    except OSError as e:
        print(f"❌ 写入文件失败：{output_file} -> {e}")
        sys.exit(1)

    # 统计输出
    print("\n✅ 转换完成")
    print(f"  - 原始规则行数：{raw_count}")
    print(f"  - 成功转换（去重后）规则数：{converted_count}")
    print(f"  - 未识别规则数（已写为注释）：{unrecognized_count}")
    print(f"  - 输出文件：{output_file}")


def main():
    urls = read_rule_urls(URL_CONFIG_FILE)
    all_rules: List[str] = []
    for url in urls:
        lines = fetch_single_url_rules(url)
        if lines:
            all_rules.extend(lines)
            print(f"  → 当前累计规则行数：{len(all_rules)}")

    if not all_rules:
        print("❌ 错误：未拉取到任何规则，退出。")
        sys.exit(1)

    merge_and_convert(all_rules, ADGUARD_OUTPUT_FILE)


if __name__ == "__main__":
    main()
