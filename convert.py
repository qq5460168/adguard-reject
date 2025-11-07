#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
功能：读取 rules.txt 中的 QuantumultX 在线规则 URL → 批量拉取规则 → 合并并转换为 AdGuard / hosts 规则
改进点：
- 新增白名单支持，可过滤不需要的规则
- 更健壮的正则，支持更宽松的域名/keyword 捕获（包括点和 Unicode）
- 去除重复，保留注释行并在输出中标注未识别规则
- 更友好的错误处理与统计信息
"""
from typing import List, Set
import re
import requests
import sys
import os

# 配置
URL_CONFIG_FILE = "rules.txt"
ADGUARD_OUTPUT_FILE = "adguard-rules.txt"
WHITE_LIST_FILE = "white.txt"  # 新增白名单文件
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


def load_white_list() -> Set[str]:
    """加载白名单域名，支持 AdGuard 白名单格式（@@||xxx^）和纯域名，返回小写域名集合"""
    white_list = set()
    if not os.path.exists(WHITE_LIST_FILE):
        print(f"ℹ️  未找到白名单文件 {WHITE_LIST_FILE}，将不进行排除操作")
        return white_list

    # 支持的白名单格式正则
    adguard_white_pattern = re.compile(r'^@@\||?https?://)?([^|^$]+)')
    domain_pattern = re.compile(r'^([a-zA-Z0-9][a-zA-Z0-9.-]+[a-zA-Z0-9])$')

    try:
        with open(WHITE_LIST_FILE, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith('#'):
                    continue  # 跳过注释和空行

                # 处理 AdGuard 白名单格式（@@开头）
                adguard_match = adguard_white_pattern.match(line)
                if adguard_match:
                    domain = adguard_match.group(1).strip('.').lower()
                    if domain:
                        white_list.add(domain)
                        continue

                # 处理纯域名格式
                domain_match = domain_pattern.match(line)
                if domain_match:
                    domain = domain_match.group(1).strip('.').lower()
                    white_list.add(domain)
                    continue

                # 未识别的格式警告
                print(f"⚠️  白名单文件第 {line_num} 行格式不支持：{line}（已跳过）")

        print(f"✅ 加载白名单成功，共 {len(white_list)} 条有效域名")
        return white_list
    except OSError as e:
        print(f"⚠️  读取白名单文件失败：{e}，将不进行排除操作")
        return set()


def is_whitelisted(rule: str, white_list: Set[str]) -> bool:
    """检查规则是否在白名单中"""
    if not white_list:
        return False

    # 提取规则中的域名部分
    domain = None
    if rule.startswith('0.0.0.0 '):
        domain = rule.split()[1].lower()
    elif rule.startswith('||') and rule.endswith('^'):
        domain = rule[2:-1].split('/')[0].lower()  # 去掉||和^，并忽略路径部分

    if not domain:
        return False

    # 检查是否匹配白名单（支持子域名）
    return any(domain == wl or domain.endswith(f'.{wl}') for wl in white_list)


def fetch_single_url_rules(url: str) -> List[str]:
    """拉取单个 URL 的规则文本并按行返回（过滤空行）"""
    try:
        print(f"\n📥 正在拉取：{url}")
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True
        )
        r.raise_for_status()
        # 尝试多种编码解码，提高兼容性
        encodings = ['utf-8-sig', 'gbk', 'latin-1']
        text = None
        for encoding in encodings:
            try:
                text = r.content.decode(encoding)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            raise UnicodeDecodeError("无法解码规则内容")
            
        lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
        print(f"✅ 拉取成功：{len(lines)} 行有效规则")
        return lines
    except requests.exceptions.RequestException as e:
        print(f"⚠️  拉取失败：{url} -> {e}")
        return []
    except UnicodeDecodeError:
        print(f"⚠️  解码失败：{url} 的内容无法正确解码")
        return []


def convert_rule_line(line: str):
    """
    将单行 QuantumultX 规则转换为目标规则。
    返回一个字符串（转换后的规则）或 None（未识别或不需要转换）。
    """
    s = line.strip()

    # host,domain,reject  -> hosts
    m = re.match(rf'host\s*,\s*{TOKEN_RE}\s*,\s*reject\s*$', s, re.I)
    if m:
        domain = m.group(1)
        if domain in ('*', ''):
            return None
        return f"0.0.0.0 {domain}"

    # host-suffix,domain, reject -> ||domain^
    m = re.match(rf'host-suffix\s*,\s*{TOKEN_RE}\s*,\s*reject\s*$', s, re.I)
    if m:
        suffix = m.group(1)
        return f"||{suffix}^"

    # host-keyword,keyword, reject -> ||keyword^
    m = re.match(rf'host-keyword\s*,\s*{TOKEN_RE}\s*,\s*reject\s*$', s, re.I)
    if m:
        keyword = m.group(1)
        return f"||{keyword}^"

    # url,protocol://domain/... , reject  -> ||domain/path^
    m = re.match(rf'url\s*,\s*(?:((?:https?|wss?)://)?)([^\s\/,]+)(/[^\s,]*)?\s*,\s*reject\s*$', s, re.I)
    if m:
        domain = m.group(2)
        path = m.group(3) or ""
        return f"||{domain}{path}^"

    # 其他 reject 形式：暂不处理
    return None


def merge_and_convert(all_rules: List[str], output_file: str, white_list: Set[str]) -> None:
    """合并所有规则并转换写入输出文件，应用白名单过滤"""
    header = [
        "# ===============================",
        "# 自动拉取+合并+转换自 QuantumultX 在线规则",
        f"# 规则来源配置：{URL_CONFIG_FILE}",
        f"# 白名单过滤：{len(white_list)} 条规则",
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
    whitelisted_count = 0
    raw_count = len(all_rules)

    for line in all_rules:
        if not line:
            continue
        stripped = line.strip()

        # 保留注释行原样（但不计入去重）
        if stripped.startswith('#'):
            out_lines.append(stripped)
            continue

        # 只处理包含 reject 的规则
        if 'reject' not in stripped.lower():
            out_lines.append(f"# 跳过非 reject 规则：{stripped}")
            continue

        converted_rule = convert_rule_line(stripped)
        if converted_rule:
            # 检查是否在白名单中
            if is_whitelisted(converted_rule, white_list):
                whitelisted_count += 1
                out_lines.append(f"# 已过滤白名单规则：{converted_rule}")
                continue
                
            if converted_rule not in converted:
                out_lines.append(converted_rule)
                converted.add(converted_rule)
                converted_count += 1
        else:
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
    print(f"  - 白名单过滤规则数：{whitelisted_count}")
    print(f"  - 未识别规则数（已写为注释）：{unrecognized_count}")
    print(f"  - 输出文件：{output_file}")


def main():
    urls = read_rule_urls(URL_CONFIG_FILE)
    white_list = load_white_list()  # 加载白名单
    
    all_rules: List[str] = []
    for url in urls:
        lines = fetch_single_url_rules(url)
        if lines:
            all_rules.extend(lines)
            print(f"  → 当前累计规则行数：{len(all_rules)}")

    if not all_rules:
        print("❌ 错误：未拉取到任何规则，退出。")
        sys.exit(1)

    merge_and_convert(all_rules, ADGUARD_OUTPUT_FILE, white_list)


if __name__ == "__main__":
    main()