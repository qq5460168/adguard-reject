#!/usr/bin/env python3
# 功能：读取 rules.txt 中的 URL → 批量拉取 QuantumultX 规则 → 合并转换为 AdGuard 规则
import re
import requests
from typing import List, Set

# 配置文件路径
URL_CONFIG_FILE = "rules.txt"       # 存放 QuantumultX 在线规则 URL 的文件
ADGUARD_OUTPUT_FILE = "adguard-rules.txt"  # 输出 AdGuard 规则文件
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"


def read_rule_urls(config_file: str) -> List[str]:
    """读取 rules.txt 中的所有 URL，返回去重后的 URL 列表"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()]
        
        # 过滤空行和注释行（以 # 开头），去重
        urls = []
        seen_urls = set()
        for url in lines:
            cleaned_url = url.strip()
            if cleaned_url and not cleaned_url.startswith("#") and cleaned_url not in seen_urls:
                urls.append(cleaned_url)
                seen_urls.add(cleaned_url)
        
        if not urls:
            print(f"❌ 错误：{config_file} 中未找到有效 URL")
            raise SystemExit(1)
        
        print(f"📋 从 {config_file} 读取到 {len(urls)} 个唯一规则 URL")
        for i, url in enumerate(urls, 1):
            print(f"  {i}. {url}")
        return urls
    
    except FileNotFoundError:
        print(f"❌ 错误：未找到 {config_file} 文件，请创建并添加 QuantumultX 规则 URL")
        raise SystemExit(1)
    except Exception as e:
        print(f"❌ 读取 {config_file} 失败：{str(e)}")
        raise SystemExit(1)


def fetch_single_url_rules(url: str) -> List[str]:
    """拉取单个 URL 的 QuantumultX 规则，返回规则列表（过滤空行）"""
    try:
        print(f"\n📥 正在拉取规则：{url}")
        response = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True
        )
        response.raise_for_status()  # 抛出 HTTP 错误状态码
        
        # 解码并处理 BOM，分割为规则行
        rules_text = response.content.decode("utf-8-sig").strip()
        rules_lines = [line.strip() for line in rules_text.splitlines() if line.strip()]
        
        print(f"✅ 拉取成功！该 URL 共 {len(rules_lines)} 行有效规则")
        return rules_lines
    
    except requests.exceptions.HTTPError as e:
        print(f"⚠️  拉取 {url} 失败：HTTP 错误 ({response.status_code})")
        return []
    except requests.exceptions.Timeout:
        print(f"⚠️  拉取 {url} 失败：请求超时（30秒）")
        return []
    except requests.exceptions.ConnectionError:
        print(f"⚠️  拉取 {url} 失败：网络连接错误")
        return []
    except Exception as e:
        print(f"⚠️  拉取 {url} 失败：{str(e)}，跳过该 URL")
        return []


def merge_and_convert(all_rules: List[str], output_file: str) -> None:
    """合并所有拉取的规则，提取 reject 规则并转换为 AdGuard 格式（去重处理）"""
    adguard_rules = []
    converted_rules = set()  # 用于去重已转换的规则
    raw_rule_count = len(all_rules)

    # 头部说明
    adguard_rules.append("# ===============================")
    adguard_rules.append("# 自动拉取+合并+转换自 QuantumultX 在线规则")
    adguard_rules.append(f"# 规则来源配置：{URL_CONFIG_FILE}")
    adguard_rules.append("# 支持规则类型：URL/host/host-suffix/host-keyword + reject")
    adguard_rules.append("# 转换工具：quantumultx-to-adguard-url-config")
    adguard_rules.append("# ===============================\n")

    converted_count = 0
    unrecognized_count = 0

    # 遍历所有规则行
    for line in all_rules:
        if not line:
            continue  # 跳过空行（已在拉取时过滤）
        
        # 保留注释行（不参与去重）
        if line.startswith("#"):
            adguard_rules.append(line)
            continue
        
        # 1. 匹配 host 规则 (host, 域名, reject)
        host_match = re.match(r'host,\s*([\w\.\-]+),\s*reject', line, re.I)
        if host_match:
            domain = host_match.group(1).strip()
            rule = f"0.0.0.0 {domain}"
            if rule not in converted_rules:
                adguard_rules.append(rule)
                converted_rules.add(rule)
                converted_count += 1
            continue
        
        # 2. 匹配 URL 规则 (url, 协议://域名/路径, reject)
        url_match = re.match(r'url,\s*(https?|wss):\/\/([\w\.\-]+)(\/[^\s,]*)?,\s*reject', line, re.I)
        if url_match:
            domain = url_match.group(2).strip()
            path = url_match.group(3) if url_match.group(3) else ""
            rule = f"||{domain}{path}^"
            if rule not in converted_rules:
                adguard_rules.append(rule)
                converted_rules.add(rule)
                converted_count += 1
            continue
        
        # 3. 匹配 host-suffix 规则 (host-suffix, 域名后缀, reject)
        suffix_match = re.match(r'host-suffix,\s*([\w\.\-]+),\s*reject', line, re.I)
        if suffix_match:
            domain = suffix_match.group(1).strip()
            rule_v4 = f"0.0.0.0 {domain}"
            rule_v6 = f":: {domain}"
            if rule_v4 not in converted_rules:
                adguard_rules.append(rule_v4)
                converted_rules.add(rule_v4)
                converted_count += 1
            if rule_v6 not in converted_rules:
                adguard_rules.append(rule_v6)
                converted_rules.add(rule_v6)
                converted_count += 1
            continue
        
        # 4. 匹配 host-keyword 规则 (host-keyword, 关键词, reject)
        keyword_match = re.match(r'host-keyword,\s*([\w\-]+),\s*reject', line, re.I)
        if keyword_match:
            keyword = keyword_match.group(1).strip()
            rule = f"||*{keyword}*$important"
            if rule not in converted_rules:
                adguard_rules.append(rule)
                converted_rules.add(rule)
                converted_count += 1
            continue
        
        # 未识别规则
        adguard_rules.append(f"# 未识别规则：{line}")
        unrecognized_count += 1

    # 写入输出文件
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(adguard_rules))
    except IOError as e:
        print(f"❌ 写入 {output_file} 失败：{str(e)}")
        raise SystemExit(1)

    # 输出统计信息
    print(f"\n✅ 所有规则转换完成！")
    print(f"📊 统计：")
    print(f"  - 原始规则总行数：{raw_rule_count}")
    print(f"  - 成功转换规则数：{converted_count}（去重后）")
    print(f"  - 未识别规则数：{unrecognized_count}")
    print(f"📄 输出文件：{output_file}")


if __name__ == "__main__":
    # 步骤1：读取 rules.txt 中的所有 URL（去重）
    rule_urls = read_rule_urls(URL_CONFIG_FILE)
    
    # 步骤2：批量拉取所有 URL 的规则并合并（过滤空行）
    all_rules: List[str] = []
    for url in rule_urls:
        single_rules = fetch_single_url_rules(url)
        if single_rules:
            all_rules.extend(single_rules)
            print(f"  → 已累计 {len(all_rules)} 行规则")
    
    if not all_rules:
        print("❌ 错误：未拉取到任何有效规则")
        raise SystemExit(1)
    
    # 步骤3：合并并转换为 AdGuard 规则（去重处理）
    merge_and_convert(all_rules, ADGUARD_OUTPUT_FILE)
