#!/usr/bin/env python3
# 功能：读取 rules.txt 中的 URL → 批量拉取 QuantumultX 规则 → 合并转换为 AdGuard 规则
import re
import requests

# 配置文件路径
URL_CONFIG_FILE = "rules.txt"       # 存放 QuantumultX 在线规则 URL 的文件
ADGUARD_OUTPUT_FILE = "adguard-rules.txt"  # 输出 AdGuard 规则文件

def read_rule_urls(config_file: str) -> list:
    """读取 rules.txt 中的所有 URL，返回去重后的 URL 列表"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()]
        # 过滤空行和注释行（以 # 开头），去重
        urls = [url for url in lines if url and not url.startswith("#")]
        if not urls:
            print(f"❌ 错误：{config_file} 中未找到有效 URL")
            raise SystemExit(1)
        print(f"📋 从 {config_file} 读取到 {len(urls)} 个规则 URL")
        for i, url in enumerate(urls, 1):
            print(f"  {i}. {url}")
        return urls
    except FileNotFoundError:
        print(f"❌ 错误：未找到 {config_file} 文件，请创建并添加 QuantumultX 规则 URL")
        raise SystemExit(1)

def fetch_single_url_rules(url: str) -> list:
    """拉取单个 URL 的 QuantumultX 规则，返回规则列表"""
    try:
        print(f"\n📥 正在拉取规则：{url}")
        response = requests.get(
            url,
            timeout=30,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        )
        response.raise_for_status()
        # 解码并分割为规则行
        rules_text = response.content.decode("utf-8-sig").strip()
        rules_lines = [line.strip() for line in rules_text.splitlines()]
        print(f"✅ 拉取成功！该 URL 共 {len(rules_lines)} 行规则")
        return rules_lines
    except requests.exceptions.RequestException as e:
        print(f"⚠️  拉取 {url} 失败：{str(e)}，跳过该 URL")
        return []

def merge_and_convert(all_rules: list, output_file: str):
    """合并所有拉取的规则，提取 reject 规则并转换为 AdGuard 格式"""
    adguard_rules = []
    # 头部说明
    adguard_rules.append("# ===============================")
    adguard_rules.append("# 自动拉取+合并+转换自 QuantumultX 在线规则")
    adguard_rules.append(f"# 规则来源配置：{URL_CONFIG_FILE}")
    adguard_rules.append("# 支持规则类型：URL/host/host-suffix/host-keyword + reject")  # 更新支持类型说明
    adguard_rules.append("# 转换工具：quantumultx-to-adguard-url-config")
    adguard_rules.append("# ===============================\n")

    converted_count = 0
    # 遍历所有规则行
    for line in all_rules:
        if not line:
            adguard_rules.append("")
            continue
        # 保留注释行
        if line.startswith("#"):
            adguard_rules.append(line)
            continue
        
        # 新增：匹配 host 规则（host, 域名, reject）
        host_match = re.match(r'host,\s*([\w\.\-]+),\s*reject', line, re.I)
        if host_match:
            domain = host_match.group(1).strip()
            adguard_rules.append(f"0.0.0.0 {domain}")  # 转换为 hosts 格式
            converted_count += 1
            continue
        
        # 1. 匹配 URL 规则
        url_match = re.match(r'url,\s*(https?|wss):\/\/([\w\.\-]+)(\/[^\s,]*)?,\s*reject', line, re.I)
        if url_match:
            domain = url_match.group(2).strip()
            path = url_match.group(3) if url_match.group(3) else ""
            adguard_rules.append(f"||{domain}{path}^")
            converted_count += 1
            continue
        
        # 2. 匹配 host-suffix 规则
        suffix_match = re.match(r'host-suffix,\s*([\w\.\-]+),\s*reject', line, re.I)
        if suffix_match:
            domain = suffix_match.group(1).strip()
            adguard_rules.append(f"0.0.0.0 {domain}")
            adguard_rules.append(f":: {domain}")
            converted_count += 1
            continue
        
        # 3. 匹配 host-keyword 规则
        keyword_match = re.match(r'host-keyword,\s*([\w\-]+),\s*reject', line, re.I)
        if keyword_match:
            keyword = keyword_match.group(1).strip()
            adguard_rules.append(f"||*{keyword}*$important")
            converted_count += 1
            continue
        
        # 未识别规则
        adguard_rules.append(f"# 未识别规则：{line}")

    # 写入输出文件
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write('\n'.join(adguard_rules))

    print(f"\n✅ 所有规则转换完成！")
    print(f"📊 统计：共处理 {len(all_rules)} 行原始规则，成功转换 {converted_count} 条拦截规则")
    print(f"📄 输出文件：{output_file}")

if __name__ == "__main__":
    # 步骤1：读取 rules.txt 中的所有 URL
    rule_urls = read_rule_urls(URL_CONFIG_FILE)
    
    # 步骤2：批量拉取所有 URL 的规则并合并
    all_rules = []
    for url in rule_urls:
        single_rules = fetch_single_url_rules(url)
        if single_rules:
            all_rules.extend(single_rules)
            all_rules.append("")  # 不同 URL 规则之间添加空行分隔
    
    if not all_rules:
        print("❌ 错误：未拉取到任何有效规则")
        raise SystemExit(1)
    
    # 步骤3：合并并转换为 AdGuard 规则
    merge_and_convert(all_rules, ADGUARD_OUTPUT_FILE)
