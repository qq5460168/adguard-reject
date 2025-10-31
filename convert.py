#!/usr/bin/env python3
# 功能：读取 QuantumultX 规则 URL → 仅转换 host, 域名, reject 为 hosts 规则 → 其他规则保持原样
import re
import requests
from typing import List

# 配置文件路径
URL_CONFIG_FILE = "rules.txt"       # 存放 QuantumultX 在线规则 URL 的文件
OUTPUT_FILE = "converted-rules.txt"  # 输出文件（保留所有规则，仅转换目标类型）

def read_rule_urls(config_file: str) -> List[str]:
    """读取规则配置文件中的 URL，返回去重后的有效列表"""
    try:
        with open(config_file, 'r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()]
        # 过滤空行、注释行，去重
        urls = list({url for url in lines if url and not url.startswith("#")})
        if not urls:
            print(f"❌ 错误：{config_file} 中无有效 URL")
            raise SystemExit(1)
        print(f"📋 读取到 {len(urls)} 个规则 URL：")
        for i, url in enumerate(urls, 1):
            print(f"  {i}. {url}")
        return urls
    except FileNotFoundError:
        print(f"❌ 错误：未找到 {config_file}，请创建并添加规则 URL")
        raise SystemExit(1)

def fetch_rules(urls: List[str]) -> List[str]:
    """批量拉取所有 URL 的规则，合并为列表"""
    all_rules = []
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
    for url in urls:
        print(f"\n📥 拉取规则：{url}")
        try:
            response = requests.get(url, timeout=30, headers=headers)
            response.raise_for_status()
            # 解码并分割规则行，保留原始格式
            rules = [line.rstrip('\n') for line in response.content.decode("utf-8-sig").splitlines()]
            all_rules.extend(rules)
            all_rules.append("")  # 不同来源规则空行分隔
            print(f"✅ 成功拉取 {len(rules)} 行规则")
        except requests.exceptions.RequestException as e:
            print(f"⚠️  拉取失败：{str(e)}，跳过该 URL")
    if not all_rules:
        print("❌ 错误：未拉取到任何规则")
        raise SystemExit(1)
    return all_rules

def convert_host_rules(all_rules: List[str]) -> List[str]:
    """仅转换 host, 域名, reject 为 0.0.0.0 域名，其他规则保持不变"""
    converted_rules = []
    converted_count = 0
    # 匹配 host 规则的正则（支持域名含 ._- 等字符，忽略大小写）
    host_pattern = re.compile(r'^host,\s*([\w\.\-]+),\s*reject$', re.IGNORECASE)
    
    for line in all_rules:
        match = host_pattern.match(line.strip())
        if match:
            domain = match.group(1).strip()
            converted_rules.append(f"0.0.0.0 {domain}")  # 转换为 hosts 格式
            converted_count += 1
        else:
            converted_rules.append(line)  # 其他规则原样保留
    
    # 添加头部说明
    header = [
        "# ===============================",
        "# 规则转换说明",
        "# 仅将 host, 域名, reject 转换为 0.0.0.0 域名（hosts 格式）",
        "# 其他类型规则保持原始格式不变",
        "# ===============================\n"
    ]
    return header + converted_rules, converted_count

def write_output(rules: List[str], output_file: str, converted_count: int):
    """写入输出文件"""
    try:
        with open(output_file, 'w', encoding='utf-8', newline='\n') as f:
            f.write('\n'.join(rules))
        print(f"\n✅ 转换完成！")
        print(f"📊 统计：共处理 {len(rules) - 6} 行原始规则（扣除头部说明）")
        print(f"📊 成功转换 {converted_count} 条 host 类型规则")
        print(f"📄 输出文件：{output_file}")
    except Exception as e:
        print(f"❌ 写入文件失败：{str(e)}")
        raise SystemExit(1)

if __name__ == "__main__":
    # 步骤1：读取规则 URL
    rule_urls = read_rule_urls(URL_CONFIG_FILE)
    # 步骤2：拉取所有规则
    all_rules = fetch_rules(rule_urls)
    # 步骤3：仅转换 host 规则
    converted_rules, count = convert_host_rules(all_rules)
    # 步骤4：写入输出
    write_output(converted_rules, OUTPUT_FILE, count)