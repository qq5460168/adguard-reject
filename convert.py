#!/usr/bin/env python3
# 功能：读取 rules.txt 中的 URL → 批量拉取 QuantumultX 规则 → 合并转换为 AdGuard 规则
import re
import requests
from typing import List, Tuple
import logging
from pathlib import Path

# 配置文件路径
URL_CONFIG_FILE = "rules.txt"
ADGUARD_OUTPUT_FILE = "adguard-rules.txt"

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(levelname)s: %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)


def read_rule_urls(config_file: str) -> List[str]:
    """读取规则配置文件中的URL，返回去重后的列表"""
    config_path = Path(config_file)
    if not config_path.exists():
        logger.error(f"❌ 未找到配置文件: {config_file}，请创建并添加规则URL")
        raise SystemExit(1)

    try:
        with config_path.open('r', encoding='utf-8') as f:
            lines = [line.strip() for line in f.readlines()]
        
        # 过滤空行、注释行并去重
        urls = list({
            url for url in lines 
            if url and not url.startswith("#")
        })

        if not urls:
            logger.error(f"❌ 配置文件 {config_file} 中未找到有效URL")
            raise SystemExit(1)

        logger.info(f"📋 从 {config_file} 读取到 {len(urls)} 个有效URL")
        for i, url in enumerate(urls, 1):
            logger.info(f"  {i}. {url}")
        return urls

    except Exception as e:
        logger.error(f"❌ 读取配置文件失败: {str(e)}")
        raise SystemExit(1)


def fetch_single_url_rules(url: str, retries: int = 2) -> List[str]:
    """拉取单个URL的规则，支持重试机制"""
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
    }

    for attempt in range(retries + 1):
        try:
            logger.info(f"\n📥 正在拉取规则 (尝试 {attempt + 1}/{retries + 1}): {url}")
            response = requests.get(
                url,
                timeout=30,
                headers=headers,
                allow_redirects=True
            )
            response.raise_for_status()
            
            # 处理编码并分割规则
            rules_text = response.content.decode("utf-8-sig").strip()
            rules_lines = [line.strip() for line in rules_text.splitlines()]
            logger.info(f"✅ 拉取成功！共 {len(rules_lines)} 行规则")
            return rules_lines

        except requests.exceptions.RequestException as e:
            if attempt < retries:
                logger.warning(f"⚠️ 拉取失败，将重试: {str(e)}")
                continue
            logger.error(f"❌ 拉取失败 (已达最大重试次数): {str(e)}")
            return []


def parse_rule(line: str) -> Tuple[List[str], bool]:
    """解析单条规则并转换，返回(转换后的规则列表, 是否成功转换)"""
    # 空行直接保留
    if not line:
        return [""], True

    # 注释行直接保留
    if line.startswith("#"):
        return [line], True

    # 1. 匹配URL规则 (url, 协议://域名/路径, reject)
    url_pattern = r'url,\s*(https?|wss):\/\/([\w\.\-]+)(\/[^\s,]*)?,\s*reject'
    url_match = re.match(url_pattern, line, re.IGNORECASE)
    if url_match:
        domain = url_match.group(2).strip()
        path = url_match.group(3) or ""
        return [f"||{domain}{path}^"], True

    # 2. 匹配host规则 (host, 域名, reject)
    host_pattern = r'host,\s*([\w\.\-]+),\s*reject'
    host_match = re.match(host_pattern, line, re.IGNORECASE)
    if host_match:
        domain = host_match.group(1).strip()
        return [f"0.0.0.0 {domain}", f":: {domain}"], True

    # 3. 匹配host-suffix规则 (host-suffix, 域名后缀, reject)
    suffix_pattern = r'host-suffix,\s*([\w\.\-]+),\s*reject'
    suffix_match = re.match(suffix_pattern, line, re.IGNORECASE)
    if suffix_match:
        domain = suffix_match.group(1).strip()
        return [f"0.0.0.0 {domain}", f":: {domain}"], True

    # 4. 匹配host-keyword规则 (host-keyword, 关键词, reject)
    keyword_pattern = r'host-keyword,\s*([^,]+),\s*reject'  # 支持含特殊字符的关键词
    keyword_match = re.match(keyword_pattern, line, re.IGNORECASE)
    if keyword_match:
        keyword = keyword_match.group(1).strip()
        return [f"||*{keyword}*$important"], True

    # 未识别的规则
    return [f"# 未识别规则: {line}"], False


def merge_and_convert(all_rules: List[str], output_file: str):
    """合并所有规则并转换为AdGuard格式"""
    adguard_rules = [
        "# ===============================",
        "# 自动拉取+合并+转换自QuantumultX在线规则",
        f"# 规则来源配置: {URL_CONFIG_FILE}",
        "# 支持规则类型: URL/host/host-suffix/host-keyword + reject",
        "# 转换工具: quantumultx-to-adguard-url-config",
        "# ===============================\n"
    ]

    converted_count = 0
    total_lines = len(all_rules)

    for line in all_rules:
        converted_lines, success = parse_rule(line)
        adguard_rules.extend(converted_lines)
        if success:
            converted_count += 1

    # 写入输出文件
    try:
        output_path = Path(output_file)
        with output_path.open('w', encoding='utf-8') as f:
            f.write('\n'.join(adguard_rules))
        
        logger.info("\n✅ 所有规则转换完成！")
        logger.info(f"📊 统计: 共处理 {total_lines} 行原始规则，成功转换 {converted_count} 条")
        logger.info(f"📄 输出文件: {output_file}")

    except Exception as e:
        logger.error(f"❌ 写入输出文件失败: {str(e)}")
        raise SystemExit(1)


def main():
    # 步骤1: 读取规则URL
    rule_urls = read_rule_urls(URL_CONFIG_FILE)
    
    # 步骤2: 批量拉取规则
    all_rules = []
    for url in rule_urls:
        single_rules = fetch_single_url_rules(url)
        if single_rules:
            all_rules.extend(single_rules)
            all_rules.append("")  # 分隔不同来源的规则
    
    if not all_rules:
        logger.error("❌ 未拉取到任何有效规则")
        raise SystemExit(1)
    
    # 步骤3: 转换并输出
    merge_and_convert(all_rules, ADGUARD_OUTPUT_FILE)


if __name__ == "__main__":
    main()