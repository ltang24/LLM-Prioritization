#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import json
import time
import random
import argparse
import re
from pathlib import Path
import logging
import cloudscraper

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def try_parse_float(s):
    try:
        return float(s)
    except Exception:
        return None

def extract_cvss_details_table(html_content: str, cve_id: str) -> list:
    soup = BeautifulSoup(html_content, 'html.parser')
    tables = soup.find_all('table')
    result = []
    for table in tables:
        ths = table.find_all('th')
        headers = [th.get_text(strip=True) for th in ths]
        if "Base Score" in headers and "Score Source" in headers and "First Seen" in headers:
            rows = table.find_all('tr')
            for i in range(1, len(rows)):
                row = rows[i]
                cells = row.find_all('td')
                if len(cells) < 7:
                    continue
                def celltxt(idx):
                    return cells[idx].get_text(strip=True) if idx < len(cells) else None
                base_score = try_parse_float(celltxt(0))
                base_severity = celltxt(1)
                cvss_vector = celltxt(2)
                exploitability_score = try_parse_float(celltxt(3))
                impact_score = try_parse_float(celltxt(4))
                score_source = celltxt(5)
                first_seen = celltxt(6)

                # 下方是你要的各项细粒度
                details = {
                    'attack_vector': None, 'attack_complexity': None, 'privileges_required': None,
                    'user_interaction': None, 'scope': None,
                    'confidentiality': None, 'integrity': None, 'availability': None
                }
                # 查找紧跟tr的下一个tr，是表格的灰色描述行
                nextrow = row.find_next_sibling('tr')
                if nextrow and nextrow.find('td', {'colspan': True}):
                    txt = nextrow.get_text(" ", strip=True)
                    # 使用正则抽取所有细分属性
                    for label in details.keys():
                        label_fmt = label.replace('_', ' ').title() + ":"
                        m = re.search(rf"{re.escape(label_fmt)}\s*([A-Za-z ]+)", txt)
                        if m:
                            details[label] = m.group(1).strip()
                item = {
                    "base_score": base_score,
                    "base_severity": base_severity,
                    "cvss_vector": cvss_vector,
                    "exploitability_score": exploitability_score,
                    "impact_score": impact_score,
                    "score_source": score_source,
                    "first_seen": first_seen,
                    **details
                }
                result.append(item)
    return result

class CVEDetailsCVSSScraper:
    def __init__(self, delay_range: tuple = (5, 15), timeout: int = 30):
        self.base_url = "https://www.cvedetails.com"
        self.delay_range = delay_range
        self.timeout = timeout
        try:
            self.session = cloudscraper.create_scraper()
            logger.info("使用cloudscraper创建会话")
        except Exception:
            self.session = requests.Session()
            logger.info("使用标准requests创建会话")
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:120.0) Gecko/20100101 Firefox/120.0',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        ]
        self.base_headers = {
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'DNT': '1',
            'Cache-Control': 'max-age=0'
        }
        self.session.headers.update(self.base_headers)
        self.session_initialized = False

    def initialize_session(self) -> bool:
        if self.session_initialized:
            return True
        try:
            user_agent = random.choice(self.user_agents)
            self.session.headers['User-Agent'] = user_agent
            self.session_initialized = True
            return True
        except Exception as e:
            logger.error(f"会话初始化失败: {e}")
            return False

    def get_safe_request(self, url: str, referer: str = None, max_retries: int = 2) -> requests.Response:
        if not self.session_initialized:
            if not self.initialize_session():
                logger.error("无法初始化会话")
                return None
        for attempt in range(max_retries):
            try:
                if referer:
                    self.session.headers['Referer'] = referer
                delay = random.uniform(*self.delay_range)
                logger.info(f"等待 {delay:.1f} 秒...")
                time.sleep(delay)
                if random.random() < 0.3:
                    self.session.headers['User-Agent'] = random.choice(self.user_agents)
                logger.info(f"正在访问: {url} (尝试 {attempt + 1}/{max_retries})")
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    return response
                elif response.status_code == 403:
                    wait_time = (attempt + 1) * 30
                    logger.warning(f"收到403错误，等待{wait_time}秒后重试...")
                    time.sleep(wait_time)
                    self.session_initialized = False
                    if not self.initialize_session():
                        logger.error("重新初始化会话失败")
                        continue
                elif response.status_code == 404:
                    logger.info(f"页面不存在: {url}")
                    return None
                else:
                    logger.warning(f"HTTP状态码: {response.status_code}")
            except Exception as e:
                logger.warning(f"请求失败 (尝试 {attempt + 1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    time.sleep(random.uniform(10, 20))
                continue
        logger.error(f"所有重试都失败了: {url}")
        return None

    def get_cve_cvss_all(self, cve_id: str):
        cve_url = f"{self.base_url}/cve/{cve_id}/"
        response = self.get_safe_request(cve_url, referer=f"{self.base_url}/browse-by-date.php")
        if response:
            all_scores = extract_cvss_details_table(response.text, cve_id)
            if all_scores and len(all_scores) > 0:
                logger.info(f"✓ {cve_id}: {len(all_scores)} 条CVSS记录")
                return all_scores
            # 保存debug页面以供排查
            with open(f"debug_{cve_id}.html", "w", encoding="utf-8") as f:
                f.write(response.text)
        logger.warning(f"CVE Details失败: {cve_id}")
        return []

    def scrape_batch(self, cve_ids, output_file: Path, resume=True):
        existing_data = {}
        if resume and output_file.exists():
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    existing_data = json.load(f)
                logger.info(f"📂 加载现有数据: {len(existing_data)} 个CVE")
            except Exception as e:
                logger.warning(f"⚠️ 加载现有数据失败: {e}")
        total = len(cve_ids)
        successful = 0
        failed = 0
        skipped = 0
        logger.info(f"🎯 开始批量爬取CVE Details CVSS...")
        logger.info(f"📊 总计: {total} 个CVE")
        for i, cve_id in enumerate(cve_ids, 1):
            if cve_id in existing_data:
                skipped += 1
                continue
            logger.info(f"[{i}/{total}] 正在处理: {cve_id}")
            scores = self.get_cve_cvss_all(cve_id)
            existing_data[cve_id] = scores
            if scores:
                successful += 1
                logger.info(f"  ✓ 成功, 共{len(scores)}条: {scores}")
            else:
                failed += 1
            if i % 5 == 0:
                self._save_data(existing_data, output_file)
        self._save_data(existing_data, output_file)
        return {
            'total_cves': total,
            'successful': successful,
            'failed': failed,
            'skipped': skipped,
            'success_rate': successful / total * 100 if total > 0 else 0,
            'output_file': str(output_file)
        }

    def _save_data(self, data, output_file: Path):
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        except Exception as e:
            logger.error(f"❌ 保存失败: {e}")

def main():
    parser = argparse.ArgumentParser(description="CVE Details CVSS 批量爬虫 (多来源全字段)")
    parser.add_argument("--cve_ids", nargs='+', help="CVE ID列表")
    parser.add_argument("--cve_file", help="包含CVE ID的文本文件")
    parser.add_argument("--output", default="./cvss_cvedetails_full.json", help="输出JSON文件路径")
    parser.add_argument("--delay_min", type=float, default=5.0, help="最小请求间隔秒数")
    parser.add_argument("--delay_max", type=float, default=15.0, help="最大请求间隔秒数")
    parser.add_argument("--no_resume", action="store_true", help="不从现有文件恢复")
    args = parser.parse_args()

    cve_ids = []
    if args.cve_file:
        with open(args.cve_file, 'r', encoding='utf-8') as f:
            cve_ids = [line.strip() for line in f if line.strip()]
    elif args.cve_ids:
        cve_ids = args.cve_ids
    else:
        logger.error("❌ 错误: 必须指定 --cve_ids 或 --cve_file")
        return

    normalized_cve_ids = []
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        normalized_cve_ids.append(cve_id)

    output_path = Path(args.output)

    print("="*60)
    print("🕷️ CVE Details CVSS全量批量爬虫")
    print("="*60)
    print(f"📊 CVE数量: {len(normalized_cve_ids)}")
    print(f"📁 输出文件: {output_path}")
    print(f"⏱️ 请求间隔: {args.delay_min}-{args.delay_max}秒")
    print(f"🔄 数据源: CVE Details")
    print("="*60)

    scraper = CVEDetailsCVSSScraper((args.delay_min, args.delay_max))
    try:
        stats = scraper.scrape_batch(
            cve_ids=normalized_cve_ids,
            output_file=output_path,
            resume=not args.no_resume
        )
        print("\n" + "="*60)
        print("📈 批量爬取完成！统计信息:")
        print("="*60)
        print(f"📊 总CVE数: {stats['total_cves']}")
        print(f"✅ 成功爬取: {stats['successful']}")
        print(f"❌ 爬取失败: {stats['failed']}")
        print(f"⏭️ 跳过已有: {stats['skipped']}")
        print(f"📈 成功率: {stats['success_rate']:.1f}%")
        print(f"📁 输出文件: {stats['output_file']}")
        print("="*60)
    except KeyboardInterrupt:
        logger.info("\n⚠️ 用户中断，已保存当前进度")
    except Exception as e:
        logger.error(f"❌ 爬取过程中发生错误: {e}")

if __name__ == "__main__":
    main()
