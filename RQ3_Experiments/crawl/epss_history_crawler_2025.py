#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import json
import time
import random
import argparse
from pathlib import Path
import logging
import cloudscraper
from datetime import datetime
import signal
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GracefulInterruptHandler:
    def __init__(self):
        self.interrupted = False
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
    def _handle_interrupt(self, signum, frame):
        self.interrupted = True
        logger.warning("\n⚠️ 接收到中断信号，正在保存当前进度...")

interrupt_handler = GracefulInterruptHandler()

def try_parse_float(s):
    try:
        if isinstance(s, str):
            s = s.replace('%', '').replace('+', '').strip()
            if s.startswith('-'):
                return -float(s[1:])
            else:
                return float(s)
        return float(s)
    except Exception:
        return None

def try_parse_date(date_str):
    if not date_str:
        return None
    try:
        for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
            try:
                return datetime.strptime(date_str.strip(), fmt).date()
            except ValueError:
                continue
        return None
    except Exception:
        return None

def extract_epss_history_table(html_content: str, cve_id: str) -> list:
    soup = BeautifulSoup(html_content, 'html.parser')
    tables = soup.find_all('table')
    result = []
    for table in tables:
        ths = table.find_all('th')
        headers = [th.get_text(strip=True) for th in ths]
        if any('Date' in h for h in headers) and any('EPSS' in h for h in headers):
            logger.info(f"找到EPSS历史表格，表头: {headers}")
            rows = table.find_all('tr')
            for i in range(1, len(rows)):
                row = rows[i]
                cells = row.find_all('td')
                if len(cells) < 5:
                    continue
                def celltxt(idx):
                    return cells[idx].get_text(strip=True) if idx < len(cells) else None
                row_number = celltxt(0)
                date_str = celltxt(1)
                old_score_str = celltxt(2)
                new_score_str = celltxt(3)
                delta_str = celltxt(4)
                date_parsed = try_parse_date(date_str)
                old_score = try_parse_float(old_score_str) / 100 if try_parse_float(old_score_str) is not None else None
                new_score = try_parse_float(new_score_str) / 100 if try_parse_float(new_score_str) is not None else None
                delta_clean = delta_str.replace('+', '').replace('-', '') if delta_str else None
                delta = try_parse_float(delta_clean) / 100 if try_parse_float(delta_clean) is not None else None
                if delta is not None and delta_str:
                    if delta_str.startswith('-') or (old_score and new_score and new_score < old_score):
                        delta = -abs(delta)
                    else:
                        delta = abs(delta)
                if old_score is not None and new_score is not None and delta is not None:
                    calculated_delta = new_score - old_score
                    if abs(calculated_delta - delta) > 0.0001:
                        logger.warning(f"Delta不一致: 计算值={calculated_delta:.6f}, 解析值={delta:.6f}")
                        delta = calculated_delta
                percentage_change = None
                if old_score is not None and old_score > 0 and delta is not None:
                    percentage_change = (delta / old_score) * 100
                item = {
                    "date": date_parsed.isoformat() if date_parsed else date_str,
                    "old_score": old_score,
                    "new_score": new_score,
                    "delta": delta,
                    "percentage_change": percentage_change,
                    "raw_old_score": old_score_str,
                    "raw_new_score": new_score_str,
                    "raw_delta": delta_str,
                    "row_number": row_number
                }
                result.append(item)
    result.sort(key=lambda x: x['date'] if x['date'] and '20' in str(x['date']) else '1900-01-01', reverse=True)
    return result

class EPSSHistoryScraper:
    def __init__(self, delay_range: tuple = (3, 8), timeout: int = 30):
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

    def get_safe_request(self, url: str, referer: str = None, max_retries: int = 3) -> requests.Response:
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

    def get_epss_history(self, cve_id: str):
        epss_url = f"{self.base_url}/epss/{cve_id}/epss-score-history.html"
        response = self.get_safe_request(epss_url, referer=f"{self.base_url}/cve/{cve_id}/")
        if response:
            epss_history = extract_epss_history_table(response.text, cve_id)
            if epss_history and len(epss_history) > 0:
                logger.info(f"✓ {cve_id}: {len(epss_history)} 条EPSS历史记录")
                return epss_history
            else:
                logger.warning(f"❌ 未找到 {cve_id} 的EPSS历史数据。")
        else:
            logger.warning(f"EPSS历史获取失败: {cve_id}")
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
        logger.info(f"🎯 开始批量爬取EPSS历史数据...")
        logger.info(f"📊 总计: {total} 个CVE")
        logger.info("\n💡 提示: 按 Ctrl+C 可以安全中断并保存进度\n")
        for i, cve_id in enumerate(cve_ids, 1):
            if interrupt_handler.interrupted:
                logger.warning("⚠️ 检测到中断信号，正在保存进度...")
                self._save_data(existing_data, output_file)
                logger.info("✅ 进度已保存，可以随时恢复")
                logger.info(f"📊 已处理: {i-1}/{total}")
                sys.exit(0)
            if cve_id in existing_data and existing_data[cve_id]:
                skipped += 1
                logger.info(f"[{i}/{total}] ⏭️ 跳过已有数据: {cve_id}")
                continue
            logger.info(f"[{i}/{total}] 正在处理: {cve_id}")
            epss_history = self.get_epss_history(cve_id)
            if epss_history and len(epss_history) > 0:
                existing_data[cve_id] = {
                    "cve_id": cve_id,
                    "epss_history": epss_history,
                    "crawl_timestamp": datetime.now().isoformat(),
                    "total_records": len(epss_history),
                    "date_range": {
                        "earliest": epss_history[-1]['date'],
                        "latest": epss_history[0]['date']
                    }
                }
                successful += 1
                logger.info(f"  ✓ 成功获取 {len(epss_history)} 条记录")
                if len(epss_history) > 0:
                    latest = epss_history[0]
                    logger.info(f"  最新记录: {latest['date']} - EPSS: {latest['new_score']}")
            else:
                failed += 1
                logger.warning(f"❌ 未找到 {cve_id} 的EPSS历史数据，不保存该CVE。")
            if i % 5 == 0:
                self._save_data(existing_data, output_file)
                logger.info(f"📁 已保存进度 ({i}/{total})")
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
            temp_file = output_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            temp_file.replace(output_file)
        except Exception as e:
            logger.error(f"❌ 保存失败: {e}")

def generate_2025_cve_ids():
    cve_prefix = "CVE-2025-"
    max_cve_number = 99999
    cve_ids = [f"{cve_prefix}{str(i).zfill(4)}" for i in range(1, max_cve_number + 1)]
    return cve_ids

def main():
    parser = argparse.ArgumentParser(description="EPSS历史数据批量爬虫")
    parser.add_argument("--crawl_2025", action="store_true", help="自动爬取2025年所有CVE")
    parser.add_argument("--output", default=None, help="输出JSON文件路径（可选，不填则自动生成带时间戳文件）")
    parser.add_argument("--delay_min", type=float, default=3.0, help="最小请求间隔秒数")
    parser.add_argument("--delay_max", type=float, default=8.0, help="最大请求间隔秒数")
    parser.add_argument("--no_resume", action="store_true", help="不从现有文件恢复")
    args = parser.parse_args()

    cve_ids = []
    if args.crawl_2025:
        cve_ids = generate_2025_cve_ids()
    else:
        logger.error("❌ 错误: 目前只支持 --crawl_2025 自动爬取全年2025")
        return

    normalized_cve_ids = []
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        normalized_cve_ids.append(cve_id)
    total_to_crawl = len(normalized_cve_ids)

    if args.output:
        output_path = Path(args.output)
    else:
        nowstr = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = Path(f"./epss_history_2025_{nowstr}.json")

    print("="*60)
    print("🕷️ EPSS历史数据批量爬虫")
    print("="*60)
    print(f"📊 CVE数量: {total_to_crawl}")
    print(f"📁 输出文件: {output_path}")
    print(f"⏱️ 请求间隔: {args.delay_min}-{args.delay_max}秒")
    print(f"🔄 数据源: CVE Details EPSS History")
    print(f"📋 CVE范围: {normalized_cve_ids[0]} ~ {normalized_cve_ids[-1]}")
    print("="*60)

    scraper = EPSSHistoryScraper((args.delay_min, args.delay_max))
    try:
        stats = scraper.scrape_batch(
            cve_ids=normalized_cve_ids,
            output_file=output_path,
            resume=not args.no_resume
        )
        print("\n" + "="*60)
        print("📈 EPSS历史数据爬取完成！统计信息:")
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
        logger.info("💡 使用相同命令可以继续之前的爬取进度")
    except Exception as e:
        logger.error(f"❌ 爬取过程中发生错误: {e}")

if __name__ == "__main__":
    main()
