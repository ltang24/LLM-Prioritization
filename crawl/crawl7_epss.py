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
from datetime import datetime, timedelta
import pandas as pd
import signal
import sys

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class GracefulInterruptHandler:
    """优雅地处理中断信号"""
    def __init__(self):
        self.interrupted = False
        signal.signal(signal.SIGINT, self._handle_interrupt)
        signal.signal(signal.SIGTERM, self._handle_interrupt)
    
    def _handle_interrupt(self, signum, frame):
        self.interrupted = True
        logger.warning("\n⚠️ 接收到中断信号，正在保存当前进度...")

interrupt_handler = GracefulInterruptHandler()

def try_parse_float(s):
    """尝试将字符串转换为浮点数，正确处理百分比格式"""
    try:
        if isinstance(s, str):
            # 移除百分号、加号、空格
            s = s.replace('%', '').replace('+', '').strip()
            # 保留负号
            if s.startswith('-'):
                return -float(s[1:])
            else:
                return float(s)
        return float(s)
    except Exception:
        return None

def try_parse_date(date_str):
    """尝试解析日期字符串"""
    if not date_str:
        return None
    try:
        # 尝试不同的日期格式
        for fmt in ['%Y-%m-%d', '%m/%d/%Y', '%d/%m/%Y']:
            try:
                return datetime.strptime(date_str.strip(), fmt).date()
            except ValueError:
                continue
        return None
    except Exception:
        return None

def extract_epss_history_table(html_content: str, cve_id: str) -> list:
    """从HTML内容中提取EPSS历史数据表格"""
    soup = BeautifulSoup(html_content, 'html.parser')
    
    # 查找包含EPSS历史数据的表格
    tables = soup.find_all('table')
    result = []
    
    for table in tables:
        # 检查表头是否包含EPSS相关字段
        ths = table.find_all('th')
        headers = [th.get_text(strip=True) for th in ths]
        
        # 查找包含Date, Old EPSS Score, New EPSS Score, Delta等字段的表格
        if any('Date' in h for h in headers) and any('EPSS' in h for h in headers):
            logger.info(f"找到EPSS历史表格，表头: {headers}")
            
            rows = table.find_all('tr')
            for i in range(1, len(rows)):  # 跳过表头
                row = rows[i]
                cells = row.find_all('td')
                
                if len(cells) < 5:  # 需要5列：#, Date, Old EPSS, New EPSS, Delta
                    continue
                
                def celltxt(idx):
                    return cells[idx].get_text(strip=True) if idx < len(cells) else None
                
                # 根据实际表格结构正确提取数据
                # 列0: # (序号)
                # 列1: Date
                # 列2: Old EPSS Score  
                # 列3: New EPSS Score
                # 列4: Delta (New - Old)
                
                row_number = celltxt(0)  # 序号
                date_str = celltxt(1)    # 日期
                old_score_str = celltxt(2)  # 旧分数
                new_score_str = celltxt(3)  # 新分数  
                delta_str = celltxt(4)      # 变化量
                
                # 解析数据
                date_parsed = try_parse_date(date_str)
                
                # 正确处理百分比格式 (0.09% -> 0.0009)
                old_score = try_parse_float(old_score_str) / 100 if try_parse_float(old_score_str) is not None else None
                new_score = try_parse_float(new_score_str) / 100 if try_parse_float(new_score_str) is not None else None
                
                # Delta处理（可能包含+/-符号）
                delta_clean = delta_str.replace('+', '').replace('-', '') if delta_str else None
                delta = try_parse_float(delta_clean) / 100 if try_parse_float(delta_clean) is not None else None
                
                # 确定delta的正负号
                if delta is not None and delta_str:
                    if delta_str.startswith('-') or (old_score and new_score and new_score < old_score):
                        delta = -abs(delta)
                    else:
                        delta = abs(delta)
                
                # 验证数据一致性
                if old_score is not None and new_score is not None and delta is not None:
                    calculated_delta = new_score - old_score
                    if abs(calculated_delta - delta) > 0.0001:  # 允许小的浮点误差
                        logger.warning(f"Delta不一致: 计算值={calculated_delta:.6f}, 解析值={delta:.6f}")
                        delta = calculated_delta  # 使用计算值
                
                # 计算百分比变化
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
    
    # 按日期排序（最新的在前）
    result.sort(key=lambda x: x['date'] if x['date'] and '20' in str(x['date']) else '1900-01-01', reverse=True)
    return result

class EPSSHistoryScraper:
    def __init__(self, delay_range: tuple = (3, 8), timeout: int = 30):
        self.base_url = "https://www.cvedetails.com"
        self.delay_range = delay_range
        self.timeout = timeout
        
        # 使用与CVSS爬虫相同的session初始化策略
        try:
            self.session = cloudscraper.create_scraper()
            logger.info("使用cloudscraper创建会话")
        except Exception:
            self.session = requests.Session()
            logger.info("使用标准requests创建会话")
        
        # 使用相同的User-Agent池
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
        """初始化会话 - 复用CVSS爬虫的逻辑"""
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
        """安全请求方法 - 复用CVSS爬虫的反爬虫策略"""
        if not self.session_initialized:
            if not self.initialize_session():
                logger.error("无法初始化会话")
                return None
                
        for attempt in range(max_retries):
            try:
                if referer:
                    self.session.headers['Referer'] = referer
                
                # 随机延迟
                delay = random.uniform(*self.delay_range)
                logger.info(f"等待 {delay:.1f} 秒...")
                time.sleep(delay)
                
                # 随机更换User-Agent
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
        """获取单个CVE的EPSS历史数据"""
        # 构建EPSS历史页面URL - 根据实际URL格式调整
        epss_url = f"{self.base_url}/epss/{cve_id}/epss-score-history.html"
        
        response = self.get_safe_request(epss_url, referer=f"{self.base_url}/cve/{cve_id}/")
        
        if response:
            epss_history = extract_epss_history_table(response.text, cve_id)
            if epss_history and len(epss_history) > 0:
                logger.info(f"✓ {cve_id}: {len(epss_history)} 条EPSS历史记录")
                return epss_history
            else:
                # 保存debug页面
                debug_file = f"debug_epss_{cve_id}.html"
                with open(debug_file, "w", encoding="utf-8") as f:
                    f.write(response.text)
                logger.warning(f"未找到EPSS历史数据，已保存debug文件: {debug_file}")
        
        logger.warning(f"EPSS历史获取失败: {cve_id}")
        return []

    def scrape_batch(self, cve_ids, output_file: Path, resume=True):
        """批量爬取EPSS历史数据"""
        existing_data = {}
        
        # 加载现有数据（支持断点续传）
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
            # 检查是否被中断
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
            
            # 构建数据结构
            existing_data[cve_id] = {
                "cve_id": cve_id,
                "epss_history": epss_history,
                "crawl_timestamp": datetime.now().isoformat(),
                "total_records": len(epss_history),
                "date_range": {
                    "earliest": epss_history[-1]['date'] if epss_history else None,
                    "latest": epss_history[0]['date'] if epss_history else None
                }
            }
            
            if epss_history:
                successful += 1
                logger.info(f"  ✓ 成功获取 {len(epss_history)} 条记录")
                # 显示最近几条记录的简要信息
                if len(epss_history) > 0:
                    latest = epss_history[0]
                    logger.info(f"  最新记录: {latest['date']} - EPSS: {latest['new_score']}")
            else:
                failed += 1
            
            # 每5个CVE保存一次（避免数据丢失）
            if i % 5 == 0:
                self._save_data(existing_data, output_file)
                logger.info(f"📁 已保存进度 ({i}/{total})")
        
        # 最终保存
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
        """保存数据到JSON文件"""
        try:
            output_file.parent.mkdir(parents=True, exist_ok=True)
            # 先写入临时文件
            temp_file = output_file.with_suffix('.tmp')
            with open(temp_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            # 原子性替换
            temp_file.replace(output_file)
        except Exception as e:
            logger.error(f"❌ 保存失败: {e}")

    def generate_summary_report(self, data_file: Path):
        """生成EPSS历史数据的统计报告"""
        try:
            with open(data_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            total_cves = len(data)
            cves_with_data = sum(1 for cve_data in data.values() if cve_data.get('epss_history'))
            total_records = sum(len(cve_data.get('epss_history', [])) for cve_data in data.values())
            
            # 分析EPSS分数分布
            all_scores = []
            date_range = {'earliest': None, 'latest': None}
            
            for cve_data in data.values():
                for record in cve_data.get('epss_history', []):
                    if record.get('new_score') is not None:
                        all_scores.append(record['new_score'])
                    
                    if record.get('date'):
                        if not date_range['earliest'] or record['date'] < date_range['earliest']:
                            date_range['earliest'] = record['date']
                        if not date_range['latest'] or record['date'] > date_range['latest']:
                            date_range['latest'] = record['date']
            
            summary = {
                'collection_info': {
                    'total_cves': total_cves,
                    'cves_with_epss_data': cves_with_data,
                    'total_epss_records': total_records,
                    'coverage_rate': (cves_with_data / total_cves * 100) if total_cves > 0 else 0
                },
                'temporal_coverage': date_range,
                'epss_statistics': {
                    'total_scores': len(all_scores),
                    'mean_score': sum(all_scores) / len(all_scores) if all_scores else 0,
                    'min_score': min(all_scores) if all_scores else None,
                    'max_score': max(all_scores) if all_scores else None,
                    'scores_above_0.1': sum(1 for s in all_scores if s > 0.001) if all_scores else 0,
                    'scores_above_0.5': sum(1 for s in all_scores if s > 0.005) if all_scores else 0
                }
            }
            
            return summary
            
        except Exception as e:
            logger.error(f"生成报告失败: {e}")
            return None

def generate_cve_range(start: str, end: str) -> list:
    """生成CVE范围列表，例如 CVE-2024-9894 到 CVE-2024-9999"""
    try:
        # 解析起始和结束CVE
        start_parts = start.split('-')
        end_parts = end.split('-')
        
        if len(start_parts) != 3 or len(end_parts) != 3:
            raise ValueError("CVE格式错误")
        
        year = start_parts[1]
        start_num = int(start_parts[2])
        end_num = int(end_parts[2])
        
        cve_list = []
        for num in range(start_num, end_num + 1):
            cve_list.append(f"CVE-{year}-{num}")
        
        return cve_list
        
    except Exception as e:
        logger.error(f"生成CVE范围失败: {e}")
        return []

def main():
    parser = argparse.ArgumentParser(description="EPSS历史数据批量爬虫")
    parser.add_argument("--cve_ids", nargs='+', help="CVE ID列表")
    parser.add_argument("--cve_file", help="包含CVE ID的文本文件")
    parser.add_argument("--cve_range", help="CVE范围，格式: CVE-2024-9894:CVE-2024-9999")
    parser.add_argument("--output", default="./epss_history_data.json", help="输出JSON文件路径")
    parser.add_argument("--delay_min", type=float, default=3.0, help="最小请求间隔秒数")
    parser.add_argument("--delay_max", type=float, default=8.0, help="最大请求间隔秒数")
    parser.add_argument("--no_resume", action="store_true", help="不从现有文件恢复")
    parser.add_argument("--generate_report", action="store_true", help="生成数据统计报告")
    args = parser.parse_args()

    # 获取CVE列表
    cve_ids = []
    if args.cve_range:
        # 解析范围格式
        if ':' in args.cve_range:
            start_cve, end_cve = args.cve_range.split(':')
            cve_ids = generate_cve_range(start_cve.strip(), end_cve.strip())
        else:
            logger.error("CVE范围格式错误，应为: CVE-2024-9894:CVE-2024-9999")
            return
    elif args.cve_file:
        with open(args.cve_file, 'r', encoding='utf-8') as f:
            cve_ids = [line.strip() for line in f if line.strip()]
    elif args.cve_ids:
        cve_ids = args.cve_ids
    else:
        logger.error("❌ 错误: 必须指定 --cve_ids, --cve_file 或 --cve_range")
        return

    # 标准化CVE ID格式
    normalized_cve_ids = []
    for cve_id in cve_ids:
        cve_id = cve_id.strip().upper()
        if not cve_id.startswith('CVE-'):
            cve_id = f'CVE-{cve_id}'
        normalized_cve_ids.append(cve_id)

    output_path = Path(args.output)

    # 如果只是生成报告
    if args.generate_report:
        if output_path.exists():
            scraper = EPSSHistoryScraper()
            report = scraper.generate_summary_report(output_path)
            if report:
                print("\n" + "="*60)
                print("📊 EPSS历史数据统计报告")
                print("="*60)
                print(json.dumps(report, indent=2, ensure_ascii=False))
                print("="*60)
        else:
            logger.error(f"数据文件不存在: {output_path}")
        return

    print("="*60)
    print("🕷️ EPSS历史数据批量爬虫")
    print("="*60)
    print(f"📊 CVE数量: {len(normalized_cve_ids)}")
    print(f"📁 输出文件: {output_path}")
    print(f"⏱️ 请求间隔: {args.delay_min}-{args.delay_max}秒")
    print(f"🔄 数据源: CVE Details EPSS History")
    if len(normalized_cve_ids) > 0:
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
        
        # 自动生成统计报告
        if stats['successful'] > 0:
            report = scraper.generate_summary_report(output_path)
            if report:
                print("\n📊 数据统计预览:")
                print(f"  有效CVE数: {report['collection_info']['cves_with_epss_data']}")
                print(f"  EPSS记录总数: {report['collection_info']['total_epss_records']}")
                print(f"  时间跨度: {report['temporal_coverage']['earliest']} ~ {report['temporal_coverage']['latest']}")
                print(f"  平均EPSS分数: {report['epss_statistics']['mean_score']:.6f}")
        
    except KeyboardInterrupt:
        logger.info("\n⚠️ 用户中断，已保存当前进度")
        logger.info("💡 使用相同命令可以继续之前的爬取进度")
    except Exception as e:
        logger.error(f"❌ 爬取过程中发生错误: {e}")

if __name__ == "__main__":
    main()