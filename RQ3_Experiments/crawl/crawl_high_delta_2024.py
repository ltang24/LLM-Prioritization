#!/usr/bin/env python3
"""
爬取2024年高EPSS变化的CVE历史数据
"""

import json
import time
import random
from pathlib import Path
from datetime import datetime
import sys
import os

# 添加原有爬虫代码的路径
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# 复用你已有的爬虫类
from epss_history_crawler_2025 import EPSSHistoryScraper

def crawl_high_delta_cves_2024():
    """爬取2024年高变化的CVE"""
    
    # 2024年高EPSS变化的50个CVE
    target_cves = [
        "CVE-2024-38856", "CVE-2024-38077", "CVE-2024-30078", "CVE-2024-30080",
        "CVE-2024-38112", "CVE-2024-38063", "CVE-2024-43461", "CVE-2024-38189",
        "CVE-2024-43491", "CVE-2024-38213", "CVE-2024-21887", "CVE-2024-21893",
        "CVE-2024-38178", "CVE-2024-38193", "CVE-2024-30087", "CVE-2024-30088",
        "CVE-2024-38106", "CVE-2024-43468", "CVE-2024-43451", "CVE-2024-38226",
        "CVE-2024-3400",  "CVE-2024-27198", "CVE-2024-1086",  "CVE-2024-20399",
        "CVE-2024-23897", "CVE-2024-4577",  "CVE-2024-21413", "CVE-2024-28995",
        "CVE-2024-32002", "CVE-2024-0519",  "CVE-2024-21762", "CVE-2024-6387",
        "CVE-2024-47575", "CVE-2024-47176", "CVE-2024-48914", "CVE-2024-45519",
        "CVE-2024-45490", "CVE-2024-45491", "CVE-2024-45492", "CVE-2024-40711",
        "CVE-2024-38080", "CVE-2024-38085", "CVE-2024-38091", "CVE-2024-38094",
        "CVE-2024-38099", "CVE-2024-38100", "CVE-2024-38102", "CVE-2024-38104",
        "CVE-2024-38107", "CVE-2024-38109"
    ]
    
    # 输出文件
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    output_file = Path(f"./epss_high_delta_2024_{timestamp}.json")
    
    print("="*60)
    print("🎯 2024年高EPSS变化CVE爬取")
    print("="*60)
    print(f"📊 目标CVE数量: {len(target_cves)}")
    print(f"📁 输出文件: {output_file}")
    print(f"🔄 数据源: CVE Details EPSS History")
    print("="*60)
    
    # 初始化爬虫
    scraper = EPSSHistoryScraper(delay_range=(3, 8))
    
    # 开始爬取
    try:
        stats = scraper.scrape_batch(
            cve_ids=target_cves,
            output_file=output_file,
            resume=True
        )
        
        print("\n" + "="*60)
        print("📈 爬取完成！统计信息:")
        print("="*60)
        print(f"📊 总CVE数: {stats['total_cves']}")
        print(f"✅ 成功爬取: {stats['successful']}")
        print(f"❌ 爬取失败: {stats['failed']}")
        print(f"⏭️ 跳过已有: {stats['skipped']}")
        print(f"📈 成功率: {stats['success_rate']:.1f}%")
        print(f"📁 输出文件: {stats['output_file']}")
        print("="*60)
        
        # 分析爬取的数据
        if output_file.exists():
            with open(output_file, 'r') as f:
                data = json.load(f)
            
            print("\n📊 数据分析:")
            for cve_id, cve_data in data.items():
                if 'epss_history' in cve_data and len(cve_data['epss_history']) > 0:
                    history = cve_data['epss_history']
                    scores = [h['new_score'] for h in history if h.get('new_score') is not None]
                    if scores:
                        max_score = max(scores)
                        min_score = min(scores)
                        delta = max_score - min_score
                        print(f"  {cve_id}: Delta={delta:.3f}, Range=[{min_score:.3f}, {max_score:.3f}]")
        
    except KeyboardInterrupt:
        print("\n⚠️ 用户中断")
    except Exception as e:
        print(f"❌ 错误: {e}")

if __name__ == "__main__":
    crawl_high_delta_cves_2024()