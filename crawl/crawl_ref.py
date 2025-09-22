#!/usr/bin/env python3
"""
快速版CVSS分析工具 - 基于官方定义，只提取reasoning
修改版：仅处理指定CVE ID列表
"""

import json, pathlib, copy, re, time, requests, bs4, argparse, random
from g4f.client import Client

# ======== 路径常量，按需修改 =========
DETAIL_ROOT = pathlib.Path(
    "./security-agent/cyber_data/cveList_V5/extract_meta"
)
REF_ROOT = pathlib.Path(
    "./security-agent/cyber_data/cveList_V5/ref"
)
# 指定CVE ID文件路径
SPECIFIED_CVE_FILE = pathlib.Path(
    "./security-agent/cyber_data/crawl/extracted_cve_ids.txt"
)
# ====================================

# 常量定义 - 快速版本
MAX_RETRIES = 3  # 减少重试次数
RATE_LIMIT_KEYWORDS = ["限流", "rate limit", "daily limit", "quota", "battle mode", "please come back later", "too many requests", "try again", "wait"]

def load_specified_cve_ids(file_path: pathlib.Path) -> set:
    """加载指定的CVE ID列表"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_ids = set()
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):  # 跳过空行和注释行
                    # 确保CVE ID格式统一，转换为大写
                    if line.upper().startswith('CVE-'):
                        cve_ids.add(line.upper())
                    else:
                        # 如果没有CVE-前缀，添加它
                        cve_ids.add(f'CVE-{line.upper()}')
            print(f"📋 从 {file_path} 加载了 {len(cve_ids)} 个指定的CVE ID")
            return cve_ids
    except FileNotFoundError:
        print(f"❌ 指定的CVE ID文件未找到: {file_path}")
        print("将继续处理所有CVE文件...")
        return set()
    except Exception as e:
        print(f"❌ 读取指定CVE ID文件时出错: {e}")
        print("将继续处理所有CVE文件...")
        return set()

def skip_url(url: str) -> bool:
    """跳过不相关的URL"""
    # 移除vuldb.com，因为它可能包含有用的漏洞信息
    bad = ("github.com/CVEProject", "twitter.com", "facebook.com", "linkedin.com")
    return any(b in url for b in bad)

def g4f_generate_fast(prompt: str, timeout: int = 30, temp: float = 0.3) -> str:
    """快速g4f API调用 - 减少等待时间"""
    client = Client()
    
    # 缩短prompt长度
    if len(prompt) > 3000:
        prompt = prompt[:3000] + "..."
    
    # 精简模型列表，只用最稳定的
    models = [
        "gpt-4o",              # 最优先
        "llama-3.1-405b",      # 备用
        "gemini-pro"           # 最后备用
    ]
    
    for model_idx, model in enumerate(models):
        print(f"    尝试模型 [{model_idx+1}/{len(models)}]: {model}")
        
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                # 减少延迟
                time.sleep(random.uniform(0.5, 2))
                
                resp = client.chat.completions.create(
                    model=model,
                    messages=[{"role": "user", "content": prompt}],
                    timeout=timeout,
                    temperature=temp,
                )
                
                content = resp.choices[0].message.content.strip()
                
                # 检测限流但快速跳过
                if any(keyword in content.lower() for keyword in RATE_LIMIT_KEYWORDS):
                    print(f"    [模型 {model} - 尝试 {attempt}/{MAX_RETRIES}] 限流，快速跳过")
                    if attempt == MAX_RETRIES:
                        break  # 不等待，直接尝试下一个模型
                    time.sleep(5)  # 只等5秒
                    continue
                
                # 检查响应质量
                if len(content) > 10 and ("{" in content or "reasoning" in content.lower()):
                    print(f"    ✓ 模型 {model} 成功 (长度: {len(content)})")
                    return content
                else:
                    print(f"    [模型 {model} - 尝试 {attempt}/{MAX_RETRIES}] 响应质量低")
                    
            except Exception as e:
                print(f"    [模型 {model} - 尝试 {attempt}/{MAX_RETRIES}] 错误: {str(e)[:50]}")
                if attempt < MAX_RETRIES:
                    time.sleep(2)  # 减少等待时间
        
        print(f"    ✗ 模型 {model} 失败")
        # 快速切换下一个模型
        if model_idx < len(models) - 1:
            time.sleep(3)  # 只等3秒
    
    print("    ✗ 所有模型失败")
    return "{}"

def fast_clean_json(raw: str) -> str:
    """快速JSON清理"""
    if not raw:
        return "{}"
    
    raw = raw.strip()
    
    # 快速清理
    if "```json" in raw:
        raw = raw.split("```json")[1].split("```")[0]
    elif "```" in raw:
        parts = raw.split("```")
        if len(parts) >= 3:
            raw = parts[1]
    
    # 修复常见问题
    raw = re.sub(r'^{\s*{', '{', raw)
    raw = re.sub(r'}\s*}$', '}', raw)
    raw = re.sub(r'\n\s*', ' ', raw)
    raw = re.sub(r'\s+', ' ', raw)
    raw = re.sub(r'"User _Interaction"', '"User_Interaction"', raw)
    raw = re.sub(r',\s*}', '}', raw)
    
    if not raw.startswith("{"):
        raw = "{" + raw
    if not raw.endswith("}"):
        raw = raw.rstrip(",") + "}"
    
    return raw

def quick_extract_reasoning(raw: str, metrics: list) -> dict:
    """快速提取CVSS reasoning - 只提取reasoning，不要值"""
    result = {}
    
    for metric in metrics:
        # 特殊处理User_Interaction的各种可能名称
        if metric == "User_Interaction":
            reasoning_patterns = [
                rf'"User_Interaction_Reasoning":\s*"([^"]+)"',
                rf'"UserInteraction_Reasoning":\s*"([^"]+)"',
                rf'"User_Interaction_reasoning":\s*"([^"]+)"',
                rf'"User Interaction Reasoning":\s*"([^"]+)"',
                rf'"user_interaction_reasoning":\s*"([^"]+)"',
            ]
        else:
            # 其他指标的reasoning模式
            reasoning_patterns = [
                rf'"{metric}_Reasoning":\s*"([^"]+)"',
                rf'"{metric}_reasoning":\s*"([^"]+)"',
                rf'"{metric} Reasoning":\s*"([^"]+)"',
                rf'"{metric.lower()}_reasoning":\s*"([^"]+)"',
            ]
        
        # 寻找reasoning
        reasoning = None
        for r_pattern in reasoning_patterns:
            reasoning_match = re.search(r_pattern, raw, re.IGNORECASE | re.DOTALL)
            if reasoning_match:
                reasoning = reasoning_match.group(1).strip().rstrip('.",')
                # 处理转义字符
                reasoning = reasoning.replace('\\"', '"').replace('\\n', ' ').replace('\\t', ' ')
                reasoning = re.sub(r'\s+', ' ', reasoning).strip()
                break
        
        # 如果找到reasoning
        if reasoning and len(reasoning) > 30:  # 要求reasoning至少30字符
            result[metric] = {
                f"{metric}_Reasoning": reasoning
            }
            print(f"      ✓ 提取到reasoning: {metric} (长度: {len(reasoning)})")
        else:
            print(f"      ✗ {metric} reasoning太短或缺失 (长度: {len(reasoning or '')})")
    
    return result

def fast_cvss_analysis(cve, url, desc, prev=None):
    """快速CVSS分析 - 基于官方定义，只生成reasoning"""
    prev = prev or {}
    print(f"分析CVSS指标: {cve} - {url}")
    
    if skip_url(url):
        print("  跳过URL")
        return prev
    
    page_text = ""
    web_content_available = False
    
    try:
        # 为VulDB等网站添加更完整的headers
        headers = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate, br",
            "DNT": "1",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
        }
        
        print(f"  访问URL: {url}")
        rsp = requests.get(url, timeout=20, headers=headers, allow_redirects=True)
        rsp.raise_for_status()
        
        print(f"  HTTP状态码: {rsp.status_code}")
        print(f"  响应内容长度: {len(rsp.text)} 字符")
        
        # 检查响应内容长度
        if len(rsp.text) < 100:
            print(f"  ! 网页内容过短 ({len(rsp.text)} 字符)，可能被阻止访问")
            print(f"  响应内容: {rsp.text[:200]}")
        else:
            # 快速解析HTML
            html = bs4.BeautifulSoup(rsp.text, "html.parser")
            for script in html(["script", "style"]):
                script.decompose()
            page_text = html.get_text()
            
            print(f"  提取的文本长度: {len(page_text)} 字符")
            print(f"  文本前200字符: {page_text[:200]}")
            
            if len(page_text.strip()) >= 50:
                web_content_available = True
                if len(page_text) > 2000:
                    page_text = page_text[:2000] + "..."
            else:
                print(f"  ! 提取的文本内容太少，将基于CVE描述进行分析")
            
    except requests.exceptions.HTTPError as e:
        if "403" in str(e):
            print(f"  ! 网站拒绝访问 (403)，将基于CVE描述进行分析")
        elif "404" in str(e):
            print(f"  ! 页面不存在 (404)，将基于CVE描述进行分析")
        else:
            print(f"  ! HTTP错误: {e}，将基于CVE描述进行分析")
    except Exception as e:
        print(f"  ! 网页访问失败: {e}，将基于CVE描述进行分析")

    # 如果网页内容不可用，使用CVE描述进行分析
    if not web_content_available:
        print(f"  使用CVE描述进行分析（描述长度: {len(desc)} 字符）")
        page_text = f"CVE描述: {desc}"
        if len(desc) < 50:
            print(f"  ! CVE描述也太短，可能无法生成完整的CVSS分析")

    # 一次性分析所有8个指标 - 基于官方CVSS定义，只提供reasoning
    print(f"  基于官方定义生成所有8个CVSS指标的reasoning...")
    
    all_in_one_prompt = f"""Analyze the following vulnerability for CVSS v3.1 Base Metrics and provide detailed reasoning for each metric based on the official CVSS definitions.

CVE: {cve}
Description: {desc}
Web Content: {page_text}

**OFFICIAL CVSS v3.1 METRIC DEFINITIONS:**

**Attack Vector (AV)** - Context by which vulnerability exploitation is possible:
This metric reflects the context by which vulnerability exploitation is possible. The metric value will be larger the more remote (logically, and physically) an attacker can be in order to exploit the vulnerable component.

**Attack Complexity (AC)** - Conditions beyond attacker's control that must exist:
This metric describes the conditions beyond the attacker's control that must exist in order to exploit the vulnerability. Such conditions may require the collection of more information about the target, or computational exceptions. The assessment of this metric excludes any requirements for user interaction.

**Privileges Required (PR)** - Level of privileges an attacker must possess:
This metric describes the level of privileges an attacker must possess before successfully exploiting the vulnerability.

**User Interaction (UI)** - Whether a human user must participate in exploitation:
This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component.

**Scope (S)** - Whether vulnerability impacts resources beyond its security scope:
The Scope metric captures whether a vulnerability in one vulnerable component impacts resources in components beyond its security scope. A security authority defines and enforces access control. If a vulnerability can affect a component in a different security scope than the vulnerable component, a Scope change occurs.

**Confidentiality Impact (C)** - Impact to confidentiality of information resources:
This metric measures the impact to the confidentiality of the information resources managed by a software component due to a successfully exploited vulnerability.

**Integrity Impact (I)** - Impact to integrity of a successfully exploited vulnerability:
This metric measures the impact to integrity of a successfully exploited vulnerability. Integrity refers to the trustworthiness and veracity of information.

**Availability Impact (A)** - Impact to availability of the impacted component:
This metric measures the impact to the availability of the impacted component resulting from a successfully exploited vulnerability.

**TASK:**
For each of the 8 metrics above, provide detailed technical reasoning (minimum 40 words) that:
1. Analyzes how this specific vulnerability relates to the metric definition
2. Considers the technical details provided in the CVE description and web content
3. Explains the reasoning without making assumptions beyond what is described
IMPORTANT: In your reasoning, you MUST NOT use any CVSS metric value or label (such as "None", "Low", "Required", "Unchanged", "High", "Network", "Local", "Physical", "Adjacent", etc.). Instead, explain the technical scenario and requirements only in descriptive language. Do NOT state or hint at any CVSS value or label.


Return your analysis in the following JSON format:

{{"Attack_Vector_Reasoning": "Analyze the exploitation context and attacker remoteness based on the vulnerability details. Consider how an attacker would need to reach the vulnerable component and what access methods are involved.", "Attack_Complexity_Reasoning": "Evaluate what conditions beyond the attacker's control must exist for successful exploitation. Consider whether special configurations, timing, or additional information gathering is required.", "Privileges_Required_Reasoning": "Assess what level of privileges or authentication an attacker needs before exploiting this vulnerability. Consider the access requirements described in the vulnerability details.", "User_Interaction_Reasoning": "Determine whether human user participation (other than the attacker) is required for successful exploitation. Consider if the vulnerability can be exploited solely by the attacker or requires user actions.", "Scope_Reasoning": "Analyze whether the vulnerability impact remains within the component's security boundaries or affects other components. Consider if exploitation crosses security authority boundaries.", "Confidentiality_Impact_Reasoning": "Evaluate the impact on information confidentiality. Consider what data could be accessed, disclosed, or compromised if this vulnerability is exploited.", "Integrity_Impact_Reasoning": "Assess the impact on data integrity and trustworthiness. Consider what information or systems could be modified, corrupted, or tampered with.", "Availability_Impact_Reasoning": "Analyze the impact on service or component availability. Consider whether exploitation could disrupt, degrade, or deny access to the affected component."}}

Provide objective technical analysis based solely on the vulnerability information provided."""
    
    raw = g4f_generate_fast(all_in_one_prompt) or "{}"
    
    # 保存完整的AI原始回答
    prev["AI_Raw_Response"] = {
        "content": raw,
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "note": "完整的AI原始回答"
    }
    
    raw = fast_clean_json(raw)
    
    # 三步解析 - 只提取reasoning
    all_metrics = ["Attack_Vector", "Attack_Complexity", "Privileges_Required", "User_Interaction", 
                   "Scope", "Confidentiality_Impact", "Integrity_Impact", "Availability_Impact"]
    
    # 第一步：尝试JSON解析
    print(f"    原始AI响应前200字符: {raw[:200]}...")
    
    try:
        result = json.loads(raw)
        
        # 处理JSON结果，只保留reasoning
        processed_results = {}
        missing_metrics = []
        
        for metric in all_metrics:
            reasoning_key = f"{metric}_Reasoning"
            if reasoning_key in result:
                reasoning = result.get(reasoning_key)
                
                # 只保留有reasoning的
                if reasoning and reasoning.strip() and len(reasoning) > 30:
                    processed_results[metric] = {
                        f"{metric}_Reasoning": reasoning
                    }
                    print(f"      ✓ 完整提取reasoning: {metric}")
                else:
                    print(f"      ✗ {metric} reasoning太短或缺失")
                    missing_metrics.append(metric)
            else:
                print(f"      ✗ 缺少指标reasoning: {metric}")
                missing_metrics.append(metric)
        
        # 显示缺失的指标
        if missing_metrics:
            print(f"    ⚠️ 缺失reasoning的指标: {missing_metrics}")
        
        if len(processed_results) >= 6:  # 提高标准，要求至少6个
            prev.update(processed_results)
            print(f"    ✓ 一次性成功提取 {len(processed_results)} 个完整reasoning")
            
            # 如果还有缺失的，尝试补充
            if len(processed_results) < 8:
                print(f"    尝试补充缺失的 {8 - len(processed_results)} 个reasoning...")
                return prev
            return prev
        elif len(processed_results) >= 3:  # 如果有3个以上完整的也接受，继续处理剩余
            prev.update(processed_results)
            print(f"    ✓ 部分成功提取 {len(processed_results)} 个完整reasoning，继续处理剩余")
            # 继续处理剩余指标
        else:
            print(f"    ✗ 只提取到 {len(processed_results)} 个完整reasoning，质量不够")
    except json.JSONDecodeError as e:
        print(f"    ✗ JSON解析失败: {str(e)}")
        print(f"    清理后的内容前500字符: {raw[:500]}...")
        print(f"    尝试手动提取reasoning...")
        
        # 恢复手动提取
        manual_results = quick_extract_reasoning(raw, all_metrics)
        if len(manual_results) > 0:
            prev.update(manual_results)
            print(f"    ✓ 手动提取成功 {len(manual_results)} 个reasoning")
        else:
            print(f"    ✗ 手动提取也失败")
    
    # 第二步：检查是否还有缺失的指标
    current_total = len([k for k in prev.keys() if not k.endswith("_Raw_Response")])
    if current_total < 8:
        print(f"    ⚠️ 当前只有 {current_total} 个reasoning，开始分组处理...")
    else:
        return prev
        
    # 第三步：分组处理 - 确保覆盖所有指标
    print(f"    开始分组处理，确保获得所有8个reasoning...")
    
    # 检查哪些指标还缺失
    missing_metrics = [m for m in all_metrics if m not in prev]
    print(f"    缺失的reasoning: {missing_metrics}")
    
    # 分组1：基础指标 (前4个)
    group1_metrics = [m for m in all_metrics[:4] if m not in prev]
    if group1_metrics:
        print(f"    处理组1缺失reasoning: {group1_metrics}")
        
        group1_prompt = f"""Analyze CVE {cve} for these specific CVSS v3.1 metrics: {', '.join(group1_metrics)}

Provide detailed technical reasoning (minimum 40 words per metric) based on the official definitions:

**Attack Vector:** Context by which vulnerability exploitation is possible. Consider how remote an attacker can be.

**Attack Complexity:** Conditions beyond attacker's control that must exist for exploitation. Consider required configurations or special conditions.

**Privileges Required:** Level of privileges an attacker must possess before successfully exploiting the vulnerability.

**User Interaction:** Whether a human user (other than the attacker) must participate in the successful compromise.
IMPORTANT: In your reasoning, you MUST NOT use any CVSS metric value or label (such as "None", "Low", "Required", "Unchanged", "High", "Network", "Local", "Physical", "Adjacent", etc.). Instead, explain the technical scenario and requirements only in descriptive language. Do NOT state or hint at any CVSS value or label.

CVE Description: {desc[:800]}
Content: {page_text[:1000]}

Analyze each requested metric objectively based on the vulnerability details provided.

Return JSON format: {{"Attack_Vector_Reasoning": "Technical analysis of exploitation context...", "Attack_Complexity_Reasoning": "Analysis of conditions required...", "Privileges_Required_Reasoning": "Assessment of privilege requirements...", "User_Interaction_Reasoning": "Evaluation of user participation needs..."}}

JSON:"""
        raw1 = g4f_generate_fast(group1_prompt) or "{}"
        raw1 = fast_clean_json(raw1)
        
        try:
            result1 = json.loads(raw1)
            # 只保留reasoning
            added_count1 = 0
            for metric in group1_metrics:
                reasoning_key = f"{metric}_Reasoning"
                if reasoning_key in result1:
                    reasoning = result1.get(reasoning_key)
                    
                    # 只保留有reasoning的
                    if reasoning and reasoning.strip() and len(reasoning) > 30:
                        prev[metric] = {
                            reasoning_key: reasoning
                        }
                        added_count1 += 1
                        print(f"      ✓ 组1完整reasoning: {metric}")
                    else:
                        print(f"      ✗ 组1 {metric} reasoning太短或缺失")
            
            print(f"    ✓ 组1成功: {added_count1} 个完整reasoning")
        except:
            print(f"    ✗ 组1JSON解析失败，尝试手动提取reasoning")
            manual1 = quick_extract_reasoning(raw1, group1_metrics)
            if len(manual1) > 0:
                prev.update(manual1)
                print(f"    ✓ 组1手动: {len(manual1)} 个reasoning")
            else:
                print(f"    ✗ 组1手动提取也失败")
        
        time.sleep(3)  # 短暂等待
    
    # 分组2：影响指标 (后4个)
    group2_metrics = [m for m in all_metrics[4:] if m not in prev]
    if group2_metrics:
        print(f"    处理组2缺失reasoning: {group2_metrics}")
        
        group2_prompt = f"""Analyze CVE {cve} for these specific CVSS v3.1 impact metrics: {', '.join(group2_metrics)}

Provide detailed technical reasoning (minimum 40 words per metric) based on the official definitions:

**Scope:** Whether a vulnerability in one component impacts resources beyond its security scope. Consider if exploitation affects other components or crosses security boundaries.

**Confidentiality Impact:** Impact to confidentiality of information resources managed by the component. Consider what data could be accessed or disclosed.

**Integrity Impact:** Impact to integrity of information. Consider what data or systems could be modified or corrupted.

**Availability Impact:** Impact to availability of the component itself. Consider service disruption, performance degradation, or resource consumption.

CVE Description: {desc[:800]}
Content: {page_text[:1000]}

Analyze each requested metric objectively based on the vulnerability details provided.

Return JSON format: {{"Scope_Reasoning": "Analysis of security boundary impact...", "Confidentiality_Impact_Reasoning": "Assessment of information disclosure risk...", "Integrity_Impact_Reasoning": "Evaluation of data modification potential...", "Availability_Impact_Reasoning": "Analysis of service availability impact..."}}

JSON:"""
        raw2 = g4f_generate_fast(group2_prompt) or "{}"
        raw2 = fast_clean_json(raw2)
        
        try:
            result2 = json.loads(raw2)
            # 只保留reasoning
            added_count2 = 0
            for metric in group2_metrics:
                reasoning_key = f"{metric}_Reasoning"
                if reasoning_key in result2:
                    reasoning = result2.get(reasoning_key)
                    
                    # 只保留有reasoning的
                    if reasoning and reasoning.strip() and len(reasoning) > 30:
                        prev[metric] = {
                            reasoning_key: reasoning
                        }
                        added_count2 += 1
                        print(f"      ✓ 组2完整reasoning: {metric}")
                    else:
                        print(f"      ✗ 组2 {metric} reasoning太短或缺失")
            
            print(f"    ✓ 组2成功: {added_count2} 个完整reasoning")
            
        except:
            print(f"    ✗ 组2JSON解析失败，尝试手动提取reasoning")
            manual2 = quick_extract_reasoning(raw2, group2_metrics)
            if len(manual2) > 0:
                prev.update(manual2)
                print(f"    ✓ 组2手动: {len(manual2)} 个reasoning")
            else:
                print(f"    ✗ 组2手动提取也失败")
    
    # 最终检查和报告
    final_count = len([k for k in prev.keys() if not k.endswith("_Raw_Response")])
    missing_final = [m for m in all_metrics if m not in prev]
    
    # 特殊处理User_Interaction缺失问题 - 只生成reasoning
    if "User_Interaction" in missing_final:
        print(f"    🔧 尝试专门补充User_Interaction reasoning...")
        
        ui_prompt = f"""Analyze CVE {cve} specifically for the User Interaction metric in CVSS v3.1.

**User Interaction Definition:** This metric captures the requirement for a human user, other than the attacker, to participate in the successful compromise of the vulnerable component. It determines whether the vulnerability can be exploited solely at the will of the attacker, or whether a separate user must participate.

CVE Description: {desc[:500]}
Web Content: {page_text[:800]}

Provide detailed technical analysis (50+ words) considering:
- Whether human user participation (other than the attacker) is required
- If the vulnerability can be exploited solely at the attacker's will
- What specific user actions, if any, would be needed
- The exploitation scenario and attack flow
IMPORTANT: In your reasoning, you MUST NOT use any CVSS metric value or label (such as "None", "Low", "Required", "Unchanged", "High", "Network", "Local", "Physical", "Adjacent", etc.). Instead, explain the technical scenario and requirements only in descriptive language. Do NOT state or hint at any CVSS value or label.


Return JSON format with detailed reasoning:
{{"User_Interaction_Reasoning": "Technical analysis of user participation requirements for this vulnerability..."}}

JSON:"""
        
        ui_raw = g4f_generate_fast(ui_prompt) or "{}"
        ui_raw = fast_clean_json(ui_raw)
        
        try:
            ui_result = json.loads(ui_raw)
            if "User_Interaction_Reasoning" in ui_result:
                prev["User_Interaction"] = {
                    "User_Interaction_Reasoning": ui_result["User_Interaction_Reasoning"]
                }
                print(f"      ✓ 成功补充User_Interaction reasoning")
                final_count = len([k for k in prev.keys() if not k.endswith("_Raw_Response")])
                missing_final = [m for m in all_metrics if m not in prev]
        except:
            print(f"      ✗ User_Interaction reasoning补充失败")
    
    if final_count == 8:
        print(f"    🎯 完美！成功获得所有8个CVSS reasoning")
    else:
        print(f"    ⚠️ 最终结果: {final_count}/8 个reasoning")
        if missing_final:
            print(f"    ❌ 仍然缺失reasoning: {missing_final}")
    
    return prev

def process_meta_fast(meta_path: pathlib.Path, skip_existing: bool = False, verbose: bool = False):
    """快速处理元数据"""
    try:
        meta = json.load(open(meta_path, encoding='utf-8'))
    except Exception as e:
        print(f"元数据读取失败 {meta_path}: {e}")
        return "failed"
    
    cve_code = meta.get('CVE Code', meta_path.stem)
    refs = meta.get("Reference", [])
    if refs == "N/A" or not refs:
        if verbose:
            print(f"跳过 {cve_code}: 无引用链接")
        return "skipped"
    
    # 路径处理
    try:
        relative_path = meta_path.relative_to(DETAIL_ROOT)
        out_file_path = REF_ROOT / relative_path
        out_file_path.parent.mkdir(parents=True, exist_ok=True)
    except Exception as e:
        print(f"路径处理失败: {e}")
        year = "2024"
        bucket = "unknown"
        out_dir = REF_ROOT / year / bucket
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file_path = out_dir / f"{cve_code}.json"
    
    # 读取现有结果
    if out_file_path.exists():
        try:
            ref_summary = json.load(open(out_file_path, encoding='utf-8'))
        except:
            ref_summary = []
    else:
        ref_summary = []
    
    # 检查跳过条件 - 简单的文件存在检查
    if skip_existing:
        # 检查输出文件是否存在
        if out_file_path.exists():
            try:
                # 检查文件是否有内容
                existing_data = json.load(open(out_file_path, encoding='utf-8'))
                if existing_data:  # 文件存在且有内容
                    if verbose:
                        print(f"跳过 {cve_code}: 输出文件已存在")
                    else:
                        print(f"跳过 {cve_code}: 已存在")
                    return "skipped"
            except:
                # 文件损坏，删除重新处理
                if verbose:
                    print(f"发现损坏文件，将重新处理: {out_file_path}")
                out_file_path.unlink(missing_ok=True)
    
    # 处理多个链接，不只是第一个
    refs = refs[:3]  # 处理前3个链接，增加成功率
    print(f"处理 {cve_code} - 快速模式（{len(refs)}个链接）")
    
    if verbose:
        print(f"输出路径: {out_file_path}")
    
    # 处理链接
    successful_analysis = False
    for i, url in enumerate(refs, 1):
        if verbose:
            print(f"  [{i}/{len(refs)}] {url}")
        else:
            print(f"  [{i}/{len(refs)}] 快速分析中...")
        
        # 查找现有记录
        idx = next((j for j, r in enumerate(ref_summary) if r.get("ref_link") == url), None)
        prev = copy.deepcopy(ref_summary[idx]["ref_summary"]) if idx is not None else {}
        
        # 简化的链接级别检查 - 只在非跳过模式下进行详细检查
        if idx is not None and prev and not skip_existing:
            complete_reasoning = 0
            for metric_name, metric_data in prev.items():
                if isinstance(metric_data, dict):
                    reasoning_key = f"{metric_name}_Reasoning"
                    if reasoning_key in metric_data:
                        reasoning = metric_data[reasoning_key]
                        if reasoning and len(reasoning) > 30:
                            complete_reasoning += 1
            
            # 检查是否为空的ref_summary
            if complete_reasoning >= 6:
                if verbose:
                    print(f"    ✓ 跳过链接，已有{complete_reasoning}个完整reasoning")
                else:
                    print(f"    ✓ 跳过链接，已有完整reasoning")
                successful_analysis = True
                break  # 已经有完整的分析，跳出循环
            elif len(prev) == 0:
                if verbose:
                    print(f"    ⚠️ 发现空的ref_summary，将重新处理")
            else:
                if verbose:
                    print(f"    ⚠️ reasoning不完整({complete_reasoning}/8)，将重新处理")
        
        # 跳过模式下的简单检查
        if skip_existing and idx is not None and prev:
            if verbose:
                print(f"    ↻ 文件存在但内容可能不完整，继续处理")
        
        # 如果是跳过模式且文件已存在，跳过详细分析
        skip_detailed_analysis = False
        if skip_existing and out_file_path.exists():
            try:
                existing_data = json.load(open(out_file_path, encoding='utf-8'))
                if existing_data and len(existing_data) > 0:
                    # 检查这个特定链接的内容
                    for entry in existing_data:
                        if entry.get("ref_link") == url:
                            entry_summary = entry.get('ref_summary', {})
                            if entry_summary and len(entry_summary) > 0:
                                # 有内容，跳过分析
                                skip_detailed_analysis = True
                                if verbose:
                                    print(f"    ✓ 跳过分析，使用现有文件")
                                break
            except:
                pass
        
        # 如果需要跳过详细分析，继续下一个链接
        if skip_detailed_analysis:
            continue
        
        # 快速分析
        summ = fast_cvss_analysis(cve_code, url, meta.get('Description', ''), prev)
        
        # 检查分析是否成功（有内容）
        if summ and len([k for k in summ.keys() if not k.endswith("_Raw_Response")]) > 0:
            successful_analysis = True
            print(f"    ✓ 成功获得CVSS分析结果")
        
        # 更新记录
        if idx is None:
            ref_summary.append({
                "ref_link": url,
                "ref_desc": "",
                "ref_summary": summ
            })
        else:
            ref_summary[idx]["ref_summary"] = summ
        
        # 如果成功获得分析结果，可以选择停止尝试更多链接
        if successful_analysis and len([k for k in summ.keys() if not k.endswith("_Raw_Response")]) >= 6:
            print(f"    ✓ 获得完整分析，停止处理其他链接")
            break
    
    # 保存结果
    try:
        with open(out_file_path, 'w', encoding='utf-8') as f:
            json.dump(ref_summary, f, indent=2, ensure_ascii=False)
        print(f"✓ 保存完成")
        return "success"
    except Exception as e:
        print(f"✗ 保存失败: {e}")
        return "failed"

def check_cve_existence(specified_cve_ids: set, start_year: int) -> dict:
    """检查指定的CVE ID是否存在对应的文件"""
    results = {
        'found': [],
        'not_found': [],
        'total_checked': len(specified_cve_ids),
        'file_samples': []
    }
    
    # 收集所有可能的CVE文件
    year_dir = DETAIL_ROOT / str(start_year)
    if not year_dir.exists():
        print(f"❌ 年份目录不存在: {year_dir}")
        return results
    
    # 收集所有CVE文件名（不带扩展名）
    all_cve_stems = set()
    bucket_dirs = [d for d in year_dir.iterdir() if d.is_dir() and d.name.endswith('xxx')]
    
    if bucket_dirs:
        print(f"📂 检查分桶目录: {[d.name for d in bucket_dirs]}")
        for bucket_dir in bucket_dirs:
            for cve_file in bucket_dir.rglob("CVE-*.json"):
                all_cve_stems.add(cve_file.stem.upper())
                if len(results['file_samples']) < 10:
                    results['file_samples'].append(cve_file.stem)
    else:
        for cve_file in year_dir.rglob("CVE-*.json"):
            all_cve_stems.add(cve_file.stem.upper())
            if len(results['file_samples']) < 10:
                results['file_samples'].append(cve_file.stem)
    
    print(f"📊 总共找到 {len(all_cve_stems)} 个CVE文件")
    print(f"📄 文件名样本: {results['file_samples'][:5]}")
    
    # 检查指定的CVE ID
    for cve_id in sorted(specified_cve_ids):
        if cve_id.upper() in all_cve_stems:
            results['found'].append(cve_id)
        else:
            results['not_found'].append(cve_id)
    
    return results

def filter_cve_files_by_ids(all_files: list, specified_ids: set, verbose: bool = False) -> list:
    """根据指定的CVE ID过滤文件列表"""
    if not specified_ids:
        print("⚠️ 未指定CVE ID，将处理所有文件")
        return all_files
    
    # 调试信息：显示样本数据
    print(f"🔍 调试信息:")
    print(f"  指定CVE ID样本 (前5个): {sorted(list(specified_ids))[:5]}")
    if all_files:
        print(f"  实际文件名样本 (前5个): {[f.stem for f in all_files[:5]]}")
    
    filtered_files = []
    matched_ids = set()
    
    # 只使用精确匹配，移除部分匹配逻辑
    for file_path in all_files:
        # 策略1: 直接匹配文件名 (不带扩展名)
        file_cve_id = file_path.stem.upper()
        
        if file_cve_id in specified_ids:
            # 精确匹配
            filtered_files.append(file_path)
            matched_ids.add(file_cve_id)
            if verbose:
                print(f"    ✅ 精确匹配: {file_cve_id}")
        elif verbose:
            print(f"    ❌ 跳过: {file_cve_id} (不在指定列表中)")
    
    # 报告匹配情况
    unmatched_ids = specified_ids - matched_ids
    print(f"📊 过滤结果:")
    print(f"  🎯 指定CVE ID: {len(specified_ids)} 个")
    print(f"  ✅ 找到匹配文件: {len(filtered_files)} 个")
    print(f"  ❌ 未找到文件: {len(unmatched_ids)} 个")
    
    if unmatched_ids:
        print(f"  未找到的CVE ID样本: {sorted(list(unmatched_ids))[:5]}{'...' if len(unmatched_ids) > 5 else ''}")
    
    # 如果没有匹配，提供调试建议
    if len(filtered_files) == 0:
        print(f"\n❌ 未找到任何匹配文件，请检查:")
        print(f"  1. CVE ID文件格式是否正确")
        print(f"  2. CVE ID是否与实际文件名匹配")
        print(f"  3. 文件路径是否正确")
        
        # 显示更多调试信息
        if specified_ids and all_files:
            first_spec = sorted(list(specified_ids))[0]
            first_file = all_files[0].stem if all_files else "无文件"
            print(f"  示例对比:")
            print(f"    指定ID: '{first_spec}'")
            print(f"    文件名: '{first_file}'")
    elif len(filtered_files) > len(specified_ids):
        print(f"\n⚠️ 警告: 找到的文件数({len(filtered_files)})超过指定CVE ID数({len(specified_ids)})")
        print(f"  这可能表示匹配逻辑有问题")
    
    return filtered_files

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="CVSS指标提取工具 - 基于官方定义，只生成reasoning（仅处理指定CVE ID）")
    parser.add_argument("--start_year", type=int, default=2025, help="开始年份（改为2025，因为文件在2025文件夹中）")
    parser.add_argument("--limit", type=int, default=None, help="文件数量限制")
    parser.add_argument("--skip_existing", action="store_true", default=True, help="跳过已有输出文件的CVE (默认开启，使用--no_skip_existing关闭)")
    parser.add_argument("--no_skip_existing", action="store_true", help="强制重新处理所有文件，包括已存在的")
    parser.add_argument("--verbose", action="store_true", help="详细输出")
    parser.add_argument("--check_only", action="store_true", help="只检查已分析文件数量，不进行处理")
    parser.add_argument("--cve_ids_file", type=str, default=str(SPECIFIED_CVE_FILE), help=f"指定CVE ID文件路径 (默认: {SPECIFIED_CVE_FILE})")
    parser.add_argument("--process_all", action="store_true", help="处理所有CVE文件，忽略指定的CVE ID列表")
    parser.add_argument("--debug_ids", action="store_true", help="调试CVE ID匹配问题，显示详细信息")
    parser.add_argument("--check_existence", action="store_true", help="检查指定CVE ID文件是否存在对应的CVE文件")
    parser.add_argument("--force_reprocess", action="store_true", help="强制重新处理有空ref_summary的文件")
    parser.add_argument("--test_url", type=str, help="测试特定URL的访问情况")
    
    args = parser.parse_args()
    
    # 如果指定了不跳过，则覆盖默认设置
    if args.no_skip_existing:
        args.skip_existing = False
    
    # 加载指定的CVE ID列表
    specified_cve_ids = set()
    if not args.process_all:
        cve_ids_file_path = pathlib.Path(args.cve_ids_file)
        specified_cve_ids = load_specified_cve_ids(cve_ids_file_path)
        if not specified_cve_ids:
            print("❌ 未能加载指定的CVE ID，将处理所有文件")
    else:
        print("🔄 处理所有CVE文件模式 (忽略指定CVE ID列表)")
    
    # 测试URL模式
    if args.test_url:
        print(f"🧪 测试URL访问: {args.test_url}")
        result = fast_cvss_analysis("TEST-CVE", args.test_url, "测试漏洞描述")
        print(f"测试结果: {result}")
        return
    
    if args.check_existence:
        print("🔍 检查CVE ID文件存在性...")
        if not specified_cve_ids:
            print("❌ 未加载到CVE ID，无法检查")
            return
            
        existence_results = check_cve_existence(specified_cve_ids, args.start_year)
        
        print(f"\n📊 存在性检查结果:")
        print(f"✅ 找到的CVE: {len(existence_results['found'])} 个")
        print(f"❌ 未找到的CVE: {len(existence_results['not_found'])} 个")
        print(f"📈 存在率: {len(existence_results['found'])/existence_results['total_checked']*100:.1f}%")
        
        if existence_results['found']:
            print(f"\n✅ 存在的CVE样本: {existence_results['found'][:5]}")
        
        if existence_results['not_found']:
            print(f"\n❌ 不存在的CVE样本: {existence_results['not_found'][:5]}")
            
        print(f"\n📂 实际文件样本: {existence_results['file_samples'][:5]}")
        
        # 分析数字范围
        if existence_results['file_samples']:
            try:
                file_numbers = []
                for sample in existence_results['file_samples']:
                    if 'CVE-2025-' in sample:
                        num_part = sample.replace('CVE-2025-', '')
                        if num_part.isdigit():
                            file_numbers.append(int(num_part))
                
                if file_numbers:
                    print(f"\n📈 实际文件数字范围: {min(file_numbers)} - {max(file_numbers)}")
                    
                # 分析指定CVE的数字范围
                specified_numbers = []
                for cve_id in list(specified_cve_ids)[:50]:  # 只分析前50个
                    if 'CVE-2025-' in cve_id:
                        num_part = cve_id.replace('CVE-2025-', '')
                        if num_part.isdigit():
                            specified_numbers.append(int(num_part))
                
                if specified_numbers:
                    print(f"📋 指定CVE数字范围: {min(specified_numbers)} - {max(specified_numbers)}")
                    
            except Exception as e:
                print(f"⚠️ 数字范围分析失败: {e}")
        
        return
    
    if args.check_only:
        print("📊 检查已分析文件数量模式...")
    else:
        print("⚡ 开始基于官方定义的CVSS reasoning分析...")
    
    print(f"起始年份: {args.start_year}")
    if args.limit:
        print(f"处理限制: {args.limit} 个文件")
    if args.skip_existing:
        print("跳过模式: 在收集文件时就跳过已有输出文件的CVE (默认开启)")
    else:
        print("强制模式: 将重新处理所有文件，包括已存在的")
    
    if not args.check_only:
        print(f"🚀 策略: 基于官方CVSS定义 + 只生成reasoning + 保留完整AI回答")
    
    processed_files = 0
    skipped_files = 0
    total_analyzed_files = 0
    
    # 收集文件并过滤已存在的
    all_cve_files = []
    skipped_during_collection = 0
    
    for year_dir in sorted(DETAIL_ROOT.iterdir(), reverse=True):
        if not year_dir.is_dir():
            continue
            
        year_name = year_dir.name
        
        try:
            year_num = int(year_name)
            if year_num != args.start_year:  # 只处理指定年份
                continue
        except ValueError:
            continue
        
        print(f"收集年份: {year_name}")
        
        year_files = []
        # 处理分桶结构 (0xxx, 1xxx, 2xxx, etc.)
        bucket_dirs = [d for d in year_dir.iterdir() if d.is_dir() and d.name.endswith('xxx')]
        
        if bucket_dirs:
            # 如果有分桶目录，从分桶中搜索
            print(f"  发现分桶目录: {[d.name for d in bucket_dirs]}")
            for bucket_dir in bucket_dirs:
                for cve_file in bucket_dir.rglob("CVE-*.json"):
                    year_files.append(cve_file)
        else:
            # 原始逻辑：直接在年份目录下搜索
            for cve_file in year_dir.rglob("CVE-*.json"):
                year_files.append(cve_file)

        year_files.sort(key=lambda x: x.stem, reverse=True)
        all_cve_files.extend(year_files)
        
        print(f"  发现 {len(year_files)} 个CVE文件")
    
    # 根据指定的CVE ID过滤文件列表（在跳过检查之前进行过滤）
    if not args.process_all and specified_cve_ids:
        print(f"\n🔍 根据指定CVE ID过滤文件...")
        if args.debug_ids:
            print(f"🐛 调试模式：详细显示匹配过程")
        all_cve_files = filter_cve_files_by_ids(all_cve_files, specified_cve_ids, args.verbose or args.debug_ids)
        
        # 如果启用调试模式且没有匹配，提供更多信息
        if args.debug_ids and len(all_cve_files) == 0:
            print(f"\n🐛 详细调试信息:")
            cve_ids_file_path = pathlib.Path(args.cve_ids_file)
            if cve_ids_file_path.exists():
                print(f"✅ CVE ID文件存在: {cve_ids_file_path}")
                try:
                    with open(cve_ids_file_path, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[:10]  # 只读前10行
                    print(f"📄 文件内容样本 (前10行):")
                    for i, line in enumerate(lines, 1):
                        print(f"  {i}: {repr(line.strip())}")
                except Exception as e:
                    print(f"❌ 读取文件失败: {e}")
            else:
                print(f"❌ CVE ID文件不存在: {cve_ids_file_path}")
            
            # 显示一些实际文件名作为参考
            print(f"\n📁 实际CVE文件名样本:")
            for year_dir in sorted(DETAIL_ROOT.iterdir(), reverse=True):
                if not year_dir.is_dir():
                    continue
                if year_dir.name == str(args.start_year):
                    # 处理分桶结构
                    bucket_dirs = [d for d in year_dir.iterdir() if d.is_dir() and d.name.endswith('xxx')]
                    if bucket_dirs:
                        print(f"  找到分桶目录: {[d.name for d in bucket_dirs[:3]]}")
                        for bucket_dir in bucket_dirs[:2]:  # 只检查前2个桶
                            sample_files = list(bucket_dir.rglob("CVE-*.json"))[:3]
                            for f in sample_files:
                                print(f"    {bucket_dir.name}/{f.name} -> stem: {f.stem}")
                    else:
                        sample_files = list(year_dir.rglob("CVE-*.json"))[:5]
                        for f in sample_files:
                            print(f"  {f.stem}")
                    break
    
    # 现在在过滤后的文件列表上应用跳过已存在文件的逻辑
    if args.skip_existing:
        print(f"\n📋 检查已存在的输出文件...")
        remaining_files = []
        skipped_existing = 0
        
        for cve_file in all_cve_files:
            try:
                relative_path = cve_file.relative_to(DETAIL_ROOT)
                out_file_path = REF_ROOT / relative_path
                
                should_skip = False
                if out_file_path.exists() and out_file_path.stat().st_size > 50:
                    # 检查文件内容是否有有效的reasoning
                    try:
                        existing_data = json.load(open(out_file_path, encoding='utf-8'))
                        if existing_data and len(existing_data) > 0:
                            # 检查第一个条目的ref_summary是否为空
                            first_entry = existing_data[0] if existing_data else {}
                            ref_summary = first_entry.get('ref_summary', {})
                            
                            # 如果ref_summary为空或者没有任何reasoning，标记为需要重新处理
                            if not ref_summary or len(ref_summary) == 0:
                                if args.verbose:
                                    cve_code = cve_file.stem
                                    print(f"    重新处理 {cve_code}: ref_summary为空")
                                should_skip = False
                            else:
                                # 检查是否有有效的reasoning
                                reasoning_count = 0
                                for metric_name, metric_data in ref_summary.items():
                                    if isinstance(metric_data, dict):
                                        reasoning_key = f"{metric_name}_Reasoning"
                                        if reasoning_key in metric_data:
                                            reasoning = metric_data[reasoning_key]
                                            if reasoning and len(reasoning) > 30:
                                                reasoning_count += 1
                                
                                if reasoning_count >= 6:
                                    should_skip = True
                                    skipped_existing += 1
                                    if args.verbose:
                                        cve_code = cve_file.stem
                                        print(f"    跳过 {cve_code}: 已有{reasoning_count}个完整reasoning")
                                else:
                                    if args.verbose:
                                        cve_code = cve_file.stem
                                        print(f"    重新处理 {cve_code}: reasoning不完整({reasoning_count}/8)")
                        else:
                            if args.verbose:
                                cve_code = cve_file.stem
                                print(f"    重新处理 {cve_code}: 文件内容为空")
                    except:
                        if args.verbose:
                            cve_code = cve_file.stem
                            print(f"    重新处理 {cve_code}: 文件损坏")
                        should_skip = False
                
                if not should_skip:
                    remaining_files.append(cve_file)
            except:
                remaining_files.append(cve_file)  # 如果路径处理失败，保留文件
        
        print(f"  过滤后有 {len(all_cve_files)} 个文件，跳过 {skipped_existing} 个已存在，剩余 {len(remaining_files)} 个")
        all_cve_files = remaining_files
    
    if args.limit and args.limit > 0:
        all_cve_files = all_cve_files[:args.limit]
        print(f"应用限制，将处理前 {len(all_cve_files)} 个文件")
    
    print(f"\n总共将处理 {len(all_cve_files)} 个CVE文件")
    
    if len(all_cve_files) == 0:
        print("未找到匹配的文件")
        return
    
    # 如果是检查模式，统计已分析文件
    if args.check_only:
        print("\n📊 统计已分析文件...")
        for i, mp in enumerate(all_cve_files, 1):
            try:
                meta = json.load(open(mp, encoding='utf-8'))
                cve_code = meta.get('CVE Code', mp.stem)
                
                # 简单检查文件是否存在
                try:
                    relative_path = mp.relative_to(DETAIL_ROOT)
                    out_file_path = REF_ROOT / relative_path
                    
                    if out_file_path.exists() and out_file_path.stat().st_size > 50:
                        total_analyzed_files += 1
                        if args.verbose:
                            file_size = out_file_path.stat().st_size
                            print(f"  ✅ {cve_code}: 文件存在 ({file_size} bytes)")
                except:
                    pass
                    
            except:
                continue
        
        print(f"\n📊 统计结果:")
        print(f"✅ 已有输出文件: {total_analyzed_files} 个文件")
        print(f"⏳ 待处理: {len(all_cve_files) - total_analyzed_files} 个文件")
        print(f"📈 已处理率: {total_analyzed_files/len(all_cve_files)*100:.1f}%")
        return
    
    # 正常处理模式
    for i, mp in enumerate(all_cve_files, 1):
        print(f"\n[{i}/{len(all_cve_files)}] {mp.relative_to(DETAIL_ROOT)}")
        
        try:
            result = process_meta_fast(mp, args.skip_existing, args.verbose)
            if result == "skipped":
                skipped_files += 1
            else:
                processed_files += 1
        except KeyboardInterrupt:
            print(f"\n中断处理")
            break
        except Exception as e:
            print(f"处理失败: {e}")
            continue
        
        # 快速模式：文件间只等5秒
        if i < len(all_cve_files):
            print(f"等待5秒...")
            time.sleep(5)
    
    print(f"\n" + "="*60)
    print("基于官方定义的reasoning分析完成！")
    print(f"✅ 成功: {processed_files} 个")
    print(f"⏭️ 跳过: {skipped_files} 个")
    if len(all_cve_files) > 0:
        print(f"🎯 完成率: {(processed_files + skipped_files)/len(all_cve_files)*100:.1f}%")
    
    # 如果使用了指定CVE ID列表，显示额外信息
    if not args.process_all and specified_cve_ids:
        print(f"🎯 指定CVE处理: {len(specified_cve_ids)} 个指定，{len(all_cve_files)} 个找到并处理")
    
    print("="*60)

if __name__ == "__main__":
    main()