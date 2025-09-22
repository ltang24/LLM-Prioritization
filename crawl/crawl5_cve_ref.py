#!/usr/bin/env python3
"""
快速版CVSS分析工具 - 基于官方定义，只提取reasoning
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
# ====================================

# 常量定义 - 快速版本
MAX_RETRIES = 3  # 减少重试次数
RATE_LIMIT_KEYWORDS = ["限流", "rate limit", "daily limit", "quota", "battle mode", "please come back later", "too many requests", "try again", "wait"]

def skip_url(url: str) -> bool:
    """跳过不相关的URL"""
    bad = ("github.com/CVEProject", "twitter.com", "facebook.com", "linkedin.com", "vuldb.com")
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
    
    try:
        rsp = requests.get(url, timeout=20, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        })
        rsp.raise_for_status()
    except Exception as e:
        print(f"  ! 网页访问失败: {e}")
        return prev
    
    # 快速解析HTML
    html = bs4.BeautifulSoup(rsp.text, "html.parser")
    for script in html(["script", "style"]):
        script.decompose()
    page_text = html.get_text()
    
    if len(page_text) > 2000:
        page_text = page_text[:2000] + "..."

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
IMPORTANT: In your reasoning, you MUST NOT use any CVSS metric value or label (such as “None”, “Low”, “Required”, “Unchanged”, “High”, “Network”, “Local”, “Physical”, “Adjacent”, etc.). Instead, explain the technical scenario and requirements only in descriptive language. Do NOT state or hint at any CVSS value or label.


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
IMPORTANT: In your reasoning, you MUST NOT use any CVSS metric value or label (such as “None”, “Low”, “Required”, “Unchanged”, “High”, “Network”, “Local”, “Physical”, “Adjacent”, etc.). Instead, explain the technical scenario and requirements only in descriptive language. Do NOT state or hint at any CVSS value or label.

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
IMPORTANT: In your reasoning, you MUST NOT use any CVSS metric value or label (such as “None”, “Low”, “Required”, “Unchanged”, “High”, “Network”, “Local”, “Physical”, “Adjacent”, etc.). Instead, explain the technical scenario and requirements only in descriptive language. Do NOT state or hint at any CVSS value or label.


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
    
    # 只处理第一个链接，快速模式
    refs = refs[:1]  # 只处理第一个链接
    print(f"处理 {cve_code} - 快速模式（1个链接）")
    
    if verbose:
        print(f"输出路径: {out_file_path}")
    
    # 处理链接
    for i, url in enumerate(refs, 1):
        if verbose:
            print(f"  [{i}/{len(refs)}] {url}")
        else:
            print(f"  [{i}/{len(refs)}] 快速分析中...")
        
        # 查找现有记录
        idx = next((i for i, r in enumerate(ref_summary) if r.get("ref_link") == url), None)
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
            
            if complete_reasoning >= 6:
                if verbose:
                    print(f"    ✓ 跳过链接，已有{complete_reasoning}个完整reasoning")
                else:
                    print(f"    ✓ 跳过链接，已有完整reasoning")
                continue
        
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
                    # 文件存在且有内容，跳过分析
                    skip_detailed_analysis = True
                    if verbose:
                        print(f"    ✓ 跳过分析，使用现有文件")
            except:
                pass
        
        # 如果需要跳过详细分析，直接继续
        if skip_detailed_analysis:
            continue
        
        # 快速分析
        summ = fast_cvss_analysis(cve_code, url, meta.get('Description', ''), prev)
        
        # 更新记录
        if idx is None:
            ref_summary.append({
                "ref_link": url,
                "ref_desc": "",
                "ref_summary": summ
            })
        else:
            ref_summary[idx]["ref_summary"] = summ
    
    # 保存结果
    try:
        with open(out_file_path, 'w', encoding='utf-8') as f:
            json.dump(ref_summary, f, indent=2, ensure_ascii=False)
        print(f"✓ 保存完成")
        return "success"
    except Exception as e:
        print(f"✗ 保存失败: {e}")
        return "failed"

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="CVSS指标提取工具 - 基于官方定义，只生成reasoning")
    parser.add_argument("--start_year", type=int, default=2024, help="开始年份")
    parser.add_argument("--limit", type=int, default=None, help="文件数量限制")
    parser.add_argument("--skip_existing", action="store_true", default=True, help="跳过已有输出文件的CVE (默认开启，使用--no_skip_existing关闭)")
    parser.add_argument("--no_skip_existing", action="store_true", help="强制重新处理所有文件，包括已存在的")
    parser.add_argument("--verbose", action="store_true", help="详细输出")
    parser.add_argument("--check_only", action="store_true", help="只检查已分析文件数量，不进行处理")
    
    args = parser.parse_args()
    
    # 如果指定了不跳过，则覆盖默认设置
    if args.no_skip_existing:
        args.skip_existing = False
    
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
        for cve_file in year_dir.rglob("CVE-*.json"):
            # 如果启用跳过模式，检查输出文件是否已存在
            if args.skip_existing:
                try:
                    relative_path = cve_file.relative_to(DETAIL_ROOT)
                    out_file_path = REF_ROOT / relative_path
                    
                    if out_file_path.exists() and out_file_path.stat().st_size > 50:
                        skipped_during_collection += 1
                        if args.verbose:
                            cve_code = cve_file.stem
                            print(f"    跳过 {cve_code}: 文件已存在")
                        continue  # 跳过已存在的文件
                except:
                    pass
            
            year_files.append(cve_file)
        
        year_files.sort(key=lambda x: x.stem, reverse=True)
        all_cve_files.extend(year_files)
        
        if args.skip_existing:
            print(f"  发现 {len(year_files) + skipped_during_collection} 个CVE文件，跳过 {skipped_during_collection} 个已存在，将处理 {len(year_files)} 个")
            skipped_during_collection = 0  # 重置计数器
        else:
            print(f"  发现 {len(year_files)} 个CVE文件")
    
    if args.limit and args.limit > 0:
        all_cve_files = all_cve_files[:args.limit]
        print(f"应用限制，将处理前 {len(all_cve_files)} 个文件")
    
    print(f"\n总共将处理 {len(all_cve_files)} 个CVE文件")
    
    if len(all_cve_files) == 0:
        print("未找到文件")
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
    print("="*60)

if __name__ == "__main__":
    main()