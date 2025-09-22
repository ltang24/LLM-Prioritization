import os, json, requests, copy
from bs4 import BeautifulSoup
from time import time
from utils import g4f_generate, skip_url, classify_attack_vector, get_cvss_vector
from collections import OrderedDict
import re

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}


desc1 = '''
- **Actor Identification**: Precisely identify and attribute the cyber threat actors or groups responsible for malicious activities, such as advanced persistent threats (e.g., APT28), by analyzing behavioral patterns, tools, and preceding intelligence. This attribution enables targeted defense strategies and threat prioritization.
- **Infrastructure Extraction**: Systematically extract, categorize, and analyze all indicators of compromise (IOCs) related to the attack infrastructure, including domains, IP addresses, URLs, and file hashes. This process supports comprehensive linkage of attack elements for effective detection and blocking of malicious resources.
- **Malware Family Classification**: Classify malware samples or toolsets involved in the attack by examining shared characteristics and behaviors. This categorization aids in recognizing known malware families, enhancing detection accuracy and facilitating appropriate response actions.
- **Signature Matching**: Identify instances where attackers reuse or repurpose established tools, techniques, or code snippets from known threat actors. By matching signatures, security teams can detect familiar attack patterns, enabling quicker attribution and mitigation efforts.
- **Temporal Pattern Analysis**: Analyze timing and activity patterns of cyber intrusions by correlating observed behaviors within defined temporal windows. This method helps align attacker actions with known work schedules or operational tempos, enhancing detection of persistent or coordinated campaigns.
- **Geographic Analysis**: Infer geographic origins or cultural indicators from attack artifacts such as malware behavior, network logs, or metadata. This spatial intelligence contributes to profiling threat actors and anticipating region-specific tactics or targets.
- **Campaign Correlation**: Connect newly observed threats or incidents to historical cyber campaigns by investigating shared indicators, tactics, or objectives. Establishing these links enhances situational awareness and enables preemptive defense measures against recurring adversary strategies.
- **Affiliation Linking**: Deduce relationships and associations between threat actors, campaigns, or organizations through integrated analysis of collected intelligence. Mapping these affiliations provides a broader understanding of adversary networks and collaborative threat landscapes.
- **Victimology Profiling**: Conduct in-depth analysis of targeted victim types to uncover attacker motivations, preferences, or identities. Understanding victim profiles supports the development of more tailored security measures and threat actor behavioral models.
'''

json1 = '''"Actor Identification": "...","Infrastructure Extraction": "...", "Malware Family Classification": "...","Signature Matching": "...", "Temporal Pattern Analysis": "...", "Geographic Analysis": "...", "Campaign Correlation": "...", "Affiliation Linking": "...", "Victimology Profiling": "..."'''


desc2 = '''
- **File System Monitoring**: Monitor and detect anomalous file system events such as suspicious creation, deletion, or access patterns during program execution. This mapping helps identify potential malicious behaviors indicative of an ongoing or imminent cyberattack.
- **Network Activity Profiling**: Capture and analyze external communication patterns exhibited during cyber intrusions, including command and control (C2) channels, beaconing, and data exfiltration attempts. Profiling these behaviors enables anomaly detection and timely disruption of attacker operations.
- **Credential Access Detection**: Detect and analyze unauthorized attempts to steal or misuse credentials from memory dumps, keyloggers, or hash extraction. Early identification of credential theft is vital to preventing unauthorized access and privilege escalations.
- **Execution Context Analysis**: Understand under what user, process, or system context the suspicious behavior occurred.
- **Command & Script Analysis**: Deconstruct suspicious commands, scripts, or batch files to identify malicious actions.
- **Privilege Escalation Detection**: Infer attempts to gain higher levels of system or network privileges.
- **Evasion Technique Identification**: Spot anti-analysis behaviors like sandbox detection, obfuscation, or dynamic payload delivery.
- **Event Sequence Reconstruction**: Timeline of attack-related events for understanding the attacker's actions and intentions.
- **TTP (Tactics, Techniques, and Procedures) Identification**: Extract attacker behavior patterns aligned with frameworks like MITRE ATT&CK.
'''

json2 = '''"File System Monitoring": "...", "Network Activity Profiling": "...", "Credential Access Detection": "...", "Execution Context Analysis": "...", "Command & Script Analysis":"...", "Privilege Escalation Detection": "...", "Evasion Technique Identification": "...", "Event Sequence Reconstruction": "...",  "TTP (Tactics, Techniques, and Procedures) Identification": "..."'''


desc3 = '''
- **Attack Vector Classification**: Determine the initial entry point or delivery method used (e.g., remote code execution, physical access).
- **Exploit Complexity Assessment**: Evaluate how easily an attacker can exploit the vulnerability, considering required conditions or constraints.
- **Privilege Requirement Analysis**: Identify whether exploitation requires specific user permissions or administrative access.
- **User Interaction Evaluation**: Assess if user actions (e.g., clicking a link, opening a file) are necessary for the exploit to succeed.
- **Attack Scope Definition**: Determine whether the vulnerability affects a single component or has broader implications across systems.
- **Impact Assessment**: Analyze the effects on confidentiality, integrity, and availability (CIA triad).
- **Severity Scoring**: Assign a standardized severity score (e.g., CVSS) to quantify the risk posed by the vulnerability.
'''

json3 = '''"Attack Vector Classification": "...", "Exploit Complexity Assessment": "...", "Privilege Requirement Analysis": "...", "User Interaction Evaluation": "...", "Attack Scope Definition": "...", "Impact Assessment": "...", "Severity Scoring": "..."'''


desc4 = '''
- **Response Playbook Recommendation**: Suggest pre-defined incident response procedures based on threat characteristics.
- **Patch Code Generation**: Automatically create or suggest code fixes to mitigate identified vulnerabilities.
- **Tool Recommendations**: Propose security tools or utilities that can detect, prevent, or respond to the threat.
- **Advisory Mapping**: Link the threat or vulnerability to relevant security advisories, bulletins, or best practices.
- **Security Control Adjustments**: Recommend changes to existing controls like firewall rules, endpoint detection settings, or group policies.
'''

json4 = '''"Response Playbook Recommendation": "...", "Patch Code Generation": "...", "Tool Recommendation": "...", "Advisory Mapping": "...", "Security Control Adjustments": "..."'''


pattern = r'(".*?"):\s(.*?)(?=(\s{2,}"|}$))'

def format_json_like(match):
    key = match.group(1)
    value = match.group(2).strip()
    value = value.rstrip(".") + "." 
    value = value.replace('"', '\\"')
    return f'{key}: "{value}",'

def gpt_summarize(cve, url: str, desc: str, prev: dict = OrderedDict()):
    print("crawling", cve, url)
    if skip_url(url):
        print("In skip list. Skip.")
        return {}
    # try:
    #     html = BeautifulSoup(requests.get(url, headers=headers, timeout=60).text, 'html.parser')
    # except requests.exceptions.Timeout:
    #     print("The request timed out. Skip.")
    #     return {}
    
    try:
        response = requests.head(url, timeout=60, headers=headers)  # Use HEAD for minimal data transfer
        # return response.status_code == 200
    except requests.ConnectionError:
        print("Connection error. URL may not exist.")
        return {}
    except requests.Timeout:
        print("Request timed out.")
        return {}
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return {}
    html = BeautifulSoup(response.text, 'html.parser')
    
    # state all targets into one prompt
    overall_str = """
    
    """
    
    for task_tube in [
        ("Threat Attribution",desc1),
        ("Behavior Analysis",desc2),
        ("Vulnerability Analysis",desc3),
        ("Response & Mitigation",desc4),
    ]:
        task = task_tube[0]
        subtasks = task_tube[1]
        if task in prev:
            continue
        
        print(f"-> crawling {task}")
        prompt = f"""

        ### Role:  
        You are an information extraction assistant. Your task is to analyze the provided HTML of a webpage describing a CVE (Common Vulnerabilities and Exposures) and extract specific information based on the specified subtask definitions and instructions.

        ### Context:  
        Below is the input HTML for CVE **{cve}**, accompanied by an abstract description: **{desc}**.

        ---

        **HTML Input:**  
        {html}

        ---

        ### Task:  
        Extract relevant information for the category **{task}**. Each key's value should contain concise, accurate, and context-relevant content extracted from the HTML.  
        Your output must match the following structure exactly:
        {json1 if task=="Threat Attribution" else json2 if task=="Behavior Analysis" else json3 if task=="Vulnerability Analysis" else json4}
        Replace "..." with concise, accurate, and context-relevant content extracted from the HTML.

        **Subtasks:**  
        {subtasks}

        ### Requirements: 
        - If a field is not applicable or not found, use `"..."` as the value.
        - If available, include specific code snippets, commit links, issue references, or technical indicators in the values.
        - Be concise and precise in your extraction.
        [Your Response]  
        """
        
        response = g4f_generate(prompt)
        if response is None:
            print("g4f_generate returned None. Skipping...")
            return {}
        response = response.strip()
        # process str
        if response:
            if response.startswith("```json"):
                response = response.split("```json")[1].split("```")[0]
            response = response.replace("\n", "").replace("\\", "").strip()
            if not response.startswith("{"):
                response = "{"+response+"}"
            response = response.replace("\'Actor Identification\'", "\"Actor Identification\"").replace("\'Infrastructure Extraction\'", "\"Infrastructure Extraction\"").replace("\'Malware Family Classification\'", "\"Malware Family Classification\"").replace("\'Signature Matching\'", "\"Signature Matching\"").replace("\'Temporal Pattern Analysis\'", "\"Temporal Pattern Analysis\"").replace("\'Geographic Analysis\'", "\"Geographic Analysis\"").replace("\'Campaign Correlation\'", "\"Campaign Correlation\"").replace("\'Affiliation Linking\'", "\"Affiliation Linking\"").replace("\'Victimology Profiling\'", "\"Victimology Profiling\"")

            response = response.replace("\'File System Monitoring\'", "\"File System Monitoring\"").replace("\'Network Activity Profiling\'", "\"Network Activity Profiling\"").replace("\'Persistence Mechanism Detection\'", "\"Persistence Mechanism Detection\"").replace("\'Lateral Movement Pathfinding\'", "\"Lateral Movement Pathfinding\"").replace("\'Credential Access Detection\'", "\"Credential Access Detection\"").replace("\'Execution Context Analysis\'", "\"Execution Context Analysis\"").replace("\'Evasion Technique Identification\'", "\"Evasion Technique Identification\"")

            response = response.replace("\'Attack Timeline Reconstruction\'", "\"Attack Timeline Reconstruction\"").replace("\'Anomaly Detection\'", "\"Anomaly Detection\"").replace("\'Command & Script Analysis\'", "\"Command & Script Analysis\"").replace("\'Privilege Escalation Detection\'", "\"Privilege Escalation Detection\"").replace("\'Event Sequence Reconstruction\'", "\"Event Sequence Reconstruction\"").replace("\'TTP (Tactics, Techniques, and Procedures) Identification\'", "\"TTP (Tactics, Techniques, and Procedures) Identification\"")

            response = response.replace("\'Attack Vector Classification\'", "\"Attack Vector Classification\"").replace("\'Exploit Complexity Assessment\'", "\"Exploit Complexity Assessment\"").replace("\'Privilege Requirement Analysis\'", "\"Privilege Requirement Analysis\"").replace("\'User Interaction Evaluation\'", "\"User Interaction Evaluation\"").replace("\'Attack Scope Definition\'", "\"Attack Scope Definition\"").replace("\'Impact Assessment\'", "\"Impact Assessment\"").replace("\'Severity Scoring\'", "\"Severity Scoring\"")

            response = response.replace("\'Response Playbook Recommendation\'", "\"Response Playbook Recommendation\"").replace("\'Patch Code Generation\'", "\"Patch Code Generation\"").replace("\'Tool Recommendation\'", "\"Tool Recommendation\"").replace("\'Advisory Mapping\'", "\"Advisory Mapping\"").replace("\'Security Control Adjustments\'", "\"Security Control Adjustments\"")
            try:
                response = json.loads(response)
            except json.JSONDecodeError:
                fixed = re.sub(pattern, format_json_like, response, flags=re.DOTALL).strip()
                fixed = fixed.rstrip(',') 
                fixed = '{' + fixed.lstrip('{').rstrip('}') + '}' 
                response = fixed.replace('",}', '"}')  
                try:
                    response = json.loads(response)
                except json.JSONDecodeError:
                    print("JSONDecodeError:", response)
                    response = {}
        prev[task] = response
    return prev


for year in [2024]:
    for month in [
        # "January", 
        # "February", 
        # "March", 
        # "April", 
        # "May", 
        # "June", 
        # "July", 
        # "August", 
        # "September", 
        "October",
        "November",
        "December"
    ]:
        for dirpath, dnames, fnames in os.walk(f"./data/cve_detail/{year}/{month}"):
            year, month = dirpath.strip('/').split('/')[-2:]
            if len(dnames) == 0:  # dirt, [], [CVE-XXXX-XXXX.json,]
                for f in fnames:
                    with open(os.path.join(dirpath, f), 'r') as json_f:
                        data = json.load(json_f)
                        cve_code = data['CVE Code']
                        
                        json_filename = f"data/cve_ref2/{year}/{month}/{cve_code}.json"
                        if os.path.exists(json_filename):
                            ref_summary = json.load(open(json_filename, 'r'))
                        else:
                            ref_summary = []
                        cve_ref = data["Reference"]
                        
                        if cve_ref == 'N/A':  # no reported reference
                            continue
                        
                        for _ref in cve_ref:
                            
                            # locate previously saved json
                            prev_idx = None
                            for _i, _prev_sum in enumerate(ref_summary):
                                if _prev_sum[ "ref_link"] == _ref['ref_link'] and _prev_sum["ref_desc"] == _ref["ref_desc"]:
                                    prev_idx = _i
                                    break
                            prev = OrderedDict() if prev_idx is None else copy.deepcopy(ref_summary[prev_idx]["ref_summary"])
                                
                            _summary = gpt_summarize(cve_code, _ref['ref_link'], _ref['ref_desc'], prev)
                            
                            
                            # if len(_summary)==0:
                            #     continue
                            
                            if prev_idx is None:  # new reference
                                ref_summary.append({
                                    "ref_link": _ref['ref_link'],
                                    "ref_desc": _ref["ref_desc"],
                                    "ref_summary": _summary,
                                })
                            else:  # existing reference, only update summary
                                ref_summary[prev_idx]["ref_summary"] = _summary
                            
                        # if len(ref_summary) == 0:
                        #     print(f"{cve_code} results nothing in summary")
                        #     continue
                        
                        os.makedirs(os.path.dirname(json_filename), exist_ok=True)
                        with open(json_filename, "w") as f:
                            json.dump(ref_summary, f)