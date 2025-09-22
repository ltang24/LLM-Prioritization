import os, json, requests, copy
from bs4 import BeautifulSoup
from time import time
from utils import g4f_generate, skip_url
from collections import OrderedDict


headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}

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
    
    for task in [
        # "- Code Snippets: Identify any relevant code examples (and code sinppet, commit, or issue) or proof-of-concept code.",
        # "- Cause of Vulnerability: Explain the root cause or conditions leading to the vulnerability.",
        # "- Threat Campaigns: Provide details about campaigns leveraging this vulnerability.",
        # "- Attributes: Describe key attributes such as affected software, versions, and configurations.",
        "- Threat Actors: Identify any associated threat actors, if mentioned.",
        "- TTPs: Provide details about attack Tactics, Techniques, and Procedures, i.e., how cybercriminals plan and execute attacks and patterns of behavior that can be used to defend against specific threats.",
        "- Infrastructure and Tools: Detail the infrastructure (domains, IPs, malware) and tools used in the attack.",
        "- Impacts: Explain the potential or observed impacts of the vulnerability.",
        "- Exploit Paths: Outline how the vulnerability can be exploited or weaponized.",
        "- Patch: Summarize recommended patching, such as codes or commits",
        "- Mitigation: Summarize recommended mitigations, or workarounds.",
    ]:
        
        task_key = task.strip('- ').split(":")[0].strip()
        if task_key in prev:
            continue
        
        print(f"-> crawling {task_key}")
        prompt = f"""

        ### Role:  
        You are an information extraction assistant. Your task is to analyze the provided HTML of a webpage describing a CVE (Common Vulnerabilities and Exposures) and extract specific information based on my instructions.

        ### Context:  
        Below is the input HTML for CVE **{cve}**, accompanied by an abstract description: **{desc}**.

        ---

        **HTML Input:**  
        {html}

        ---

        ### Task:  
        Carefully extract and organize all relevant information regarding:  
        **{task}**

        ### Requirements:  
        - Present the extracted information in a clear, structured, and detailed format.  
        - Ensure accuracy and completeness in your response.  
        - Use appropriate formatting (e.g., tables, lists, or sections) to improve readability.
        - Include any relevant code examples, code sinppet, commit, or issue if available.
        - Be brief, no redundant prefix wording such as "Sure! Here is"
        [Your Response]  

        """
        
        response = g4f_generate(prompt)
        prev[task_key] = response
            
    return prev


for year in [2025]:
    for month in [
        "January", 
        "February", 
        "March", 
        # "April", 
        # "May", 
        # "June", 
        # "July", 
        # "August", 
        # "September", 
        # "October",
        # "November",
        # "December"
    ]:
        for dirpath, dnames, fnames in os.walk(f"./data/cve_detail/{year}/{month}"):
            year, month = dirpath.strip('/').split('/')[-2:]
            if len(dnames) == 0:  # dirt, [], [CVE-XXXX-XXXX.json,]
                for f in fnames:
                    with open(os.path.join(dirpath, f), 'r') as json_f:
                        data = json.load(json_f)
                        cve_code = data['CVE Code']
                        
                        json_filename = f"data/cve_ref/{year}/{month}/{cve_code}.json"
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