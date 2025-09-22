import os, json, requests
from bs4 import BeautifulSoup

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}


# Function to scrape CVE details from the webpage
def scrape_cve_details(url):
    # Send request to the webpage
    response = requests.get(url, headers=headers)
    soup = BeautifulSoup(response.text, "html.parser")

    # Extract CVE name
    # print(soup)
    cve_code = soup.find("h1").text.strip()
    cve_code = cve_code.split(":")[-1].strip()

    # Extract description
    description = soup.find(
        "div", {"id": "cvedetailssummary", "class": "cvedetailssummary-text"}
    ).text.strip()

    # Extract NVD link
    nvd_link = soup.find("a", href=lambda href: href and "nvd.nist.gov" in href)
    nvd_link = nvd_link["href"] if nvd_link else "N/A"

    # Extract vulnerability categories
    vuln_categories = []
    for vuln_category_section in soup.find_all("span", {"class": "ssc-vuln-cat"}):
        vuln_categories.append(vuln_category_section.get_text(strip=True))
    vuln_categories = ";".join(vuln_categories) if len(vuln_categories) > 0 else "N/A"

    # Extract affected products
    affected_products_list = soup.find("ul", {"id": "affectedCPEsList"})
    if affected_products_list is not None:
        affected_products = [
            li.get_text(strip=True) for li in affected_products_list.find_all("li")
        ]
        affected_products = (
            "\n" + "\n".join(affected_products) if len(affected_products) > 0 else "N/A"
        )
    else:
        affected_products = "N/A"

    # Get EPSS score and history
    epss_score = "N/A"
    for section in soup.find_all("div", {"class": "cved-card"}):
        if "Exploit prediction scoring system (EPSS)" not in section.get_text():
            continue
        if len(section.find_all("span")) == 0:
            assert "We don't have an EPSS score for this CVE yet" in section.get_text()
            continue
        assert len(section.find_all("span")) == 2
        epss_score = (
            section.find_all("span")[0].get_text().strip()
            + " Probability of exploitation activity in the next 30 days\n"
        )
        epss_score += (
            section.find_all("span")[1].get_text().strip()
            + " Percentile, the proportion of vulnerabilities that are scored at or less"
        )

    epss_hostory_link = (
        f"https://www.cvedetails.com/epss/{cve_code}/epss-score-history.html"
    )
    epss_hostory_response = requests.get(epss_hostory_link, headers=headers)
    epss_hostory_soup = BeautifulSoup(epss_hostory_response.text, "html.parser")

    epss_history = []
    for table in epss_hostory_soup.find_all("div", {"class": "table-responsive"}):
        if (
            "Old EPSS Score" not in table.get_text()
            or "New EPSS Score" not in table.get_text()
        ):
            continue
        for tr in table.find_all("tr"):
            row_texts = [td.get_text(strip=True) for td in tr]
            epss_history.append(" ".join(row_texts))
    epss_history = "\n" + "\n".join(epss_history) if len(epss_history) > 0 else "N/A"

    # Extract CVSS score
    cvss_score = (
        soup.find("div", {"class": "cvssbox"}).get_text(strip=True)
        if soup.find("div", {"class": "cvssbox"})
        else "N/A"
    )

    # Extract CWE IDs
    cwe = []
    for _link in soup.find_all("a"):
        if "cwe-details" in _link.get("href"):
            cwe.append(
                {"CWE_ID": _link.get_text(strip=True), "CWE_link": _link.get("href")}
            )

    # Extract reference links
    ref_info = []
    ref_section = soup.find_all("div", {"class": "cved-card"})[-1]
    # if ref_section:
    #     for link in ref_section.find_all('a'):
    #         ref_info.append(link['href'])
    if ref_section:
        for li in ref_section.find_all(
            "li",
            {"class": "list-group-item border-0 border-top list-group-item-action"},
        ):
            _all_li = li.find_all("a")
            ref_link = _all_li[0]["href"]
            ref_cve_link = (
                "https://www.cvedetails.com" + _all_li[1]["href"]
                if len(_all_li) > 1
                else "N/A"
            )
            ref_desc = li.find("div", {"class": "d-flex row"}).get_text(strip=True)
            ref_info.append(
                {
                    "ref_link": ref_link,
                    "ref_desc": ref_desc,
                    "ref_cve_link": ref_cve_link,
                }
            )
    ref_info = ref_info if ref_info else "N/A"

    # Return the scraped data
    return {
        "CVE Code": cve_code,
        "Description": description,
        "NVD Link": nvd_link,
        "Vulnerability Categories": vuln_categories,
        "Affected Products": affected_products,
        "EPSS Score": epss_score,
        "EPSS History": epss_history,
        "CVSS Scores": cvss_score,
        "CWE": cwe,
        "Reference": ref_info,
    }


# # Example usage
# # url = "https://www.cvedetails.com/cve/CVE-2019-1010260/"
# url = "https://www.cvedetails.com/cve/CVE-2024-51568/"
# # url = "https://www.cvedetails.com/cve/CVE-2014-2208/"
# cve_details = scrape_cve_details(url)

# # Display the scraped data
# for key, value in cve_details.items():
#     print(f"{key}: {value}")


data = {}
base_directory = "./data/cve_link"
# Traverse the directory structure
from tqdm import tqdm

for year in os.listdir(base_directory):
    year_path = os.path.join(base_directory, year)

    if os.path.isdir(year_path):
        for month in os.listdir(year_path):
            month_path = os.path.join(year_path, month)

            if os.path.isdir(month_path):
                json_file_path = os.path.join(month_path, "link.json")

                # Check if link.json exists
                if os.path.isfile(json_file_path):
                    with open(json_file_path, "r") as f:
                        try:
                            # Read and parse the JSON file
                            data[f"{year}/{month}/link.json"] = json.load(f)
                        except json.JSONDecodeError:
                            print(f"Error decoding JSON in file: {json_file_path}")

# data.keys():
# ['2015/December/link.json', '2015/August/link.json', ...]


def save_file(year, month, fid, data_to_save):
    save_path = f"data/cve_detail/{year}/{month}/{fid}.json"
    os.makedirs(os.path.dirname(save_path), exist_ok=True)
    with open(save_path, "w") as f:
        json.dump(data_to_save, f)


# MAX_CVE_PER_DOC = 100
TARGET = [
    "2025-January",
    "2025-February",
    "2025-March",
    "2025-April",
    "2025-May",
    "2025-June",
    "2025-July",
    "2025-August",
    "2025-September",
    "2025-October",
    "2025-November",
    "2025-December",
]
for k, v in data.items():
    year, month, _ = k.split("/")
    if len(TARGET) > 0 and f"{year}-{month}" not in TARGET:
        continue
    # batch = []
    # fid = 0
    for url in tqdm(v, desc=f"crawling {year}-{month}..."):
        cve_code = url.split("/")[-2]
        if os.path.exists(f"data/cve_detail/{year}/{month}/{cve_code}.json"):
            continue

        try:
            # print(url)
            cve_details = scrape_cve_details(url)
        except Exception as e:
            print(url)
            print(e)
            continue

        assert cve_code == cve_details["CVE Code"], (cve_code, cve_details["CVE Code"])
        save_file(year, month, cve_code, cve_details)

        # batch.append(cve_details)
        # if len(batch) == MAX_CVE_PER_DOC:
        #     save_file(year, month, fid, batch)
        #     batch = []
        #     fid += 1
    # if len(batch) > 0:
    #     save_file(year, month, fid, batch)
