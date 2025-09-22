# first, crawl all year-to-month links
# second, given an link for each month, extract all CVE links

import os, json
import requests
from bs4 import BeautifulSoup

# Base URL for CVEs by date
base_url = "https://www.cvedetails.com/browse-by-date.php"
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36"
}


# Step 1: Function to get all yearly CVE list URLs
def get_yearly_cve_list_links():
    response = requests.get(base_url, headers=headers)
    if response.status_code == 403:
        print("Access Denied (403 Forbidden)")
        return {}

    soup = BeautifulSoup(response.text, "html.parser")

    # Find all links to each year
    years_section = soup.find_all("a", href=True)

    yearly_cve_links = {}
    for link in years_section:
        href = link["href"]
        if (
            "/vulnerability-list/year" in href
        ):  # Only consider links leading to yearly CVE lists
            full_url = "https://www.cvedetails.com" + href
            year_name = link.text.strip()
            if not year_name.isdigit():  # could mix month url
                continue
            yearly_cve_links[year_name] = full_url

    return yearly_cve_links


# Step 2: Function to get all monthly CVE list URLs for a given year
def get_monthly_cve_list_links(year_url):
    response = requests.get(year_url, headers=headers)
    if response.status_code == 403:
        print("Access Denied (403 Forbidden)")
        return {}

    soup = BeautifulSoup(response.text, "html.parser")

    # Find all links to each month within the year
    months_section = soup.find_all("a", href=True)
    monthly_cve_links = {}
    for link in months_section:
        href = link["href"]
        if (
            "/vulnerability-list/year" in href and "/month" in href
        ):  # Only consider links leading to monthly CVE lists
            full_url = "https://www.cvedetails.com" + href
            month_name = link.text.strip()
            monthly_cve_links[month_name] = full_url

    return monthly_cve_links


# Step 3: Iterate over each year and get monthly CVE links
def get_year_to_month_cve_links():
    # Step 1: Get yearly CVE links
    yearly_links = get_yearly_cve_list_links()
    # Store results in a dictionary
    y2m_cve_links = {}

    # For each year, get the monthly links
    for year, year_url in yearly_links.items():
        print(f"Fetching months for year: {year}")
        monthly_links = get_monthly_cve_list_links(year_url)
        print(monthly_links)
        y2m_cve_links[year] = monthly_links

    return y2m_cve_links


# Step 4: Function to get all CVE links across all pages
def get_all_cve_links_per_month(month_url):
    all_cve_links = []

    # Loop through each page and get the CVE links

    assert "page=1" in month_url
    _response_1 = requests.get(month_url, headers=headers)
    _soup_1 = BeautifulSoup(_response_1.content, "html.parser")

    page_num = 1
    while True:
        page_url = month_url.replace("?page=1", f"?page={page_num}")
        print(f"Scraping page {page_url}")
        cve_links = []
        _response = requests.get(page_url, headers=headers)
        _soup = BeautifulSoup(_response.content, "html.parser")

        # NOTE: for large page number, CVE website will automatically route to page1
        if page_num > 1 and _soup == _soup_1:
            break

        # List to hold the CVE links
        cve_links = []
        # Find all 'a' tags that contain '/cve/' in the href attribute
        for link in _soup.find_all("a", href=True):
            if "/cve/" in link["href"]:
                full_link = "https://www.cvedetails.com" + link["href"]
                cve_links.append(full_link)

        all_cve_links.extend(cve_links)
        page_num += 1

    return all_cve_links


# Run the full process to get all CVE links
y2m_cve_links = get_year_to_month_cve_links()


TARGET = []
for year in [
    # 2015,
    # 2016,
    # 2017,
    # 2018,
    # 2019,
    # 2020,
    # 2021,
    # 2022,
    # 2023,
    2024,
    2025,
]:
    for month in [
        # "January",
        # "February",
        # "March",
        "April",
        # "May",
        # "June",
        # "July",
        # "August",
        # "September",
        # "October",
        # "November",
        # "December"
    ]:
        TARGET.append(f"{year}-{month}")

# Output the results
for year, months in y2m_cve_links.items():
    print(f"\nYear: {year}")
    for month, url in months.items():
        if len(TARGET) > 0 and f"{year}-{month}" not in TARGET:
            continue
        print(f"  {month}: {url}")
        # Scrape all CVE links for the given month
        monthly_cve_links = get_all_cve_links_per_month(url)

        # # Print or save the CVE links
        # for link in monthly_cve_links:
        #     print(link)
        save_path = f"data/cve_link/{year}/{month}/link.json"
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, "w") as f:
            json.dump(monthly_cve_links, f)
