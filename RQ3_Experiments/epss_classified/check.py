import os

# 文件路径
cve_txt_path = "/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_top50_sample.txt"
base_dir = "/home/xiaoqun/cveList_V5/extract_meta/2025"

# 读取 CVE 列表
with open(cve_txt_path, "r") as f:
    cve_list = [line.strip() for line in f if line.strip().startswith("CVE-")]

print(f"📄 共读取 {len(cve_list)} 个 CVE ID...\n")

found = []
not_found = []

for cve in cve_list:
    cve_year = cve.split("-")[1]
    cve_suffix = cve.split("-")[2]
    folder_prefix = cve_suffix[0] + "xxx"
    json_path = os.path.join(base_dir, folder_prefix, f"{cve}.json")

    if os.path.isfile(json_path):
        print(f"✅ FOUND: {cve} at {json_path}")
        found.append(cve)
    else:
        print(f"❌ MISSING: {cve}")
        not_found.append(cve)

# 总结
print("\n📊 总结:")
print(f"✅ 已找到: {len(found)}")
print(f"❌ 未找到: {len(not_found)}")

# 可选：保存结果
with open("missing_cves.txt", "w") as f:
    for cve in not_found:
        f.write(cve + "\n")
