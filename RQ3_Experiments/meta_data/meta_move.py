#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import shutil
from pathlib import Path
from typing import List, Dict, Tuple

# ====== 路径配置 ======
SRC_ROOT = Path("/home/xiaoqun/cveList_V5/extract_meta/2025")
ID_LIST_FILE = Path("/home/xiaoqun/RQ3_Experimants/epss_classified/epss_trend_top50_sample.txt")
DEST_DIR = Path("/home/xiaoqun/RQ3_Experimants/meta_data")

# True=移动(move)，False=拷贝(copy)
MOVE = False

# 只认 .json
CANDIDATE_SUFFIX = ".json"

# 是否放宽为“包含式匹配”（默认严格精确匹配）
RELAXED_FUZZY = False  # 改成 True 可兼容如 CVE-2025-0001_meta.json 这类文件名


def read_cve_ids(id_file: Path) -> List[str]:
    """从 txt 中读取 CVE ID，忽略 # 注释和空行；去重但保持顺序。"""
    ids: List[str] = []
    pat = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
    with id_file.open("r", encoding="utf-8") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            m = pat.match(s)
            if m:
                # 统一大写
                ids.append(m.group(0).upper())

    seen = set()
    out: List[str] = []
    for x in ids:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def index_all_json(src_root: Path) -> Tuple[Dict[str, Path], Dict[str, List[Path]]]:
    """
    递归索引 src_root 下所有 .json 文件。
    返回:
      exact_map: { "CVE-2025-0001": /path/to/CVE-2025-0001.json }  (精确文件名)
      contains_map: { "CVE-2025-0001": [含该片段的所有 .json 路径] } (仅作为调试/可选放宽)
    """
    exact_map: Dict[str, Path] = {}
    contains_map: Dict[str, List[Path]] = {}

    for p in src_root.rglob("*.json"):
        if not p.is_file():
            continue
        name_upper = p.name.upper()
        stem_upper = p.stem.upper()

        # 精确：文件名恰好是 CVE-YYYY-NNNN.json
        if re.fullmatch(r"CVE-\d{4}-\d{4,}\.JSON", name_upper):
            exact_map[stem_upper] = p

        # 记录包含式：文件名包含 CVE-YYYY-NNNN 片段（不一定恰好等于）
        m = re.search(r"CVE-\d{4}-\d{4,}", name_upper)
        if m:
            key = m.group(0)
            contains_map.setdefault(key, []).append(p)

    return exact_map, contains_map


def ensure_dest() -> None:
    DEST_DIR.mkdir(parents=True, exist_ok=True)


def copy_or_move_exact(src: Path, dst: Path, move: bool = False) -> Tuple[bool, str]:
    """
    精确同名复制/移动：
    - 若目标已存在同名文件：跳过（不生成 _1/_2）
    - 返回 (是否执行了写入, 说明)
    """
    if dst.exists():
        return False, "目标已存在，跳过"
    try:
        if move:
            shutil.move(str(src), str(dst))
        else:
            shutil.copy2(str(src), str(dst))
        return True, "完成"
    except Exception as e:
        return False, f"失败: {e}"


def main():
    ensure_dest()

    # 读取 id
    cve_ids = read_cve_ids(ID_LIST_FILE)
    print(f"读取到 {len(cve_ids)} 个 CVE ID。")
    if not cve_ids:
        print("没有可用的 CVE ID，退出。")
        return

    # 建立索引（递归）
    print(f"正在递归索引 {SRC_ROOT} 下的 .json 文件 ...")
    exact_map, contains_map = index_all_json(SRC_ROOT)
    print(f"索引完成：精确可用 {len(exact_map)} 个；包含式候选 {len(contains_map)} 个键。")

    copied_count = 0
    moved_count = 0
    covered_cves = 0
    missing: List[str] = []
    skipped_exist: List[str] = []
    failed: List[str] = []
    debug_tips: List[str] = []

    for cve in cve_ids:
        key = cve.upper()

        # 精确匹配（优先）
        src = exact_map.get(key)

        # 若没有精确命中且允许放宽，则尝试“包含式”
        if src is None and RELAXED_FUZZY:
            candidates = contains_map.get(key, [])
            # 为了仍尽量唯一，优先找“恰好等于 stem 的文件”，其次长度最短者
            if candidates:
                exact_stem = [p for p in candidates if p.stem.upper() == key]
                src = exact_stem[0] if exact_stem else sorted(candidates, key=lambda x: len(x.name))[0]

        if src is None:
            missing.append(cve)
            # 给一点调试提示：若在包含式里有记录但被关闭了放宽
            if (not RELAXED_FUZZY) and (key in contains_map):
                debug_tips.append(f"{cve}: 找到 {len(contains_map[key])} 个包含式候选，但当前为严格精确匹配。可将 RELAXED_FUZZY=True 查看。")
            continue

        dst = DEST_DIR / f"{key}{CANDIDATE_SUFFIX}"
        ok, msg = copy_or_move_exact(src, dst, move=MOVE)
        if ok:
            covered_cves += 1
            if MOVE:
                moved_count += 1
            else:
                copied_count += 1
            print(f"[{cve}] -> {dst} | {msg}")
        else:
            if msg.startswith("目标已存在"):
                skipped_exist.append(cve)
                print(f"[{cve}] 跳过：{msg}")
            else:
                failed.append(cve)
                print(f"[{cve}] 处理失败：{msg}")

    op = "移动" if MOVE else "拷贝"
    print("\n==== 汇总 ====")
    print(f"覆盖的 CVE 数（成功处理的唯一 CVE 数）：{covered_cves}")
    print(f"{op} 成功的文件数：{moved_count if MOVE else copied_count}")
    print(f"目标已存在而跳过：{len(skipped_exist)}")
    print(f"未找到源文件（严格={not RELAXED_FUZZY}）：{len(missing)}")
    print(f"处理失败：{len(failed)}")
    print(f"目标目录：{DEST_DIR}")

    if debug_tips:
        print("\n—— 调试提示（仅提示前 20 条）——")
        for tip in debug_tips[:20]:
            print("  •", tip)

    # 写出清单
    if missing:
        miss_file = DEST_DIR / "missing_cve_ids.txt"
        miss_file.write_text("\n".join(missing), encoding="utf-8")
        print(f"已写出缺失清单: {miss_file}")

    if skipped_exist:
        skipped_file = DEST_DIR / "skipped_exists_cve_ids.txt"
        skipped_file.write_text("\n".join(skipped_exist), encoding="utf-8")
        print(f"已写出已存在而跳过清单: {skipped_file}")

    if failed:
        failed_file = DEST_DIR / "failed_cve_ids.txt"
        failed_file.write_text("\n".join(failed), encoding="utf-8")
        print(f"已写出失败清单: {failed_file}")


if __name__ == "__main__":
    main()
