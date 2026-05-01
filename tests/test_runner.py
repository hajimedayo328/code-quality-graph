"""Code Quality Graph 動作検証ランナー。

各テストパターンを analyze_multiple_files に投げて、期待値と照合する。
LLM抜きで静的解析・スメル検出・グラフ指標・スコア計算が正しく動くかを確認。
"""

import os
import sys
import tempfile
from pathlib import Path

# docs/ ディレクトリをimportパスに追加
DOCS = Path(__file__).resolve().parent.parent / "docs"
sys.path.insert(0, str(DOCS))

from web_analyzer import analyze_multiple_files  # noqa: E402
from test_patterns import ALL_PATTERNS  # noqa: E402


def _check(label: str, ok: bool, detail: str = "") -> tuple[bool, str]:
    mark = "✅" if ok else "❌"
    line = f"  {mark} {label}"
    if detail:
        line += f"  → {detail}"
    return ok, line


def run_pattern(name: str, pattern: dict) -> dict:
    """1パターンを解析、期待値と比較した結果dictを返す。"""
    files = pattern["files"]
    expected = pattern["expected"]
    print(f"\n{'='*70}")
    print(f"📂 Pattern {name}")
    print(f"{'='*70}")
    print(f"  ファイル数: {len(files)}")
    for fname in files.keys():
        print(f"    - {fname}")

    try:
        result = analyze_multiple_files(files)
    except Exception as e:
        print(f"  ❌ 解析失敗: {type(e).__name__}: {e}")
        return {"pattern": name, "ok": False, "fatal": str(e)}

    stats = result["stats"]
    nodes = result["nodes"]
    modules = result["modules"]
    warnings = result["warnings"]
    duplicates = result["duplicates"]
    cycles = result["cycles"]
    edges = result["edges"]

    print(f"\n  📊 結果サマリ:")
    print(f"    関数数: {stats['n_functions']} / 行数: {stats['n_lines']} / "
          f"スコア: {stats['avg_score']} / "
          f"重複: {len(duplicates)} / 循環: {len(cycles)}")

    # 各関数の詳細
    print(f"  関数別:")
    for n in nodes:
        smells = n.get("code_smells", [])
        smell_types = ", ".join(s["type"] for s in smells) if smells else "-"
        kind_indicator = "🌐" if n.get("is_isolated") else " "
        print(f"    {kind_indicator} {n['label']:30s} "
              f"score={n['score']:3d} kind={n.get('kind', '?'):10s} "
              f"type={n.get('func_type', '?'):10s} "
              f"smells=[{smell_types}]")

    # モジュール別スメル
    for m in modules:
        m_smells = m.get("code_smells", [])
        if m_smells:
            for s in m_smells:
                print(f"    📦 {m['name']}: {s['type']}: {s['message'][:80]}")

    # ===== 検証 =====
    print(f"\n  🔍 期待値検証:")
    checks = []

    # n_functions
    if "n_functions" in expected:
        ok, line = _check(
            f"関数数 == {expected['n_functions']}",
            stats["n_functions"] == expected["n_functions"],
            f"actual={stats['n_functions']}",
        )
        checks.append(ok); print(line)

    # n_files
    if "n_files" in expected:
        ok, line = _check(
            f"ファイル数 == {expected['n_files']}",
            stats["n_files"] == expected["n_files"],
            f"actual={stats['n_files']}",
        )
        checks.append(ok); print(line)

    # min_avg_score
    if "min_avg_score" in expected:
        ok, line = _check(
            f"平均スコア >= {expected['min_avg_score']}",
            stats["avg_score"] >= expected["min_avg_score"],
            f"actual={stats['avg_score']}",
        )
        checks.append(ok); print(line)

    # max_score (このパターンの最大スコア・神関数で悲惨な値想定)
    if "max_score" in expected:
        max_s = max((n["score"] for n in nodes), default=100)
        ok, line = _check(
            f"最高スコア <= {expected['max_score']}（=スコア悲惨）",
            max_s <= expected["max_score"],
            f"actual_max={max_s}",
        )
        checks.append(ok); print(line)

    # max_smells_total（正常系で「ほぼスメルなし」を確認）
    if "max_smells_total" in expected:
        total = sum(len(n.get("code_smells", [])) for n in nodes)
        ok, line = _check(
            f"スメル合計 <= {expected['max_smells_total']}",
            total <= expected["max_smells_total"],
            f"actual={total}",
        )
        checks.append(ok); print(line)

    # min_smells（神関数で大量スメル想定）
    if "min_smells" in expected:
        total = sum(len(n.get("code_smells", [])) for n in nodes)
        ok, line = _check(
            f"スメル合計 >= {expected['min_smells']}",
            total >= expected["min_smells"],
            f"actual={total}",
        )
        checks.append(ok); print(line)

    # expected_smells（神関数で出るべきスメル種類）
    if "expected_smells" in expected:
        all_types = set()
        for n in nodes:
            for s in n.get("code_smells", []):
                all_types.add(s["type"])
        for st in expected["expected_smells"]:
            ok, line = _check(
                f"スメル '{st}' 検出",
                st in all_types,
            )
            checks.append(ok); print(line)

    # expected_isolated_functions
    if "expected_isolated_functions" in expected:
        isolated_labels = {n["label"] for n in nodes if n.get("is_isolated")}
        for fn in expected["expected_isolated_functions"]:
            ok, line = _check(
                f"'{fn}' が isolated 判定",
                fn in isolated_labels,
                f"actual_isolated={isolated_labels}",
            )
            checks.append(ok); print(line)

    # expected_module_smells
    if "expected_module_smells" in expected:
        all_mod_smells = set()
        for m in modules:
            for s in m.get("code_smells", []):
                all_mod_smells.add(s["type"])
        for ms in expected["expected_module_smells"]:
            ok, line = _check(
                f"モジュールスメル '{ms}' 検出",
                ms in all_mod_smells,
                f"actual={all_mod_smells}",
            )
            checks.append(ok); print(line)

    # expected_func_types
    if "expected_func_types" in expected:
        type_map = {n["label"]: n.get("func_type", "?") for n in nodes}
        for fn, expected_type in expected["expected_func_types"].items():
            actual = type_map.get(fn, "(missing)")
            ok, line = _check(
                f"'{fn}' の func_type == '{expected_type}'",
                actual == expected_type,
                f"actual='{actual}'",
            )
            checks.append(ok); print(line)

    # has_entry_func
    if "has_entry_func" in expected:
        entries = {n["label"] for n in nodes if n.get("is_entry")}
        ok, line = _check(
            f"'{expected['has_entry_func']}' が entry 判定",
            expected["has_entry_func"] in entries,
            f"entries={entries}",
        )
        checks.append(ok); print(line)

    # has_hub
    if expected.get("has_hub"):
        hubs = [n for n in nodes if n.get("kind") == "hub"]
        ok, line = _check(
            "HUB 判定の関数が1個以上",
            len(hubs) >= 1,
            f"hub_count={len(hubs)} ({[h['label'] for h in hubs]})",
        )
        checks.append(ok); print(line)

    # expected_hubs（特定の関数が hub になることを期待）
    if "expected_hubs" in expected:
        hub_labels = {n["label"] for n in nodes if n.get("kind") == "hub"}
        for hn in expected["expected_hubs"]:
            ok, line = _check(
                f"'{hn}' が HUB 判定",
                hn in hub_labels,
                f"actual_hubs={hub_labels}",
            )
            checks.append(ok); print(line)

    # min_cross_module_edges
    if "min_cross_module_edges" in expected:
        node_module = {n["id"]: n["module"] for n in nodes}
        cross = sum(
            1 for e in edges
            if node_module.get(e["source"]) and node_module.get(e["target"])
            and node_module[e["source"]] != node_module[e["target"]]
        )
        ok, line = _check(
            f"異モジュール間エッジ >= {expected['min_cross_module_edges']}",
            cross >= expected["min_cross_module_edges"],
            f"actual={cross}",
        )
        checks.append(ok); print(line)

    # min_duplicates
    if "min_duplicates" in expected:
        ok, line = _check(
            f"重複組 >= {expected['min_duplicates']}",
            len(duplicates) >= expected["min_duplicates"],
            f"actual={len(duplicates)}",
        )
        checks.append(ok); print(line)

    # 結果集計
    passed = sum(checks)
    total = len(checks)
    overall = passed == total
    mark = "🎉 PASS" if overall else "⚠️ FAIL"
    print(f"\n  {mark}: {passed}/{total} checks")

    return {
        "pattern": name,
        "ok": overall,
        "passed": passed,
        "total": total,
        "stats": stats,
        "n_smells_total": sum(len(n.get("code_smells", [])) for n in nodes),
    }


def main():
    print("="*70)
    print("🧪 Code Quality Graph 動作検証ランナー")
    print(f"   patterns: {len(ALL_PATTERNS)}")
    print("="*70)

    results = []
    for name, pattern in ALL_PATTERNS.items():
        try:
            r = run_pattern(name, pattern)
            results.append(r)
        except Exception as e:
            print(f"  ❌ Pattern {name} で例外: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            results.append({"pattern": name, "ok": False, "fatal": str(e)})

    # 最終サマリ
    print(f"\n{'='*70}")
    print("📊 最終結果")
    print(f"{'='*70}")
    n_pass = sum(1 for r in results if r.get("ok"))
    n_fail = len(results) - n_pass
    print(f"  PASS: {n_pass}/{len(results)}    FAIL: {n_fail}/{len(results)}")
    print()
    for r in results:
        mark = "✅" if r.get("ok") else "❌"
        line = f"  {mark} {r['pattern']:25s}"
        if "passed" in r:
            line += f"  {r['passed']}/{r['total']} checks"
        if "fatal" in r:
            line += f"  💀 {r['fatal']}"
        print(line)

    return 0 if n_fail == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
