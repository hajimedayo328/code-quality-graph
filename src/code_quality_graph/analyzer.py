"""コード品質グラフ分析ツール v3.

Pythonコードをグラフ理論で多角的に分析し、
素人でも「どこがヤバいか」がわかるレポートを生成する。

9つの分析レイヤー:
  1. コールグラフ: 関数の呼び出し関係
  2. Import依存グラフ: ファイル間の依存
  3. 変更影響グラフ: 1箇所変えたらどこまで壊れるか
  4. 重複コードグラフ: 似たコードのクラスタリング
  5. 認知的複雑度: 読みにくさの数値化（SonarQube互換）
  6. 技術的負債: 修正コストの分単位表示
  7. セキュリティチェック: 危険なパターン検出
  8. Git履歴連携: ホットスポット検出（変更頻度×複雑度）
  9. 総合スコア: 全レイヤーを統合した品質判定

使い方:
  python analyzer.py [対象ディレクトリ]
  python analyzer.py ../FX/correlation_network/integrated/

出力: code_quality_report.html
"""

from __future__ import annotations

import ast
import sys
import json
import re
import hashlib
import subprocess
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np


# ========== データ構造 ==========

@dataclass
class FunctionInfo:
    name: str
    qualified_name: str
    file: str
    line: int
    end_line: int
    n_lines: int
    n_args: int
    calls: list[str] = field(default_factory=list)
    complexity: int = 1           # サイクロマティック複雑度
    cognitive_complexity: int = 0  # 認知的複雑度（SonarQube互換）
    docstring: bool = False
    is_private: bool = False
    source_hash: str = ""
    security_issues: list[str] = field(default_factory=list)
    tech_debt_minutes: int = 0    # 技術的負債（修正コスト分）


@dataclass
class ModuleInfo:
    name: str
    file: str
    n_lines: int
    imports: list[str] = field(default_factory=list)
    import_from: list[tuple[str, str]] = field(default_factory=list)
    functions: list[str] = field(default_factory=list)
    classes: list[str] = field(default_factory=list)
    global_vars: list[str] = field(default_factory=list)
    git_commits: int = 0          # Git変更回数
    git_last_modified: str = ""   # 最終変更日
    security_issues: list[str] = field(default_factory=list)


# ========== AST解析 ==========

class CodeAnalyzer:
    def __init__(self, root_dir: str):
        self.root = Path(root_dir).resolve()
        self.functions: dict[str, FunctionInfo] = {}
        self.modules: dict[str, ModuleInfo] = {}

    def analyze(self) -> None:
        for f in sorted(self.root.rglob("*.py")):
            if "__pycache__" in str(f):
                continue
            self._analyze_file(f)

    def _analyze_file(self, filepath: Path) -> None:
        try:
            source = filepath.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(filepath))
        except (SyntaxError, UnicodeDecodeError):
            return

        rel_path = filepath.relative_to(self.root)
        module_name = str(rel_path).replace("/", ".").replace("\\", ".").removesuffix(".py")
        lines = source.splitlines()

        mod = ModuleInfo(name=module_name, file=str(rel_path), n_lines=len(lines))

        # imports
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    mod.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    mod.imports.append(node.module)
                    for alias in (node.names or []):
                        mod.import_from.append((node.module, alias.name))

        # global vars
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        mod.global_vars.append(target.id)

        # functions
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                class_name = self._find_parent_class(tree, node)
                qname = f"{module_name}.{class_name}.{node.name}" if class_name else f"{module_name}.{node.name}"

                calls = []
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        call_name = self._get_call_name(child)
                        if call_name:
                            calls.append(call_name)

                complexity = 1
                for child in ast.walk(node):
                    if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler,
                                          ast.With, ast.Assert, ast.comprehension)):
                        complexity += 1
                    elif isinstance(child, ast.BoolOp):
                        complexity += len(child.values) - 1

                end_line = getattr(node, "end_lineno", node.lineno)

                # ソースハッシュ（重複検出用）
                func_source = "\n".join(lines[node.lineno - 1:end_line]) if end_line <= len(lines) else ""
                # 空白・コメント除去した正規化ハッシュ
                normalized = "\n".join(
                    l.strip() for l in func_source.splitlines()
                    if l.strip() and not l.strip().startswith("#")
                )
                source_hash = hashlib.md5(normalized.encode()).hexdigest()[:12]

                # 認知的複雑度
                cog_complexity = _calc_cognitive_complexity(node)

                # セキュリティチェック
                sec_issues = _check_security(node, func_source if end_line <= len(lines) else "")

                # 技術的負債（分単位の修正コスト推定）
                debt = _estimate_tech_debt(end_line - node.lineno + 1, complexity, cog_complexity, len(sec_issues))

                func = FunctionInfo(
                    name=node.name, qualified_name=qname,
                    file=str(rel_path), line=node.lineno,
                    end_line=end_line, n_lines=end_line - node.lineno + 1,
                    n_args=len(node.args.args), calls=calls,
                    complexity=complexity,
                    cognitive_complexity=cog_complexity,
                    docstring=bool(node.body) and isinstance(node.body[0], ast.Expr)
                              and isinstance(node.body[0].value, ast.Constant),
                    is_private=node.name.startswith("_"),
                    source_hash=source_hash,
                    security_issues=sec_issues,
                    tech_debt_minutes=debt,
                )
                self.functions[qname] = func
                mod.functions.append(qname)

            elif isinstance(node, ast.ClassDef):
                mod.classes.append(f"{module_name}.{node.name}")

        self.modules[module_name] = mod

    def _find_parent_class(self, tree, target) -> str | None:
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for child in ast.walk(node):
                    if child is target:
                        return node.name
        return None

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None


# ========== Layer 1: コールグラフ ==========

def build_call_graph(analyzer: CodeAnalyzer) -> tuple[list[str], list[tuple[str, str]]]:
    """関数間の呼び出し関係グラフ."""
    func_names = set(analyzer.functions.keys())
    short_map = defaultdict(list)
    for qname in func_names:
        short_map[qname.rsplit(".", 1)[-1]].append(qname)

    edges = []
    for qname, func in analyzer.functions.items():
        for call in func.calls:
            for target in short_map.get(call, []):
                if target != qname:
                    edges.append((qname, target))

    return list(func_names), edges


# ========== Layer 2: Import依存グラフ ==========

def build_import_graph(analyzer: CodeAnalyzer) -> tuple[list[str], list[tuple[str, str]], list[list[str]]]:
    """ファイル間の依存関係グラフ + 循環検出."""
    mod_names = list(analyzer.modules.keys())
    edges = []

    for mname, mod in analyzer.modules.items():
        for imp in mod.imports:
            # プロジェクト内のモジュールへのimportのみ
            for target in mod_names:
                if imp == target or imp.endswith(f".{target.split('.')[-1]}"):
                    if target != mname:
                        edges.append((mname, target))
                        break

    # 循環検出
    cycles = _detect_cycles_in_modules(mod_names, edges)
    return mod_names, edges, cycles


def _detect_cycles_in_modules(nodes: list[str], edges: list[tuple[str, str]]) -> list[list[str]]:
    adj = defaultdict(list)
    for a, b in edges:
        adj[a].append(b)

    cycles = []
    node_set = set(nodes)
    for start in nodes:
        stack = [(start, [start])]
        visited = set()
        while stack and len(cycles) < 20:
            curr, path = stack.pop()
            if len(path) > 6:
                continue
            for nxt in adj.get(curr, []):
                if nxt not in node_set:
                    continue
                if nxt == start and len(path) > 1:
                    cycle_key = tuple(sorted(path))
                    if cycle_key not in visited:
                        visited.add(cycle_key)
                        cycles.append(path + [start])
                elif nxt not in path:
                    stack.append((nxt, path + [nxt]))
    return cycles[:10]


# ========== Layer 3: 変更影響グラフ ==========

def calc_impact_scores(
    func_nodes: list[str],
    call_edges: list[tuple[str, str]],
    mod_nodes: list[str],
    import_edges: list[tuple[str, str]],
    analyzer: CodeAnalyzer,
) -> dict[str, dict]:
    """各関数/モジュールを変更した時の影響範囲を計算."""

    # 関数レベル: 逆方向の到達可能性（この関数を変えたら何が壊れる？）
    reverse_adj = defaultdict(set)
    for src, dst in call_edges:
        reverse_adj[dst].add(src)  # dstを変えたら、srcに影響

    func_impact = {}
    for func in func_nodes:
        # BFSで到達可能ノード数を計算
        visited = set()
        queue = [func]
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            for parent in reverse_adj.get(curr, []):
                if parent not in visited:
                    queue.append(parent)
        affected = len(visited) - 1  # 自分自身を除く
        func_impact[func] = {
            "affected_functions": affected,
            "risk": "高" if affected >= 5 else "中" if affected >= 2 else "低",
        }

    # モジュールレベル
    mod_reverse = defaultdict(set)
    for src, dst in import_edges:
        mod_reverse[dst].add(src)

    mod_impact = {}
    for mod in mod_nodes:
        visited = set()
        queue = [mod]
        while queue:
            curr = queue.pop(0)
            if curr in visited:
                continue
            visited.add(curr)
            for parent in mod_reverse.get(curr, []):
                if parent not in visited:
                    queue.append(parent)
        mod_impact[mod] = {
            "affected_modules": len(visited) - 1,
            "risk": "高" if len(visited) - 1 >= 3 else "中" if len(visited) - 1 >= 1 else "低",
        }

    return {"functions": func_impact, "modules": mod_impact}


# ========== Layer 4: 重複コードグラフ ==========

def find_duplicates(analyzer: CodeAnalyzer) -> list[dict]:
    """ソースハッシュで重複・類似関数を検出."""
    hash_groups = defaultdict(list)
    for qname, func in analyzer.functions.items():
        if func.n_lines >= 3:  # 3行以上の関数のみ
            hash_groups[func.source_hash].append(qname)

    duplicates = []
    for h, funcs in hash_groups.items():
        if len(funcs) >= 2:
            duplicates.append({
                "hash": h,
                "functions": funcs,
                "names": [analyzer.functions[f].name for f in funcs],
                "files": list(set(analyzer.functions[f].file for f in funcs)),
                "lines": analyzer.functions[funcs[0]].n_lines,
            })

    return sorted(duplicates, key=lambda x: -x["lines"])


# ========== Layer 5: 認知的複雑度 (SonarQube互換) ==========

def _calc_cognitive_complexity(func_node: ast.AST) -> int:
    """認知的複雑度を計算する.

    SonarQubeの定義に基づく:
    - ネストが深くなるほどペナルティが増える（+ネスト深度）
    - break/continue/goto は+1
    - if/elif/else, for, while, except は+1 + ネスト深度
    - 論理演算子の混在（and/or混在）は+1
    - 再帰呼び出しは+1
    """
    score = 0

    def walk(node, nesting=0):
        nonlocal score

        increment_nesting = False

        if isinstance(node, (ast.If, ast.For, ast.While)):
            score += 1 + nesting
            increment_nesting = True
        elif isinstance(node, ast.ExceptHandler):
            score += 1 + nesting
            increment_nesting = True
        elif isinstance(node, ast.BoolOp):
            # and/or混在で+1
            score += 1
        elif isinstance(node, (ast.Break, ast.Continue)):
            score += 1

        # elifは追加の+1なし（SonarQube仕様: elseは+1, elifは+1だがネスト加算なし）
        if isinstance(node, ast.If) and hasattr(node, 'orelse') and node.orelse:
            for child in node.orelse:
                if isinstance(child, ast.If):
                    # elif: +1だがネスト加算なし
                    score += 1

        next_nesting = nesting + 1 if increment_nesting else nesting

        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # ネストされた関数はさらに+1
                score += 1 + nesting
                walk(child, nesting + 1)
            else:
                walk(child, next_nesting)

    walk(func_node)
    return score


# ========== Layer 6: 技術的負債 ==========

def _estimate_tech_debt(n_lines: int, complexity: int, cognitive: int,
                        n_security: int) -> int:
    """技術的負債を分単位で推定する.

    修正コスト目安:
    - 長い関数の分割: 行数に比例（50行超過分 × 2分）
    - 複雑度の低減: 超過分 × 5分
    - 認知的複雑度の低減: 超過分 × 3分
    - セキュリティ修正: 1件 × 15分
    """
    debt = 0
    if n_lines > 50:
        debt += (n_lines - 50) * 2
    if complexity > 8:
        debt += (complexity - 8) * 5
    if cognitive > 15:
        debt += (cognitive - 15) * 3
    debt += n_security * 15
    return debt


# ========== Layer 7: セキュリティチェック ==========

SECURITY_PATTERNS = [
    (r'\beval\s*\(', "eval() の使用: 任意コード実行の危険"),
    (r'\bexec\s*\(', "exec() の使用: 任意コード実行の危険"),
    (r'\b__import__\s*\(', "__import__() の使用: 動的インポートは危険"),
    (r'(password|passwd|secret|api_key|apikey|token)\s*=\s*["\']', "秘密情報のハードコード"),
    (r'pickle\.loads?\s*\(', "pickle.load: 信頼できないデータのデシリアライズは危険"),
    (r'subprocess\.(call|run|Popen)\s*\(.*shell\s*=\s*True', "shell=True: コマンドインジェクションの危険"),
    (r'os\.system\s*\(', "os.system(): コマンドインジェクションの危険"),
    (r'\.format\s*\(.*\bsql\b', "SQL文字列フォーマット: SQLインジェクションの危険"),
    (r'f["\'].*SELECT.*FROM.*\{', "f-stringでSQL構築: SQLインジェクションの危険"),
    (r'verify\s*=\s*False', "SSL検証無効化: 中間者攻撃の危険"),
    (r'chmod\s*\(\s*0o?777', "chmod 777: 全ユーザーに全権限"),
    (r'tempfile\.mk(s?temp|dtemp)\s*\(', "一時ファイル: 競合状態の可能性（tempfile.NamedTemporaryFileを推奨）"),
]


def _check_security(func_node: ast.AST, source: str) -> list[str]:
    """セキュリティの基本チェック."""
    issues = []
    for pattern, message in SECURITY_PATTERNS:
        if re.search(pattern, source, re.IGNORECASE):
            issues.append(message)
    return issues


def check_module_security(source: str) -> list[str]:
    """モジュールレベルのセキュリティチェック."""
    issues = []
    for pattern, message in SECURITY_PATTERNS:
        if re.search(pattern, source, re.IGNORECASE):
            issues.append(message)
    return issues


# ========== Layer 8: Git履歴連携（ホットスポット検出） ==========

def analyze_git_history(root: Path) -> dict[str, dict]:
    """Git履歴から各ファイルの変更頻度と最終変更日を取得する.

    ホットスポット = 変更頻度が高い × 複雑度が高い → 最もバグが出やすい場所
    """
    git_data = {}

    try:
        # gitリポジトリか確認
        result = subprocess.run(
            ["git", "rev-parse", "--is-inside-work-tree"],
            cwd=str(root), capture_output=True, text=True, timeout=5,
        )
        if result.returncode != 0:
            return {}

        # 各ファイルのcommit数
        result = subprocess.run(
            ["git", "log", "--format=%H", "--name-only", "--diff-filter=AMRC",
             "--since=1 year ago", "--", "*.py"],
            cwd=str(root), capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {}

        file_commits = defaultdict(int)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith(("commit ", "Merge:")) and len(line) != 40:
                file_commits[line] += 1

        # 最終変更日
        for filepath, commits in file_commits.items():
            try:
                date_result = subprocess.run(
                    ["git", "log", "-1", "--format=%ci", "--", filepath],
                    cwd=str(root), capture_output=True, text=True, timeout=5,
                )
                last_modified = date_result.stdout.strip()[:10] if date_result.returncode == 0 else ""
            except Exception:
                last_modified = ""

            git_data[filepath] = {
                "commits": commits,
                "last_modified": last_modified,
            }

    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return git_data


def calc_hotspots(
    analyzer: CodeAnalyzer,
    git_data: dict[str, dict],
) -> list[dict]:
    """ホットスポット = 変更頻度 × 複雑度が高いファイル."""
    hotspots = []

    for mname, mod in analyzer.modules.items():
        filepath = mod.file
        git_info = git_data.get(filepath, {})
        commits = git_info.get("commits", 0)

        if commits == 0:
            continue

        # ファイル内の最大複雑度
        max_complexity = 0
        max_cognitive = 0
        for fname in mod.functions:
            func = analyzer.functions.get(fname)
            if func:
                max_complexity = max(max_complexity, func.complexity)
                max_cognitive = max(max_cognitive, func.cognitive_complexity)

        # ホットスポットスコア = 変更回数 × 最大複雑度
        score = commits * (max_complexity + max_cognitive)

        hotspots.append({
            "file": filepath,
            "module": mname,
            "commits": commits,
            "max_complexity": max_complexity,
            "max_cognitive": max_cognitive,
            "hotspot_score": score,
            "last_modified": git_info.get("last_modified", ""),
        })

    return sorted(hotspots, key=lambda x: -x["hotspot_score"])


# ========== Layer 9: 総合スコア ==========

def calc_quality_scores(
    analyzer: CodeAnalyzer,
    call_edges: list[tuple[str, str]],
    import_cycles: list[list[str]],
    impact: dict,
    duplicates: list[dict],
) -> tuple[dict[str, int], dict[str, int], list[dict]]:
    """関数スコア、モジュールスコア、警告リストを返す."""

    # 被呼び出し数
    in_degree = defaultdict(int)
    for _, dst in call_edges:
        in_degree[dst] += 1

    duplicate_funcs = set()
    for d in duplicates:
        duplicate_funcs.update(d["functions"])

    # 関数スコア
    func_scores = {}
    warnings = []

    for qname, func in analyzer.functions.items():
        score = 100
        reasons = []

        if func.n_lines > 100:
            score -= 30
            reasons.append(f"{func.n_lines}行もある。50行以下に分割しよう")
        elif func.n_lines > 50:
            score -= 15
            reasons.append(f"{func.n_lines}行。長めなので分割を検討")

        if func.complexity > 15:
            score -= 30
            reasons.append(f"複雑度{func.complexity}。分岐が多すぎて読めない")
        elif func.complexity > 8:
            score -= 15
            reasons.append(f"複雑度{func.complexity}。やや複雑")

        if not func.docstring and not func.is_private and func.n_lines > 10:
            score -= 5
            reasons.append("説明コメントがない")

        affected = impact["functions"].get(qname, {}).get("affected_functions", 0)
        if affected >= 5:
            score -= 10
            reasons.append(f"変更すると{affected}個の関数に影響する")

        if in_degree.get(qname, 0) >= 10:
            score -= 5
            reasons.append(f"{in_degree[qname]}箇所から呼ばれている。変更注意")

        if qname in duplicate_funcs:
            score -= 10
            reasons.append("他の関数とほぼ同じコード。共通化を検討")

        if func.n_args > 7:
            score -= 5
            reasons.append(f"引数が{func.n_args}個。多すぎ")

        # 認知的複雑度
        if func.cognitive_complexity > 25:
            score -= 20
            reasons.append(f"認知的複雑度{func.cognitive_complexity}。読むのが非常に困難")
        elif func.cognitive_complexity > 15:
            score -= 10
            reasons.append(f"認知的複雑度{func.cognitive_complexity}。読みにくい")

        # セキュリティ
        for issue in func.security_issues:
            score -= 15
            reasons.append(f"セキュリティ: {issue}")

        func_scores[qname] = max(0, min(100, score))

        for reason in reasons:
            severity = "high" if score < 50 else "medium" if score < 70 else "info"
            warnings.append({
                "target": func.name,
                "target_full": qname,
                "file": func.file,
                "line": func.line,
                "severity": severity,
                "message": reason,
                "fix": _suggest_fix(reason),
            })

    # モジュールスコア
    mod_scores = {}
    for mname, mod in analyzer.modules.items():
        score = 100
        if mod.n_lines > 500:
            score -= 20
            warnings.append({
                "target": mname.split(".")[-1] + ".py",
                "target_full": mname,
                "file": mod.file, "line": 0,
                "severity": "high",
                "message": f"{mod.n_lines}行。ファイルが大きすぎる",
                "fix": "責任ごとにファイルを分割しよう。1ファイル200-400行が理想",
            })
        elif mod.n_lines > 300:
            score -= 10

        mod_affected = impact["modules"].get(mname, {}).get("affected_modules", 0)
        if mod_affected >= 3:
            score -= 10
            warnings.append({
                "target": mname.split(".")[-1] + ".py",
                "target_full": mname,
                "file": mod.file, "line": 0,
                "severity": "medium",
                "message": f"変更すると{mod_affected}個のファイルに影響する",
                "fix": "このファイルを変える前に、影響先のテストを確認しよう",
            })

        # 循環依存
        for cycle in import_cycles:
            if mname in cycle:
                score -= 20
                break

        mod_scores[mname] = max(0, min(100, score))

    # 循環依存の警告
    for cycle in import_cycles:
        names = [c.split(".")[-1] for c in cycle]
        warnings.append({
            "target": " → ".join(names),
            "target_full": cycle[0],
            "file": "", "line": 0,
            "severity": "high",
            "message": f"循環依存: {' → '.join(names)}",
            "fix": "AがBを使い、BがAを使う構造。共通部分を別ファイルに抽出しよう",
        })

    # 重複の警告
    for dup in duplicates:
        names = [n for n in dup["names"]]
        warnings.append({
            "target": ", ".join(names),
            "target_full": dup["functions"][0],
            "file": ", ".join(dup["files"]),
            "line": 0,
            "severity": "medium",
            "message": f"ほぼ同じコード: {', '.join(names)}（{dup['lines']}行）",
            "fix": "共通の関数に統合しよう。DRY原則（Don't Repeat Yourself）",
        })

    return func_scores, mod_scores, warnings


def _suggest_fix(reason: str) -> str:
    if "行もある" in reason or "長め" in reason:
        return "処理のまとまりごとに関数に切り出そう。1関数50行以下が目安"
    if "複雑度" in reason:
        return "早期リターン（条件に合わなければすぐreturn）で分岐を減らせる"
    if "説明コメント" in reason:
        return '関数の先頭に """この関数は何をするか""" を1行書こう'
    if "影響する" in reason:
        return "この関数を変える時は、呼び出し元も確認しよう"
    if "呼ばれている" in reason:
        return "よく使われる関数。テストを書いてから変更しよう"
    if "同じコード" in reason:
        return "共通の関数にまとめよう。引数で差分を吸収する"
    if "引数が" in reason:
        return "関連する引数をdataclassや辞書にまとめよう"
    return "コードを見直そう"


# ========== 次にやることガイド ==========

def generate_action_guide(
    analyzer: "CodeAnalyzer",
    func_scores: dict[str, int],
    warnings: list[dict],
    impact: dict,
    duplicates: list[dict],
) -> list[dict]:
    """「次にやること」をステップバイステップで生成する.

    最もスコアが低い関数から順に、具体的な改善手順を出す。
    初心者が「何から手を付ければいいか」を迷わないようにする。
    """
    actions = []

    # スコアが低い順にソート
    sorted_funcs = sorted(func_scores.items(), key=lambda x: x[1])

    for qname, score in sorted_funcs[:5]:  # 上位5件まで
        func = analyzer.functions.get(qname)
        if func is None:
            continue

        steps = []
        priority = "high" if score < 50 else "medium" if score < 70 else "low"

        # 問題の種類に応じたステップを生成
        if func.n_lines > 100:
            steps.append({
                "step": "関数を分割する",
                "detail": f"この関数は{func.n_lines}行。以下の手順で分割しよう:",
                "substeps": [
                    "関数内のコメントや空行を探す。それが処理の区切り",
                    "区切りごとに新しい関数名を考える（例: _validate_input, _process_data）",
                    "区切り部分を新しい関数にコピーし、元の場所は関数呼び出しに置き換える",
                    "動作が変わっていないことを確認する（テストがあれば実行）",
                ],
                "time": f"約{func.n_lines // 25}分",
            })
        elif func.n_lines > 50:
            steps.append({
                "step": "長い関数を短くする",
                "detail": f"この関数は{func.n_lines}行。50行以下が目標",
                "substeps": [
                    "繰り返し出てくるパターンを探す",
                    "if文の中身が長い場合、中身を別関数に切り出す",
                    "ループの中身が長い場合も同様",
                ],
                "time": f"約{max(5, func.n_lines // 10)}分",
            })

        if func.complexity > 8 or func.cognitive_complexity > 15:
            steps.append({
                "step": "分岐を減らす",
                "detail": f"複雑度{func.complexity} / 認知的複雑度{func.cognitive_complexity}。読みにくい",
                "substeps": [
                    "「早期リターン」を使う: 条件を満たさない場合にすぐreturnする",
                    "例: if not x: return None を関数の最初に置く",
                    "深いネスト（if の中の if の中の for...）を平坦にする",
                    "条件が複雑な場合、条件を変数に入れる（is_valid = x > 0 and y < 10）",
                ],
                "time": f"約{max(5, (func.complexity - 8) * 3)}分",
            })

        if not func.docstring and not func.is_private and func.n_lines > 10:
            steps.append({
                "step": "説明を書く",
                "detail": "この関数が何をするか、1行で書こう",
                "substeps": [
                    '関数の最初の行に """この関数は〇〇を△△する.""" と書く',
                    "引数が3つ以上あるなら、各引数の説明も書く",
                ],
                "time": "約2分",
            })

        if func.security_issues:
            steps.append({
                "step": "セキュリティ問題を修正する",
                "detail": f"{len(func.security_issues)}件のセキュリティ問題がある",
                "substeps": [f"修正: {issue}" for issue in func.security_issues],
                "time": f"約{len(func.security_issues) * 10}分",
            })

        affected = impact["functions"].get(qname, {}).get("affected_functions", 0)
        if affected >= 3:
            steps.append({
                "step": "変更前にテストを書く",
                "detail": f"この関数を変えると{affected}個の関数に影響する。先にテストを書いて安全網を作ろう",
                "substeps": [
                    f"pytest でテストファイルを作る（test_{func.name}.py）",
                    "現在の動作を確認するテストを最低1つ書く",
                    "テストが通ることを確認してからリファクタリングする",
                ],
                "time": "約10分",
            })

        if qname in {f for d in duplicates for f in d["functions"]}:
            steps.append({
                "step": "重複コードを統合する",
                "detail": "他の関数とほぼ同じコードがある",
                "substeps": [
                    "重複している関数を見比べて、違いを確認する",
                    "共通部分を1つの関数にまとめる",
                    "違いは引数で吸収する",
                ],
                "time": "約15分",
            })

        if steps:
            total_time = sum(
                int(s["time"].replace("約", "").replace("分", ""))
                for s in steps if "分" in s["time"]
            )
            actions.append({
                "function": func.name,
                "file": func.file,
                "line": func.line,
                "score": score,
                "priority": priority,
                "steps": steps,
                "total_time": f"約{total_time}分",
            })

    return actions


def _build_action_guide_html(actions: list[dict]) -> str:
    """「次にやること」のHTML生成."""
    if not actions:
        return '<p style="color:#34c759;font-weight:600">問題は見つかりませんでした。コードは健康です！</p>'

    parts = []

    # 最優先の1つを大きく表示
    top = actions[0]
    parts.append(f'''
    <div style="background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);
                border-radius:16px;padding:28px 32px;color:#fff;margin-bottom:24px">
      <div style="font-size:12px;text-transform:uppercase;letter-spacing:1px;opacity:0.8">
        今日やるべき1つ
      </div>
      <div style="font-size:24px;font-weight:700;margin:8px 0">
        {top["function"]} を改善する
      </div>
      <div style="font-size:14px;opacity:0.9">
        {top["file"]}:{top["line"]} / スコア {top["score"]}点 / 推定 {top["total_time"]}
      </div>
    </div>
    ''')

    # 各アクションの詳細
    for i, action in enumerate(actions):
        bg = "#fff5f5" if action["priority"] == "high" else "#fffff0" if action["priority"] == "medium" else "#f0fff4"
        border_color = "#fed7d7" if action["priority"] == "high" else "#fefcbf" if action["priority"] == "medium" else "#c6f6d5"
        label_color = "#c53030" if action["priority"] == "high" else "#975a16" if action["priority"] == "medium" else "#276749"
        label = "優先度: 高" if action["priority"] == "high" else "優先度: 中" if action["priority"] == "medium" else "優先度: 低"

        steps_html = ""
        for j, step in enumerate(action["steps"]):
            substeps = "".join(f'<li style="margin:4px 0;color:#4a5568">{s}</li>' for s in step["substeps"])
            steps_html += f'''
            <div style="margin-bottom:16px">
              <div style="display:flex;align-items:center;gap:8px;margin-bottom:6px">
                <span style="background:#667eea;color:#fff;width:24px;height:24px;border-radius:50%;
                             display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;flex-shrink:0">
                  {j+1}
                </span>
                <span style="font-weight:600;font-size:15px">{step["step"]}</span>
                <span style="color:#a0aec0;font-size:12px;margin-left:auto">{step["time"]}</span>
              </div>
              <div style="margin-left:32px;font-size:13px;color:#718096">{step["detail"]}</div>
              <ol style="margin-left:48px;margin-top:6px;font-size:13px">{substeps}</ol>
            </div>
            '''

        parts.append(f'''
        <div style="background:{bg};border:1px solid {border_color};border-radius:12px;
                    padding:20px 24px;margin-bottom:12px">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
            <div>
              <span style="font-weight:700;font-size:16px">{action["function"]}</span>
              <span style="color:#a0aec0;font-size:13px;margin-left:8px">{action["file"]}:{action["line"]}</span>
            </div>
            <div style="display:flex;gap:8px;align-items:center">
              <span style="color:{label_color};font-size:12px;font-weight:600">{label}</span>
              <span style="background:{label_color};color:#fff;padding:2px 10px;border-radius:8px;
                           font-size:12px;font-weight:600">スコア {action["score"]}</span>
            </div>
          </div>
          {steps_html}
        </div>
        ''')

    return "\n".join(parts)


# ========== グラフ指標 ==========

def calc_graph_metrics(nodes: list[str], edges: list[tuple[str, str]]) -> dict:
    n = len(nodes)
    if n == 0:
        return {"density": 0, "components": 0, "avg_degree": 0}

    node_idx = {name: i for i, name in enumerate(nodes)}
    out_adj = defaultdict(set)
    in_adj = defaultdict(set)
    for src, dst in edges:
        if src in node_idx and dst in node_idx:
            out_adj[src].add(dst)
            in_adj[dst].add(src)

    total_degree = {name: len(out_adj.get(name, set())) + len(in_adj.get(name, set())) for name in nodes}
    density = len(edges) / (n * (n - 1)) if n > 1 else 0

    # 連結成分
    visited = set()
    components = 0
    for node in nodes:
        if node in visited:
            continue
        components += 1
        queue = [node]
        while queue:
            curr = queue.pop()
            if curr in visited:
                continue
            visited.add(curr)
            for nxt in out_adj.get(curr, set()) | in_adj.get(curr, set()):
                if nxt not in visited:
                    queue.append(nxt)

    # PageRank
    pr = {name: 1.0 / n for name in nodes}
    for _ in range(30):
        new_pr = {}
        for name in nodes:
            rank = 0.15 / n
            for src in in_adj.get(name, set()):
                out_count = len(out_adj.get(src, set()))
                if out_count > 0:
                    rank += 0.85 * pr[src] / out_count
            new_pr[name] = rank
        pr = new_pr

    # 最も呼ばれている関数
    in_counts = {name: len(in_adj.get(name, set())) for name in nodes}
    most_called = max(in_counts.items(), key=lambda x: x[1]) if in_counts else ("", 0)

    return {
        "density": round(density, 4),
        "components": components,
        "avg_degree": round(sum(total_degree.values()) / n, 1) if n > 0 else 0,
        "pagerank": pr,
        "in_degree": in_counts,
        "most_called": most_called,
        "isolated": [name for name in nodes if total_degree[name] == 0],
    }


# ========== HTML生成 ==========

def generate_report(
    analyzer: CodeAnalyzer,
    call_nodes: list[str], call_edges: list[tuple[str, str]],
    mod_nodes: list[str], import_edges: list[tuple[str, str]], import_cycles: list,
    impact: dict, duplicates: list[dict],
    func_scores: dict[str, int], mod_scores: dict[str, int],
    warnings: list[dict],
    call_metrics: dict,
    output_path: Path,
    hotspots: list[dict] | None = None,
    total_debt: int = 0,
    sec_count: int = 0,
) -> None:

    all_func_scores = list(func_scores.values())
    avg_score = round(np.mean(all_func_scores), 1) if all_func_scores else 0
    health = "healthy" if avg_score >= 80 else "caution" if avg_score >= 60 else "danger"
    health_label = {"healthy": "健康", "caution": "要注意", "danger": "要改善"}[health]

    n_high = sum(1 for w in warnings if w["severity"] == "high")
    n_medium = sum(1 for w in warnings if w["severity"] == "medium")

    # ノードデータ
    nodes_json = []
    short_to_q = defaultdict(list)
    for qname in analyzer.functions:
        short_to_q[qname.rsplit(".", 1)[-1]].append(qname)

    for qname, func in analyzer.functions.items():
        module = qname.rsplit(".", 1)[0] if "." in qname else ""
        pr = call_metrics.get("pagerank", {}).get(qname, 0)
        in_deg = call_metrics.get("in_degree", {}).get(qname, 0)
        nodes_json.append({
            "id": qname, "label": func.name, "module": module,
            "file": func.file, "line": func.line,
            "lines": func.n_lines, "complexity": func.complexity,
            "cognitive": func.cognitive_complexity,
            "score": func_scores.get(qname, 100),
            "pagerank": round(pr, 5), "in_degree": in_deg,
            "impact": impact["functions"].get(qname, {}).get("affected_functions", 0),
            "is_isolated": qname in call_metrics.get("isolated", []),
            "debt_min": func.tech_debt_minutes,
            "security": len(func.security_issues),
        })

    edges_json = [{"source": s, "target": t} for s, t in call_edges]

    # モジュールデータ
    modules_json = []
    for mname, mod in analyzer.modules.items():
        modules_json.append({
            "name": mname, "file": mod.file, "lines": mod.n_lines,
            "n_functions": len(mod.functions), "n_imports": len(mod.imports),
            "score": mod_scores.get(mname, 100),
            "impact": impact["modules"].get(mname, {}).get("affected_modules", 0),
        })

    # 次にやることガイド
    action_guide = generate_action_guide(analyzer, func_scores, warnings, impact, duplicates)
    action_guide_html = _build_action_guide_html(action_guide)

    html = _render_html(
        nodes_json, edges_json, modules_json, warnings, duplicates,
        avg_score, health, health_label, n_high, n_medium,
        len(analyzer.modules), len(analyzer.functions),
        sum(m.n_lines for m in analyzer.modules.values()),
        len(call_edges), call_metrics, len(import_cycles),
        hotspots=hotspots or [], total_debt=total_debt, sec_count=sec_count,
        action_guide_html=action_guide_html,
    )
    output_path.write_text(html, encoding="utf-8")


def _render_html(nodes, edges, modules, warnings, duplicates,
                 avg_score, health, health_label, n_high, n_medium,
                 n_files, n_functions, n_lines, n_edges, metrics, n_cycles,
                 hotspots=None, total_debt=0, sec_count=0,
                 action_guide_html=""):

    warnings_html = _build_warnings_html(warnings)
    modules_html = _build_modules_html(modules)
    functions_html = _build_functions_html(nodes)
    duplicates_html = _build_duplicates_html(duplicates)
    impact_html = _build_impact_html(nodes)
    hotspots_html = _build_hotspots_html(hotspots or [])
    debt_hours = total_debt / 60

    return f"""<!DOCTYPE html>
<html lang="ja">
<head>
<meta charset="utf-8">
<title>Code Quality Graph v2</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ background: #f5f5f7; color: #1d1d1f; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; font-size: 15px; line-height: 1.7; }}

.header {{ background: #fff; border-bottom: 1px solid #e5e5e5; padding: 32px 40px; }}
.header h1 {{ font-size: 28px; font-weight: 700; letter-spacing: -0.5px; }}
.header .subtitle {{ color: #86868b; font-size: 14px; margin-top: 6px; }}
.health-badge {{ display: inline-block; padding: 4px 16px; border-radius: 20px; font-size: 14px; font-weight: 600; margin-left: 12px; vertical-align: middle; }}
.health-badge.healthy {{ background: #e8f8ef; color: #1b7a3d; }}
.health-badge.caution {{ background: #fef3cd; color: #856404; }}
.health-badge.danger {{ background: #fde8e8; color: #c0392b; }}

.container {{ max-width: 1200px; margin: 0 auto; padding: 32px 24px; }}

.cards {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 32px; }}
@media (max-width: 768px) {{ .cards {{ grid-template-columns: repeat(2, 1fr); }} }}
.card {{ background: #fff; border-radius: 16px; padding: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }}
.card .value {{ font-size: 36px; font-weight: 700; }}
.card .value.green {{ color: #34c759; }}
.card .value.orange {{ color: #ff9500; }}
.card .value.red {{ color: #ff3b30; }}
.card .label {{ font-size: 14px; font-weight: 600; margin-top: 4px; }}
.card .desc {{ font-size: 12px; color: #86868b; margin-top: 4px; line-height: 1.4; }}

.section {{ background: #fff; border-radius: 16px; padding: 28px 32px; margin-bottom: 24px; box-shadow: 0 1px 4px rgba(0,0,0,0.05); }}
.section-title {{ font-size: 20px; font-weight: 700; margin-bottom: 8px; }}
.section-desc {{ font-size: 13px; color: #86868b; margin-bottom: 20px; }}

.tabs {{ display: flex; gap: 4px; margin-bottom: 20px; border-bottom: 1px solid #e5e5e5; padding-bottom: 0; }}
.tab {{ padding: 10px 20px; cursor: pointer; font-size: 14px; font-weight: 500; color: #86868b; border-bottom: 2px solid transparent; transition: all 0.2s; }}
.tab:hover {{ color: #1d1d1f; }}
.tab.active {{ color: #007aff; border-bottom-color: #007aff; }}
.tab-content {{ display: none; }}
.tab-content.active {{ display: block; }}

.two-col {{ display: grid; grid-template-columns: 3fr 2fr; gap: 24px; margin-bottom: 24px; }}
@media (max-width: 900px) {{ .two-col {{ grid-template-columns: 1fr; }} }}

.graph-box {{ position: relative; }}
canvas {{ width: 100%; height: 520px; border-radius: 12px; }}
#graphCanvas {{ background: #f5f5f7; }}
.controls {{ position: absolute; top: 12px; right: 12px; display: flex; gap: 6px; }}
.controls button {{ background: #fff; border: 1px solid #d2d2d7; padding: 8px 16px; border-radius: 10px; cursor: pointer; font-size: 13px; font-weight: 500; }}
.controls button:hover {{ background: #f0f0f0; }}

.warning {{ padding: 14px 18px; border-radius: 12px; margin-bottom: 8px; }}
.warning.high {{ background: #fff5f5; border: 1px solid #fed7d7; }}
.warning.medium {{ background: #fffff0; border: 1px solid #fefcbf; }}
.warning.info {{ background: #f0f9ff; border: 1px solid #bee3f8; }}
.warning-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }}
.warning .tag {{ font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 6px; }}
.warning.high .tag {{ background: #fed7d7; color: #c53030; }}
.warning.medium .tag {{ background: #fefcbf; color: #975a16; }}
.warning.info .tag {{ background: #bee3f8; color: #2b6cb0; }}
.warning .target {{ font-weight: 600; font-size: 14px; }}
.warning .msg {{ font-size: 14px; margin-top: 2px; }}
.warning .fix {{ font-size: 13px; color: #718096; margin-top: 8px; padding-top: 8px; border-top: 1px solid rgba(0,0,0,0.05); }}
.warning .fix::before {{ content: "直し方: "; font-weight: 600; }}
.warning .loc {{ font-size: 12px; color: #a0aec0; }}

table {{ width: 100%; border-collapse: collapse; }}
th {{ text-align: left; font-size: 12px; color: #86868b; font-weight: 600; padding: 10px 14px; border-bottom: 2px solid #e5e5e5; }}
td {{ padding: 12px 14px; border-bottom: 1px solid #f0f0f0; font-size: 14px; }}
tr:hover td {{ background: #f9f9fb; }}

.score-pill {{ display: inline-block; padding: 3px 10px; border-radius: 8px; font-weight: 700; font-size: 13px; min-width: 42px; text-align: center; }}
.score-pill.s-good {{ background: #e8f8ef; color: #1b7a3d; }}
.score-pill.s-ok {{ background: #fef3cd; color: #856404; }}
.score-pill.s-bad {{ background: #fde8e8; color: #c0392b; }}

.impact-bar {{ display: inline-block; height: 8px; border-radius: 4px; background: #007aff; opacity: 0.6; vertical-align: middle; margin-left: 8px; }}

.module-row {{ display: flex; align-items: center; gap: 12px; padding: 10px 0; border-bottom: 1px solid #f5f5f5; }}
.module-row .name {{ font-weight: 600; min-width: 180px; }}
.module-row .bar {{ height: 8px; border-radius: 4px; background: linear-gradient(90deg, #007aff, #5ac8fa); opacity: 0.7; }}
.module-row .info {{ color: #86868b; font-size: 13px; white-space: nowrap; }}

.dup-card {{ padding: 14px 18px; border-radius: 12px; background: #faf5ff; border: 1px solid #e9d8fd; margin-bottom: 8px; }}
.dup-card .funcs {{ font-weight: 600; }}
.dup-card .detail {{ font-size: 13px; color: #6b46c1; margin-top: 4px; }}

.legend {{ display: flex; gap: 16px; flex-wrap: wrap; margin-top: 12px; font-size: 12px; color: #86868b; }}
.legend-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; vertical-align: middle; margin-right: 4px; }}
</style>
</head>
<body>

<div class="header">
  <h1>Code Quality Graph <span class="health-badge {health}">{health_label}</span></h1>
  <p class="subtitle">{n_files}ファイル / {n_functions}関数 / {n_lines}行 / {n_edges}本の呼び出し関係</p>
</div>

<div class="container">

  <div class="cards">
    <div class="card">
      <div class="value {'green' if avg_score >= 80 else 'orange' if avg_score >= 60 else 'red'}">{avg_score}</div>
      <div class="label">品質スコア</div>
      <div class="desc">100点満点。80以上で健康</div>
    </div>
    <div class="card">
      <div class="value {'red' if n_high > 5 else 'orange' if n_high > 0 else 'green'}">{n_high}</div>
      <div class="label">重要な問題</div>
      <div class="desc">すぐ直した方がいい</div>
    </div>
    <div class="card">
      <div class="value {'red' if n_cycles > 0 else 'green'}">{n_cycles}</div>
      <div class="label">循環依存</div>
      <div class="desc">ファイルが互いに依存。0が理想</div>
    </div>
    <div class="card">
      <div class="value {'red' if debt_hours > 8 else 'orange' if debt_hours > 2 else 'green'}">{debt_hours:.1f}h</div>
      <div class="label">技術的負債</div>
      <div class="desc">全部直すのにかかる推定時間</div>
    </div>
  </div>

  <div class="cards" style="margin-top:-16px">
    <div class="card">
      <div class="value {'red' if sec_count > 3 else 'orange' if sec_count > 0 else 'green'}">{sec_count}</div>
      <div class="label">セキュリティ問題</div>
      <div class="desc">危険なパターンの検出数</div>
    </div>
    <div class="card">
      <div class="value {'orange' if len(metrics.get('isolated',[])) > 3 else 'green'}">{len(metrics.get('isolated',[]))}</div>
      <div class="label">孤立した関数</div>
      <div class="desc">どこからも使われていない</div>
    </div>
    <div class="card">
      <div class="value">{len(hotspots or [])}</div>
      <div class="label">ホットスポット</div>
      <div class="desc">変更頻度×複雑度が高い危険箇所</div>
    </div>
    <div class="card">
      <div class="value {'red' if n_cycles > 0 else 'green'}">{n_cycles}</div>
      <div class="label">循環依存</div>
      <div class="desc">ファイルが互いに依存。0が理想</div>
    </div>
  </div>

  <!-- タブ切り替え -->
  <div class="section">
    <div class="tabs">
      <div class="tab active" onclick="switchTab('actions')">次にやること</div>
      <div class="tab" onclick="switchTab('problems')">問題点</div>
      <div class="tab" onclick="switchTab('graph')">2Dマップ</div>
      <div class="tab" onclick="switchTab('graph3d')">3Dマップ</div>
      <div class="tab" onclick="switchTab('impact')">変更影響</div>
      <div class="tab" onclick="switchTab('duplicates')">重複コード</div>
      <div class="tab" onclick="switchTab('files')">ファイル</div>
      <div class="tab" onclick="switchTab('hotspots')">ホットスポット</div>
      <div class="tab" onclick="switchTab('functions')">全関数</div>
    </div>

    <!-- 次にやることタブ -->
    <div id="tab-actions" class="tab-content active">
      <div class="section-desc">スコアが低い関数から順に、具体的な改善手順を表示。上から1つずつやっていこう</div>
      {action_guide_html}
    </div>

    <!-- 問題点タブ -->
    <div id="tab-problems" class="tab-content">
      <div class="section-desc">上から順に重要。「直し方」も参考にしてください</div>
      {warnings_html}
    </div>

    <!-- 呼び出しマップタブ -->
    <div id="tab-graph" class="tab-content">
      <div class="section-desc">丸 = 関数、線 = 呼び出し関係。大きい丸ほど多くの場所から使われている。色はファイルごとのグループ</div>
      <div class="graph-box">
        <div class="controls">
          <button onclick="resetView()">リセット</button>
          <button onclick="toggleLabels()">名前 ON/OFF</button>
        </div>
        <canvas id="graphCanvas"></canvas>
      </div>
      <div class="legend">
        <span><span class="legend-dot" style="background:#ff3b30"></span>孤立（使われてない）</span>
        <span><span class="legend-dot" style="background:#007aff"></span>通常</span>
        <span>丸が大きい = よく使われる関数</span>
      </div>
    </div>

    <!-- 3Dマップタブ -->
    <div id="tab-graph3d" class="tab-content">
      <div class="section-desc">マウスでドラッグして回転、スクロールでズーム。ノードの大きさ = 重要度、色 = モジュール</div>
      <div id="graph3d-container" style="width:100%;height:600px;border-radius:12px;background:#0a0a1a;position:relative"></div>
    </div>

    <!-- 変更影響タブ -->
    <div id="tab-impact" class="tab-content">
      <div class="section-desc">この関数/ファイルを変更したら、どこまで影響するか。バーが長いほど影響が大きい</div>
      {impact_html}
    </div>

    <!-- 重複コードタブ -->
    <div id="tab-duplicates" class="tab-content">
      <div class="section-desc">ほぼ同じコードが複数箇所にある。共通化すればコード量が減ってメンテが楽になる</div>
      {duplicates_html if duplicates_html else '<p style="color:#86868b">重複コードは見つかりませんでした</p>'}
    </div>

    <!-- ファイルタブ -->
    <div id="tab-files" class="tab-content">
      <div class="section-desc">バーの長さ = コード量。長すぎるファイルは分割を検討</div>
      {modules_html}
    </div>

    <!-- ホットスポットタブ -->
    <div id="tab-hotspots" class="tab-content">
      <div class="section-desc">よく変更されるファイル × 複雑なコード = バグが生まれやすい場所。Git履歴から自動検出</div>
      {hotspots_html}
    </div>

    <!-- 全関数タブ -->
    <div id="tab-functions" class="tab-content">
      <div class="section-desc">スコアが低い順。赤い関数ほど改善が必要</div>
      {functions_html}
    </div>
  </div>

</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
<script>
const nodes = {json.dumps(nodes)};
const edges = {json.dumps(edges)};
let showLabels = true;

// タブ切り替え
function switchTab(name) {{
  document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(el => el.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  event.target.classList.add('active');
  if (name === 'graph') {{
    setTimeout(() => {{
      initCanvas();
      frame = 0;
      animate();
    }}, 100);
  }}
  if (name === 'graph3d') {{ init3D(); }}
}}

// グラフ描画
const canvas = document.getElementById('graphCanvas');
const ctx = canvas.getContext('2d');
let W = 900, H = 520;

const COLORS = ['#007aff','#34c759','#ff9500','#af52de','#5ac8fa','#ffcc00','#ff2d55','#64d2ff','#30d158','#ff6b6b'];
const moduleColors = {{}};
let colorIdx = 0;
nodes.forEach(n => {{
  if (!(n.module in moduleColors)) {{ moduleColors[n.module] = COLORS[colorIdx++ % COLORS.length]; }}
}});

const positions = {{}};
let canvasInited = false;

function initCanvas() {{
  const c = document.getElementById('graphCanvas');
  if (!c) return;
  W = c.parentElement.clientWidth || 900;
  H = 520;
  const dpr = window.devicePixelRatio || 1;
  c.width = W * dpr;
  c.height = H * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

  // ノード位置を再初期化
  nodes.forEach((n, i) => {{
    const angle = (i / nodes.length) * Math.PI * 2;
    const r = Math.min(W, H) * 0.3 + Math.random() * 50;
    positions[n.id] = {{ x: W/2 + Math.cos(angle)*r, y: H/2 + Math.sin(angle)*r, vx: 0, vy: 0 }};
  }});
  canvasInited = true;
}}

function simulate() {{
  if (!canvasInited) return;
  const repulsion = Math.max(2000, W * 3);
  nodes.forEach(a => {{
    nodes.forEach(b => {{
      if (a.id === b.id) return;
      const pa = positions[a.id], pb = positions[b.id];
      if (!pa || !pb) return;
      const dx = pa.x-pb.x, dy = pa.y-pb.y;
      const dist = Math.max(Math.sqrt(dx*dx+dy*dy), 1);
      const f = repulsion / (dist*dist);
      pa.vx += (dx/dist)*f; pa.vy += (dy/dist)*f;
    }});
  }});
  edges.forEach(e => {{
    const pa = positions[e.source], pb = positions[e.target];
    if (!pa || !pb) return;
    const dx = pb.x-pa.x, dy = pb.y-pa.y;
    const dist = Math.max(Math.sqrt(dx*dx+dy*dy), 1);
    const f = dist * 0.003;
    pa.vx += (dx/dist)*f; pa.vy += (dy/dist)*f;
    pb.vx -= (dx/dist)*f; pb.vy -= (dy/dist)*f;
  }});
  nodes.forEach(n => {{
    const p = positions[n.id];
    if (!p) return;
    p.vx += (W/2-p.x)*0.001; p.vy += (H/2-p.y)*0.001;
    p.vx *= 0.88; p.vy *= 0.88;
    p.x += p.vx; p.y += p.vy;
    p.x = Math.max(30, Math.min(W-30, p.x));
    p.y = Math.max(30, Math.min(H-30, p.y));
  }});
}}

function draw() {{
  if (!canvasInited) return;
  ctx.fillStyle = '#f5f5f7';
  ctx.fillRect(0, 0, W, H);
  edges.forEach(e => {{
    const pa = positions[e.source], pb = positions[e.target];
    if (!pa || !pb) return;
    ctx.strokeStyle = 'rgba(0,0,0,0.06)';
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pa.x, pa.y); ctx.lineTo(pb.x, pb.y); ctx.stroke();
  }});
  nodes.forEach(n => {{
    const p = positions[n.id];
    const r = Math.max(3, 3 + n.in_degree * 2 + n.pagerank * 200);
    ctx.shadowColor = 'rgba(0,0,0,0.08)'; ctx.shadowBlur = 4;
    ctx.beginPath(); ctx.arc(p.x, p.y, r, 0, Math.PI*2);
    ctx.fillStyle = n.is_isolated ? '#ff3b30' : moduleColors[n.module] || '#007aff';
    ctx.globalAlpha = n.score < 50 ? 0.95 : 0.65;
    ctx.fill(); ctx.shadowBlur = 0; ctx.globalAlpha = 1;
    if (showLabels && r > 5) {{
      ctx.fillStyle = '#1d1d1f'; ctx.font = '500 11px -apple-system, sans-serif';
      ctx.fillText(n.label, p.x+r+4, p.y+4);
    }}
  }});
}}

let frame = 0;
function animate() {{ if (frame < 250) simulate(); draw(); frame++; requestAnimationFrame(animate); }}
function resetView() {{ initCanvas(); frame = 0; }}
function toggleLabels() {{ showLabels = !showLabels; }}

// 2D クリック → ノード情報ポップアップ
canvas.addEventListener('click', (e) => {{
  if (!canvasInited) return;
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const mx = (e.clientX - rect.left);
  const my = (e.clientY - rect.top);
  let hit = null;
  nodes.forEach(n => {{
    const p = positions[n.id];
    if (!p) return;
    const r = Math.max(3, 3 + n.in_degree * 2 + n.pagerank * 200);
    const dx = mx - p.x, dy = my - p.y;
    if (dx*dx + dy*dy < (r+5)*(r+5)) hit = n;
  }});
  if (hit) {{
    showNodePopup(hit, e.clientX, e.clientY);
  }} else {{
    hideNodePopup();
  }}
}});

// ポップアップ
let popup = null;
function showNodePopup(n, x, y) {{
  hideNodePopup();
  popup = document.createElement('div');
  const sc = n.score >= 80 ? '#34c759' : n.score >= 60 ? '#ff9500' : '#ff3b30';
  popup.innerHTML = `
    <div style="font-weight:700;font-size:16px;margin-bottom:8px">${{n.label}}</div>
    <div style="display:grid;grid-template-columns:auto auto;gap:4px 16px;font-size:13px">
      <span style="color:#86868b">ファイル</span><span>${{n.file}}:${{n.line}}</span>
      <span style="color:#86868b">スコア</span><span style="color:${{sc}};font-weight:700">${{n.score}}点</span>
      <span style="color:#86868b">行数</span><span>${{n.lines}}行</span>
      <span style="color:#86868b">複雑さ</span><span>${{n.complexity}}</span>
      <span style="color:#86868b">認知的</span><span>${{n.cognitive}}</span>
      <span style="color:#86868b">影響範囲</span><span>${{n.impact}}関数</span>
      <span style="color:#86868b">被呼出</span><span>${{n.in_degree}}箇所</span>
      <span style="color:#86868b">負債</span><span>${{n.debt_min}}分</span>
    </div>
    <div style="margin-top:10px;padding-top:8px;border-top:1px solid #e5e5e5">
      <a href="vscode://file/${{encodeURIComponent(n.file)}}:${{n.line}}"
         style="color:#007aff;text-decoration:none;font-size:13px;font-weight:500">
         VS Codeで開く
      </a>
    </div>
  `;
  popup.style.cssText = `position:fixed;left:${{x+12}}px;top:${{y-10}}px;
    background:#fff;border-radius:12px;padding:16px 20px;
    box-shadow:0 8px 30px rgba(0,0,0,0.15);z-index:1000;
    max-width:320px;border:1px solid #e5e5e5`;
  document.body.appendChild(popup);
}}
function hideNodePopup() {{
  if (popup) {{ popup.remove(); popup = null; }}
}}
document.addEventListener('keydown', (e) => {{ if (e.key === 'Escape') hideNodePopup(); }});

// ========== 3Dグラフ ==========
let scene3d, camera3d, renderer3d, controls3d, graph3dInited = false;
const pos3d = {{}};
const COLORS3D = [0x007aff, 0x34c759, 0xff9500, 0xaf52de, 0x5ac8fa,
                   0xffcc00, 0xff2d55, 0x64d2ff, 0x30d158, 0xff6b6b];
const modColor3d = {{}};
let ci3d = 0;
nodes.forEach(n => {{ if (!(n.module in modColor3d)) modColor3d[n.module] = COLORS3D[ci3d++ % COLORS3D.length]; }});

function init3D() {{
  if (graph3dInited) return;
  graph3dInited = true;
  const container = document.getElementById('graph3d-container');
  const w = container.clientWidth, h = 600;

  scene3d = new THREE.Scene();
  scene3d.background = new THREE.Color(0x0a0a1a);
  scene3d.fog = new THREE.Fog(0x0a0a1a, 300, 800);

  camera3d = new THREE.PerspectiveCamera(60, w/h, 1, 2000);
  camera3d.position.set(0, 0, 250);

  renderer3d = new THREE.WebGLRenderer({{ antialias: true }});
  renderer3d.setSize(w, h);
  renderer3d.setPixelRatio(window.devicePixelRatio);
  container.appendChild(renderer3d.domElement);

  controls3d = new THREE.OrbitControls(camera3d, renderer3d.domElement);
  controls3d.enableDamping = true;
  controls3d.dampingFactor = 0.05;

  // ライト
  const ambient = new THREE.AmbientLight(0x404060, 0.6);
  scene3d.add(ambient);
  const point = new THREE.PointLight(0xffffff, 1.2, 500);
  point.position.set(100, 100, 100);
  scene3d.add(point);

  // ノード配置（球面状に初期配置）
  nodes.forEach((n, i) => {{
    const phi = Math.acos(-1 + (2*i) / nodes.length);
    const theta = Math.sqrt(nodes.length * Math.PI) * phi;
    const r = 80 + Math.random() * 40;
    pos3d[n.id] = {{
      x: r * Math.cos(theta) * Math.sin(phi),
      y: r * Math.sin(theta) * Math.sin(phi),
      z: r * Math.cos(phi),
      vx: 0, vy: 0, vz: 0
    }};

    const size = Math.max(1.5, 1.5 + n.in_degree * 0.8 + n.pagerank * 80);
    const geo = new THREE.SphereGeometry(size, 16, 16);
    const color = n.is_isolated ? 0xff3b30 : modColor3d[n.module] || 0x007aff;
    const mat = new THREE.MeshPhongMaterial({{
      color: color,
      emissive: color,
      emissiveIntensity: n.score < 50 ? 0.5 : 0.15,
      shininess: 80,
      transparent: true,
      opacity: n.score < 50 ? 1.0 : 0.75,
    }});
    const mesh = new THREE.Mesh(geo, mat);
    mesh.position.set(pos3d[n.id].x, pos3d[n.id].y, pos3d[n.id].z);
    mesh.userData = n;
    scene3d.add(mesh);

    // テキストラベル（スプライト）
    if (size > 2) {{
      const canvas2 = document.createElement('canvas');
      const ctx2 = canvas2.getContext('2d');
      canvas2.width = 256;
      canvas2.height = 64;
      ctx2.fillStyle = 'rgba(0,0,0,0)';
      ctx2.fillRect(0, 0, 256, 64);
      ctx2.font = '24px -apple-system, sans-serif';
      ctx2.fillStyle = '#ffffff';
      ctx2.textAlign = 'center';
      ctx2.fillText(n.label, 128, 40);
      const tex = new THREE.CanvasTexture(canvas2);
      const spriteMat = new THREE.SpriteMaterial({{ map: tex, transparent: true, opacity: 0.85 }});
      const sprite = new THREE.Sprite(spriteMat);
      sprite.position.set(pos3d[n.id].x, pos3d[n.id].y + size + 3, pos3d[n.id].z);
      sprite.scale.set(size * 4, size * 1, 1);
      scene3d.add(sprite);
    }}
  }});

  // エッジ
  const edgeMat = new THREE.LineBasicMaterial({{ color: 0x334455, transparent: true, opacity: 0.25 }});
  edges.forEach(e => {{
    const pa = pos3d[e.source], pb = pos3d[e.target];
    if (!pa || !pb) return;
    const geo = new THREE.BufferGeometry().setFromPoints([
      new THREE.Vector3(pa.x, pa.y, pa.z),
      new THREE.Vector3(pb.x, pb.y, pb.z),
    ]);
    const line = new THREE.Line(geo, edgeMat);
    scene3d.add(line);
  }});

  // パーティクル背景
  const starGeo = new THREE.BufferGeometry();
  const starVerts = [];
  for (let i = 0; i < 500; i++) {{
    starVerts.push((Math.random()-0.5)*600, (Math.random()-0.5)*600, (Math.random()-0.5)*600);
  }}
  starGeo.setAttribute('position', new THREE.Float32BufferAttribute(starVerts, 3));
  const starMat = new THREE.PointsMaterial({{ color: 0x334466, size: 0.5 }});
  scene3d.add(new THREE.Points(starGeo, starMat));

  setup3DInteraction();
  animate3D();
}}

function animate3D() {{
  requestAnimationFrame(animate3D);
  controls3d.update();
  scene3d.rotation.y += 0.001;
  renderer3d.render(scene3d, camera3d);
}}

function setup3DInteraction() {{
  const raycaster = new THREE.Raycaster();
  const mouse = new THREE.Vector2();
  let hovered = null;
  const tip = document.createElement('div');
  tip.style.cssText = `position:fixed;display:none;background:rgba(10,10,26,0.92);
    color:#fff;padding:12px 16px;border-radius:10px;font-size:13px;z-index:1000;
    pointer-events:none;box-shadow:0 4px 20px rgba(0,0,0,0.4);
    font-family:-apple-system,sans-serif;max-width:280px;backdrop-filter:blur(8px)`;
  document.body.appendChild(tip);

  renderer3d.domElement.addEventListener('mousemove', (e) => {{
    const rect = renderer3d.domElement.getBoundingClientRect();
    mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
    mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

    raycaster.setFromCamera(mouse, camera3d);
    const meshes = scene3d.children.filter(c => c.isMesh);
    const intersects = raycaster.intersectObjects(meshes);

    if (intersects.length > 0 && intersects[0].object.userData && intersects[0].object.userData.label) {{
      const n = intersects[0].object.userData;
      hovered = n;
      const sc = n.score >= 80 ? '#34c759' : n.score >= 60 ? '#ff9500' : '#ff3b30';
      tip.innerHTML = `
        <div style="font-weight:700;font-size:15px;margin-bottom:6px">${{n.label}}</div>
        <div style="color:#a0aec0;font-size:12px;margin-bottom:6px">${{n.file}}:${{n.line}}</div>
        <div style="display:grid;grid-template-columns:auto auto;gap:2px 12px;font-size:12px">
          <span style="color:#a0aec0">スコア</span><span style="color:${{sc}};font-weight:700">${{n.score}}点</span>
          <span style="color:#a0aec0">行数</span><span>${{n.lines}}</span>
          <span style="color:#a0aec0">複雑さ</span><span>${{n.complexity}}</span>
          <span style="color:#a0aec0">認知的</span><span>${{n.cognitive}}</span>
          <span style="color:#a0aec0">影響</span><span>${{n.impact}}関数</span>
        </div>
      `;
      tip.style.display = 'block';
      tip.style.left = (e.clientX + 14) + 'px';
      tip.style.top = (e.clientY - 10) + 'px';
      renderer3d.domElement.style.cursor = 'pointer';
    }} else {{
      hovered = null;
      tip.style.display = 'none';
      renderer3d.domElement.style.cursor = 'grab';
    }}
  }});

  renderer3d.domElement.addEventListener('click', (e) => {{
    if (hovered) showNodePopup(hovered, e.clientX, e.clientY);
  }});
}}
</script>
</body>
</html>"""


def _build_warnings_html(warnings: list[dict]) -> str:
    order = {"high": 0, "medium": 1, "info": 2}
    sorted_w = sorted(warnings, key=lambda x: order.get(x["severity"], 3))
    parts = []
    for w in sorted_w:
        loc = f'<div class="loc">{w["file"]}:{w["line"]}</div>' if w["file"] and w["line"] else ""
        parts.append(
            f'<div class="warning {w["severity"]}">'
            f'<div class="warning-header"><span class="tag">{w["severity"].upper()}</span>'
            f'<span class="target">{w["target"]}</span></div>'
            f'<div class="msg">{w["message"]}</div>'
            f'{loc}'
            f'<div class="fix">{w["fix"]}</div>'
            f'</div>'
        )
    return "\n".join(parts) if parts else '<p style="color:#86868b">問題は見つかりませんでした</p>'


def _build_modules_html(modules: list[dict]) -> str:
    sorted_m = sorted(modules, key=lambda x: -x["lines"])
    max_lines = max((m["lines"] for m in sorted_m), default=1)
    parts = []
    for m in sorted_m:
        bar_w = max(4, int(m["lines"] / max_lines * 300))
        sc = "s-good" if m["score"] >= 80 else "s-ok" if m["score"] >= 60 else "s-bad"
        name = m["name"].split(".")[-1] + ".py"
        parts.append(
            f'<div class="module-row">'
            f'<span class="score-pill {sc}">{m["score"]}</span>'
            f'<span class="name">{name}</span>'
            f'<div class="bar" style="width: {bar_w}px"></div>'
            f'<span class="info">{m["lines"]}行 / {m["n_functions"]}関数 / 影響{m["impact"]}ファイル</span>'
            f'</div>'
        )
    return "\n".join(parts)


def _build_functions_html(nodes: list[dict]) -> str:
    sorted_n = sorted(nodes, key=lambda x: x["score"])
    rows = []
    for n in sorted_n:
        sc = "s-good" if n["score"] >= 80 else "s-ok" if n["score"] >= 60 else "s-bad"
        tags = ""
        if n["is_isolated"]:
            tags += '<span style="background:#fde8e8;color:#c0392b;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600">未使用？</span>'
        if n.get("security", 0) > 0:
            tags += '<span style="background:#fde8e8;color:#c0392b;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600;margin-left:4px">脆弱性</span>'
        if n["in_degree"] >= 5:
            tags += '<span style="background:#fef0e6;color:#c2410c;padding:2px 6px;border-radius:4px;font-size:11px;font-weight:600;margin-left:4px">重要</span>'
        debt = f'{n.get("debt_min", 0)}分' if n.get("debt_min", 0) > 0 else "-"
        rows.append(
            f'<tr>'
            f'<td><span class="score-pill {sc}">{n["score"]}</span></td>'
            f'<td><strong>{n["label"]}</strong></td>'
            f'<td style="color:#86868b">{n["file"]}:{n["line"]}</td>'
            f'<td>{n["lines"]}</td>'
            f'<td>{n["complexity"]}</td>'
            f'<td>{n.get("cognitive", 0)}</td>'
            f'<td>{debt}</td>'
            f'<td>{tags}</td>'
            f'</tr>'
        )
    header = '<table><tr><th>スコア</th><th>関数名</th><th>場所</th><th>行数</th><th>複雑さ</th><th>認知的</th><th>負債</th><th>タグ</th></tr>'
    return header + "\n".join(rows) + "</table>"


def _build_duplicates_html(duplicates: list[dict]) -> str:
    if not duplicates:
        return ""
    parts = []
    for dup in duplicates:
        names = ", ".join(dup["names"])
        files = ", ".join(dup["files"])
        parts.append(
            f'<div class="dup-card">'
            f'<div class="funcs">{names}</div>'
            f'<div class="detail">{dup["lines"]}行のほぼ同じコード / {files}</div>'
            f'</div>'
        )
    return "\n".join(parts)


def _build_hotspots_html(hotspots: list[dict]) -> str:
    if not hotspots:
        return '<p style="color:#86868b">Git履歴がないか、ホットスポットは見つかりませんでした</p>'
    max_score = max(h["hotspot_score"] for h in hotspots) if hotspots else 1
    rows = []
    for h in hotspots[:15]:
        bar_w = max(4, int(h["hotspot_score"] / max_score * 300))
        risk_color = "#ff3b30" if h["hotspot_score"] > max_score * 0.7 else "#ff9500" if h["hotspot_score"] > max_score * 0.3 else "#34c759"
        name = h["file"].split("\\")[-1].split("/")[-1]
        rows.append(
            f'<div style="display:flex;align-items:center;gap:12px;padding:10px 0;border-bottom:1px solid #f5f5f5">'
            f'<span style="min-width:180px;font-weight:600">{name}</span>'
            f'<div style="height:8px;border-radius:4px;background:{risk_color};opacity:0.7;width:{bar_w}px"></div>'
            f'<span style="color:#86868b;font-size:13px">'
            f'{h["commits"]}回変更 / 複雑度{h["max_complexity"]} / 認知{h["max_cognitive"]}'
            f'</span>'
            f'<span style="color:#a0aec0;font-size:12px">{h.get("last_modified", "")}</span>'
            f'</div>'
        )
    return "\n".join(rows)


def _build_impact_html(nodes: list[dict]) -> str:
    sorted_n = sorted(nodes, key=lambda x: -x["impact"])
    top = [n for n in sorted_n if n["impact"] > 0][:20]
    if not top:
        return '<p style="color:#86868b">影響範囲の大きい関数はありません</p>'
    max_impact = max(n["impact"] for n in top) if top else 1
    rows = []
    for n in top:
        bar_w = max(4, int(n["impact"] / max_impact * 300))
        risk_color = "#ff3b30" if n["impact"] >= 5 else "#ff9500" if n["impact"] >= 2 else "#34c759"
        rows.append(
            f'<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:1px solid #f5f5f5">'
            f'<span style="min-width:180px;font-weight:600">{n["label"]}</span>'
            f'<div style="height:8px;border-radius:4px;background:{risk_color};opacity:0.7;width:{bar_w}px"></div>'
            f'<span style="color:#86868b;font-size:13px">変更すると{n["impact"]}個の関数に影響</span>'
            f'</div>'
        )
    return "\n".join(rows)


# ========== メイン ==========

def main():
    target = sys.argv[1] if len(sys.argv) > 1 else "."

    print("=" * 60)
    print("  Code Quality Graph v3")
    print(f"  対象: {target}")
    print("=" * 60)

    analyzer = CodeAnalyzer(target)
    analyzer.analyze()

    print(f"\n  ファイル:    {len(analyzer.modules)}")
    print(f"  関数:        {len(analyzer.functions)}")
    print(f"  総行数:      {sum(m.n_lines for m in analyzer.modules.values())}")

    # Layer 1: コールグラフ
    print("\n  Layer 1: コールグラフ...")
    call_nodes, call_edges = build_call_graph(analyzer)
    call_metrics = calc_graph_metrics(call_nodes, call_edges)
    print(f"    エッジ: {len(call_edges)}本 | 密度: {call_metrics['density']}")

    # Layer 2: Import依存
    print("  Layer 2: Import依存...")
    mod_nodes, import_edges, import_cycles = build_import_graph(analyzer)
    print(f"    依存: {len(import_edges)}本 | 循環: {len(import_cycles)}件")

    # Layer 3: 変更影響
    print("  Layer 3: 変更影響...")
    impact = calc_impact_scores(call_nodes, call_edges, mod_nodes, import_edges, analyzer)

    # Layer 4: 重複コード
    print("  Layer 4: 重複コード...")
    duplicates = find_duplicates(analyzer)
    print(f"    重複グループ: {len(duplicates)}件")

    # Layer 5: 認知的複雑度
    print("  Layer 5: 認知的複雑度...")
    cog_values = [f.cognitive_complexity for f in analyzer.functions.values()]
    if cog_values:
        print(f"    平均: {np.mean(cog_values):.1f} | 最大: {max(cog_values)}")

    # Layer 6: 技術的負債
    print("  Layer 6: 技術的負債...")
    total_debt = sum(f.tech_debt_minutes for f in analyzer.functions.values())
    debt_hours = total_debt / 60
    print(f"    合計: {total_debt}分 ({debt_hours:.1f}時間)")

    # Layer 7: セキュリティ
    print("  Layer 7: セキュリティ...")
    sec_count = sum(len(f.security_issues) for f in analyzer.functions.values())
    print(f"    検出: {sec_count}件")

    # Layer 8: Git履歴
    print("  Layer 8: Git履歴...")
    git_data = analyze_git_history(Path(target).resolve())
    hotspots = calc_hotspots(analyzer, git_data)
    print(f"    Git対象ファイル: {len(git_data)} | ホットスポット: {len(hotspots)}件")

    # Layer 9: 総合スコア
    print("  Layer 9: 総合スコア...")
    func_scores, mod_scores, warnings = calc_quality_scores(
        analyzer, call_edges, import_cycles, impact, duplicates,
    )

    all_scores = list(func_scores.values())
    print(f"    平均スコア: {np.mean(all_scores):.1f}" if all_scores else "    関数なし")
    print(f"    警告: {sum(1 for w in warnings if w['severity']=='high')}件(高) / "
          f"{sum(1 for w in warnings if w['severity']=='medium')}件(中)")

    # HTML生成
    output = Path(target) / "code_quality_report.html"
    if not output.parent.exists():
        output = Path("code_quality_report.html")

    generate_report(
        analyzer, call_nodes, call_edges, mod_nodes, import_edges,
        import_cycles, impact, duplicates, func_scores, mod_scores,
        warnings, call_metrics, output,
        hotspots=hotspots, total_debt=total_debt, sec_count=sec_count,
    )
    print(f"\n  レポート: {output}")
    print("  ブラウザで開いてください")


if __name__ == "__main__":
    main()
