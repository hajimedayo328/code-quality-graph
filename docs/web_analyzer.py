"""ブラウザ（Pyodide）から呼ばれる薄いラッパー.

ユーザー入力のPythonコード文字列を受け取り、
analyzer.py の各レイヤーを走らせて JSON 互換の dict を返す。

Git 履歴連携（Layer 8）はブラウザでは動かないため無効化。
"""

from __future__ import annotations

import os
import json
from pathlib import Path
from collections import defaultdict

from analyzer import (
    CodeAnalyzer,
    build_call_graph,
    build_import_graph,
    calc_impact_scores,
    find_duplicates,
    calc_quality_scores,
    calc_graph_metrics,
)


WORK_DIR = "/tmp/cqg_user"


def _reset_workdir() -> None:
    os.makedirs(WORK_DIR, exist_ok=True)
    # 既存の .py を掃除（前回解析の残骸を消す）
    for f in Path(WORK_DIR).rglob("*.py"):
        try:
            f.unlink()
        except OSError:
            pass


def analyze_single_file(code: str, filename: str = "user_code.py") -> dict:
    """単一のコード文字列を解析してJSON互換dictを返す."""
    _reset_workdir()
    target = Path(WORK_DIR) / filename
    target.write_text(code, encoding="utf-8")
    return _run_analysis(WORK_DIR)


def analyze_multiple_files(files: dict[str, str]) -> dict:
    """複数ファイルを解析する.

    files: {ファイル名: コード文字列} の辞書
    """
    _reset_workdir()
    for filename, code in files.items():
        # パス検証: ディレクトリトラバーサル防止
        safe_name = Path(filename).name  # パス区切りを除去
        if not safe_name.endswith(".py"):
            safe_name = safe_name + ".py"
        target = Path(WORK_DIR) / safe_name
        target.write_text(code, encoding="utf-8")
    return _run_analysis(WORK_DIR)


def _run_analysis(workdir: str) -> dict:
    analyzer = CodeAnalyzer(workdir)
    analyzer.analyze()

    # Layer 1: コールグラフ
    call_nodes, call_edges = build_call_graph(analyzer)
    call_metrics = calc_graph_metrics(call_nodes, call_edges)

    # Layer 2: Import依存
    mod_nodes, import_edges, import_cycles = build_import_graph(analyzer)

    # Layer 3: 変更影響
    impact = calc_impact_scores(call_nodes, call_edges, mod_nodes, import_edges, analyzer)

    # Layer 4: 重複コード
    duplicates = find_duplicates(analyzer)

    # Layer 6: 技術的負債
    total_debt = sum(f.tech_debt_minutes for f in analyzer.functions.values())

    # Layer 7: セキュリティ
    sec_count = sum(len(f.security_issues) for f in analyzer.functions.values())

    # Layer 9: 総合スコア
    func_scores, mod_scores, warnings = calc_quality_scores(
        analyzer, call_edges, import_cycles, impact, duplicates,
    )

    # ====== JSON化 ======
    # ===== 構造的異常スコア（グラフ理論×統計） =====
    # 各関数の複数メトリクスを z-score 合算 → 「外れ値=構造的に怪しい」の0-100スコア
    nodes_for_anomaly = []
    for qname, func in analyzer.functions.items():
        pr = call_metrics.get("pagerank", {}).get(qname, 0)
        bc = call_metrics.get("betweenness", {}).get(qname, 0)
        in_deg = call_metrics.get("in_degree", {}).get(qname, 0)
        out_deg = call_metrics.get("out_degree", {}).get(qname, 0)
        nodes_for_anomaly.append({
            "id": qname,
            "complexity": func.complexity,
            "cognitive": func.cognitive_complexity,
            "lines": func.n_lines,
            "n_args": func.n_args,
            "pagerank": pr,
            "betweenness": bc,
            "in_degree": in_deg,
            "out_degree": out_deg,
        })
    anomaly_scores = _calc_anomaly_scores(nodes_for_anomaly)
    # ===== kind 分類（HUB / BRIDGE / DANGER / ISOLATED / NORMAL） =====
    kinds = _classify_node_kinds(
        list(analyzer.functions.values()),
        call_metrics,
        func_scores,
    )

    nodes_json = []
    for qname, func in analyzer.functions.items():
        module = qname.rsplit(".", 1)[0] if "." in qname else ""
        pr = call_metrics.get("pagerank", {}).get(qname, 0)
        in_deg = call_metrics.get("in_degree", {}).get(qname, 0)
        out_deg = call_metrics.get("out_degree", {}).get(qname, 0)
        bc = call_metrics.get("betweenness", {}).get(qname, 0)
        nodes_json.append({
            "id": qname,
            "label": func.name,
            "module": module,
            "file": func.file,
            "line": func.line,
            "lines": func.n_lines,
            "complexity": func.complexity,
            "cognitive": func.cognitive_complexity,
            "score": func_scores.get(qname, 100),
            "pagerank": round(pr, 5),
            "in_degree": in_deg,
            "out_degree": out_deg,
            "betweenness": bc,
            "impact": impact["functions"].get(qname, {}).get("affected_functions", 0),
            "is_isolated": qname in call_metrics.get("isolated", []),
            "debt_min": func.tech_debt_minutes,
            "security": len(func.security_issues),
            # ===== Tier 1 (IDE化) =====
            "func_type": getattr(func, "func_type", "function"),
            "is_entry": getattr(func, "is_entry", False),
            "decorators": getattr(func, "decorators", []),
            "is_generator": getattr(func, "is_generator", False),
            "n_args": func.n_args,
            "is_private": func.is_private,
            "docstring": func.docstring,
            # ===== 構造的異常スコア（0-100、高いほど他関数と異質） =====
            "anomaly_score": anomaly_scores.get(qname, 0),
            # ===== コードスメル（静的検出、層A） =====
            "code_smells": getattr(func, "code_smells", []),
            "max_nest_depth": getattr(func, "max_nest_depth", 0),
            # ===== ノード分類（hub/bridge/danger/isolated/normal） =====
            "kind": kinds.get(qname, "normal"),
            # ===== ダンダーメソッド（__init__等、ISOLATED 判定が誤解を招く） =====
            "is_dunder": getattr(func, "is_dunder", False),
            # ===== セキュリティ問題の具体内容（LLMプロンプトに渡す） =====
            "security_issues": list(getattr(func, "security_issues", [])),
        })

    # エッジ重み = 同じ caller→callee ペアの呼び出し回数
    from collections import Counter
    edge_counts = Counter(call_edges)
    edges_json = [
        {"source": s, "target": t, "weight": edge_counts[(s, t)]}
        for (s, t) in edge_counts.keys()
    ]
    module_edges_json = [{"source": s, "target": t} for s, t in import_edges]

    modules_json = []
    for mname, mod in analyzer.modules.items():
        modules_json.append({
            "name": mname,
            "file": mod.file,
            "lines": mod.n_lines,
            "n_functions": len(mod.functions),
            "n_imports": len(mod.imports),
            "score": mod_scores.get(mname, 100),
            "impact": impact["modules"].get(mname, {}).get("affected_modules", 0),
            "code_smells": getattr(mod, "code_smells", []),
        })

    # 平均スコア
    all_scores = list(func_scores.values())
    avg_score = round(sum(all_scores) / len(all_scores), 1) if all_scores else 100.0

    n_high = sum(1 for w in warnings if w["severity"] == "high")
    n_medium = sum(1 for w in warnings if w["severity"] == "medium")

    stats = {
        "n_files": len(analyzer.modules),
        "n_functions": len(analyzer.functions),
        "n_lines": sum(m.n_lines for m in analyzer.modules.values()),
        "n_edges": len(call_edges),
        "avg_score": avg_score,
        "n_high": n_high,
        "n_medium": n_medium,
        "n_cycles": len(import_cycles),
        "debt_minutes": total_debt,
        "debt_hours": round(total_debt / 60, 1),
        "sec_count": sec_count,
        "isolated_count": len(call_metrics.get("isolated", [])),
        "density": call_metrics.get("density", 0),
        "components": call_metrics.get("components", 0),
    }

    return {
        "stats": stats,
        "nodes": nodes_json,
        "edges": edges_json,
        "module_edges": module_edges_json,
        "modules": modules_json,
        "warnings": warnings,
        "duplicates": duplicates,
        "cycles": import_cycles,
        "hotspots": [],  # ブラウザ版ではGit履歴なし
        "parse_errors": getattr(analyzer, "parse_errors", []),
    }


def analyze_json(code: str) -> str:
    """JSON文字列を返す便利ラッパー."""
    return json.dumps(analyze_single_file(code), ensure_ascii=False, default=str)


# ========== 実行トレース（縦長3D + 値遷移ログ用）==========

def _detect_gui_libraries(files: dict[str, str]) -> dict:
    """ユーザーコードで使われているランタイム機能を検出。

    動く:
      matplotlib → 画像キャプチャ可能
      input() → stdin 入力欄で値を流せる
      open() → 仮想ファイルシステムで読み書き
      sys.argv → 引数欄で指定可能
      random → seed 固定オプション
    動かない:
      tkinter / pygame / turtle / PIL.show / requests / urllib / threading / subprocess / socket
    """
    detected = {
        "matplotlib": False,
        "uses_input": False,
        "uses_open": False,
        "uses_argv": False,
        "uses_random": False,
        "blocked": [],
    }
    blocked_patterns = [
        ("tkinter", r"\bimport\s+tkinter|\bfrom\s+tkinter\b|\bimport\s+Tkinter\b"),
        ("pygame", r"\bimport\s+pygame\b|\bfrom\s+pygame\b"),
        ("turtle", r"\bimport\s+turtle\b|\bfrom\s+turtle\b"),
        ("PIL.Image.show", r"\.show\(\s*\).*#.*PIL|Image\.open.*\.show\(\)"),
        ("requests", r"\bimport\s+requests\b|\bfrom\s+requests\b"),
        ("urllib", r"\bimport\s+urllib\b|\bfrom\s+urllib\b"),
        ("threading", r"\bimport\s+threading\b|\bfrom\s+threading\b"),
        ("multiprocessing", r"\bimport\s+multiprocessing\b|\bfrom\s+multiprocessing\b"),
        ("subprocess", r"\bimport\s+subprocess\b|\bfrom\s+subprocess\b"),
        ("socket", r"\bimport\s+socket\b|\bfrom\s+socket\b"),
    ]
    mpl_pat = re.compile(r"\bimport\s+matplotlib\b|\bfrom\s+matplotlib\b|\bmatplotlib\.pyplot\b|\bimport\s+pyplot\b")
    input_pat = re.compile(r"\binput\s*\(")
    open_pat = re.compile(r"\bopen\s*\(")
    argv_pat = re.compile(r"\bsys\.argv\b|\bargparse\b")
    random_pat = re.compile(r"\bimport\s+random\b|\bfrom\s+random\b|\brandom\.")
    for code in files.values():
        if mpl_pat.search(code):
            detected["matplotlib"] = True
        if input_pat.search(code):
            detected["uses_input"] = True
        if open_pat.search(code):
            detected["uses_open"] = True
        if argv_pat.search(code):
            detected["uses_argv"] = True
        if random_pat.search(code):
            detected["uses_random"] = True
        for name, pat in blocked_patterns:
            if re.search(pat, code) and name not in detected["blocked"]:
                detected["blocked"].append(name)
    return detected


def _capture_matplotlib_figures() -> list[dict]:
    """現在開いている matplotlib の全 Figure を PNG (base64) としてキャプチャ。

    matplotlib が読み込まれていない場合は空リストを返す。
    キャプチャ後は close() してメモリを解放。
    """
    images: list[dict] = []
    try:
        import matplotlib
        # 非対話バックエンド固定（tkinter等を呼び出さない）
        matplotlib.use("Agg", force=True)
        import matplotlib.pyplot as plt
        import base64 as _b64
        nums = plt.get_fignums()
        for i, num in enumerate(nums):
            try:
                fig = plt.figure(num)
                buf = io.BytesIO()
                fig.savefig(buf, format="png", bbox_inches="tight", dpi=100)
                buf.seek(0)
                b64 = _b64.b64encode(buf.read()).decode("ascii")
                # 画像サイズ取得
                w, h = fig.get_size_inches()
                images.append({
                    "index": i + 1,
                    "data_url": f"data:image/png;base64,{b64}",
                    "width_in": round(w, 2),
                    "height_in": round(h, 2),
                    "title": (fig._suptitle.get_text() if getattr(fig, "_suptitle", None) else "") or "",
                })
            except Exception:  # noqa: BLE001
                pass
        # 解放（次回実行時に積み重ならないように）
        plt.close("all")
    except ImportError:
        pass
    except Exception:  # noqa: BLE001
        pass
    return images


def trace_execution(
    files: dict[str, str],
    expr: str,
    stdin_lines: list | None = None,
    virtual_files: dict | None = None,
    argv: list | None = None,
    random_seed: int | None = None,
) -> dict:
    """ユーザー指定の式を実行し、関数呼び出しを引数・戻り値・順序付きで記録。

    expr 例: "add(2, 3)" / "main()" / "TaskManager().add(Task(1, 'x', 3, '2030-01-01'))"
    stdin_lines: input() に流す値のリスト。順番に消費され、不足するとEOFErrorに親切メッセージを添える。
    virtual_files: {filename: content} のdict。open()でこの辞書から読み書きする（実FS非依存）。
    argv: sys.argv に注入する文字列リスト。argv[0] は自動で "<trace>" になる。
    random_seed: int を渡すと random.seed(int) で再現性確保。
    """
    # GUI系ライブラリ検出（matplotlib/tkinter/pygame等の事前警告用）
    gui_info = _detect_gui_libraries(files)

    # matplotlib があれば事前に Agg バックエンドへ切り替え（重要：import 時点で決定するため）
    if gui_info["matplotlib"]:
        try:
            import matplotlib
            matplotlib.use("Agg", force=True)
        except ImportError:
            pass

    # input() 差し替え用バッファ（list なら無限イテレーション安全に取り出す）
    stdin_buf = list(stdin_lines) if stdin_lines else []
    stdin_consumed: list[dict] = []  # {prompt, value} の履歴

    namespace, load_errors = _build_namespace(files)
    user_funcs = _extract_user_funcs(files)

    # input() を差し替える（namespace と builtins 両方に注入）
    import builtins as _builtins
    _orig_input = _builtins.input
    _stdin_idx = [0]

    def _patched_input(prompt=""):
        # プロンプトは stdout に出す（本物の input() の挙動）
        if prompt:
            try:
                print(prompt, end="")
            except Exception:  # noqa: BLE001
                pass
        idx = _stdin_idx[0]
        if idx < len(stdin_buf):
            val = str(stdin_buf[idx])
            _stdin_idx[0] = idx + 1
            stdin_consumed.append({"prompt": str(prompt), "value": val})
            # echo して stdin 値が見えるように
            try:
                print(val)
            except Exception:  # noqa: BLE001
                pass
            return val
        # 値が足りない → 親切エラー
        raise EOFError(
            f"input() が呼ばれましたが stdin 値が不足しています "
            f"(入力済み {len(stdin_consumed)} 行、追加で {idx + 1} 行目が必要)。"
            f"\nUI の「stdin に流す値」欄に追加してください。"
        )

    _builtins.input = _patched_input
    namespace["input"] = _patched_input

    # ===== open() 仮想ファイルシステム =====
    vfiles: dict = dict(virtual_files) if virtual_files else {}
    vfiles_io: dict = {}  # 書き込み内容を蓄積するバッファ
    _orig_open = _builtins.open

    def _patched_open(file, mode="r", *args, **kwargs):  # noqa: ARG001
        # ファイル名を文字列化（PathLike対応）
        try:
            fname = os.fspath(file) if hasattr(os, "fspath") else str(file)
        except Exception:  # noqa: BLE001
            fname = str(file)
        # WORK_DIR 配下の解析対象ファイルは実FS、それ以外は仮想FSにフォールバック
        # （analyze_multiple_files 後の解析結果ファイルを読みたいケースは稀なので仮想FS優先）
        is_binary = "b" in mode
        is_write = any(c in mode for c in ("w", "a", "x"))
        if is_write:
            # 書き込み: 仮想FSのバッファに溜める
            buf = io.BytesIO() if is_binary else io.StringIO()
            # close 時に vfiles_io に保存するラッパーを作る
            class _CapturedFile:
                def __init__(self, b, fname, append=False):
                    self._buf = b
                    self._fname = fname
                    self._append = append
                    self._closed = False
                def write(self, data):
                    return self._buf.write(data)
                def writelines(self, lines):
                    for ln in lines:
                        self._buf.write(ln)
                def read(self, *a):
                    return ""
                def __enter__(self):
                    return self
                def __exit__(self, *exc):
                    self.close()
                    return False
                def __iter__(self):
                    return iter([])
                def close(self):
                    if self._closed:
                        return
                    self._closed = True
                    val = self._buf.getvalue()
                    if self._append and self._fname in vfiles:
                        prev = vfiles[self._fname]
                        if isinstance(prev, str) and isinstance(val, str):
                            val = prev + val
                        elif isinstance(prev, bytes) and isinstance(val, bytes):
                            val = prev + val
                    vfiles[self._fname] = val
                    vfiles_io[self._fname] = val
                def flush(self):
                    pass
            return _CapturedFile(buf, fname, append=("a" in mode))
        # 読み取り
        if fname in vfiles:
            content = vfiles[fname]
            if is_binary:
                if isinstance(content, str):
                    content = content.encode("utf-8")
                return io.BytesIO(content)
            if isinstance(content, bytes):
                content = content.decode("utf-8", errors="replace")
            return io.StringIO(content)
        # 仮想FS にないファイル → 親切エラー
        raise FileNotFoundError(
            f"open('{fname}') が呼ばれましたが、その名前の仮想ファイルがありません。\n"
            f"UI の「仮想ファイル」欄に <ファイル名>=<内容> 形式で追加してください。\n"
            f"（現在の仮想ファイル: {list(vfiles.keys())}）"
        )

    _builtins.open = _patched_open
    namespace["open"] = _patched_open

    # ===== sys.argv 注入 =====
    _orig_argv = sys.argv[:]
    if argv is not None:
        sys.argv = ["<trace>"] + [str(a) for a in argv]
    else:
        sys.argv = ["<trace>"]

    # ===== random.seed 固定（再現性） =====
    if random_seed is not None:
        try:
            import random as _random
            _random.seed(int(random_seed))
        except Exception:  # noqa: BLE001
            pass

    # 暴走防止の上限値
    MAX_STEPS = 2000          # トレース総ステップ数（call+return合計）
    MAX_DEPTH = 80            # 再帰・呼び出しネスト深さ
    MAX_STDOUT = 10_000       # 標準出力バイト数

    trace: list[dict] = []
    step = [0]
    depth = [0]
    call_stack: list[dict] = []  # 対応する return で埋めるため
    truncated = {"reason": None}  # 打ち切り理由

    def _safe_repr(v) -> str:
        try:
            r = repr(v)
            return r if len(r) <= 120 else r[:117] + "..."
        except Exception:
            return "<unprintable>"

    def tracer(frame, event, arg):  # noqa: ARG001
        # ★ 暴走打ち切り（無限ループ・暴走再帰対策）
        if step[0] >= MAX_STEPS:
            if truncated["reason"] is None:
                truncated["reason"] = f"トレース上限({MAX_STEPS}ステップ)到達、以降は記録のみスキップ（実行は続行）"
            return None  # 以降このフレームのイベントは記録しない（実行は止めない）
        if depth[0] > MAX_DEPTH:
            if truncated["reason"] is None:
                truncated["reason"] = f"再帰/ネスト深さ上限({MAX_DEPTH})到達、深い呼び出しは記録スキップ"
            return None

        name = frame.f_code.co_name
        if name not in user_funcs:
            return tracer
        # 標準ライブラリの同名関数は除外（contextlib.RedirectStdout.__init__ 等の偶然衝突防止）
        filename = frame.f_code.co_filename
        if "/lib/python" in filename or "/site-packages/" in filename or "<frozen" in filename:
            return tracer
        if event == "call":
            step[0] += 1
            args = {}
            try:
                # call イベント時点では f_locals は引数のみ（ローカル変数代入前）
                arg_count = frame.f_code.co_argcount
                arg_names = list(frame.f_code.co_varnames[:arg_count])
                for k in arg_names:
                    if k in frame.f_locals:
                        args[k] = _safe_repr(frame.f_locals[k])
            except Exception:
                pass
            entry = {
                "step": step[0],
                "event": "call",
                "func": name,
                "args": args,
                "depth": depth[0],
                "lineno": frame.f_lineno,
                "return_value": None,
                "return_step": None,
            }
            trace.append(entry)
            call_stack.append(entry)
            depth[0] += 1
        elif event == "return":
            depth[0] = max(0, depth[0] - 1)
            ret_repr = _safe_repr(arg)
            step[0] += 1
            ret_entry = {
                "step": step[0],
                "event": "return",
                "func": name,
                "value": ret_repr,
                "depth": depth[0],
            }
            trace.append(ret_entry)
            # 対応する call を逆順で探して return_value/return_step を埋める
            for i in range(len(call_stack) - 1, -1, -1):
                if call_stack[i]["func"] == name:
                    call_stack[i]["return_value"] = ret_repr
                    call_stack[i]["return_step"] = step[0]
                    call_stack.pop(i)
                    break
        return tracer

    captured = io.StringIO()
    expr_value = None
    error_msg = None
    try:
        sys.settrace(tracer)
        with redirect_stdout(captured):
            # 1回の実行で「副作用＋結果取得」を済ませる
            # 単一式なら eval、複文なら exec にフォールバック
            try:
                code_obj = compile(expr, "<expr>", "eval")
                expr_value = _safe_repr(eval(code_obj, namespace))
            except SyntaxError:
                # eval できない（代入や複文など）→ exec
                code_obj = compile(expr, "<expr>", "exec")
                exec(code_obj, namespace)
    except RuntimeError as e:
        msg = str(e)
        if "asyncio.run" in msg or "event loop" in msg or "running event loop" in msg:
            error_msg = (
                "asyncio.run() は Pyodide のブラウザ環境ではトレース実行できません。\n"
                "→ 「別の関数で実行」から asyncio を使わない関数を選んでください。\n"
                "（例: add / multiply / TaskManager().add(...) 等）\n"
                "もしくはコード側で asyncio.run(...) 行を削るかコメントアウトしてください。"
            )
        else:
            error_msg = f"{type(e).__name__}: {e}"
    except Exception as e:  # noqa: BLE001
        error_msg = f"{type(e).__name__}: {e}"
    finally:
        sys.settrace(None)
        # 差し替え物は必ず元に戻す（リークすると次回セッションを汚染）
        try:
            _builtins.input = _orig_input
        except Exception:  # noqa: BLE001
            pass
        try:
            _builtins.open = _orig_open
        except Exception:  # noqa: BLE001
            pass
        try:
            sys.argv = _orig_argv
        except Exception:  # noqa: BLE001
            pass

    # stdout 上限（巨大出力防止）
    stdout_text = captured.getvalue()
    stdout_truncated = False
    if len(stdout_text) > MAX_STDOUT:
        stdout_text = stdout_text[:MAX_STDOUT] + f"\n... (上限{MAX_STDOUT}バイト超、以降省略)"
        stdout_truncated = True

    # matplotlib の Figure を PNG (base64) として吸い出す（描画系コード対応）
    images = _capture_matplotlib_figures()

    return {
        "trace": trace,
        "stdout": stdout_text,
        "stdout_truncated": stdout_truncated,
        "expr_value": expr_value,
        "error": error_msg,
        "load_errors": load_errors,
        "user_funcs": sorted(user_funcs),
        "truncated": truncated["reason"],
        "limits": {"max_steps": MAX_STEPS, "max_depth": MAX_DEPTH, "max_stdout": MAX_STDOUT},
        "images": images,
        "gui_info": gui_info,
        "stdin_consumed": stdin_consumed,
        "stdin_provided": len(stdin_buf),
        "files_written": [
            {
                "name": k,
                "size": len(v) if isinstance(v, (str, bytes)) else 0,
                "preview": (v[:500] + "...") if isinstance(v, str) and len(v) > 500
                           else (v.decode("utf-8", errors="replace")[:500] + "...") if isinstance(v, bytes) and len(v) > 500
                           else (v if isinstance(v, str) else v.decode("utf-8", errors="replace") if isinstance(v, bytes) else str(v)),
            }
            for k, v in vfiles_io.items()
        ],
    }


def _classify_node_kinds(funcs: list, call_metrics: dict, func_scores: dict) -> dict:
    """各関数を hub / bridge / danger / isolated / normal に分類。

    フロント側 classifyNodes と整合。バックエンド側でも同じ判定が
    できるようにテストランナーから利用可能に。
    閾値はサンプル規模が小さい場合も拾えるよう、フロント版より少し緩める。
    """
    isolated = set(call_metrics.get("isolated", []))
    pagerank = call_metrics.get("pagerank", {})
    betweenness = call_metrics.get("betweenness", {})
    in_degree = call_metrics.get("in_degree", {})

    n = max(1, len(funcs))
    # 上位 max(1, ceil(20%)) を候補に
    top_n = max(1, (n + 4) // 5)

    sorted_pr = sorted(funcs, key=lambda f: pagerank.get(f.qualified_name, 0), reverse=True)
    sorted_bc = sorted(funcs, key=lambda f: betweenness.get(f.qualified_name, 0), reverse=True)

    # PageRank 上位 + 「平均PR の2倍以上」または「in_degree >= 2」を hub に
    pr_vals = [pagerank.get(f.qualified_name, 0) for f in funcs]
    avg_pr = sum(pr_vals) / n if pr_vals else 0
    hub_ids: set = set()
    for f in sorted_pr[:top_n]:
        pr_v = pagerank.get(f.qualified_name, 0)
        in_v = in_degree.get(f.qualified_name, 0)
        if pr_v > max(0.05, avg_pr * 1.8) or in_v >= 2:
            hub_ids.add(f.qualified_name)

    bridge_ids: set = set()
    for f in sorted_bc[:top_n]:
        bc_v = betweenness.get(f.qualified_name, 0)
        if bc_v > 0.001:
            bridge_ids.add(f.qualified_name)

    result: dict[str, str] = {}
    for f in funcs:
        qn = f.qualified_name
        score = func_scores.get(qn, 100)
        if qn in isolated:
            kind = "isolated"
        elif len(f.security_issues) > 0 or score < 60:
            kind = "danger"
        elif qn in hub_ids:
            kind = "hub"
        elif qn in bridge_ids:
            kind = "bridge"
        else:
            kind = "normal"
        result[qn] = kind
    return result


def _calc_anomaly_scores(nodes_for_anomaly: list[dict]) -> dict:
    """各関数の「構造的異常度」(0-100) を計算。

    複数メトリクス（複雑度・認知・行数・引数・PageRank・媒介性・in/out-degree）の
    z-score を合算し、外れ値ほど高スコア。「他関数と比べて異質な関数」を見つける。
    LLM の意味判定とクロスして「グラフ的にも怪しい × LLM が違和感」を高優先化する用途。
    """
    if not nodes_for_anomaly:
        return {}
    metric_keys = ["complexity", "cognitive", "lines", "n_args",
                   "pagerank", "betweenness", "in_degree", "out_degree"]
    n = len(nodes_for_anomaly)
    means: dict[str, float] = {}
    stds: dict[str, float] = {}
    for k in metric_keys:
        vals = [float(node.get(k, 0) or 0) for node in nodes_for_anomaly]
        m = sum(vals) / n
        var = sum((v - m) ** 2 for v in vals) / n
        means[k] = m
        stds[k] = max(0.1, var ** 0.5)
    result: dict[str, int] = {}
    for node in nodes_for_anomaly:
        z_sum = 0.0
        for k in metric_keys:
            v = float(node.get(k, 0) or 0)
            z = abs((v - means[k]) / stds[k])
            z_sum += min(z, 5.0)  # 1指標あたり上限5σ
        # 全8指標で z_sum 最大40。0-100 に正規化（z_sum=10で100=異常）
        score = min(100, round(z_sum * 10))
        result[node["id"]] = score
    return result


# ========== Phase C: doctest実行 + 関数呼び出しトレース ==========

import sys
import io
import ast
import re
import doctest as _doctest_mod
from contextlib import redirect_stdout


def _extract_user_funcs(files: dict[str, str]) -> set[str]:
    """ファイル群からユーザー定義関数名を抽出（settrace のフィルタ用）."""
    funcs = set()
    for code in files.values():
        try:
            tree = ast.parse(code)
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    funcs.add(node.name)
        except SyntaxError:
            # ASTでパースできなければ正規表現フォールバック
            for m in re.finditer(r"^\s*def\s+(\w+)", code, re.MULTILINE):
                funcs.add(m.group(1))
    return funcs


def _build_namespace(files: dict[str, str]) -> tuple[dict, list[str]]:
    """全ファイルを単一の名前空間で実行し、エラーがあれば収集."""
    namespace: dict = {"__name__": "__main__"}
    errors: list[str] = []
    for fname, code in files.items():
        try:
            exec(compile(code, fname, "exec"), namespace)
        except Exception as e:  # noqa: BLE001
            errors.append(f"{fname}: {type(e).__name__}: {e}")
    return namespace, errors


def _collect_tests(files: dict[str, str], extra_tests: str = "") -> list[dict]:
    """各ファイル内のdoctest + extra_tests のdoctestを抽出して統合."""
    parser = _doctest_mod.DocTestParser()
    blocks: list[dict] = []
    for fname, code in files.items():
        try:
            for ex in parser.get_examples(code):
                blocks.append(
                    {
                        "file": fname,
                        "lineno": ex.lineno,
                        "source": ex.source.rstrip("\n"),
                        "want": ex.want.rstrip("\n"),
                    }
                )
        except Exception:  # noqa: BLE001
            continue
    if extra_tests and extra_tests.strip():
        try:
            for ex in parser.get_examples(extra_tests):
                blocks.append(
                    {
                        "file": "(custom)",
                        "lineno": ex.lineno,
                        "source": ex.source.rstrip("\n"),
                        "want": ex.want.rstrip("\n"),
                    }
                )
        except Exception:  # noqa: BLE001
            pass
    return blocks


def _compare_outputs(want: str, got: str) -> bool:
    """doctest風の緩い比較（行末空白 / 末尾改行を許容）."""
    if not want.strip() and not got.strip():
        return True
    return want.strip() == got.strip()


def run_doctests_with_trace(files: dict[str, str], extra_tests: str = "") -> dict:
    """doctest形式のテストを実行し、関数呼び出しトレースを返す.

    files: {ファイル名: コード文字列}
    extra_tests: ユーザーがUI上で追加したdoctest文字列（任意）

    戻り値:
      {
        "summary": {"total": N, "pass": K, "fail": L, "load_errors": [...]},
        "user_funcs": [...],
        "results": [
          {
            "file": "...", "lineno": N, "source": "...", "want": "...",
            "actual": "...", "status": "pass|fail",
            "error": str|None,
            "trace": ["func1", "func2", ...]  # 呼び出された順
          },
          ...
        ]
      }
    """
    # 1. 全ファイルロード（共通の名前空間）
    namespace, load_errors = _build_namespace(files)
    user_funcs = _extract_user_funcs(files)

    # 2. テスト抽出
    tests = _collect_tests(files, extra_tests)

    results = []
    for tb in tests:
        trace: list[str] = []

        def tracer(frame, event, arg):  # noqa: ARG001
            if event == "call":
                name = frame.f_code.co_name
                if name in user_funcs and name != "<module>":
                    trace.append(name)
            return tracer

        captured = io.StringIO()
        actual = ""
        error_msg = None
        passed = False
        try:
            sys.settrace(tracer)
            with redirect_stdout(captured):
                # mode='single' で >>> 風の自動 repr 出力を再現
                code_obj = compile(tb["source"], "<doctest>", "single")
                exec(code_obj, namespace)
            sys.settrace(None)
            actual = captured.getvalue().rstrip("\n")
            passed = _compare_outputs(tb["want"], actual)
        except Exception as e:  # noqa: BLE001
            sys.settrace(None)
            actual = captured.getvalue().rstrip("\n")
            error_msg = f"{type(e).__name__}: {e}"
            want = tb["want"]
            # Traceback記法で同じ例外型ならpass扱い
            if "Traceback" in want and type(e).__name__ in want:
                passed = True
            else:
                passed = False

        results.append(
            {
                "file": tb["file"],
                "lineno": tb["lineno"],
                "source": tb["source"],
                "want": tb["want"],
                "actual": actual,
                "status": "pass" if passed else "fail",
                "error": error_msg,
                "trace": trace,
            }
        )

    n_pass = sum(1 for r in results if r["status"] == "pass")
    n_fail = sum(1 for r in results if r["status"] == "fail")

    return {
        "summary": {
            "total": len(results),
            "pass": n_pass,
            "fail": n_fail,
            "load_errors": load_errors,
        },
        "user_funcs": sorted(user_funcs),
        "results": results,
    }
