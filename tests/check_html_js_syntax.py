"""docs/index.html の <script> 内の JS 構文を node でチェック。

template literal 内のバッククォート混入で起きる SyntaxError を
push 前に検出する目的。

使い方:
  python tests/check_html_js_syntax.py
  → exit code 0 なら OK、非0 なら構文エラー
"""

import re
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    html_path = Path(__file__).resolve().parent.parent / "docs" / "index.html"
    text = html_path.read_text(encoding="utf-8")

    # 通常の <script> ブロック（type=module は ESM なので除外）
    blocks = re.findall(
        r'<script(?![^>]*type="module")[^>]*>(.*?)</script>',
        text,
        flags=re.DOTALL,
    )
    if not blocks:
        print("⚠ <script> ブロックが見つかりません")
        return 1

    # 全部結合してチェック
    combined = "\n".join(blocks)

    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".js", delete=False
    ) as tmp:
        tmp.write(combined)
        tmp_path = tmp.name

    try:
        result = subprocess.run(
            ["node", "--check", tmp_path],
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
        if result.returncode == 0:
            print(f"[OK] JS syntax valid ({len(combined)} chars, {len(blocks)} blocks)")
            return 0
        else:
            print("[NG] syntax error detected:")
            print(result.stderr)
            return 2
    except FileNotFoundError:
        print("[WARN] node not found. Install Node.js")
        return 3
    finally:
        Path(tmp_path).unlink(missing_ok=True)


if __name__ == "__main__":
    sys.exit(main())
