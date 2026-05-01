"""Code Quality Graph 動作検証用テストパターン集。

各パターンは「狙い（期待される検出）」をコメントに明示。
analyzer.py が想定通りの結果を出すか、test_runner.py で照合する。
"""

# ==============================================================
# Pattern A: 正常系（良いコード、検出すべき問題ほぼなし）
# ==============================================================
PATTERN_A_CLEAN = {
    "files": {
        "math_utils.py": '''"""数学ユーティリティ。"""


def add(a: int, b: int) -> int:
    """足し算。

    >>> add(2, 3)
    5
    """
    return a + b


def multiply(a: int, b: int) -> int:
    """掛け算。

    >>> multiply(2, 3)
    6
    """
    return a * b


def average(values: list) -> float:
    """平均値。空リストは0.0を返す。

    >>> average([1, 2, 3])
    2.0
    >>> average([])
    0.0
    """
    if not values:
        return 0.0
    return sum(values) / len(values)
''',
    },
    "expected": {
        "n_functions": 3,
        "min_avg_score": 90,           # 全部良いはず
        "max_smells_total": 0,         # スメル無し
        "max_n_high_warnings": 0,      # 警告無し
    },
}

# ==============================================================
# Pattern B: 論理逆転バグ（filter_expensive 系）
# ==============================================================
PATTERN_B_LOGIC_INVERSION = {
    "files": {
        "filter.py": '''"""フィルタ関数集。意図と実装が逆になってるバグあり。"""


def filter_expensive(prices: list, threshold: int = 1000) -> list:
    """threshold より高い価格だけ返す。

    >>> filter_expensive([500, 1500, 2000], 1000)
    [1500, 2000]
    """
    # BUG: 不等号の向きが逆（< にすべきは >）
    return [p for p in prices if p < threshold]


def filter_cheap(prices: list, threshold: int = 1000) -> list:
    """threshold より安い価格だけ返す（こっちは正しい）。

    >>> filter_cheap([500, 1500, 2000], 1000)
    [500]
    """
    return [p for p in prices if p < threshold]
''',
    },
    "expected": {
        "n_functions": 2,
        # filter_expensive は doctest と実装が矛盾するので、Phase C 実行で fail するはず
        # 静的解析（analyzer）では検出できない、LLMタスクの仕事
        # ここでは test_runner で「Phase C のテスト失敗」を確認する
        "expected_doctest_failures": ["filter_expensive"],
    },
}

# ==============================================================
# Pattern C: 神関数（巨大・複雑・深ネスト・マジック数字）
# 50行超 + 引数8個 + ネスト深 + マジック数字 + 冗長条件 + early_return パターン
# ==============================================================
PATTERN_C_GOD_FUNCTION = {
    "files": {
        "report.py": '''"""巨大な神関数。ほぼ全てのスメルを発動させる。"""


def generate_report(data, mode, format_type, options, filters, sort_by, output_path, debug):
    if data == None:
        return None
    else:
        result = ""
    count = 0
    for i in range(len(data)):
        item = data[i]
        if mode == "verbose":
            if format_type == "html":
                if filters and item.get("status") == "active":
                    if item.get("priority") > 5:
                        if item.get("category") in ["A", "B", "C"]:
                            score = item.get("value", 0) * 1.5 + 23.7
                            if score > 42:
                                if debug == True:
                                    result += "<div class='item'>" + str(item) + "</div>"
                                    count += 1
                                else:
                                    result += "<p>" + str(item) + "</p>"
                            elif score > 17:
                                result += "<span>" + str(item) + "</span>"
                            else:
                                result += "<small>" + str(item) + "</small>"
            elif format_type == "json":
                if item.get("priority") > 5:
                    result += '{"item":' + str(item) + '}'
                    count += 1
                else:
                    result += '{"item":null}'
            elif format_type == "csv":
                result += str(item.get("id", 0)) + "," + str(item.get("name", ""))
                if item.get("value", 0) > 999:
                    result += ",HIGH"
                elif item.get("value", 0) > 567:
                    result += ",MID"
                else:
                    result += ",LOW"
                result += "\\n"
            elif format_type == "xml":
                result += "<row>" + str(item) + "</row>"
                count += 1
        elif mode == "compact":
            result += str(item.get("id", 0)) + ";"
            count += 1
        else:
            result += str(item) + "\\n"
    if sort_by == None:
        return result
    if output_path != None:
        with open(output_path, "w") as f:
            f.write(result)
    return result
''',
    },
    "expected": {
        "n_functions": 1,
        "expected_smells": [
            "deep_nesting",        # ネスト 6+ 段
            "magic_number",        # 23.7, 42, 17, 999, 567 etc
            "redundant_condition", # debug == True, sort_by == None, data == None
            "long_param_list",     # 引数 8 個
            "early_return",        # data==None: return + else
            "too_long_function",   # 50行超
        ],
        "min_smells": 5,           # 6種のうち少なくとも5種出るはず
        "max_score": 30,           # スコア悲惨
    },
}

# ==============================================================
# Pattern D: 多モジュール正常系（呼び出し関係が綺麗）
# ==============================================================
PATTERN_D_MULTI_MODULE = {
    "files": {
        "core.py": '''"""コアロジック。"""

from helpers import normalize, log


def process(data: dict) -> dict:
    """データを正規化してログ。

    >>> process({"name": "  Alice  "})
    {'name': 'Alice'}
    """
    log("processing")
    return {k: normalize(v) for k, v in data.items()}


def main() -> None:
    """エントリポイント。"""
    data = {"name": "  Bob  "}
    result = process(data)
    log(f"result: {result}")


if __name__ == "__main__":
    main()
''',
        "helpers.py": '''"""ヘルパー関数。"""


def normalize(value):
    """文字列なら strip、それ以外そのまま。

    >>> normalize("  hello  ")
    'hello'
    >>> normalize(42)
    42
    """
    if isinstance(value, str):
        return value.strip()
    return value


def log(message: str) -> None:
    """ログ出力。"""
    print(f"[LOG] {message}")
''',
    },
    "expected": {
        "n_functions": 4,           # process, main, normalize, log
        "n_files": 2,
        "min_avg_score": 80,
        # main は entry 判定されるべき
        "has_entry_func": "main",
        # log は in_degree>=2 で HUB 判定されるはず（_classify_node_kinds の緩めた閾値）
        "expected_hubs": ["log"],
        # 異モジュール間エッジが存在するはず（process→normalize, main→process等）
        "min_cross_module_edges": 2,
    },
}

# ==============================================================
# Pattern E: 未使用 import + 未使用関数
# ==============================================================
PATTERN_E_DEAD_CODE = {
    "files": {
        "ghost.py": '''"""未使用コードを集めたファイル。"""

import os         # 未使用
import sys        # 未使用
from json import dumps, loads  # loads のみ使用、dumps 未使用
from typing import List


def used_func(items: List[int]) -> str:
    """使われる関数。

    >>> used_func([1, 2])
    '[1, 2]'
    """
    # dumps を使わず str() で済ませてる（dumps が dead）
    return loads(str(items).replace("'", '"')).__class__.__name__ if False else str(items)


def unused_helper_one():
    """誰からも呼ばれない関数。"""
    return "ghost1"


def unused_helper_two():
    """これも誰からも呼ばれない。"""
    return "ghost2"


def main():
    """エントリ。"""
    print(used_func([1, 2, 3]))


if __name__ == "__main__":
    main()
''',
    },
    "expected": {
        "n_functions": 4,
        "expected_isolated_functions": ["unused_helper_one", "unused_helper_two"],
        "expected_module_smells": ["unused_import"],
    },
}

# ==============================================================
# Pattern F: async + generator（形状検出用）
# ==============================================================
PATTERN_F_SHAPES = {
    "files": {
        "shapes.py": '''"""関数種別 (func_type) の検出テスト用。"""

import asyncio


def regular_func():
    """通常関数（球）。"""
    return 1


async def async_func():
    """async関数（トーラス）。"""
    await asyncio.sleep(0)
    return 2


def gen_func():
    """generator（トーラスノット）。"""
    for i in range(3):
        yield i


class MyClass:
    """クラスメソッド（立方体）テスト。"""

    def method_one(self):
        return self.value

    @staticmethod
    def static_method():
        return "static"


def main():
    """エントリ（八面体）。"""
    print(regular_func())


if __name__ == "__main__":
    main()
''',
    },
    "expected": {
        "n_functions": 6,  # regular, async, gen, method_one, static_method, main
        "expected_func_types": {
            "regular_func": "function",
            "async_func": "async",
            "gen_func": "generator",
            "method_one": "method",
            "static_method": "method",
            "main": "entry",
        },
    },
}

# ==============================================================
# Pattern G: 重複コード
# ==============================================================
PATTERN_G_DUPLICATES = {
    "files": {
        "dup.py": '''"""ほぼ同じコードが3箇所にある（重複検出テスト）。

source_hash は変数名込みの正規化ハッシュなので、変数名を揃えて完全一致させる。
"""


def calculate_total_a(items):
    total = 0
    for x in items:
        if x > 0:
            total += x
        else:
            total += 0
    return total


def calculate_total_b(items):
    total = 0
    for x in items:
        if x > 0:
            total += x
        else:
            total += 0
    return total


def calculate_sum(items):
    total = 0
    for x in items:
        if x > 0:
            total += x
        else:
            total += 0
    return total
''',
    },
    "expected": {
        "n_functions": 3,
        "min_duplicates": 1,  # 少なくとも1組の重複
    },
}

# ==============================================================
# 全パターン
# ==============================================================
ALL_PATTERNS = {
    "A_clean":             PATTERN_A_CLEAN,
    "B_logic_inversion":   PATTERN_B_LOGIC_INVERSION,
    "C_god_function":      PATTERN_C_GOD_FUNCTION,
    "D_multi_module":      PATTERN_D_MULTI_MODULE,
    "E_dead_code":         PATTERN_E_DEAD_CODE,
    "F_shapes":            PATTERN_F_SHAPES,
    "G_duplicates":        PATTERN_G_DUPLICATES,
}
