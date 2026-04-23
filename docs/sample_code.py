"""サンプルコード: 簡易タスク管理システム

このコードには意図的にいくつかの問題が含まれており、
Code Quality Graph の分析機能をデモするためのサンプルです。

含まれる問題:
- 長すぎる関数
- 複雑度が高い関数（深いネスト）
- 重複コード
- セキュリティ問題（eval, ハードコード秘密鍵）
- 孤立した未使用関数
- 多くの場所から呼ばれる重要関数
"""

import os
import json

# ハードコード秘密鍵（セキュリティ問題）
API_KEY = "sk-proj-1234567890abcdef"
DATABASE_PASSWORD = "admin123"


# ========== 共通ユーティリティ（よく呼ばれる） ==========

def log(message):
    """ログ出力"""
    print(f"[LOG] {message}")


def format_date(date_str):
    """日付フォーマット"""
    return date_str.replace("-", "/")


def validate_id(task_id):
    """ID検証"""
    if not isinstance(task_id, int):
        return False
    if task_id <= 0:
        return False
    return True


# ========== タスク管理 ==========

def create_task(task_id, title, priority, deadline):
    """タスク作成"""
    if not validate_id(task_id):
        log("無効なID")
        return None
    task = {
        "id": task_id,
        "title": title,
        "priority": priority,
        "deadline": format_date(deadline),
        "status": "open",
    }
    log(title)
    return task


def update_task(task_id, title, priority, deadline):
    """タスク更新（create_taskと重複コード）"""
    if not validate_id(task_id):
        log("無効なID")
        return None
    task = {
        "id": task_id,
        "title": title,
        "priority": priority,
        "deadline": format_date(deadline),
        "status": "open",
    }
    log(title)
    return task


def delete_task(task_id):
    """タスク削除"""
    if not validate_id(task_id):
        return False
    log(f"タスク削除: {task_id}")
    return True


# ========== 重複コードのサンプル（別クラスで同一実装） ==========

class CartCalculator:
    def total(self, items, tax_rate):
        total = 0
        for item in items:
            total = total + item["price"]
        total = total * (1 + tax_rate)
        return total


class OrderCalculator:
    def total(self, items, tax_rate):
        total = 0
        for item in items:
            total = total + item["price"]
        total = total * (1 + tax_rate)
        return total


# ========== 複雑なフィルタリング（複雑度高） ==========

def filter_tasks(tasks, priority=None, status=None, deadline_before=None,
                 deadline_after=None, title_contains=None, min_id=None,
                 max_id=None, assignee=None, tag=None):
    """大量の条件でタスクをフィルタリング（引数が多すぎ + 複雑度高）"""
    result = []
    for task in tasks:
        if priority is not None:
            if task["priority"] != priority:
                continue
        if status is not None:
            if task["status"] != status:
                continue
        if deadline_before is not None:
            if task["deadline"] >= deadline_before:
                continue
        if deadline_after is not None:
            if task["deadline"] <= deadline_after:
                continue
        if title_contains is not None:
            if title_contains not in task["title"]:
                continue
        if min_id is not None:
            if task["id"] < min_id:
                continue
        if max_id is not None:
            if task["id"] > max_id:
                continue
        if assignee is not None:
            if task.get("assignee") != assignee:
                continue
        if tag is not None:
            if tag not in task.get("tags", []):
                continue
        result.append(task)
    return result


# ========== レポート生成（非常に長く認知的複雑度が高い） ==========

def generate_report(tasks, report_type, include_summary, include_details,
                    format_type, output_file):
    """レポート生成（長すぎ・ネスト深すぎ）"""
    report_lines = []

    if report_type == "weekly":
        if include_summary:
            report_lines.append("=== 週次レポート ===")
            total = 0
            completed = 0
            for task in tasks:
                if task["status"] == "open":
                    total += 1
                else:
                    if task["status"] == "completed":
                        completed += 1
                        if task.get("priority") == "high":
                            report_lines.append(f"  重要完了: {task['title']}")
                        else:
                            if task.get("priority") == "medium":
                                report_lines.append(f"  中程度完了: {task['title']}")
                            else:
                                report_lines.append(f"  低優先度完了: {task['title']}")
            report_lines.append(f"総タスク: {total}")
            report_lines.append(f"完了: {completed}")
        if include_details:
            for task in tasks:
                if task["status"] == "open":
                    if task.get("priority") == "high":
                        report_lines.append(f"[!] {task['title']} (締切: {task['deadline']})")
                    else:
                        report_lines.append(f"    {task['title']}")
    elif report_type == "monthly":
        if include_summary:
            report_lines.append("=== 月次レポート ===")
            by_priority = {"high": 0, "medium": 0, "low": 0}
            for task in tasks:
                p = task.get("priority", "low")
                if p in by_priority:
                    by_priority[p] += 1
            for priority, count in by_priority.items():
                report_lines.append(f"{priority}: {count}")
    elif report_type == "daily":
        report_lines.append("=== 日次レポート ===")
        for task in tasks:
            report_lines.append(f"- {task['title']}")

    # 出力フォーマット変換
    if format_type == "json":
        result = json.dumps({"lines": report_lines})
    elif format_type == "text":
        result = "\n".join(report_lines)
    elif format_type == "html":
        result = "<ul>" + "".join(f"<li>{l}</li>" for l in report_lines) + "</ul>"
    else:
        result = str(report_lines)

    if output_file:
        with open(output_file, "w") as f:
            f.write(result)

    log(f"レポート生成完了: {report_type}")
    return result


# ========== セキュリティ問題を含む関数 ==========

def run_user_script(script_text):
    """ユーザースクリプト実行（危険: eval使用）"""
    return eval(script_text)  # セキュリティリスク


def execute_shell_command(command):
    """シェル実行（危険: os.system）"""
    os.system(command)  # セキュリティリスク


# ========== 誰からも呼ばれない孤立関数 ==========

def unused_helper():
    """この関数はどこからも呼ばれていない"""
    return 42


def another_orphan():
    """これも孤立"""
    return "lonely"


# ========== メイン ==========

def main():
    """エントリーポイント"""
    tasks = []
    t1 = create_task(1, "資料準備", "high", "2026-05-01")
    t2 = create_task(2, "論文読解", "medium", "2026-05-03")
    tasks.append(t1)
    tasks.append(t2)

    high_tasks = filter_tasks(tasks, priority="high", status="open")
    log(f"重要タスク: {len(high_tasks)}件")

    report = generate_report(
        tasks, report_type="weekly",
        include_summary=True, include_details=True,
        format_type="text", output_file=None,
    )
    log(report)


if __name__ == "__main__":
    main()
