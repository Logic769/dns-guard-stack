#!/usr/bin/env bash
# 跑仓库自带的测试。
#
# 为什么要在临时目录里跑：这批测试是为"发布目录布局"写的（所有 .py 与 tests/ 同级，
# 测试用相对路径读 guard.py / alt_adapter.py 等源码）。仓库把代码分在 core/ tools/ probes/，
# 所以这里先把它们摊平到一个临时目录，再按原始布局执行 —— 与生产环境一致。
#
# 用法：
#   tests/run.sh                # 跑全部
#   tests/run.sh -v             # 详细
#   tests/run.sh test_cn_typing # 只跑某个模块
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY="${PYTHON:-python3}"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

cp "$ROOT"/core/*.py "$WORK"/ 2>/dev/null || true
cp "$ROOT"/core/*.json "$WORK"/ 2>/dev/null || true
cp "$ROOT"/tools/*.py "$WORK"/ 2>/dev/null || true
cp "$ROOT"/probes/*.py "$WORK"/ 2>/dev/null || true
cp "$ROOT"/firewall/*.py "$WORK"/ 2>/dev/null || true
cp -a "$ROOT"/tests "$WORK"/tests

cd "$WORK/tests"
export PYTHONDONTWRITEBYTECODE=1
exec "$PY" -B -m unittest discover -s . -t . -p "test_*.py" "$@"
