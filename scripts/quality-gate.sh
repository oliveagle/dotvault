#!/usr/bin/env bash
# scripts/quality-gate.sh - dotvault 质量检查门禁
#
# 用法: ./scripts/quality-gate.sh [--all|--format|--test|--coverage|--length|--lint|--install-hook|--help]
#
# 质量标准:
#   - cargo fmt 100% 格式化
#   - cargo clippy 零警告 (-D warnings)
#   - cargo test 全部通过
#   - 行覆盖率 > 80%
#   - 文件行数 100-500
#   - 无 TODO/FIXME/placeholder/BUG/HACK 标记 (零容忍)
#   - 目录结构: 无 binary / 测试文件在根目录

set -e

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

COVERAGE_THRESHOLD=80

show_help() {
  cat <<EOF
用法: $0 [选项]

选项:
  --all           运行所有检查 (默认)
  --format        仅检查代码格式
  --lint          仅运行 clippy
  --test          仅运行测试
  --coverage      仅检查覆盖率
  --length        仅检查文件行数
  --structure     仅检查目录结构
  --install-hook  安装 pre-commit git hook
  --help          显示此帮助信息
EOF
}

install_hook() {
  if [ ! -d ".git/hooks" ]; then
    echo -e "${RED}❌ .git/hooks 不存在，不是 git 仓库${NC}"
    exit 1
  fi
  cat > .git/hooks/pre-commit <<'EOF'
#!/usr/bin/env bash
echo "运行质量检查..."
./scripts/quality-gate.sh --all
EOF
  chmod +x .git/hooks/pre-commit
  echo -e "${GREEN}✅ pre-commit hook 已安装${NC}"
}

check_format() {
  echo "检查代码格式 (cargo fmt)..."
  if cargo fmt --check; then
    echo -e "${GREEN}✅ 格式检查通过${NC}"
  else
    echo -e "${RED}❌ 格式问题: 运行 'cargo fmt'${NC}"
    exit 1
  fi
}

check_lint() {
  echo "检查 clippy (零警告)..."
  if cargo clippy --all-targets -- -D warnings; then
    echo -e "${GREEN}✅ clippy 检查通过${NC}"
  else
    echo -e "${RED}❌ clippy 发现警告${NC}"
    exit 1
  fi
}

run_tests() {
  echo "运行测试 (cargo test)..."
  # Single-threaded: several tests mutate process-global env vars
  # (DOTVAULT_CONFIG / DOTVAULT_BACKUP_DIR) and would race if parallelized.
  if RUST_TEST_THREADS=1 cargo test; then
    echo -e "${GREEN}✅ 测试通过${NC}"
  else
    echo -e "${RED}❌ 测试失败${NC}"
    exit 1
  fi
}

# 覆盖率检查: 行覆盖率 > 80%。
# 优先使用 cargo-llvm-cov (macOS/arm64 友好); 回退提示安装。
check_coverage() {
  echo "检查覆盖率 (目标 > ${COVERAGE_THRESHOLD}%)..."
  if ! cargo llvm-cov --version >/dev/null 2>&1; then
    echo -e "${RED}❌ cargo-llvm-cov 未安装${NC}"
    echo "  安装: cargo install cargo-llvm-cov && rustup component add llvm-tools-preview"
    exit 1
  fi
  # 若有系统 LLVM 工具 (Xcode), 用它避免 rustup 镜像 404。
  if command -v xcrun >/dev/null 2>&1; then
    export LLVM_COV="${LLVM_COV:-$(xcrun --find llvm-cov 2>/dev/null)}"
    export LLVM_PROFDATA="${LLVM_PROFDATA:-$(xcrun --find llvm-profdata 2>/dev/null)}"
  fi

  # --summary-only 输出末行含 TOTAL...Cover%, 解析后与阈值比较。
  # --test-threads=1: env-mutating + file-locking tests must serialize.
  local output
  output="$(cargo llvm-cov --no-cfg-coverage --summary-only -- --test-threads=1 2>&1 || true)"
  echo "$output" | tail -n 15

  local cov
  # 只取 TOTAL 那一行的百分比; 其顺序为 Regions%, Functions%, Lines%,
  # Branches%(未启用分支统计时为 "-"). Lines 覆盖率是第 3 个百分比。
  local total_line
  total_line="$(echo "$output" | grep -E '^TOTAL' | head -1)"
  cov="$(echo "$total_line" | grep -oE '[0-9]+\.[0-9]+%' | sed 's/%//' | sed -n '3p')"
  if [ -z "$cov" ]; then
    echo -e "${RED}❌ 无法解析覆盖率结果${NC}"
    exit 1
  fi
  # 比较浮点数
  if awk "BEGIN {exit !($cov >= $COVERAGE_THRESHOLD)}"; then
    echo -e "${GREEN}✅ 行覆盖率: ${cov}% (>= ${COVERAGE_THRESHOLD}%)${NC}"
  else
    echo -e "${RED}❌ 行覆盖率: ${cov}% < ${COVERAGE_THRESHOLD}%${NC}"
    exit 1
  fi
}

check_file_length() {
  echo "检查文件行数 (100-500)..."
  local fail=0
  while IFS= read -r f; do
    local lines
    lines=$(wc -l < "$f" | tr -d ' ')
    if [ "$lines" -gt 500 ]; then
      echo -e "${RED}❌ $f 超过 500 行 ($lines 行)${NC}"
      fail=1
    elif [ "$lines" -lt 100 ] && [ "$lines" -gt 10 ]; then
      echo -e "${YELLOW}⚠️  $f 低于 100 行 ($lines 行)${NC}"
    fi
  done < <(find . -type f -name "*.rs" ! -path "*/target/*" ! -path "*/.git/*")
  if [ "$fail" -eq 1 ]; then exit 1; fi
  echo -e "${GREEN}✅ 文件行数检查通过${NC}"
}

check_structure() {
  echo "检查目录结构..."
  local fail=0
  # 根目录 binary
  if ls *.exe *.bin *.dll *.so *.dylib *.app 2>/dev/null | grep -q .; then
    echo -e "${RED}❌ 根目录发现 binary 文件${NC}"
    fail=1
  fi
  # 根目录测试文件
  if ls test_*.rs *_test.rs 2>/dev/null | grep -q .; then
    echo -e "${RED}❌ 根目录发现测试文件${NC}"
    fail=1
  fi
  # git tracked binary / build 输出
  if git rev-parse --git-dir >/dev/null 2>&1; then
    if [ -n "$(git ls-files | grep -E '\.(exe|bin|dll|so|dylib|app)$' || true)" ]; then
      echo -e "${RED}❌ 发现 binary 被 git tracked${NC}"
      fail=1
    fi
    if [ -n "$(git ls-files | grep -E '^(build|dist|bin|target)/' || true)" ]; then
      echo -e "${RED}❌ 发现构建目录被 git tracked${NC}"
      fail=1
    fi
  fi
  if [ "$fail" -eq 1 ]; then exit 1; fi
  echo -e "${GREEN}✅ 目录结构检查通过${NC}"
}

check_placeholders() {
  echo "检查 placeholder / bug 标记 (零容忍)..."
  if grep -rn "TODO\|FIXME\|placeholder\|Not implemented\|TBD\|BUG\|HACK\|XXX\|WORKAROUND" \
    --include="*.rs" src/ 2>/dev/null; then
    echo -e "${RED}❌ 发现 placeholder / bug 标记，必须修复${NC}"
    exit 1
  fi
  echo -e "${GREEN}✅ 无 placeholder / bug 标记${NC}"
}

main() {
  case "${1:---all}" in
    --all)
      check_structure
      check_format
      check_lint
      run_tests
      check_coverage
      check_file_length
      check_placeholders
      echo -e "${GREEN}🎉 所有质量检查通过${NC}"
      ;;
    --format) check_format ;;
    --lint) check_lint ;;
    --test) run_tests ;;
    --coverage) check_coverage ;;
    --length) check_file_length ;;
    --structure) check_structure ;;
    --placeholders) check_placeholders ;;
    --install-hook) install_hook ;;
    --help) show_help ;;
    *) echo "未知选项: $1"; show_help; exit 1 ;;
  esac
}

main "$@"
