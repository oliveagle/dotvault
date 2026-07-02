---
name: dotvault
description: "用 dotvault 管理项目的加密密钥/API key/token,并以 .env 格式导出。SSH key 加密,按 namespace 隔离各应用。触发: store a secret, API key, generate .env, manage secrets, 密钥, 加密存储, 环境变量"
---

# dotvault skill

用 dotvault 给项目存取密钥(API key、token、password),并以 `.env` 兼容格式导出。
所有密钥用用户的 SSH 私钥加密,按 namespace 隔离不同应用。

## 核心原则

- **先确认环境**:运行 `dotvault version` 确认已安装(若有新版会在 stderr 提示);若项目根没有 `.dotvault_key`,先 `dotvault init <namespace>`。
- **SSH key 是必须的**:每次操作都要 `--key`(默认 `~/.ssh/id_ed25519`,或设 `DOTVAULT_KEY` 环境变量,或 `dotvault config --set-key`)。
- **fail-fast,不擅自做主**:`set` 已存在的 key 会报错(先 `rm`);`get`/`rm` 不存在的 key 会报错。绝不静默覆盖。
- **明文输出走 stdout**:命令提示信息走 stderr,`export`/`get` 的密文走 stdout,可直接重定向。

## 命令速查

```sh
# 一次性环境引导(创建 ~/.dotvault/ + 默认配置;幂等,不覆盖已有配置)
dotvault install

# 绑定项目到 namespace(在项目根目录跑,会写 ./.dotvault_key)
dotvault --key ~/.ssh/id_ed25519 init <namespace>

# 存密钥(key 名必须匹配 [A-Za-z_][A-Za-z0-9_]*)
dotvault --key ~/.ssh/id_ed25519 set <NAME> <value>

# 取单个值(无尾换行,适合 $(...) 捕获)
dotvault --key ~/.ssh/id_ed25519 get <NAME>

# 列出当前 namespace 的 key 名
dotvault --key ~/.ssh/id_ed25519 list

# 导出全部为 KEY=VALUE (.env 格式)
dotvault --key ~/.ssh/id_ed25519 export
dotvault --key ~/.ssh/id_ed25519 export > .env

# 删除(不存在则报错)
dotvault --key ~/.ssh/id_ed25519 rm <NAME>

# 管理 namespace
dotvault --key ~/.ssh/id_ed25519 ns list
dotvault --key ~/.ssh/id_ed25519 ns remove <namespace>

# 体检 / 换 SSH key / 看版本
dotvault --key ~/.ssh/id_ed25519 doctor
dotvault --key ~/.ssh/id_ed25519 rekey --new-key <PATH>
dotvault version                       # 输出版本+git hash;若新版可用,stderr 提示一行
```

省略 `--key` 的方式:`export DOTVAULT_KEY=~/.ssh/id_ed25519`,或 `dotvault config --set-key <path>`。

## 升级

`dotvault version` 会在 stderr 提示是否有新版(在线检查,缓存 1 小时)。升级用单独的脚本(不是子命令,因为二进制不能在运行时替换自己):

```sh
scripts/upgrade.sh          # 幂等:已最新就退出 0,否则下载 + sha256 校验 + 替换二进制
# 或重新跑安装脚本(效果一样):
curl -fsSL https://raw.githubusercontent.com/oliveagle/dotvault/main/scripts/install.sh | bash
```

## export / list 合并 global + project

`export` 和 `list` 会**合并 global 和 project 两个 namespace**,用 `# === <ns> ===` 注释行分区(project 在后,覆盖 global 的同名 key)。输出符合 .env 语法(`#` 开头的行被 dotenv 工具忽略):

```
# === global ===
GITHUB_TOKEN=ghp_xxx
# === namespace: myapp ===
DB_PASSWORD=s3cret
```

- 同名 key:project 的赢(global 区不显示被覆盖的)。
- 加 `--global`:只导出 global(不合并)。
- 无项目 `.dotvault_key`:只导出 global。

## global namespace(跨项目共享的密钥)

`install` 会自动创建一个名为 `global` 的特殊 namespace,access_key 存在 `~/.dotvault/access_key`。适合放跨项目通用的密钥(GITHUB_TOKEN、个人的 SSH passphrase 等)。

```sh
# 存到 global(显式 --global)
dotvault --global set GITHUB_TOKEN ghp_xxx

# 项目没有 .dotvault_key 时,set/get/export 自动 fallback 到 global
dotvault set PERSONAL_API_KEY xxx     # 无 .dotvault_key → 写进 global

# 从 global 导出
dotvault --global export
dotvault --global get GITHUB_TOKEN

# 强制用 global(即使项目已绑定)
dotvault --global list
```

优先级:`--global` 显式指定 > 项目 `.dotvault_key` > (无 key 文件时)自动 fallback 到 global。

## 典型工作流

### 场景 1:项目首次配置密钥
```sh
dotvault --key ~/.ssh/id_ed25519 init myapp          # 建 namespace + 写 .dotvault_key
dotvault set DATABASE_URL "postgres://..."            # 存
dotvault set API_TOKEN "ghp_xxx"
dotvault set STRIPE_KEY "sk_live_xxx"
dotvault export > .env                                # 生成 .env
```

### 场景 2:运行时注入密钥(不落盘)
```sh
# 启动前临时载入到当前 shell
eval "$(dotvault export | sed 's/^/export /')"

# 或 CI 里取单个 token
TOKEN=$(dotvault get API_TOKEN)
```

### 场景 3:多项目共享 / 切换 namespace
- 多个项目共享一个 namespace:复制 `.dotvault_key` 文件即可。
- 切换当前项目的 namespace:重新 `dotvault init <other>`(覆盖 `.dotvault_key`),或手改文件第一行。

## 模型与安全

- **SSH key 每次都要**:它解密 namespace 下的 vault.bin。真正的密钥持有者。
- **access_key**:存在项目的 `.dotvault_key`(明文,namespace 名 + 随机 key),用来选择并授权 namespace。每次操作会校验它和注册表里 SSH-key 加密的那份一致 —— 防止改文件冒充别的 namespace。
- **namespace 名**:`[a-z0-9][a-z0-9-_]*`,严格校验防路径穿越。
- **存储**:`~/.dotvault/namespaces/<ns>/vault.bin`(AES-256-GCM 密封)+ `.access_key.enc`。
- **并发**:每个 namespace 有独占锁,多进程同时写不会丢更新。

## 常见错误处理

| 错误 | 原因 / 解决 |
|------|------------|
| `no access key at .dotvault_key` | 项目还没 `init <ns>`,先绑定 namespace |
| `secret "X" already exists` | 已存在,先 `rm X` 再 `set` |
| `fingerprint mismatch` | SSH key 不对;换对的 key,或 `rekey` |
| `access key rejected` | `.dotvault_key` 被改坏/从别处拷错;重新 `init` 或恢复正确文件 |
| `timed out waiting for lock` | 别的进程卡住了;`rm ~/.dotvault/namespaces/<ns>/.lock` |
| legacy PEM format | `ssh-keygen -p -m PEM -f <key>` 转成 OpenSSH 格式 |

## 重要约束

- 不要把 `.dotvault_key` 提交到 git(它在 `.gitignore` 里)。
- `set` 不自动覆盖 —— 这是有意的 fail-fast 设计,助手不应绕过(不要帮用户自动 `rm`+`set`,先问用户)。
- 路径含 `~` 的,助手展开成绝对路径再传给命令更稳妥。
