---
name: dotvault
description: "用 dotvault 管理项目的加密密钥/API key/token,并以 .env 格式导出。age 多接收方加密,每个团队成员用自己的 SSH 私钥解密。触发: store a secret, API key, generate .env, manage secrets, 密钥, 加密存储, 环境变量, add-key, 授权队友"
---

# dotvault skill

用 dotvault 给项目存取密钥(API key、token、password),并以 `.env` 兼容格式
导出。密钥存在项目根的 `.vault` 文件里([age](https://age-encryption.org) 加密),
提交进 git;团队每个成员用自己的 SSH 私钥解密。

## 核心原则

- **先确认环境**:运行 `dotvault version` 确认已安装;若项目根没有 `.vault`,
  先 `dotvault init`。
- **SSH key 是必须的**:每次操作都要 `--key`(默认 `~/.ssh/id_ed25519`,或设
  `DOTVAULT_KEY` 环境变量,或 `dotvault config --set-key`)。能解密 = 你的公钥
  在 `.vault.keys` 里。
- **fail-fast,不擅自做主**:`set` 已存在的 key 会报错(先 `rm`);`get`/`rm`
  不存在的 key 会报错。绝不静默覆盖。
- **明文输出走 stdout**:命令提示走 stderr,`export`/`get` 的密文走 stdout,
  可直接重定向。

## 命令速查

```sh
# 一次性环境引导(创建 ~/.dotvault/ + 默认配置;幂等,不覆盖已有配置)
dotvault install

# 在项目根创建 .vault + .vault.keys(用你自己的公钥作为初始接收方)
dotvault --key ~/.ssh/id_ed25519 init

# 存密钥(key 名必须匹配 [A-Za-z_][A-Za-z0-9_]*)
dotvault --key ~/.ssh/id_ed25519 set <NAME> <value>

# 取单个值(无尾换行,适合 $(...) 捕获)
dotvault --key ~/.ssh/id_ed25519 get <NAME>

# 列出 key 名 / 导出全部为 KEY=VALUE
dotvault --key ~/.ssh/id_ed25519 list
dotvault --key ~/.ssh/id_ed25519 export
dotvault --key ~/.ssh/id_ed25519 export > .env

# 删除(不存在则报错)
dotvault --key ~/.ssh/id_ed25519 rm <NAME>

# 授权队友(公钥行 / *.pub 文件 / @文件)
dotvault --key ~/.ssh/id_ed25519 add-key ~/.ssh/bob_id_ed25519.pub

# 吊销队友(按指纹 SHA256:... 或 label)
dotvault --key ~/.ssh/id_ed25519 remove-key <FINGERPRINT|LABEL>

# 列出已授权的接收方
dotvault --key ~/.ssh/id_ed25519 list-keys

# 体检 / 看版本
dotvault --key ~/.ssh/id_ed25519 doctor
dotvault version                       # 输出版本+git hash;若新版可用,stderr 提示一行
```

省略 `--key` 的方式:`export DOTVAULT_KEY=~/.ssh/id_ed25519`,或
`dotvault config --set-key <path>`。

## 团队协作(多接收方)

`.vault` 是 age 多接收方加密文件:加密到 `.vault.keys` 里**每一个**公钥,任一
授权私钥都能解密。加/减队友 = 改清单 + 重新加密。

```sh
# Alice 创建项目 vault 并加 secret
dotvault init
dotvault set DB_PASSWORD s3cret

# Alice 授权 Bob(用他的公钥)
dotvault add-key ~/.ssh/bob_id_ed25519.pub

# Bob 拉取后(更新后的 .vault + .vault.keys 已 commit),用自己的 key 解密
dotvault get DB_PASSWORD                # OK
```

**吊销的局限(重要)**:`remove-key` 只重新加密**当前** `.vault`。已提交进 git
历史的旧密文仍可被吊销者解密(旧 file key 曾包装给他)。真要吊销,必须同时
**轮换 secret 值**(`set` 新的密码/token),让历史密文失效。

谁能改 `.vault.keys`?有仓库写权限的人(它只是个提交进 git 的文件)。和 sops /
git-crypt 同一信任模型。

## 典型工作流

### 场景 1:项目首次配置密钥
```sh
dotvault --key ~/.ssh/id_ed25519 init                  # 建 .vault + .vault.keys
dotvault set DATABASE_URL "postgres://..."             # 存
dotvault set API_TOKEN "ghp_xxx"
dotvault set STRIPE_KEY "sk_live_xxx"
dotvault export > .env                                 # 生成 .env
```

### 场景 2:运行时注入密钥(不落盘)
```sh
# 启动前临时载入到当前 shell
eval "$(dotvault export | sed 's/^/export /')"

# 或 CI 里取单个 token
TOKEN=$(dotvault get API_TOKEN)
```

### 场景 3:新人加入 / 离开
```sh
# 加入:管理员 add-key 后提交,新人 pull 即可解密
dotvault add-key ~/.ssh/newguy.pub
git add .vault .vault.keys && git commit -m "vault: add newguy"

# 离开:remove-key + 轮换 secret
dotvault remove-key SHA256:xxx
dotvault set DB_PASSWORD <新的密码>    # 轮换,让历史密文失效
```

## 模型与安全

- **`.vault`**:age 加密文件(ChaCha20-Poly1305 AEAD),加密到 `.vault.keys`
  全部公钥。每个接收方一条 stanza(密钥槽)。
- **`.vault.keys`**:人类可读 JSON,列出授权公钥 + 指纹 + label。提交进 git,
  可审计。
- **授权 = 持有对应私钥**:你的公钥在清单里 → 你能解密。无单独 access token。
- **存储位置**:密钥只在项目的 `.vault` / `.vault.keys`,**提交进 git**。
  `~/.dotvault/` 只有 config / backups / 更新缓存,**无任何 secret**。
- **并发**:项目 `.vault` 有独占锁(`.vault.lock`,gitignored),多进程同时写
  不会丢更新。
- **不自动迁移**:v0.3 的集中式 namespace 格式不兼容,需手动 `init` + 重新 `set`。

## 常见错误处理

| 错误 | 原因 / 解决 |
|------|------------|
| `no vault at .vault` | 项目还没 `init`,先创建 |
| `secret "X" already exists` | 已存在,先 `rm X` 再 `set` |
| `decryption failed: no matching key` | 你的私钥不在 `.vault.keys` 里;找管理员 `add-key` 你的公钥 |
| `key ... is already authorized` | add-key 重复;该公钥已在清单 |
| `cannot remove the last authorized key` | 至少保留一个接收方,否则 vault 无法恢复 |
| `timed out waiting for lock` | 别的进程卡住了;`rm ./.vault.lock` |
| legacy PEM format | `ssh-keygen -p -m PEM -f <key>` 转成 OpenSSH 格式 |

## 重要约束

- `.vault` 和 `.vault.keys` **要提交进 git**(团队共享)。只有 `.vault.lock`
  在 `.gitignore` 里。
- `set` 不自动覆盖 —— 这是有意的 fail-fast 设计,助手不应绕过(不要帮用户自动
  `rm`+`set`,先问用户)。
- `remove-key` 后务必提醒用户轮换 secret,否则历史密文仍可被吊销者解密。
- 路径含 `~` 的,助手展开成绝对路径再传给命令更稳妥。
