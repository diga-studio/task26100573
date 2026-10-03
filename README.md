# luna_delivery

可恢复的分发列表投递库。调用方完成收件人展开/去重后，把一条最长
64 MiB 的字节流持久接收进来，随后按可恢复的增量方式为每名收件人生成
独立加密的投递副本，全部完成后一次性原子发布。

## 安全与持久化设计

- 正文：submit 时用随机消息密钥做分块 AES-256-GCM（1 MiB/块，随机 nonce
  前缀 + 块序号）流式加密落盘 `messages/<request_id>.msg`；消息密钥用
  32 字节本地主密钥（AES-256-GCM）封装后存 SQLite。明文与明文对称密钥
  从不落盘（含暂存文件，临时文件一律先加密再写）。
- 副本：advance 逐收件人从消息密文流式解密→用该收件人独立的随机
  AES-256 数据密钥重新分块加密，写入 `copies/<rid>/<recipient>.bin`
  （先写 `*.tmp` 再原子 rename + 目录 fsync）；数据密钥以收件人
  RSA-2048 公钥做 RSA-OAEP-SHA256 封装后存 SQLite。每个收件人一个小事务
  提交，`limit=1` 也留下可跨重启复用的进度。
- 发布：全部副本提交后，单个 SQLite 事务把投递置为 `published` 并删除
  消息密钥，随后删除消息密文文件。发布前任何 `read` 都返回未可见，
  发布后全员可读，不存在部分可见的中间态。
- 崩溃恢复：重启打开同一存储目录时清理孤儿消息文件与 `*.tmp`；已提交
  副本原样复用（密文不变），未提交的重写。SQLite 使用 WAL +
  `synchronous=FULL`。
- 幂等：`request_id` 的身份由「内容 SHA-256 + 收件人集合（含公钥，
  顺序无关）哈希」共同决定。重复 submit 相同内容返回原投递；内容、
  成员或任一公钥不同抛 `ConflictError`，原投递不受影响。
- 内存：全程 1 MiB 分块流式处理，submit/advance 相对解释器基线的额外
  峰值内存 < 24 MiB（有 64 MiB 输入的自动化测试验证）。

## API

```python
from luna_delivery import DeliveryStore, Recipient, decrypt_copy

store = DeliveryStore("/path/to/store", master_key)  # master_key: 32 bytes
store.submit(request_id, [Recipient(rid, pubkey_pem), ...], stream)  # -> request_id
status = store.advance(request_id, limit)   # 可反复调用直到 status.state == "published"
copy = store.read(request_id, recipient_id) # 仅发布后可见，否则 NotVisibleError
plaintext = decrypt_copy(recipient_private_key_pem, copy)  # 独立解密
```

`EncryptedCopy` 包含独立程序解密所需的全部信息：`algorithm`
（`RSA-OAEP-SHA256+AES-256-GCM-chunked`）、`wrapped_data_key`、
`nonce_prefix`、`chunk_size`、`ciphertext`。密文按块拼接，第 i 块的
GCM nonce 为 `nonce_prefix || i(4 字节大端)`，每块密文比明文多 16 字节
GCM tag。

## 运行测试

```bash
python3 -m pytest tests/ -q
```

测试覆盖：基本往返与全有/全无可见性、收件人乱序的幂等重投、内容/公钥/
成员变更的冲突重投、风扇出中途 SIGKILL 后移除输入源再恢复（旧副本密文
逐字节不变）、副本产生与进度提交之间 SIGKILL、发布前后 SIGKILL、submit
提交前 SIGKILL 的孤儿清理，以及 64 MiB 输入下的内存上界。崩溃均通过
真实子进程 SIGKILL 注入（库内 `LUNA_DELIVERY_KILL_AT` 测试钩子），
不以可捕获异常代替。
