# resilient-delivery

可恢复的分发列表投递库。SQLite + 本地文件持久化，`cryptography` 真实加密
（AES-256-GCM 分块流式加密，数据密钥以 RSA-OAEP-SHA256 封装）。

## 模型

- 调用方完成收件人展开与去重，每项提供唯一 `recipient_id` 与 RSA-2048 公钥。
- 正文与附件已合成为一条 ≤ 64 MiB 的字节流，库不解析邮件格式。
- 明文与明文对称密钥永不落盘：消息在 `submit` 时以随机消息密钥流式加密后
  存储，消息密钥由 32 字节本地主密钥（仅在内存中）封装后入库。
- 每个收件人使用独立随机数据密钥；副本逐块生成、逐块提交（单收件人事务），
  `limit=1` 时留下可跨重启复用的进度。全部提交后一次原子 UPDATE 发布，
  发布前任何收件人都不可 `read`，发布后全部可读。

## 使用

```python
import os
from resilient_delivery import DeliveryService, Recipient, decrypt_copy

master_key = os.urandom(32)                      # 重启时需提供同一主密钥
svc = DeliveryService("/path/to/storage", master_key)

recipients = [Recipient("alice", alice_pubkey_der), ...]   # 公钥 DER/PEM 或对象
status = svc.submit("request-123", recipients, stream)     # stream 只顺序读一次

status = svc.advance("request-123", limit=10)    # 可反复调用直至 state == "published"

copy = svc.read("request-123", "alice")          # 仅已发布后可读
# copy 包含独立程序解密所需的全部信息：
#   key_wrap="RSA-OAEP-SHA256", wrapped_data_key, algorithm="AES-256-GCM-CHUNKED",
#   nonce_prefix, chunk_size, ciphertext
plaintext = decrypt_copy(alice_private_key, copy)  # 独立解密（测试/示例）
```

幂等性：同一 `request_id` 携带相同字节流与相同收件人集合（顺序无关）重复
`submit` 返回原投递；内容、成员或任一公钥不同则抛 `ConflictError`，原投递不变。

崩溃恢复：进程可在任意时刻被强杀。重启后以同一存储路径与主密钥重新打开，
反复调用 `advance` 收敛到恰好每人一个可解密副本；已提交副本原样复用，
已发布投递不会退回不可见。

## 存储布局

```
storage/
  delivery.db                  SQLite 元数据（WAL, synchronous=FULL）
  messages/<request_id>.msg    消息密文（分块 AES-256-GCM）
  copies/<request_id>/<rid>.copy  各收件人密文副本
  tmp/                         暂存区（fsync 后原子 rename）
```

## 运行测试

```bash
python3 -m pytest tests/ -q
```

依赖：`cryptography`（运行）、`pytest`（测试）。崩溃恢复测试通过
`tests/crash_worker.py` 子进程在精确提交点 SIGKILL 自身模拟强杀。
