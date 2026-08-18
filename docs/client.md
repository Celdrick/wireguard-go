## 配置生成脚本

可使用仓库内脚本一次性生成服务端和多个客户端配置：

```bash
bash scripts/gen-configs.sh \
  --server-endpoint 152.67.198.96 \
  --clients win1,linux1 \
  --output-dir ./out/demo
```

也可先复制 `scripts/example.env` 再使用：

```bash
bash scripts/gen-configs.sh --config scripts/example.env
```
