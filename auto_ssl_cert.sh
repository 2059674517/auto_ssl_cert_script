#!/bin/bash
# 脚本内容...
# 判断今天是否是执行日（每10天一次）
LAST_RUN_FILE="/yourpath/ssl_cert_last_run"
TODAY=$(date +%s)

# 如果上次执行文件不存在，创建它并执行
if [ ! -f "$LAST_RUN_FILE" ]; then
    echo "$TODAY" > "$LAST_RUN_FILE"
    python3 /yourpath/auto_ssl_cert.py
    exit 0
fi

# 读取上次执行时间
LAST_RUN=$(cat "$LAST_RUN_FILE")
DAYS_SINCE=$(( (TODAY - LAST_RUN) /86400 ))  # 86400秒 = 1天

# 如果距离上次执行超过或等于10天，执行并更新时间
if [ $DAYS_SINCE -ge 10 ]; then
    python3 /yourpath/auto_ssl_cert.py
    echo "$TODAY" > "$LAST_RUN_FILE"
fi