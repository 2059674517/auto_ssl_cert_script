#!/bin/bash
# �ű�����...
# �жϽ����Ƿ���ִ���գ�ÿ10��һ�Σ�
LAST_RUN_FILE="/yourpath/ssl_cert_last_run"
TODAY=$(date +%s)

# ����ϴ�ִ���ļ������ڣ���������ִ��
if [ ! -f "$LAST_RUN_FILE" ]; then
    echo "$TODAY" > "$LAST_RUN_FILE"
    python3 /yourpath/auto_ssl_cert.py
    exit 0
fi

# ��ȡ�ϴ�ִ��ʱ��
LAST_RUN=$(cat "$LAST_RUN_FILE")
DAYS_SINCE=$(( (TODAY - LAST_RUN) /86400 ))  # 86400�� = 1��

# ��������ϴ�ִ�г��������10�죬ִ�в�����ʱ��
if [ $DAYS_SINCE -ge 10 ]; then
    python3 /yourpath/auto_ssl_cert.py
    echo "$TODAY" > "$LAST_RUN_FILE"
fi