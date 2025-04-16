#!/bin/bash

LOGFILE="./install_and_run.log"
ENC_KEY="1234567890abcdef1234567890abcdef"  # 可修改为你的加密key

echo "======== Web3 自动安装与运行脚本 ========"
echo "安装过程日志将保存到 $LOGFILE"
echo "========================================="

# 选择是否创建虚拟环境
read -p "是否创建 Python 虚拟环境？(y/n): " use_venv

if [[ $use_venv == "y" ]]; then
  echo "[INFO] 创建虚拟环境..." | tee -a "$LOGFILE"
  python3 -m venv venv >> "$LOGFILE" 2>&1
  source venv/bin/activate
else
  echo "[INFO] 使用全局 Python 环境" | tee -a "$LOGFILE"
fi

# 安装系统依赖
echo "[INFO] 安装 Node.js、npm、pm2、curl、Python pip..." | tee -a "$LOGFILE"
sudo apt update -y >> "$LOGFILE" 2>&1
sudo apt install -y nodejs npm python3-pip curl >> "$LOGFILE" 2>&1
sudo npm install -g pm2 >> "$LOGFILE" 2>&1

# 安装 Python 依赖
echo "[INFO] 安装 Python 库..." | tee -a "$LOGFILE"
pip install web3 requests cryptography >> "$LOGFILE" 2>&1

# 输入 PRIVATE_KEY
read -sp "请输入你的 PRIVATE_KEY（不会回显）: " PRIVATE_KEY
echo
export PRIVATE_KEY="$PRIVATE_KEY"

# 创建任务脚本 /tmp/x.py
echo "[INFO] 生成主任务脚本..." | tee -a "$LOGFILE"
cat <<EOF > /tmp/x.py
import os
print("✅ 脚本成功运行！你的 PRIVATE_KEY 是:", os.getenv("PRIVATE_KEY"))
EOF

# 创建加密脚本 /tmp/enc.py
cat <<EOF > /tmp/enc.py
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

key = os.environ.get('ENC_KEY', '')[:32].encode()
iv = b"1234567890abcdef"
cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
encryptor = cipher.encryptor()

with open("/tmp/x.py", "rb") as f:
    data = f.read()

with open("/tmp/x.enc", "wb") as f:
    f.write(encryptor.update(data) + encryptor.finalize())

print("✅ 脚本已加密为 /tmp/x.enc")
EOF

# 执行加密
echo "[INFO] 正在加密脚本..." | tee -a "$LOGFILE"
ENC_KEY=$ENC_KEY python3 /tmp/enc.py >> "$LOGFILE" 2>&1

# 选择是否 pm2 托管
read -p "是否使用 pm2 后台运行脚本？(y/n): " use_pm2

if [[ $use_pm2 == "y" ]]; then
  echo "[INFO] 使用 pm2 启动脚本..." | tee -a "$LOGFILE"
  pm2 start /tmp/x.py --interpreter python3 --name crosschain >> "$LOGFILE" 2>&1
  pm2 save >> "$LOGFILE" 2>&1
  echo "✅ 已使用 pm2 托管运行任务：crosschain"
else
  echo "[INFO] 直接运行脚本..." | tee -a "$LOGFILE"
  python3 /tmp/x.py
fi

echo "✅ 所有操作完成！"
