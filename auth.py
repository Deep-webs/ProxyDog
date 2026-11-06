"""认证层：面板账号（PBKDF2）+ API Key + 会话。

设计取舍：
- 不引入 Flask-Login / bcrypt 之类的额外依赖，PBKDF2-HMAC-SHA256 12 万轮足够；
- 会话密钥持久化在 data/secret.key，重启不会把所有人踢下线；
- API Key 用于给外部程序调用取用接口，可单独停用/删除，泄漏了也不用改密码；
- 保留旧的 `?token=` 方式，方便已经从脚本里调过的场景继续用。
"""

import hashlib
import hmac
import os
import secrets

ITERATIONS = 120_000


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                             bytes.fromhex(salt), ITERATIONS)
    return dk.hex(), salt


def verify_password(password, pwd_hash, salt):
    calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               bytes.fromhex(salt), ITERATIONS).hex()
    return hmac.compare_digest(calc, pwd_hash or "")


def random_password(length=12):
    """去掉容易混淆的字符，方便手抄。"""
    alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def new_api_key():
    return "pd-" + secrets.token_urlsafe(24)


def load_or_create_secret(path):
    if os.path.exists(path):
        with open(path, "rb") as fh:
            data = fh.read()
        if len(data) >= 32:
            return data
    data = secrets.token_bytes(48)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    try:
        os.chmod(path, 0o600)
    except Exception:
        pass
    return data


class LoginGuard:
    """同一 IP 连续失败 N 次锁 M 分钟，防止面板被在线爆破。"""

    def __init__(self, max_fail=5, lock_minutes=10):
        self.max_fail = max_fail
        self.lock_seconds = lock_minutes * 60
        self._fails = {}          # ip -> [count, last_ts]

    def locked(self, ip):
        import time
        rec = self._fails.get(ip)
        if not rec:
            return 0
        count, last = rec
        if count < self.max_fail:
            return 0
        left = int(self.lock_seconds - (time.time() - last))
        return max(0, left)

    def fail(self, ip):
        import time
        count, _ = self._fails.get(ip, (0, 0))
        self._fails[ip] = (count + 1, time.time())

    def reset(self, ip):
        self._fails.pop(ip, None)
