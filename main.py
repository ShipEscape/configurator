import hmac
import os
import re
import shlex
import socket
import subprocess
import threading
import time

import dbus
from flask import Flask, Response, jsonify, redirect, request, send_from_directory

DATA_DIR = "/home/xzt/terminal/data"
PASSWORD = os.environ.get("PORTAL_PASSWORD", "")
RESTART_CMD = "systemctl restart --no-block shipescape-terminal"
BUS = "com.github.davesteele.comitup"
ID_RE = re.compile(r"^[\w.-]{1,64}$", re.ASCII)
ADDR_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}:(\d{1,5})$")

app = Flask(__name__, static_folder="static")

def get_current_portal_host() -> str:
    """动态获取当前面向该客户端的真实服务端 IP:Port"""
    host = request.host.split(":")[0]

    # 如果请求头已经是 IP、.local 域名或 localhost，说明客户端已经完成了重定向，直接使用
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host) or host.endswith(".local") or host == "localhost":
        return request.host

    # 客户端通过外部域名访问
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect((request.remote_addr or "8.8.8.8", 80))
            local_ip = s.getsockname()[0]
    except OSError:
        local_ip = socket.gethostbyname(socket.gethostname())

    port = request.environ.get("SERVER_PORT", "80")
    return f"{local_ip}:{port}" if port not in ("80", "443") else local_ip

def is_local_request() -> bool:
    """判断请求是否已经访问在本机服务域名/IP 下。"""
    host = request.host.split(":")[0]
    return bool(re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", host) or host.endswith(".local") or host == "localhost")


@app.before_request
def portal_gateway_dispatch():
    if not is_local_request():
        return redirect(f"http://{get_current_portal_host()}/", code=302)

    if PASSWORD and request.path.startswith("/api/"):
        a = request.authorization
        if not (a and hmac.compare_digest(a.password or "", PASSWORD)):
            return Response("需要密码", 401, {"WWW-Authenticate": 'Basic realm="portal"'})


def ciu():
    return dbus.Interface(dbus.SystemBus().get_object(BUS, "/com/github/davesteele/comitup"), BUS)


def valid_addr(a: str) -> bool:
    m = ADDR_RE.match(a)
    return bool(m and 0 < int(m.group(1)) < 65536)


def read_file(path: str) -> str:
    try:
        return open(path, encoding="utf-8").read().strip("\x00\n ")
    except OSError:
        return ""


def write_file(name: str, text: str):
    os.makedirs(DATA_DIR, exist_ok=True)
    path = os.path.join(DATA_DIR, name)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        f.write(text)
    try:
        st = os.stat(DATA_DIR)
        os.chown(tmp, st.st_uid, st.st_gid)
    except (AttributeError, PermissionError):
        pass
    os.replace(tmp, path)


def apply(ssid: str, pw: str):
    if ssid:
        try:
            ciu().connect(ssid, pw)
            for _ in range(40):
                state, conn = ciu().state()
                if str(state) == "CONNECTED" and str(conn) == ssid:
                    break
                time.sleep(1)
        except Exception as e:
            print(f"连接 Wi-Fi 失败：{e}")
    if RESTART_CMD:
        subprocess.run(shlex.split(RESTART_CMD))


@app.get("/api/wifi")
def api_wifi():
    try:
        c = ciu()
        state, conn = c.state()
        best = {}
        for ap in c.access_points():
            s, strg = str(ap["ssid"]), int(float(ap["strength"]))
            if s and (s not in best or strg > best[s]["strength"]):
                best[s] = {"ssid": s, "strength": strg, "secure": str(ap["security"]) == "encrypted"}
                
        local_host = f"{socket.gethostname()}.local"
        
        return jsonify(
            state=str(state),
            connection=str(conn),
            hostnames=[local_host],  # 此处直接返回系统的主机名，即 ['raspberrypi.local']
            points=sorted(best.values(), key=lambda p: -p["strength"])
        )
    except Exception as e:
        return jsonify(error=f"无法访问 Comitup：{e}"), 503


@app.get("/api/config")
def api_config_get():
    return jsonify(
        device_id=read_file(os.path.join(DATA_DIR, "device_id.txt")),
        server_ip_port=read_file(os.path.join(DATA_DIR, "server_ip_port.txt")),
        serial=read_file("/proc/device-tree/serial-number")
    )


@app.post("/api/config")
def api_config_set():
    d = request.get_json(silent=True) or {}
    did = str(d.get("device_id", "")).strip()
    addr = str(d.get("server_ip_port", "")).strip()
    ssid, pw = str(d.get("ssid", "")), str(d.get("password", ""))

    # 设备 ID 校验：非空时只允许 字母/数字/下划线/点/短横线，长度 1~64 位
    if did and not ID_RE.match(did):
        return jsonify(error="设备 ID 只能包含字母、数字、下划线、点和短横线（最多 64 位）"), 400
    if not valid_addr(addr):
        return jsonify(error="服务器地址不能为空，格式为 主机:端口，例如 192.168.1.10:8080"), 400
    if ssid and pw and not 8 <= len(pw) <= 63:
        return jsonify(error="Wi-Fi 密码长度应为 8 到 63 位"), 400

    write_file("device_id.txt", did)
    write_file("server_ip_port.txt", addr)

    if ssid or RESTART_CMD:
        threading.Timer(1.0, apply, (ssid, pw)).start()
    return jsonify(ok=True, wifi=bool(ssid), restart=bool(RESTART_CMD))


@app.get("/api/config/test")
def api_config_test():
    addr = request.args.get("addr", "").strip()
    if not valid_addr(addr):
        return jsonify(ok=False, error="地址格式应为 主机:端口"), 400
    host, port = addr.rsplit(":", 1)
    try:
        socket.create_connection((host, int(port)), timeout=3).close()
        return jsonify(ok=True)
    except OSError as e:
        return jsonify(ok=False, error=e.strerror or str(e))


@app.get("/")
def index():
    return send_from_directory(app.static_folder, "index.html")


@app.errorhandler(404)
def fallback(_):
    if request.path.startswith("/api/"):
        return jsonify(error="未找到"), 404

    return redirect(f"http://{get_current_portal_host()}/", code=302)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 80)), threaded=True)