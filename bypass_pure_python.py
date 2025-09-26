import sys
sys.path.append(".local/lib/python3.13/site-packages")
import binascii
from mitmproxy import http
import Login_pb2
from decrypt_pure import AESUtils
from proto_pure import ProtobufUtils
import requests
import time
from mitmproxy.tools.main import mitmdump
import threading

# Use pure Python implementations
aesUtils = AESUtils()
protoUtils = ProtobufUtils()

def hexToOctetStream(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str)

def fetchUIDsFromServer():
    """Always fetch UIDs from server in real-time (no cache, no local file)."""
    try:
        print("[UID] Fetching UIDs from server...")
        response = requests.get("http://node1.danink.cloud:19109/raw/uid", timeout=10)
        response.raise_for_status()
        
        uids = []
        for line in response.text.strip().split('\n'):
            line = line.strip()
            if line and line.isdigit():
                uids.append(line)
        
        print(f"[UID] Loaded {len(uids)} UIDs from server")
        return uids
        
    except requests.RequestException as e:
        print(f"[UID] Error fetching from server: {e}")
        return []
    except Exception as e:
        print(f"[UID] Unexpected error: {e}")
        return []

# --- Background auto update ---
def autoUpdateUIDs(interval=5):
    def loop():
        while True:
            try:
                fetchUIDsFromServer()  # always live fetch
            except Exception as e:
                print(f"[UID] Auto update error: {e}")
            time.sleep(interval)
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()
# -------------------------------

def checkUIDExists(uid: str) -> bool:
    uid = uid.strip()
    valid_uids = fetchUIDsFromServer()  # always live fetch
    return uid in valid_uids

class MajorLoginInterceptor:
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.request.method.upper() == "POST" and "/MajorLogin" in flow.request.path:
            enc_body = flow.request.content.hex()
            dec_body = aesUtils.decrypt_aes_cbc(enc_body)
            body = protoUtils.decode_protobuf(dec_body.hex(), Login_pb2.LoginReq)

            body.deviceData = "KqsHTxnXXUCG8sxXFVB2j0AUs3+0cvY/WgLeTdfTE/KPENeJPpny2EPnJDs8C8cBVMcd1ApAoCmM9MhzDDXabISdK31SKSFSr06eVCZ4D2Yj/C7G"
            body.reserved20 = b"\u0013RFC\u0007\u000e\\Q1"

            binary_data = body.SerializeToString()
            finalEncContent = aesUtils.encrypt_aes_cbc(
                hexToOctetStream(binary_data.hex())
            )
            flow.request.content = bytes.fromhex(finalEncContent.hex())

    def response(self, flow: http.HTTPFlow) -> None:
        if (
            flow.request.method.upper() == "POST"
            and "MajorLogin".lower() in flow.request.path.lower()
        ):
            respBody = flow.response.content.hex()
            decodedBody = protoUtils.decode_protobuf(respBody, Login_pb2.getUID)
            checkUID = checkUIDExists(str(decodedBody.uid))

            if not checkUID:
                flow.response.content = (
                    f"[FF00FF]╔════════════════════════╗\n"
                    f"[FF00FF][00FF00]★ BUY THE UID BYPASS FROM ★ [FF00FF]║ [00FF00]★ 1nOnlySahil ★ [FF00FF]║\n"
                    f"[FF00FF]╠════════════════════════╣\n"
                    f"[FFFF33] ➜ UID: [FFFFFF]{decodedBody.uid}\n"
                    f"[FF00FF]╚════════════════════════╝\n"
                ).encode()
                flow.response.status_code = 400
                return None

addons = [MajorLoginInterceptor()]

if __name__ == "__main__":

    mitmdump([
        "-s", "bypass_pure_python.py",
        "-p", "20010",
        "--set", "block_global=false"
    ])
