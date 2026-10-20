#!/usr/bin/env python3
# 把 uploads/ 旧文件迁入 D1 分片池（公共 tag=home），走 catbox-test 分片接口。
# 用法: python3 migrate_to_d1.py [uploads目录]
import base64, json, subprocess, sys, os, hashlib

SHARD = "https://utau-catbox-test.pages.dev/api/shards"
ORIGIN = "https://songyuheng800.github.io"
CHUNK = 900 * 1024
ALLOWED = {"ust", "ustx", "vsq", "vsqx", "vpr", "pp2", "pp3", "zip", "rar"}

def curl_post(path, obj):
    body = json.dumps(obj).encode()
    p = subprocess.run(
        ["curl", "-sk", "--max-time", "60", "--retry", "3",
         "-X", "POST", SHARD + path,
         "-H", f"Origin: {ORIGIN}",
         "-H", "Content-Type: application/json",
         "--data-binary", "@-"],
        input=body, capture_output=True)
    try:
        return json.loads(p.stdout.decode())
    except Exception:
        return {"ok": False, "msg": "bad response: " + p.stdout[:200].decode(errors="ignore")}

def migrate_file(path):
    raw = open(path, "rb").read()
    name = os.path.basename(path)
    chunk_count = max(1, -(-len(raw) // CHUNK))
    init = curl_post("/init", {
        "name": name, "mime": "application/octet-stream",
        "totalSize": len(raw), "chunkCount": chunk_count,
        "tags": ["home"], "uploader": "migrate",
    })
    if not init.get("ok"):
        return name, False, init.get("msg")
    fid = init["fileId"]
    for i in range(chunk_count):
        part = raw[i * CHUNK:(i + 1) * CHUNK]
        h = hashlib.sha256(part).hexdigest()
        r = curl_post("/chunk", {"fileId": fid, "index": i,
                                 "data": base64.b64encode(part).decode(), "hash": h})
        if not r.get("ok"):
            return name, False, f"chunk {i}: {r.get('msg')}"
    fin = curl_post("/finalize", {"fileId": fid})
    if not fin.get("ok"):
        return name, False, "finalize: " + str(fin.get("msg"))
    return name, True, fid

def main():
    src = sys.argv[1] if len(sys.argv) > 1 else "uploads"
    ok, fail = [], []
    for fn in sorted(os.listdir(src)):
        ext = fn.rsplit(".", 1)[-1].lower() if "." in fn else ""
        if ext not in ALLOWED:
            continue
        name, success, info = migrate_file(os.path.join(src, fn))
        (ok if success else fail).append((name, info))
        print(("OK  " if success else "FAIL"), name, info)
    print(f"\n成功 {len(ok)}，失败 {len(fail)}")

if __name__ == "__main__":
    main()
