#!/usr/bin/env python3
"""GUARDDOG live recording v5 — CDP Input API for clicks/typing (trusted events,
pixel-exact at the element's own coordinates) + xdotool ghost cursor so the
recording SHOWS the mouse pointing where it clicks.

Why v5: v4 used xdotool clicks at CDP-measured viewport coords; the X11 pointer
landed on a different widget (input never received focus -> value stayed empty).
CDP Input.dispatchMouseEvent hits the exact element; xdotool mousemove only
draws the visible cursor at the same spot.
"""
import json, os, random, subprocess, sys, time, urllib.request

V, W, H = 99, 1600, 900
OUT = "/home/ubuntu/guarddog/demo/video"
DASH = "http://localhost:8090"
ATTACKER = "0xe613519ae37b0aa867ad249bb38f1355bec0a51c"
CLEAN = "0x00000000000000000000000000000000c0ffee99"
CDP_PORT = 9222

def sh(cmd):
    return subprocess.run(cmd, shell=True, capture_output=True, text=True)

class CDP:
    def __init__(self, port):
        import websocket
        url = None
        for _ in range(4):
            try:
                lst = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json/list", timeout=5))
                for t in lst:
                    if "localhost:8090" in (t.get("url") or ""):
                        url = t["webSocketDebuggerUrl"]; break
                if not url and lst: url = lst[0]["webSocketDebuggerUrl"]
            except Exception: pass
            if url: break
            time.sleep(2)
        if not url: raise RuntimeError("no CDP target")
        self.ws = websocket.create_connection(url, timeout=60)
        self.n = 0
    def _send(self, method, params=None):
        self.n += 1
        self.ws.send(json.dumps({"id": self.n, "method": method, "params": params or {}}))
        while True:
            m = json.loads(self.ws.recv())
            if m.get("id") == self.n:
                if "error" in m: raise RuntimeError(m["error"].get("message", "?"))
                return m.get("result", {})
    def eval(self, expr):
        res = self._send("Runtime.evaluate", {"expression": expr, "returnByValue": True, "awaitPromise": True})
        if "exceptionDetails" in res:
            raise RuntimeError("JS: " + str(res["exceptionDetails"].get("text", "")))
        return res.get("result", {}).get("value")
    def mouse(self, x, y, typ="mousePressed", button="left", clicks=1):
        self._send("Input.dispatchMouseEvent", {
            "type": typ, "x": x, "y": y, "button": button, "buttons": 1 if button == "left" else 0,
            "clickCount": clicks})
    def click(self, x, y):
        self.mouse(x, y, "mouseMoved", "none", 0)
        time.sleep(0.05)
        self.mouse(x, y, "mousePressed")
        time.sleep(0.04)
        self.mouse(x, y, "mouseReleased")
    def text(self, s):
        self._send("Input.insertText", {"text": s})

def ghost(x, y):
    """move the REAL X cursor so the recording shows the pointer"""
    sh(f"DISPLAY=:{V} xdotool mousemove {int(x)} {int(y)}")

def glide(x, y, steps=7):
    for _ in range(steps):
        ghost(x + random.randint(-2, 2), y + random.randint(-2, 2))
        time.sleep(0.04)

def center(jsel):
    sel = json.dumps(jsel)
    v = c.eval(f"(() => {{ const el=document.querySelector({sel}); if(!el) return null; const r=el.getBoundingClientRect(); if(r.width<2||r.height<2) return null; return JSON.stringify({{x:Math.round(r.x+r.width/2), y:Math.round(r.y+r.height/2), w:Math.round(r.width), h:Math.round(r.height)}}); }})()")
    return json.loads(v) if v else None

def click_el(jsel, label, dwell=0.6, wait=20):
    pos = None
    for _ in range(wait):
        pos = center(jsel)
        if pos: break
        time.sleep(1)
    if not pos: raise RuntimeError(f"element not found: {label}")
    glide(pos["x"], pos["y"])
    time.sleep(dwell)
    ghost(pos["x"], pos["y"]); time.sleep(0.15)
    c.click(pos["x"], pos["y"])
    time.sleep(0.3)
    L(f"  click {label} @ ({pos['x']},{pos['y']})")
    return pos

def fill(jsel, value, label):
    pos = click_el(jsel, label, dwell=0.45)
    # select-all + clear via CDP key events
    c._send("Input.dispatchKeyEvent", {"type": "keyDown", "windowsVirtualKeyCode": 65, "modifiers": 2, "key": "a"})
    c._send("Input.dispatchKeyEvent", {"type": "keyUp", "windowsVirtualKeyCode": 65, "modifiers": 2, "key": "a"})
    time.sleep(0.15)
    c._send("Input.dispatchKeyEvent", {"type": "keyDown", "windowsVirtualKeyCode": 8, "key": "Backspace"})
    c._send("Input.dispatchKeyEvent", {"type": "keyUp", "windowsVirtualKeyCode": 8, "key": "Backspace"})
    time.sleep(0.15)
    # type char by char so the on-screen typing is visible
    for ch in value:
        c.text(ch)
        time.sleep(0.035)
    time.sleep(0.3)
    got = c.eval(f"document.querySelector({json.dumps(jsel)}).value")
    L(f"  typed {label}: {got}")
    return got

# ---------------- boot ----------------
sh(f"rm -f /tmp/.X{V}-lock /tmp/.X11-unix/X{V}")
sh("pkill -9 -f Xvfb; pkill -9 -f gd-rec5; sleep 1")
subprocess.Popen(["Xvfb", f":{V}", "-screen", "0", f"{W}x{H}x24"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(2)
sh("rm -rf /tmp/gd-rec5")
chrome = subprocess.Popen([
    "google-chrome", "--user-data-dir=/tmp/gd-rec5", "--no-first-run", "--disable-infobars",
    "--disable-gpu", "--no-sandbox", f"--window-size={W},{H}", "--window-position=0,0",
    f"--remote-debugging-port={CDP_PORT}", "--remote-allow-origins=*", f"--app={DASH}"
], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={**os.environ, "DISPLAY": f":{V}"})

for _ in range(25):
    time.sleep(2)
    try:
        c = CDP(CDP_PORT); break
    except Exception: pass
else: sys.exit("CDP never came up")

for _ in range(25):
    if c.eval("document.querySelectorAll('button').length"): break
    time.sleep(1)
time.sleep(2)

ff = subprocess.Popen([
    "ffmpeg","-y","-f","x11grab","-framerate","24","-video_size",f"{W}x{H}","-draw_mouse","1",
    f"-i",f":{V}","-c:v","libx264","-pix_fmt","yuv420p","-preset","medium","-crf","20",
    f"{OUT}/raw5.mp4"], stdout=open("/tmp/ff5.log","w"), stderr=subprocess.STDOUT)
time.sleep(2)

log = []
def L(s): log.append(str(s)); print(s, flush=True)

try:
    L("[1] landing")
    for p in ((320,420),(760,470),(1040,380),(820,560)): glide(*p); time.sleep(0.45)
    click_el("button[onclick='enterApp()']", "Enter Ops", dwell=0.9)
    time.sleep(3.0)

    L("[2] dashboard — hover sidebar")
    glide(70,250); time.sleep(0.6); glide(72,320); time.sleep(1.2)
    time.sleep(2.5)

    L("[3] decoys")
    click_el("button[data-page='decoys']", "nav Decoys")
    time.sleep(3.4)

    L("[4] threats")
    click_el("button[data-page='threats']", "nav Threat Feed")
    time.sleep(3.4)

    L("[5] leash — attacker DENY")
    click_el("button[data-page='leash']", "nav Leash Check")
    time.sleep(1.6)
    fill("#lc-addr", ATTACKER, "attacker address")
    click_el("#lc-btn", "Run check")
    time.sleep(5.0)
    L("  RESULT#1: " + str(c.eval('document.querySelector("#lc-out").textContent')))

    L("[6] leash — clean ALLOW")
    fill("#lc-addr", CLEAN, "clean address")
    click_el("#lc-btn", "Run check (2)")
    time.sleep(8.0)
    L("  RESULT#2: " + str(c.eval('document.querySelector("#lc-out").textContent')))

    L("[7] actions — MPC live")
    click_el("button[data-page='actions']", "nav Actions")
    time.sleep(1.8)
    click_el("#mpc-btn", "Request MPC signature")
    time.sleep(6)
    L("  MPC#1: " + str(c.eval('document.querySelector("#mpc-out").textContent')))
    for _ in range(14):
        glide(1000, 505); time.sleep(2.2)
        glide(1000, 525); time.sleep(2.2)
    L("  MPC#2: " + str(c.eval('document.querySelector("#mpc-out").textContent')))

    L("[8] stop")
    time.sleep(1.5)
finally:
    ff.terminate(); time.sleep(3)
    chrome.terminate(); time.sleep(1)
    sh("pkill -9 -f gd-rec5; pkill -9 -f Xvfb")
    sh(f"rm -f /tmp/.X{V}-lock /tmp/.X11-unix/X{V}")

print("DONE raw5")
print("duration:", sh(f"ffprobe -v error -show_entries format=duration -of csv=p=0 {OUT}/raw5.mp4").stdout.strip())
open("/tmp/rec5_result.txt","w").write("\n".join(log))
