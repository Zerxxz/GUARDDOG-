#!/usr/bin/env python3
"""GUARDDOG demo — deterministic final build.

Pipeline (single source of truth, no PTS drift):
  1. body.mp4   = raw5 recording, cropped (hide Chrome banner), slow drift motion, NO captions
  2. base.mp4   = title card + body + outro via concat FILTER (re-encode, correct PTS)
  3. final.mp4  = base + captions burned at FINAL timeline (raw_time + TITLE) + fades
  4. audio      = ElevenLabs segments placed at raw_time + TITLE, padded to full length
"""
import json, os, subprocess

V = "/home/ubuntu/guarddog/demo/video"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONTB = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"
MONO = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"

TITLE = 2.8
OUTRO = 4.2
SRC = 89.0
TOTAL = TITLE + SRC + OUTRO

def sh(c):
    return subprocess.run(c, shell=True, capture_output=True, text=True)

def esc(s):
    for a, b in [("\\", "\\\\"), (":", r"\:"), ("'", r"\'"), (",", r"\,"), ("%", r"\%"),
                 ("[", r"\["), ("]", r"\]"), ("—", r"\—"), ("✗", r"\✗"), ("✓", r"\✓")]:
        s = s.replace(a, b)
    return s

def run(cmd, label):
    r = sh(cmd)
    if r.returncode != 0:
        print(f"{label} ERR:", r.stderr[-1400:]); raise SystemExit(1)
    print(f"{label} ok")

# ---------- 1. title & outro cards ----------
run(f"""ffmpeg -y -f lavfi -i color=c=0x0a0a0a:s=1600x900:d={TITLE} -vf \
"drawtext=fontfile={FONTB}:text='GUARDDOG':fontcolor=0xffffff:fontsize=112:x=(w-text_w)/2:y=(h-text_h)/2-58,\
drawtext=fontfile={FONT}:text='the immune system for AI agents':fontcolor=0x9a9a9a:fontsize=30:x=(w-text_w)/2:y=(h-text_h)/2+22,\
drawtext=fontfile={MONO}:text='live on testnet  ·  NEAR HACKATHON':fontcolor=0x555555:fontsize=19:x=(w-text_w)/2:y=(h-text_h)/2+82,\
fade=t=in:st=0:d=0.8,fade=t=out:st={TITLE-0.9}:d=0.9" \
-c:v libx264 -pix_fmt yuv420p -preset medium -r 24 {V}/card_title.mp4""", "title card")

run(f"""ffmpeg -y -f lavfi -i color=c=0x0a0a0a:s=1600x900:d={OUTRO} -vf \
"drawtext=fontfile={FONTB}:text='GUARDDOG':fontcolor=0xffffff:fontsize=96:x=(w-text_w)/2:y=(h-text_h)/2-72,\
drawtext=fontfile={FONT}:text='Learned from real attackers.':fontcolor=0xb0b0b0:fontsize=30:x=(w-text_w)/2:y=(h-text_h)/2+10,\
drawtext=fontfile={FONT}:text='Enforced where it cannot be bypassed.':fontcolor=0xb0b0b0:fontsize=30:x=(w-text_w)/2:y=(h-text_h)/2+54,\
drawtext=fontfile={MONO}:text='github.com/Zerxxz/GUARDDOG-':fontcolor=0x666666:fontsize=22:x=(w-text_w)/2:y=(h-text_h)/2+136,\
fade=t=in:st=0:d=0.9" \
-c:v libx264 -pix_fmt yuv420p -preset medium -r 24 {V}/card_outro.mp4""", "outro card")

# ---------- 2. body: crop banner + slow drift motion (no captions) ----------
run(f"""ffmpeg -y -i {V}/raw5.mp4 -vf \
"crop=1600:848:0:44,scale=1740:978,crop=1600:900:x='70+52*sin(t/13.0)':y='39+30*cos(t/9.5)'" \
-c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -r 24 -t {SRC} {V}/body.mp4""", "body")

# ---------- 3. concat via filter (re-encode → correct PTS) ----------
run(f"""ffmpeg -y -i {V}/card_title.mp4 -i {V}/body.mp4 -i {V}/card_outro.mp4 \
-filter_complex "[0:v][1:v][2:v]concat=n=3:v=1:a=0[v]" -map "[v]" \
-c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -r 24 {V}/base.mp4""", "concat")

# ---------- 4. captions at FINAL timeline ----------
CAPS = [
    (0.5,  10.6, "Every AI agent that holds money is a target."),
    (13.6, 8.8,  "Sentinel — bait wallets on Base Sepolia"),
    (20.6, 7.6,  "Trap catches the drainer, fingerprints the attack"),
    (26.1, 8.1,  "Verdict published to NEAR — verifiable on chain"),
    (30.1, 8.1,  "Leash — the pre-sign firewall"),
    (36.6, 6.2,  "✗ DENY [blocklist] — transaction never signed"),
    (45.1, 5.7,  "✓ ALLOW — all checks passed"),
    (55.1, 10.0, "NEAR Chain Signatures — 8-node MPC"),
    (71.1, 6.0,  "✓ signature in 14.1s — signed by the network"),
    (78.1, 7.3,  "Built for the NEAR Hackathon"),
]
vf = []
for start, dur, text in CAPS:
    st = start + TITLE
    en = st + dur
    vf.append(
        f"drawtext=fontfile={FONTB}:text='{esc(text)}':fontcolor=0xffffff:fontsize=30:"
        f"box=1:boxcolor=0x0a0a0a@0.78:boxborderw=14:"
        f"x=(w-text_w)/2:y='h-th-44+16*(1-min(1,max(0,(t-{st-0.4})/0.4)))':"
        f"alpha='if(lt(t,{st}),0,if(lt(t,{st+0.4}),(t-{st})/0.4,if(gt(t,{en}),max(0,({en}-t)/0.35),1)))':"
        f"enable='between(t,{st},{en+0.35})'"
    )
vf.append("fade=t=in:st=0:d=0.6")
vf.append(f"fade=t=out:st={TOTAL-1.6}:d=1.6")
run(f"""ffmpeg -y -i {V}/base.mp4 -filter_complex "[0:v]{','.join(vf)}[v]" -map "[v]" \
-c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -r 24 -t {TOTAL} {V}/final.mp4""", "captions")

# ---------- 5. audio ----------
PLAN = json.load(open(f"{V}/nar/plan.json"))
ainputs, afilters = [], []
for i, seg in enumerate(PLAN):
    ainputs += ["-i", seg["path"]]
    st = int((seg["start"] + TITLE) * 1000)
    afilters.append(f"[{i}:a]adelay={st}|{st}[a{i}]")
labels = "".join(f"[a{i}]" for i in range(len(PLAN)))
fc = (f"{';'.join(afilters)};{labels}amix=inputs={len(PLAN)}:normalize=0:duration=longest,"
      f"apad=pad_dur={OUTRO+2},atrim=0:{TOTAL}[aout]")
run(f"ffmpeg -y {' '.join(ainputs)} -filter_complex \"{fc}\" -map \"[aout]\" -c:a aac -b:a 192k {V}/nar_mix2.m4a", "audio mix")

run(f"""ffmpeg -y -i {V}/final.mp4 -i {V}/nar_mix2.m4a -map 0:v -map 1:a \
-c:v copy -c:a copy -t {TOTAL} {V}/final_v3.mp4""", "mux")

print("\nDONE:", V + "/final_v3.mp4")
print("duration:", sh(f"ffprobe -v error -show_entries format=duration -of csv=p=0 {V}/final_v3.mp4").stdout.strip())
print("size:", sh(f"ls -la {V}/final_v3.mp4").stdout.strip())
