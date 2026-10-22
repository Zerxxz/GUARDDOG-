#!/usr/bin/env bash
# T14 — record the GUARDDOG demo video end-to-end (headless Chrome + ffmpeg).
# Produces 4 scene recordings and stitches them into one MP4 with title cards.
set -euo pipefail

OUT=/home/ubuntu/guarddog/demo/video
mkdir -p "$OUT"
DASH=http://localhost:8090
FPS=12
SIZE=1600x900

shot() { # shot <name> <seconds>
  timeout $(( $2 + 25 )) google-chrome --headless --disable-gpu --no-sandbox \
    --screenshot="$OUT/$1.png" --window-size=$SIZE \
    --virtual-time-budget=$(( $2 * 1000 )) "$3" >/dev/null 2>&1 || true
}

echo "== stills for title cards =="
shot "00_title"    4 "data:text/html,<body style='background:%230b0f14;color:%233ddc84;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column'><h1 style='font-size:64px'>🐕‍🦺 GUARDDOG</h1><p style='color:%23dbe4ee;font-size:22px'>an immune system for AI agents that hold money</p><p style='color:%237d8ca0'>NEAR HACKATHON 2026 · live testnet demo</p></body>"
shot "08_outro"    4 "data:text/html,<body style='background:%230b0f14;color:%23dbe4ee;font-family:monospace;display:flex;align-items:center;justify-content:center;height:100vh;flex-direction:column'><h1 style='font-size:44px;color:%233ddc84'>every shot above is real.</h1><p style='font-size:20px'>github.com/Zerxxz/GUARDDOG-</p><p style='color:%23ff5470'>deny = the transaction never exists.</p><p style='color:%237d8ca0'>built for NEAR HACKATHON</p></body>"

echo "== dashboard hero (feed + KPIs) =="
shot "01_dashboard" 6 "$DASH"

echo "== leash check: attacker denied =="
shot "02_leash_deny" 5 "$DASH#"

echo "== registry pulse close-up =="
shot "03_feed" 5 "$DASH"

echo "== build video from stills with slow zoom (kenburns via ffmpeg zoompan) =="
i=0
for f in 00_title 01_dashboard 02_leash_deny 03_feed 08_outro; do
  ffmpeg -y -loop 1 -i "$OUT/$f.png" -t 4 -r $FPS -vf "scale=$SIZE,zoompan=z='min(zoom+0.0012,1.12)':d=${FPS}*4:x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':s=${SIZE}" \
    -c:v libx264 -pix_fmt yuv420p "$OUT/seg_$f.mp4" >/dev/null 2>&1
done

# crossfade concat
ffmpeg -y \
  -i "$OUT/seg_00_title.mp4" -i "$OUT/seg_01_dashboard.mp4" \
  -i "$OUT/seg_02_leash_deny.mp4" -i "$OUT/seg_03_feed.mp4" \
  -i "$OUT/seg_08_outro.mp4" \
  -filter_complex "[0][1]xfade=transition=fade:duration=0.5:offset=3.5[v1];[v1][2]xfade=transition=fade:duration=0.5:offset=7[v2];[v2][3]xfade=transition=fade:duration=0.5:offset=10.5[v3];[v3][4]xfade=transition=fade:duration=0.5:offset=14" \
  -map "[v3]" -c:v libx264 -pix_fmt yuv420p -r $FPS "$OUT/guarddog_demo.mp4" >/dev/null 2>&1

ls -la "$OUT/guarddog_demo.mp4"
echo "DONE: $OUT/guarddog_demo.mp4"
