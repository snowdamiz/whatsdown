#!/bin/zsh
# AUDIO=audio2.wav ./mux.sh -> ../brag.mp4 (video-silent.mp4 + $AUDIO at -14 LUFS, true peak under -1 dB) and ../brag.jpg (frame 0: the opening card)
set -e
cd "${0:A:h}"
I=$(ffmpeg -hide_banner -i "${AUDIO:-audio.wav}" -af ebur128 -f null - 2>&1 | awk '/Summary/{s=1} s&&/ I:/{print $2; exit}')
GAIN=$(echo "-14 - ($I)" | bc -l)
ffmpeg -loglevel error -y -i video-silent.mp4 -i "${AUDIO:-audio.wav}" -map 0:v -map 1:a -c:v copy \
  -af "volume=${GAIN}dB,alimiter=limit=0.89:level=false" -c:a aac -b:a 256k -movflags +faststart -shortest ../brag.mp4
ffmpeg -loglevel error -y -i ../brag.mp4 -frames:v 1 -q:v 2 ../brag.jpg
ffmpeg -hide_banner -i ../brag.mp4 -af ebur128=peak=true -f null - 2>&1 | grep -E "^\s+(I|Peak):"
ffprobe -v error -show_entries format=duration:stream=codec_name,width,height,nb_frames -of compact ../brag.mp4
