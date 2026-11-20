#!/usr/bin/env python3
"""Stage only an allowlisted replay, its timestamp-checked video and static UI."""
import argparse
import gzip
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from share import encode, export_shared, require

ASSETS = ("index.html", "style.css", "theme.js", "app.js", "model.js", "evidence.js", "environment.js")


def video_pts(path):
    result = subprocess.run([
        "ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
        "packet=pts_time", "-of", "json", str(path),
    ], check=True, capture_output=True, timeout=60)
    return sorted(float(p["pts_time"]) for p in json.loads(result.stdout)["packets"])


def stage(index, calibration, source_video, trimmed_video, first_pts, output):
    replay, plan = export_shared(index, calibration, source_video)
    require(not output.exists(), "output directory must be new")
    require(0 <= plan["video_start_seconds"] - first_pts <= 0.1,
            "first retained frame must immediately precede the calibrated cut")
    source = [t for t in video_pts(source_video) if first_pts <= t < plan["video_end_seconds"]]
    delivered = video_pts(trimmed_video)
    require(source and source[0] == first_pts and len(source) == len(delivered),
            "trimmed video frame selection differs from source")
    timestamp_error = max(abs((a-first_pts)-b) for a, b in zip(source, delivered))
    require(timestamp_error <= 0.001, "video encoding changed presentation timing")
    require(trimmed_video.stat().st_size <= 128*1024**2, "video exceeds shared asset limit")
    root = Path(__file__).resolve().parent
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    output.mkdir(parents=True)
    for name in ASSETS:
        shutil.copyfile(root/name, output/name)
    raw = encode(replay)
    (output/"replay.json.gz").write_bytes(gzip.compress(raw, compresslevel=9, mtime=0))
    shutil.copyfile(trimmed_video, output/"gameplay.mp4")
    media = dict(video=dict(
        url="/gameplay.mp4", alignment="motion_calibrated",
        start_seconds=round(first_pts+plan["original_video_offset_seconds"]-plan["original_source_start_seconds"], 9),
        uncertainty_seconds=plan["calibration_uncertainty_seconds"]+timestamp_error,
        method="HUD health transitions aligned to recorded samples; trimmed video preserves source presentation timestamps.",
        scope="This saved excerpt only. Camera aim, field of view and visibility remain unverified.",
    ), annotations=None, labels=None)
    (output/"media.json").write_bytes(encode(media))
    policy = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; media-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    config = dict(
        framework=None, buildCommand="", installCommand="",
        rewrites=[dict(source="/replay.json", destination="/replay.json.gz")],
        headers=[
            dict(source="/(.*)", headers=[
                dict(key="Content-Security-Policy", value=policy),
                dict(key="X-Content-Type-Options", value="nosniff"),
                dict(key="Referrer-Policy", value="no-referrer"),
            ]),
            *[dict(source=path, headers=[dict(key="Content-Type", value="application/json"),
                dict(key="Content-Encoding", value="gzip")]) for path in ("/replay.json", "/replay.json.gz")],
        ],
    )
    (output/"vercel.json").write_bytes(encode(config))
    files = {p.name: dict(bytes=p.stat().st_size, sha256=hashlib.sha256(p.read_bytes()).hexdigest())
             for p in sorted(output.iterdir()) if p.is_file()}
    receipt = dict(schema="overwatch-decoder.shared-site/1", revision=revision, frames=len(replay["frames"]),
                   duration_seconds=replay["end_seconds"], replay_decoded_sha256=hashlib.sha256(raw).hexdigest(),
                   video_frames=len(delivered), video_timestamp_error_seconds=timestamp_error, files=files)
    (output/"version.json").write_bytes(encode(receipt))
    return receipt


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("index", type=Path)
    parser.add_argument("--calibration", type=Path, required=True)
    parser.add_argument("--source-video", type=Path, required=True)
    parser.add_argument("--trimmed-video", type=Path, required=True)
    parser.add_argument("--first-video-pts", type=float, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(stage(args.index, args.calibration, args.source_video,
                           args.trimmed_video, args.first_video_pts, args.output_dir)))
