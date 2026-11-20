#!/usr/bin/env python3
"""Serve one explicit private replay and its UI on IPv4 loopback only."""
import argparse
import hashlib
import json
import math
import re
import signal
import sys
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent))
from chunks import checked_index

STATIC = {"/": ("index.html", "text/html; charset=utf-8"),
          "/index.html": ("index.html", "text/html; charset=utf-8"),
          "/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/theme.js": ("theme.js", "text/javascript; charset=utf-8"),
          "/model.js": ("model.js", "text/javascript; charset=utf-8"),
          "/evidence.js": ("evidence.js", "text/javascript; charset=utf-8"),
          "/environment.js": ("environment.js", "text/javascript; charset=utf-8"),
          "/style.css": ("style.css", "text/css; charset=utf-8")}
MAX_REPLAY = 128 * 1024 * 1024
MAX_EVIDENCE = 1024 * 1024


def read_document(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_EVIDENCE + 1)
    if len(raw) > MAX_EVIDENCE:
        raise ValueError("Evidence document exceeds 1 MiB")
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Evidence document must be an object")
    return data


def checked_environment(data, source_sha256):
    """Pin an explicit map sidecar. The renderer also checks all ray geometry."""
    def shape(value, required, optional=()):
        return isinstance(value, dict) and set(required) <= value.keys() <= set(required) | set(optional)

    def digest(value):
        return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None

    if (not shape(data, ("schema", "replay_source_sha256", "observed_build_sha256", "map", "mode", "registration", "surveys"))
        or data["schema"] != "overwatch-decoder.replay-environment/1" or not digest(source_sha256)
        or data["replay_source_sha256"] != source_sha256 or not digest(data["observed_build_sha256"])
        or any(not isinstance(data[k], str) or not 0 < len(data[k]) <= 120 or not data[k].isprintable()
               for k in ("map", "mode"))):
        raise ValueError("Map surfaces do not match the selected replay")
    registration = data["registration"]
    if (not shape(registration, ("kind", "validation", "evidence_sha256")) or registration["kind"] != "identity"
        or registration["validation"] != "controlled_coordinate_pairs" or not digest(registration["evidence_sha256"])):
        raise ValueError("Map surfaces require verified coordinate registration")
    surveys = data["surveys"]
    if not isinstance(surveys, list) or not 1 <= len(surveys) <= 16:
        raise ValueError("Invalid map survey count")
    total = 0
    for survey in surveys:
        if (not shape(survey, ("schema", "map", "mode", "observed_build_sha256", "coordinate_space", "replay_registration",
                               "visibility", "coverage", "source", "rays"), ("survey", "planar_patches"))
            or survey["schema"] != "overwatch-decoder.environment-surface-samples/1"
            or any(survey[k] != data[k] for k in ("map", "mode", "observed_build_sha256"))
            or survey["coordinate_space"] != "workshop_world" or survey["replay_registration"] is not None
            or survey["visibility"] != "unknown" or survey["coverage"] != "sparse_first_hit_rays"
            or not shape(survey["source"], ("kind", "sha256", "rule_sha256", "position_tolerance"))
            or not all(digest(survey["source"][k]) for k in ("sha256", "rule_sha256"))):
            raise ValueError("Invalid map survey scope")
        rays = survey["rays"]
        if not isinstance(rays, list) or not 1 <= len(rays) <= 500:
            raise ValueError("Invalid map ray count")
        total += len(rays)
        if total > 4096:
            raise ValueError("Invalid total map ray count")
        for index, ray in enumerate(rays):
            if (not shape(ray, ("index", "origin", "end", "returned_hit", "returned_normal", "status"),
                          ("hit_elapsed_seconds", "normal_elapsed_seconds"))
                or type(ray["index"]) is not int or ray["index"] != index
                or ray["status"] not in ("surface_hit", "miss_or_endpoint", "origin_ambiguous")):
                raise ValueError("Invalid map ray shape")
        patches = survey.get("planar_patches", [])
        if not isinstance(patches, list) or len(patches) > 36:
            raise ValueError("Invalid map patch count")
        for patch in patches:
            if not shape(patch, ("kind", "ray_indices")) or patch["kind"] != "derived_between_samples":
                raise ValueError("Invalid map patch shape")
            corners = patch["ray_indices"]
            if (not isinstance(corners, list) or len(corners) != 4
                or not all(type(i) is int and 0 <= i < len(rays) and rays[i]["status"] == "surface_hit" for i in corners)
                or len(set(corners)) != 4):
                raise ValueError("Invalid map patch corners")
    payload = json.dumps(data, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")
    if len(payload) > MAX_EVIDENCE:
        raise ValueError("Map surfaces exceed 1 MiB")
    return payload


def checked_alignment(data, source_sha256, video_sha256):
    if (data.get("schema") != "overwatch-decoder.replay-alignment/1" or
            data.get("source_sha256") != source_sha256 or
            data.get("video_sha256") != video_sha256):
        raise ValueError("Calibration does not match the selected recording/video")
    offset, uncertainty = data.get("offset_seconds"), data.get("uncertainty_seconds")
    if (type(offset) not in (int, float) or not math.isfinite(offset) or abs(offset) > 3600 or
            type(uncertainty) not in (int, float) or not math.isfinite(uncertainty) or uncertainty < 0):
        raise ValueError("Invalid calibration timing")
    return {"alignment": "motion_calibrated", "start_seconds": offset,
            "uncertainty_seconds": uncertainty,
            "method": str(data.get("method", ""))[:1000],
            "scope": str(data.get("scope", ""))[:300]}



def recorder_clock_metadata(index):
    """This estimate assumes --video is a timestamp-preserving remux of this session."""
    timing = index.get('video_timing', {})
    if not isinstance(timing, dict) or timing.get('status') != 'conditional_recorder_clock':
        return dict(alignment='unavailable', start_seconds=0, uncertainty_seconds=None,
                    scope='No verified source-clock bracket. Video starts on its own clock; adjust the offset manually.')
    offset, uncertainty = timing.get('start_seconds'), timing.get('uncertainty_seconds')
    if (type(offset) not in (int,float) or not math.isfinite(offset) or abs(offset) > 3600 or
            type(uncertainty) not in (int,float) or not math.isfinite(uncertainty) or uncertainty < 0):
        raise ValueError('Invalid recorder clock estimate')
    return dict(alignment='recorder_clock_bounded', start_seconds=offset, uncertainty_seconds=uncertainty,
                method='This session’s launch and source-frame receipt bounds; assumes timestamp-preserving remux.',
                scope='Conditional source-clock bracket only. Capture content and presentation time are not exact.')

def byte_range(value, size):
    """One bounded HTTP byte range, including open-ended and suffix requests."""
    if value is None:
        return 0, size - 1, 200
    match = re.fullmatch(r"bytes=(\d*)-(\d*)", value) if len(value) <= 100 else None
    if not match or not any(match.groups()) or size == 0:
        raise ValueError("Invalid range")
    first, last = match.groups()
    if not first:
        length = int(last)
        if length <= 0:
            raise ValueError("Invalid suffix range")
        return max(0, size - length), size - 1, 206
    start, end = int(first), min(int(last), size - 1) if last else size - 1
    if start >= size or end < start:
        raise ValueError("Unsatisfiable range")
    return start, end, 206


class Handler(BaseHTTPRequestHandler):
    server_version = "OverwatchDecoderReplay/1"

    def __init__(self, *args, replay, video=None, video_offset=0,
                 video_uncertainty=None, annotations=None, labels=None, calibration=None, chunks=None, chunk_index=None,
                 environment=None, **kwargs):
        self.replay = replay
        self.chunks = chunks or {}
        self.chunk_index = chunk_index
        self.video = video
        self.environment = environment
        self.media_metadata = {"video": {"url": "/gameplay.mp4", "start_seconds": video_offset,
            "uncertainty_seconds": video_uncertainty, "alignment": "estimated"} if video else None,
            "annotations": annotations, "labels": labels}
        if environment is not None:
            self.media_metadata["environment"] = {"url": "/environment.json"}
        if video and calibration:
            self.media_metadata["video"].update(calibration)
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        self.respond(False)

    def do_GET(self):
        self.respond(True)

    def respond(self, body):
        port = self.server.server_port
        allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}"}
        allowed_origins = {f"http://{host}" for host in allowed_hosts}
        if self.headers.get("Host") not in allowed_hosts:
            self.send_error(403, "Loopback Host required")
            return
        if self.headers.get("Origin") and self.headers["Origin"] not in allowed_origins:
            self.send_error(403, "Same-origin requests only")
            return
        path = urlsplit(self.path).path
        # A user may open the empty UI shell from another page. This permits
        # only top-level document navigation, never cross-site data/media reads,
        # subframes, scripts or fetch. Host/Origin checks above still apply.
        ui_navigation = (path in ("/", "/index.html") and self.command == "GET"
                         and self.headers.get("Sec-Fetch-Mode") == "navigate"
                         and self.headers.get("Sec-Fetch-Dest") == "document")
        if self.headers.get("Sec-Fetch-Site") == "cross-site" and not ui_navigation:
            self.send_error(403, "Cross-site requests are not allowed")
            return
        if (path == "/media.json" or (path == "/replay.json" and self.chunk_index)
            or (path == "/environment.json" and self.environment is not None)):
            payload = self.environment if path == "/environment.json" else json.dumps(
                self.chunk_index if path == "/replay.json" else self.media_metadata, allow_nan=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            if body:
                self.wfile.write(payload)
            return
        if path == "/replay.json":
            file, mime = self.replay, "application/json; charset=utf-8"
        elif path in self.chunks:
            file, mime = self.chunks[path], "application/json; charset=utf-8"
        elif path == "/gameplay.mp4" and self.video:
            file, mime = self.video, "video/mp4"
        elif path in STATIC:
            name, mime = STATIC[path]
            file = Path(__file__).resolve().parent / name
        else:
            self.send_error(404)
            return
        try:
            # Pin the open file for this response; never serve arbitrary directories.
            with file.open("rb") as stream:
                import os
                size = os.fstat(stream.fileno()).st_size
                if path == "/replay.json" and size > MAX_REPLAY:
                    self.send_error(413, "Replay exceeds 128 MiB")
                    return
                start, end, status = 0, size - 1, 200
                if path == "/gameplay.mp4":
                    try:
                        start, end, status = byte_range(self.headers.get("Range"), size)
                    except ValueError:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{size}")
                        self.send_header("Content-Length", "0")
                        self.end_headers()
                        return
                self.send_response(status)
                self.send_header("Content-Type", mime)
                self.send_header("Content-Length", str(end - start + 1))
                if path == "/gameplay.mp4":
                    self.send_header("Accept-Ranges", "bytes")
                if status == 206:
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Cross-Origin-Resource-Policy", "same-origin")
                self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self'; media-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
                self.end_headers()
                if body:
                    stream.seek(start)
                    remaining = end - start + 1
                    while remaining > 0 and (chunk := stream.read(min(256 * 1024, remaining))):
                        self.wfile.write(chunk)
                        remaining -= len(chunk)
        except (BrokenPipeError, ConnectionResetError):
            pass
        except FileNotFoundError:
            self.send_error(404)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("replay", type=Path)
    parser.add_argument("--port", type=int, default=8787)
    parser.add_argument("--pid-file", type=Path)
    parser.add_argument("--video", type=Path, help="Explicit local browser-compatible MP4")
    parser.add_argument("--video-offset", type=float,
                        help="Estimated replay seconds corresponding to video time zero")
    parser.add_argument("--video-uncertainty", type=float)
    parser.add_argument("--annotations", type=Path, help="Private source-bound user suggestions")
    parser.add_argument("--labels", type=Path, help="Private source-bound video observations and scoped object bindings")
    parser.add_argument("--alignment", type=Path, help="Source/video-bound motion calibration")
    parser.add_argument("--environment", type=Path, help="Explicit source-bound, registered map surface samples")
    args = parser.parse_args()
    replay = args.replay.resolve(strict=True)
    if not replay.is_file() or replay.stat().st_size > MAX_REPLAY:
        parser.error("Replay must be a file no larger than 128 MiB")
    chunk_index, chunks = checked_index(replay)
    if not 0 <= args.port <= 65535:
        parser.error("Invalid port")
    if args.video_offset is not None and (not math.isfinite(args.video_offset) or abs(args.video_offset) > 86400):
        parser.error("Invalid video offset")
    if args.video_uncertainty is not None and (not math.isfinite(args.video_uncertainty) or args.video_uncertainty < 0):
        parser.error("Invalid video uncertainty")
    video = args.video.resolve(strict=True) if args.video else None
    if video and (not video.is_file() or video.suffix.lower() != ".mp4"):
        parser.error("Video must be an explicit MP4 file")
    annotations = None
    if args.annotations:
        if args.annotations.stat().st_size > 1024 * 1024:
            parser.error("Annotations exceed 1 MiB")
        data = json.loads(args.annotations.read_text())
        if not isinstance(data, dict) or len(data.get("objects", [])) > 4096:
            parser.error("Invalid annotation document")
        annotations = {"source_sha256": str(data.get("source_sha256", ""))[:64],
                       "context": str(data.get("context", ""))[:1000],
                       "objects": [{"key": str(item["key"])[:256], "label": str(item["label"])[:100]} for item in data.get("objects", [])],
                       "validation": "user_suggestion_unverified"}
    labels, calibration, environment = None, None, None
    if video and args.video_offset is None and chunk_index and chunk_index.get("repeat_windows") is True:
        calibration = recorder_clock_metadata(chunk_index)
    if args.labels or args.alignment or args.environment:
        source_sha256 = (chunk_index or json.loads(replay.read_text(encoding="utf-8"))).get("source_sha256")
        if args.labels:
            data = read_document(args.labels)
            if data.get("schema") != "overwatch-decoder.replay-evidence/1" or data.get("source_sha256") != source_sha256:
                parser.error("Labels do not match the selected recording")
            labels = {key: data[key] for key in ("schema", "source_sha256", "observations", "bindings", "context") if key in data}
        if args.alignment:
            if not video:
                parser.error("Calibration requires video")
            with video.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            calibration = checked_alignment(read_document(args.alignment), source_sha256, digest)
        if args.environment:
            try:
                environment = checked_environment(read_document(args.environment), source_sha256)
            except (OSError, ValueError, RecursionError) as error:
                parser.error(f"Invalid environment sidecar: {error}")
    server = ThreadingHTTPServer(("127.0.0.1", args.port), partial(Handler, replay=replay,
        video=video, video_offset=args.video_offset or 0, video_uncertainty=args.video_uncertainty,
        annotations=annotations, labels=labels, calibration=calibration, chunks=chunks, chunk_index=chunk_index,
        environment=environment))
    import os
    if args.pid_file:
        args.pid_file.parent.mkdir(parents=True, exist_ok=True)
        args.pid_file.write_text(str(os.getpid()) + "\n", encoding="ascii")
    print(json.dumps({"url": f"http://127.0.0.1:{server.server_port}", "pid": os.getpid()}), flush=True)
    def stop(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if args.pid_file and args.pid_file.exists() and args.pid_file.read_text().strip() == str(os.getpid()):
            args.pid_file.unlink()


if __name__ == "__main__":
    main()
