# Desktop video backend

`VideoCapture(ffmpegPath, outputDirectory, displayIndex, emit,
encoder: "h264_amf")` provides `StartAsync(CancellationToken)`, idempotent
`StopAsync()`, `Summary` / `Snapshot()`, `IsRunning`, and `IAsyncDisposable`.
Instances are single use. The caller owns a visible recording UI and session
manifest. `emit` can run on background threads and must be thread-safe and
nonblocking (queue UI work); callback failures stop recording. Slow synchronous
file or callback I/O can overrun cooperative deadlines.

Only the BCL is required. Production capture requires Windows and an explicitly
supplied FFmpeg executable. The backend does not download binaries, acquire
privileges, install a hook, attach to a game, or select a software encoder.
FFmpeg's version/build banner remains in the private stderr log. The caller
should record the supplied binary hash and version in its session manifest.

The graph requests DXGI desktop duplication (`ddagrab`), full native display
size, a maximum 30 fps and hardware cursor capture. Static desktops can cause
repeated images, and backpressure can reduce sampling frequency. DXGI output
indices usually correspond to Windows screen indices minus one, but the selected
screen must be checked on the actual machine. See the [FFmpeg ddagrab
contract](https://ffmpeg.org/ffmpeg-filters.html#ddagrab).

AMF is the default: `h264_amf`, speed quality, transcoding usage, CBR around
6 Mbps, GOP 60, no B frames. On the tested AMD driver, direct desktop textures
and GPU format conversion failed. The explicit AMF path therefore uses
`hwdownload,format=bgra,format=nv12` before hardware encoding. This includes
GPU readback, CPU color conversion and upload; it is not an all-GPU pipeline.
Metadata declares the CPU conversion. Measure its overhead on the actual machine.
The alternatives are `h264_nvenc` with preset p1 / CBR and `h264_qsv` with preset
veryfast / lookahead off. NVENC requests D3D11 frames directly; QSV requests a
direct GPU `hwmap` to a derived QSV device. There is no CPU encoder fallback or
retry with another encoder. Unsupported drivers, pixel formats, device sharing
or options fail. NVIDIA and Intel configurations are untested on hardware.
Primary option definitions: [AMF](https://github.com/FFmpeg/FFmpeg/blob/master/libavcodec/amfenc_h264.c),
[NVENC](https://github.com/FFmpeg/FFmpeg/blob/master/libavcodec/nvenc_h264.c),
[QSV](https://github.com/FFmpeg/FFmpeg/blob/master/libavcodec/qsvenc_h264.c),
[hardware mapping](https://github.com/FFmpeg/FFmpeg/blob/master/libavfilter/vf_hwmap.c).

The child runs BelowNormal when the OS permits; failure to apply that priority is
reported. `StartAsync` waits up to 15 seconds for nonzero encoding progress and a
source frame with the expected time base, and requires a nonempty video file in
production. This is startup evidence, not independent media verification.
`StopAsync` sends `q` with bounded stdin waits, allows 8 seconds to finish, then
kills only its own FFmpeg process and waits at most another 2 seconds. Stream
draining gets 2 seconds. It never kills an entire process tree. Forced stop,
unexpected exit, nonzero exit, missing frame evidence and log failures remain
explicit. A caller should await disposal before finalizing its session.

Outputs are new files under the caller's session directory:

- `desktop.mkv`: H.264 video in Matroska, flushing packets and requesting 1-second
  clusters. This improves interrupted-file recovery; it does not guarantee a
  complete or playable tail. Existing media is never overwritten (`-n`).
- `ffmpeg.stderr.log`: JSONL text records with parent QPC receipt ticks, including
  source timestamp diagnostics and actual FFmpeg errors.
- `video-frames.jsonl`: source frame ordinal, raw PTS, confirmed microsecond PTS
  or null, dimensions and receipt QPC. These are input-filter observations, not
  assertions that every input frame reached the encoder/container.
- `video-progress.jsonl`: bounded FFmpeg progress blocks plus receipt QPC.
  [FFmpeg documents](https://ffmpeg.org/ffmpeg.html#Generic-options) these as
  periodic key/value groups, ending with `progress=continue` or `progress=end`.

Each log is capped at 64 MiB and each incoming line at 8,192 characters; a breach
stops capture with an explicit failure. The child also receives a 10-hour / 64-GiB
media ceiling. Reaching it without a requested stop is an unexpected exit, not
silent success. The caller should monitor free disk space. Private video and logs
must not be committed or uploaded to GitHub.

## Clock evidence and limits

Current [ddagrab source](https://github.com/FFmpeg/FFmpeg/blob/master/libavfilter/vsrc_ddagrab.c)
subtracts a private `first_pts` from `av_gettime_relative()` and emits a 1/1,000,000
time base. Real-frame PTS is sampled after acquiring an image; repeated frames
use the polling clock. The actual image can predate that timestamp, including
the initial probed texture. On Windows, [av_gettime_relative](https://github.com/FFmpeg/FFmpeg/blob/master/libavutil/time.c)
rescales QueryPerformanceCounter to microseconds. Thus relative source PTS does
not expose its original QPC epoch. These source findings must be checked against
the shipped FFmpeg build; the backend reports that correspondence as unverified.

`showinfo=checksum=0` logs frame timestamps without reading hardware pixel planes
for checksums ([source](https://github.com/FFmpeg/FFmpeg/blob/master/libavfilter/vf_showinfo.c)).
The backend requires the emitted time-base declaration to confirm microsecond
units. It stores each log receipt's QPC, bounds the hidden epoch below by the
parent's process-launch-before tick and above by the minimum receipt tick minus
source PTS, expanding both ends by a two-microsecond rounding allowance. Log buffering makes this a
potentially broad interval. Process launch is never labeled the first frame.
These bounds concern source clock sampling, not exact display presentation or
pixel acquisition.

The command requests `-copyts`, passthrough frame timing, microsecond encoder
time base and disabled negative-timestamp adjustment. [FFmpeg's timestamp
contract](https://ffmpeg.org/ffmpeg.html#Advanced-options) explicitly permits
muxer changes even with copyts; verify the final container using ffprobe before
asserting source-to-muxed PTS correspondence. `-debug_ts` is deliberately not
parsed: FFmpeg warns that its format can change and it cannot restore the private
ddagrab epoch.

For tighter synchronization, the visible UI should display an alternating color /
counter calibration tile on the selected screen while startup runs. Log every
actually painted tile state with QPC brackets, keep it visible through
`StartAsync`, then close it. Matching decoded video frames to those intervals
provides independent bounded evidence. Paint request time is not proof of exact
scanout. This backend neither decodes calibration frames nor claims exact
first-frame timing, presentation time or verified media.

## Portable verification

The sibling `SessionRecorder.VideoTests/VideoTests.csproj` links only this backend
and exercises configuration plus local synthetic child processes. It checks
explicit encoders, declared AMF CPU conversion, no CPU encoder fallback, timestamp parsing/bounds, stderr/stdout drains,
`q` completion, unexpected/nonzero exit, malformed timing, oversized lines,
forced child kill, cancellation, no overwrite and repeated stop/start behavior.
It creates no desktop capture and performs no hardware encoding. Native tests
must verify the chosen screen, AMF driver/path, dimensions, actual frame pacing,
calibration matching, muxed PTS, media decode/recovery and the visible UI.
