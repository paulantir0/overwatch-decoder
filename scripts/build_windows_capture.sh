#!/usr/bin/env bash
# Source-only repository; private tool binaries, configurations and captures stay under .runs.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet="${OVERWATCH_DECODER_DOTNET:-$root/.tools/dotnet/dotnet}"
[[ -x "$dotnet" ]] || { echo 'Set OVERWATCH_DECODER_DOTNET to a .NET 10 SDK executable.' >&2; exit 3; }
revision="$(git -C "$root" rev-parse HEAD)"
if [[ -n "$(git -C "$root" status --porcelain --untracked-files=normal -- windows scripts/build_windows_capture.sh)" ]]; then revision="$revision-dirty"; fi
export DOTNET_CLI_HOME="$root/.runs/dotnet-home" NUGET_PACKAGES="$root/.runs/nuget"
export DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1 DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
for project in SessionRecorder.Tests/InputAudioTests SessionRecorder.VideoTests/VideoTests SessionRecorder.CoreTests/CoreTests; do
  "$dotnet" run --project "$root/windows/$project.csproj" -c Release -p:UseSharedCompilation=false -nodeReuse:false
done
output="${1:-$root/.runs/windows-capture/$revision}"
"$dotnet" publish "$root/windows/SessionRecorder/SessionRecorder.csproj" -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:BuildRevision="$revision" -p:UseSharedCompilation=false -nodeReuse:false --nologo -o "$output"
printf '%s\n' "$revision" > "$output/REVISION"
sha256sum "$output/Overwatch Decoder Recorder.exe" > "$output/SHA256SUMS"
echo "Windows recorder: $output/Overwatch Decoder Recorder.exe"
