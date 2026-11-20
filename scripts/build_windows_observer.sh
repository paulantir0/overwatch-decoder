#!/usr/bin/env bash
# Build a self-contained Windows x64 console executable. Output stays ignored.
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet="${OVERWATCH_DECODER_DOTNET:-$root/.tools/dotnet/dotnet}"
[[ -x "$dotnet" ]] || { echo 'Set OVERWATCH_DECODER_DOTNET to a .NET 10 SDK executable.' >&2; exit 3; }
revision="$(git -C "$root" rev-parse HEAD)"
if [[ -n "$(git -C "$root" status --porcelain --untracked-files=normal -- windows/Observer scripts/build_windows_observer.sh)" ]]; then
  revision="$revision-dirty"
fi
export DOTNET_CLI_HOME="$root/.runs/dotnet-home"
export NUGET_PACKAGES="$root/.runs/nuget"
export DOTNET_CLI_TELEMETRY_OPTOUT=1
export DOTNET_NOLOGO=1
export DOTNET_SKIP_FIRST_TIME_EXPERIENCE=1
output="${1:-$root/.runs/windows-observer/$revision}"
"$dotnet" build "$root/windows/Observer/Observer.csproj" -c Release \
  -p:BuildRevision="$revision" -p:UseSharedCompilation=false -nodeReuse:false --nologo
"$dotnet" "$root/windows/Observer/bin/Release/net10.0/overwatch-decoder-observer.dll" self-test
"$dotnet" publish "$root/windows/Observer/Observer.csproj" -c Release -r win-x64 --self-contained true \
  -p:PublishSingleFile=true -p:IncludeNativeLibrariesForSelfExtract=true \
  -p:BuildRevision="$revision" -p:UseSharedCompilation=false -nodeReuse:false --nologo -o "$output"
printf '%s\n' "$revision" > "$output/REVISION"
sha256sum "$output/overwatch-decoder-observer.exe" > "$output/SHA256SUMS"
echo "Windows executable: $output/overwatch-decoder-observer.exe"
