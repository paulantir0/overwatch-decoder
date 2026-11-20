using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

// Plain, fixed paths only. No discovery, pointer decoding, collection search or target writes.
internal static class PointerPaths
{
    internal const int MaximumPaths = 32, MaximumHops = 4, MaximumCalls = 1024;
    internal const uint MaximumOffset = 1024 * 1024;
    internal sealed record RelativeGuard(uint Offset, byte[] Expected);
    internal sealed record Hop(uint Offset, RelativeGuard[] Guards);
    internal sealed record Path(string Name, ulong Root, int[] RootGuards, Hop[] Hops);
    internal delegate FieldStream.Reading Reader(ulong address, int size, ref string? terminal);
    internal sealed record ReadEvidence(bool attempted, string? address_hex, string? bytes_hex,
        long? start_ticks, long? end_ticks, string? error)
    {
        internal static ReadEvidence Missing => new(false, null, null, null, null, "not_attempted");
        internal static ReadEvidence From(ulong address, FieldStream.Reading read) => new(read.Attempted,
            read.Attempted ? Hex(address) : null, read.Bytes is null ? null : Convert.ToHexStringLower(read.Bytes),
            read.Attempted ? read.Start : null, read.Attempted ? read.End : null, read.Error);
    }
    internal sealed record GuardEvidence(bool ok, ReadEvidence read);
    internal sealed class HopState(Hop hop)
    {
        internal ulong? Slot, Node;
        internal byte[]? Pointer;
        internal ReadEvidence Before = ReadEvidence.Missing, After = ReadEvidence.Missing;
        internal GuardEvidence[] Pre = hop.Guards.Select(_ => new GuardEvidence(false, ReadEvidence.Missing)).ToArray();
        internal GuardEvidence[] Post = hop.Guards.Select(_ => new GuardEvidence(false, ReadEvidence.Missing)).ToArray();
        internal object Evidence() => new { pointer_before = Before, guards_before = Pre, guards_after = Post, pointer_after = After };
    }
    internal sealed class State(Path path)
    {
        internal string? Error;
        internal ulong? Leaf;
        internal HopState[] Hops = path.Hops.Select(h => new HopState(h)).ToArray();
        internal object Evidence(int id) => new { path_id = id, status = Error is null ? "observed" : "unknown", reason = Error,
            hops = Hops.Select(h => h.Evidence()) };
    }
    internal static string Hex(ulong address) => address.ToString("x16");
    internal static bool Add(ulong address, uint offset, int width, out ulong result)
    {
        result = 0;
        if (width <= 0 || address == 0 || address > (ulong)long.MaxValue - offset - (uint)(width - 1)) return false;
        result = address + offset; return true;
    }
    internal static ulong? FieldAddress(State path, FieldStream.Field field, ref string? reason)
    {
        if (reason is not null || path.Leaf is not { } leaf) return null;
        if (Add(leaf, field.Offset, field.Width, out ulong address)) return address;
        reason = "path_field_range"; return null;
    }
    internal static State[] Resolve(FieldStream.Profile profile, Reader read, Func<int, bool> rootOk, ref string? terminal)
    {
        Path[] paths = profile.Paths!;
        var states = paths.Select(p => new State(p)).ToArray();
        for (int id = 0; id < paths.Length; id++)
        {
            Path path = paths[id]; State state = states[id];
            if (terminal is not null || path.RootGuards.Any(g => !rootOk(g)))
            { state.Error = terminal ?? "path_root_guard_before"; continue; }
            ulong current = path.Root; var seen = new HashSet<ulong> { current };
            for (int n = 0; n < path.Hops.Length; n++)
            {
                Hop hop = path.Hops[n]; HopState h = state.Hops[n];
                if (!Add(current, hop.Offset, 8, out ulong slot)) { state.Error = "pointer_range"; break; }
                h.Slot = slot; var r = read(slot, 8, ref terminal); h.Before = ReadEvidence.From(slot, r);
                if (r.Bytes is null) { state.Error = r.Error ?? "pointer_read"; break; }
                h.Pointer = r.Bytes; ulong node = BinaryPrimitives.ReadUInt64LittleEndian(r.Bytes);
                if (node == 0) { state.Error = "pointer_null"; break; }
                if (!Add(node, 0, 1, out _)) { state.Error = "pointer_range"; break; }
                if (!seen.Add(node)) { state.Error = "pointer_cycle"; break; }
                h.Node = node;
                for (int g = 0; g < hop.Guards.Length; g++)
                {
                    var guard = hop.Guards[g];
                    if (!Add(node, guard.Offset, guard.Expected.Length, out ulong address))
                    { state.Error ??= "path_guard_range"; continue; }
                    var gr = read(address, guard.Expected.Length, ref terminal);
                    bool ok = gr.Bytes is not null && gr.Bytes.AsSpan().SequenceEqual(guard.Expected);
                    h.Pre[g] = new(ok, ReadEvidence.From(address, gr));
                    if (!ok) state.Error ??= gr.Error ?? "path_guard_mismatch_before";
                }
                if (state.Error is not null) break;
                current = node;
            }
            if (state.Error is null) state.Leaf = current;
        }
        return states;
    }
    internal static void Postcheck(FieldStream.Profile profile, State[] states, Reader read, ref string? terminal)
    {
        for (int id = states.Length - 1; id >= 0; id--)
        {
            var path = profile.Paths![id]; State state = states[id];
            for (int n = path.Hops.Length - 1; n >= 0; n--)
            {
                var hop = path.Hops[n]; var h = state.Hops[n];
                if (h.Node is { } node)
                    for (int g = hop.Guards.Length - 1; g >= 0; g--)
                    {
                        var guard = hop.Guards[g];
                        if (!Add(node, guard.Offset, guard.Expected.Length, out ulong address)) continue;
                        var r = read(address, guard.Expected.Length, ref terminal);
                        bool ok = r.Bytes is not null && r.Bytes.AsSpan().SequenceEqual(guard.Expected);
                        h.Post[g] = new(ok, ReadEvidence.From(address, r));
                        if (!ok) state.Error ??= r.Error ?? "path_guard_mismatch_after";
                    }
                if (h.Slot is { } slot)
                {
                    var r = read(slot, 8, ref terminal); h.After = ReadEvidence.From(slot, r);
                    bool same = r.Bytes is not null && h.Pointer is not null && r.Bytes.AsSpan().SequenceEqual(h.Pointer);
                    if (!same) state.Error ??= r.Error ?? "pointer_changed";
                }
            }
        }
    }
    internal static void Finish(FieldStream.Profile profile, State[] states, Func<int, bool> rootOk, string? terminal)
    {
        for (int id = 0; id < states.Length; id++)
        {
            if (terminal is not null) states[id].Error = terminal;
            else if (profile.Paths![id].RootGuards.Any(g => !rootOk(g))) states[id].Error ??= "path_root_guard_after";
        }
    }

    internal static FieldStream.Profile Parse(JsonElement root, byte[] raw)
    {
        static ObservationException Invalid() => new("invalid_field_profile", "Pointer profile is malformed, unguarded or unsupported.");
        static void Need(bool ok) { if (!ok) throw Invalid(); }
        static void Limit(bool ok) { if (!ok) throw new ObservationException("field_profile_limit", "Pointer profile exceeds a declared limit."); }
        static void Keys(JsonElement e, params string[] names)
        {
            Need(e.ValueKind == JsonValueKind.Object); var seen = new HashSet<string>();
            foreach (var p in e.EnumerateObject()) Need(seen.Add(p.Name) && names.Contains(p.Name));
        }
        static string Label(JsonElement e, string key)
        { string s = e.GetProperty(key).GetString() ?? ""; Need(s.Length is > 0 and <= 64 && s.All(c => char.IsAsciiLetterOrDigit(c) || c is '_' or '-' or '.')); return s; }
        static uint Offset(JsonElement e, string key)
        { uint n = e.GetProperty(key).GetUInt32(); Limit(n <= MaximumOffset); return n; }
        static ulong Address(JsonElement e, string key, int width)
        { ulong a = e.GetProperty(key).GetUInt64(); Need(Add(a, 0, width, out _)); return a; }
        int declarations = 0;
        byte[] Expected(JsonElement e)
        {
            Limit(++declarations <= FieldStream.MaximumGuards);
            string hex = e.GetProperty("bytes_hex").GetString() ?? "";
            Need(hex.Length is > 0 and <= FieldStream.MaximumGuardBytes * 2 && hex.Length % 2 == 0 && hex.All(Uri.IsHexDigit));
            return Convert.FromHexString(hex);
        }
        var guards = new List<FieldStream.Guard>();
        int GuardId(ulong address, byte[] bytes)
        {
            int id = guards.FindIndex(g => g.Address == address && g.Expected.AsSpan().SequenceEqual(bytes));
            if (id < 0) { id = guards.Count; guards.Add(new(address, bytes)); } return id;
        }
        int[] AbsoluteGuards(JsonElement parent)
        {
            if (!parent.TryGetProperty("guards", out var list)) return [];
            Need(list.ValueKind == JsonValueKind.Array); var ids = new List<int>();
            foreach (var g in list.EnumerateArray())
            { Keys(g, "address", "bytes_hex"); byte[] b = Expected(g); ids.Add(GuardId(Address(g, "address", b.Length), b)); }
            return ids.Distinct().ToArray();
        }
        RelativeGuard[] RelativeGuards(JsonElement list)
        {
            Need(list.ValueKind == JsonValueKind.Array && list.GetArrayLength() > 0); var gs = new List<RelativeGuard>();
            foreach (var g in list.EnumerateArray())
            { Keys(g, "offset", "bytes_hex"); var next = new RelativeGuard(Offset(g, "offset"), Expected(g));
              Need(gs.All(x => x.Offset != next.Offset));
              foreach (var prior in gs)
                  for (int i = 0; i < next.Expected.Length; i++)
                  { long j = (long)next.Offset + i - prior.Offset; Need(j < 0 || j >= prior.Expected.Length || prior.Expected[j] == next.Expected[i]); }
              gs.Add(next); }
            return gs.ToArray();
        }
        void Compatible(int[] ids)
        {
            Need(ids.Select(i => guards[i].Address).Distinct().Count() == ids.Length);
            var expected = new Dictionary<ulong, byte>();
            foreach (int id in ids)
                for (int n = 0; n < guards[id].Expected.Length; n++)
                {
                    ulong a = guards[id].Address + (ulong)n; byte b = guards[id].Expected[n];
                    Need(!expected.TryGetValue(a, out byte previous) || previous == b); expected[a] = b;
                }
        }
        bool v3 = root.GetProperty("schema").GetString() == "overwatch-decoder.field-profile/3";
        if (v3) Keys(root, "schema", "target", "guards", "paths", "fields", "absolute_guard_reads");
        else { Keys(root, "schema", "target", "guards", "paths", "fields"); Need(root.GetProperty("schema").GetString() == "overwatch-decoder.field-profile/2"); }
        GuardBatches.Policy? policy = v3 ? GuardBatches.ParsePolicy(root) : null;
        JsonElement t = root.GetProperty("target"); Keys(t, "pid", "image_name", "creation_file_time", "executable_sha256", "architecture");
        var target = new TargetIdentity(t.GetProperty("pid").GetInt32(), t.GetProperty("image_name").GetString() ?? "", "",
            t.GetProperty("creation_file_time").GetInt64(), t.GetProperty("executable_sha256").GetString() ?? "", t.GetProperty("architecture").GetString() ?? "");
        Need(target.Pid > 0 && target.CreationFileTime > 0 && target.Architecture == "x64" && target.ImageName.Length is > 0 and <= 128 &&
            !target.ImageName.Any(c => char.IsControl(c) || c is '/' or '\\') && target.ExecutableSha256.Length == 64 && target.ExecutableSha256.All(Uri.IsHexDigit));
        int[] global = AbsoluteGuards(root); var paths = new List<Path>(); var pathNames = new HashSet<string>();
        JsonElement ps = root.GetProperty("paths"); Need(ps.ValueKind == JsonValueKind.Array); Limit(ps.GetArrayLength() <= MaximumPaths && (v3 || ps.GetArrayLength() > 0));
        foreach (var p in ps.EnumerateArray())
        {
            Keys(p, "name", "root_address", "root_guards", "hops"); string name = Label(p, "name"); Need(pathNames.Add(name));
            ulong address = Address(p, "root_address", 1); var rootGuards = RelativeGuards(p.GetProperty("root_guards"));
            var ids = new List<int>(global);
            foreach (var g in rootGuards) { Need(Add(address, g.Offset, g.Expected.Length, out ulong a)); ids.Add(GuardId(a, g.Expected)); }
            int[] rootIds = ids.Distinct().ToArray(); Compatible(rootIds);
            var hs = p.GetProperty("hops"); Need(hs.ValueKind == JsonValueKind.Array); Limit(hs.GetArrayLength() is > 0 and <= MaximumHops);
            var hops = new List<Hop>();
            foreach (var h in hs.EnumerateArray())
            { Keys(h, "pointer_offset", "destination_guards"); hops.Add(new(Offset(h, "pointer_offset"), RelativeGuards(h.GetProperty("destination_guards")))); }
            paths.Add(new(name, address, rootIds, hops.ToArray()));
        }
        JsonElement fs = root.GetProperty("fields"); Need(fs.ValueKind == JsonValueKind.Array); Limit(fs.GetArrayLength() is > 0 and <= FieldStream.MaximumFields);
        var fields = new List<FieldStream.Field>(); var names = new HashSet<string>();
        foreach (var field in fs.EnumerateArray())
        {
            Keys(field, "name", "type", "address", "path", "offset", "guards", "min", "max"); string name = Label(field, "name"); Need(names.Add(name));
            string type = field.GetProperty("type").GetString() ?? "";
            int components = type switch { "u8" or "i32" or "f32" or "f64" => 1, "f32x3" => 3, "f32x4" or "i32x4" => 4, _ => throw Invalid() };
            int width = type == "u8" ? 1 : type == "f64" ? 8 : 4 * components; bool fixedAddress = field.TryGetProperty("address", out _); bool pathAddress = field.TryGetProperty("path", out var pn);
            Need(fixedAddress != pathAddress && field.TryGetProperty("offset", out _) == pathAddress);
            int? pathId = pathAddress ? paths.FindIndex(p => p.Name == pn.GetString()) : null; Need(!pathAddress || pathId >= 0);
            int[] ids = global.Concat(AbsoluteGuards(field)).Concat(pathId is { } id ? paths[id].RootGuards : []).Distinct().ToArray();
            Need(ids.Length > 0); Compatible(ids);
            double? Range(string key) => field.TryGetProperty(key, out var v) ? v.GetDouble() : null;
            double? min = Range("min"), max = Range("max"); Need(!(min > max) && (min is null || double.IsFinite(min.Value)) && (max is null || double.IsFinite(max.Value)));
            fields.Add(new(name, type, fixedAddress ? Address(field, "address", width) : 0, width, components, min, max, ids, pathId, pathAddress ? Offset(field, "offset") : 0));
        }
        Need(paths.Select((_, id) => id).All(id => fields.Any(f => f.PathId == id)));
        int relativeBytes = paths.Sum(p => p.Hops.Sum(h => h.Guards.Sum(g => g.Expected.Length)));
        int relativeCount = paths.Sum(p => p.Hops.Sum(h => h.Guards.Length)); int hopsCount = paths.Sum(p => p.Hops.Length);
        int bytes = 2 * guards.Sum(g => g.Expected.Length) + 2 * relativeBytes + 16 * hopsCount + fields.Sum(f => f.Width);
        int calls = 2 * (guards.Count + relativeCount + hopsCount) + fields.Count;
        var profile = new FieldStream.Profile(target, Convert.ToHexStringLower(SHA256.HashData(raw)), guards.ToArray(), fields.ToArray(), bytes, raw, paths.ToArray());
        if (policy is not null)
        {
            var batches = GuardBatches.Build(profile, policy);
            return profile with { ReadBytes = batches.ReadBytes, Batching = batches };
        }
        Limit(bytes <= FieldStream.MaximumReadBytesPerFrame && calls <= MaximumCalls);
        // Conservative serialization bound reserves field/metadata space and each attempted or omitted trace record.
        Limit(8192 + fields.Count * 768 + guards.Count * 320 + (relativeCount * 2 + hopsCount * 2) * 512 <= FieldStream.MaximumLineBytes);
        return profile;
    }
}
