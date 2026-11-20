using System.Buffers.Binary;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

// A private, profile-declared object binding, not a person, team or visibility decoder.
// No target reads or game-specific addresses occur here. Original field evidence remains authoritative.
internal sealed class EntityIdentityProjection
{
    private const string HandleSuffix = "_handle_candidate_i32";
    private sealed record Binding(FieldStream.Field? Field, uint? Expected, string? Error);
    private sealed record Actor(int Ordinal, string Prefix, Binding Handle, FieldStream.Field? Position,
        string? Error, string? Key, string? Rotation, string[] Pools, string? HeroLow, string? HeroHigh);
    private readonly Binding self;
    private readonly Actor[] actors;
    private readonly record struct Value(string? Type, string? Status, int? Integer);

    private EntityIdentityProjection(FieldStream.Profile profile, FieldStream.Field? selfField, FieldStream.Field[] actorFields)
    {
        var fields = profile.Fields.ToDictionary(f => f.Name, StringComparer.Ordinal);
        self = Bind(profile, selfField);
        actors = actorFields.Select(handle =>
        {
            string prefix = handle.Name[..10];
            int ordinal = int.Parse(prefix.AsSpan(6), CultureInfo.InvariantCulture);
            fields.TryGetValue(prefix + "_position_candidate", out var position);
            var binding = Bind(profile, handle);
            string? error = binding.Error;
            if (error is null && (position is null || position.Type != "f32x3" || position.PathId is not null || position.Timer is not null))
                error = "unsupported_position_binding";
            if (error is null && Expected(profile, position!, handle.Address) != binding.Expected)
                error = "position_identity_not_guarded";
            string? Existing(string suffix) => fields.ContainsKey(prefix + suffix) ? prefix + suffix : null;
            return new Actor(ordinal, prefix, binding, position, error,
                error is null ? Key(profile.Target, binding.Expected!.Value, handle.Address, position!.Address) : null,
                Existing("_raw_quaternion_candidate"),
                fields.Keys.Where(n => n.StartsWith(prefix + "_pool_", StringComparison.Ordinal) && n.EndsWith("_direct_candidate", StringComparison.Ordinal)).Order(StringComparer.Ordinal).ToArray(),
                Existing("_hero_0000_resource_low_i32"), Existing("_hero_0000_resource_high_i32"));
        }).OrderBy(a => a.Ordinal).ToArray();
    }

    internal static EntityIdentityProjection? Create(FieldStream.Profile profile)
    {
        var self = profile.Fields.FirstOrDefault(f => f.Name == "self_handle_candidate_i32");
        var actors = profile.Fields.Where(f => f.Name.Length == 10 + HandleSuffix.Length &&
            f.Name.StartsWith("actor_", StringComparison.Ordinal) && f.Name.EndsWith(HandleSuffix, StringComparison.Ordinal) &&
            f.Name.AsSpan(6, 4).IndexOfAnyExceptInRange('0', '9') < 0).ToArray();
        return self is null && actors.Length == 0 ? null : new(profile, self, actors);
    }

    private static Binding Bind(FieldStream.Profile profile, FieldStream.Field? field)
    {
        if (field is null) return new(null, null, "missing_handle_field");
        if (field.Type != "i32" || field.Width != 4 || field.PathId is not null || field.Timer is not null)
            return new(field, null, "unsupported_handle_binding");
        uint? expected = Expected(profile, field, field.Address);
        return new(field, expected, expected is null ? "handle_not_guarded" : null);
    }

    // A referenced exact guard must cover the complete handle; conflicting guards reject the binding.
    private static uint? Expected(FieldStream.Profile profile, FieldStream.Field field, ulong address)
    {
        uint? expected = null;
        foreach (int index in field.Guards)
        {
            var guard = profile.Guards[index];
            if (address < guard.Address || guard.Expected.Length < 4 || address - guard.Address > (ulong)(guard.Expected.Length - 4)) continue;
            uint word = BinaryPrimitives.ReadUInt32LittleEndian(guard.Expected.AsSpan((int)(address - guard.Address), 4));
            if (expected is not null && expected != word) return null;
            expected = word;
        }
        return expected;
    }

    private static string Key(TargetIdentity target, uint handle, ulong handleSource, ulong positionSource)
    {
        using var bytes = new MemoryStream();
        using (var writer = new BinaryWriter(bytes, Encoding.UTF8, leaveOpen: true))
        {
            writer.Write("overwatch-decoder.process-object-binding/1"); writer.Write(target.Pid); writer.Write(target.CreationFileTime);
            writer.Write(target.ExecutableSha256.ToLowerInvariant()); writer.Write(target.Architecture);
            writer.Write(handle); writer.Write(handleSource); writer.Write(positionSource);
        }
        return "object:" + Convert.ToHexStringLower(SHA256.HashData(bytes.GetBuffer().AsSpan(0, (int)bytes.Length)));
    }

    internal void Write(Utf8JsonWriter writer, IReadOnlyDictionary<string, FieldStream.FieldResult> fields) =>
        Write(writer, name => fields.TryGetValue(name, out var value)
            ? new(value.type, value.status, value.value is int integer ? integer : null) : default);

    internal void Write(Utf8JsonWriter writer, JsonElement fields) => Write(writer, name =>
    {
        if (!fields.TryGetProperty(name, out var field)) return default;
        int? integer = field.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int n) ? n : null;
        return new(field.GetProperty("type").GetString(), field.GetProperty("status").GetString(), integer);
    });

    private static (uint? Handle, string? Error) Resolve(Binding binding, Func<string, Value> get)
    {
        if (binding.Error is not null) return (null, binding.Error);
        var value = get(binding.Field!.Name);
        if (value.Status != "observed" || value.Type != "i32" || value.Integer is null) return (null, "handle_unobserved");
        uint handle = unchecked((uint)value.Integer.Value);
        return handle != binding.Expected ? (null, "handle_guard_value_mismatch") : (handle, null);
    }

    private void Write(Utf8JsonWriter w, Func<string, Value> get)
    {
        var resolved = actors.Select(actor =>
        {
            var (handle, error) = Resolve(actor.Handle, get);
            error ??= actor.Error;
            if (error is null && (get(actor.Position!.Name).Status != "observed" || get(actor.Position.Name).Type != "f32x3")) error = "position_unobserved";
            return (Handle: handle, Error: error);
        }).ToArray();
        var duplicates = resolved.Where(r => r.Handle is not null).GroupBy(r => r.Handle!.Value).Where(g => g.Count() > 1).Select(g => g.Key).ToHashSet();
        for (int i = 0; i < resolved.Length; i++)
            if (resolved[i].Handle is { } handle && duplicates.Contains(handle)) resolved[i].Error = "ambiguous_handle";
        var own = Resolve(self, get);
        int selfIndex = -1;
        if (own.Error is null)
        {
            var matches = Enumerable.Range(0, actors.Length).Where(i => resolved[i].Error is null && resolved[i].Handle == own.Handle &&
                actors[i].Handle.Field!.Address == self.Field!.Address).ToArray();
            if (matches.Length == 1) selfIndex = matches[0];
        }
        string? selfError = own.Error ?? (selfIndex < 0 ? "self_actor_not_uniquely_observed" : null);
        w.WritePropertyName("entity_identity"); w.WriteStartObject();
        w.WriteString("schema", "overwatch-decoder.entity-identity/1"); w.WriteString("identity_scope", "profile_declared_process_object");
        w.WriteBoolean("public_state_eligible", false); w.WriteBoolean("continuity_across_gaps", false);
        w.WriteBoolean("participant_identity_validated", false);
        w.WriteString("self_status", selfError is null ? "observed" : "unknown");
        w.WriteString("self_reason", selfError); w.WriteString("self_object_key", selfIndex < 0 ? null : actors[selfIndex].Key);
        w.WritePropertyName("actors"); w.WriteStartArray();
        for (int i = 0; i < actors.Length; i++)
        {
            var actor = actors[i]; var value = resolved[i]; bool observed = value.Error is null;
            w.WriteStartObject(); w.WriteNumber("source_ordinal", actor.Ordinal);
            w.WriteString("object_key", observed ? actor.Key : null); w.WriteString("identity_status", observed ? "observed" : "unknown");
            w.WriteString("reason", value.Error);
            if (observed) w.WriteNumber("handle", value.Handle!.Value); else w.WriteNull("handle");
            if (observed && selfIndex >= 0) w.WriteBoolean("is_self", i == selfIndex); else w.WriteNull("is_self");
            w.WriteString("handle_field", actor.Handle.Field!.Name); w.WriteString("position_field", actor.Position?.Name);
            w.WriteString("rotation_field", actor.Rotation); LiveFieldOutput.Property(w, "pool_fields", actor.Pools);
            if (actor.HeroLow is not null || actor.HeroHigh is not null)
            {
                w.WriteString("hero_resource_low_field", actor.HeroLow); w.WriteString("hero_resource_high_field", actor.HeroHigh);
                // Field references preserve the separate read brackets; no atomic 64-bit read is claimed.
                var low = actor.HeroLow is null ? default : get(actor.HeroLow);
                var high = actor.HeroHigh is null ? default : get(actor.HeroHigh);
                string? resource = observed && low.Status == "observed" && high.Status == "observed" && low.Type == "i32" && high.Type == "i32" && low.Integer is { } l && high.Integer is { } h
                    ? "0x" + (((ulong)unchecked((uint)h) << 32) | unchecked((uint)l)).ToString("x16", CultureInfo.InvariantCulture) : null;
                w.WriteString("hero_resource_candidate", resource);
            }
            w.WriteEndObject();
        }
        w.WriteEndArray(); w.WriteEndObject();
    }
}
