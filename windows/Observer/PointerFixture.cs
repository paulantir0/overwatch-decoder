using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OverwatchDecoder.Observer;

/// <summary>Dedicated controlled child. Mutates only its own allocations; no game or existing fixture layout.</summary>
public static class PointerFixture
{
    public static readonly byte[] Magic = Encoding.ASCII.GetBytes("OWDPTR02");
    public const int RootSize = 32, LeafSize = 16, PointerOffset = 8, ValueOffset = 8, IndependentOffset = 16;

    public static void Run(int seconds)
    {
        if (seconds is < 1 or > 60) throw new ObservationException("invalid_arguments", "Pointer fixture duration must be 1 to 60 seconds.");
        nint root = 0, a = 0, b = 0;
        try
        {
            root = Marshal.AllocHGlobal(RootSize); a = Marshal.AllocHGlobal(LeafSize); b = Marshal.AllocHGlobal(LeafSize);
            Marshal.Copy(new byte[RootSize], 0, root, RootSize);
            foreach (nint leaf in new[] { a, b }) { Marshal.Copy(new byte[LeafSize], 0, leaf, LeafSize); Marshal.Copy(Magic, 0, leaf, Magic.Length); }
            Marshal.Copy(Magic, 0, root, Magic.Length); Marshal.WriteInt32(a, ValueOffset, 7); Marshal.WriteInt32(b, ValueOffset, 42);
            Marshal.WriteInt32(root, IndependentOffset, 99); Marshal.WriteInt64(root, PointerOffset, (long)a);
            Program.Emit("pointer_fixture_ready", new { label = "SYNTHETIC FIXTURE", schema = "overwatch-decoder.pointer-fixture/1",
                pid = Environment.ProcessId, root_address = (ulong)root, root_bytes = RootSize, leaf_bytes = LeafSize,
                private_address_trace = true, maximum_commands = 64, maximum_command_chars = 16 });
            Console.Out.Flush();
            var clock = Stopwatch.StartNew(); Task<string?>? pending = null; int commands = 0;
            while (clock.Elapsed.TotalSeconds < seconds)
            {
                // A blocked stdin task never accesses allocations; process exit ends it after this bounded loop.
                pending ??= Task.Run(ReadCommand);
                if (!pending.IsCompleted) { Thread.Sleep(25); continue; }
                string? command = pending.GetAwaiter().GetResult(); pending = null;
                if (command is null or "stop") break;
                if (++commands > 64) throw new ObservationException("fixture_command_limit", "Pointer fixture command limit exceeded.");
                switch (command)
                {
                    case "a": Marshal.WriteInt64(root, PointerOffset, (long)a); break;
                    case "b": Marshal.Copy(Magic, 0, b, Magic.Length); Marshal.WriteInt64(root, PointerOffset, (long)b); break;
                    case "null": Marshal.WriteInt64(root, PointerOffset, 0); break;
                    case "bad": Marshal.WriteInt64(b, 0, 0); Marshal.WriteInt64(root, PointerOffset, (long)b); break;
                    default: throw new ObservationException("invalid_fixture_command", "Pointer fixture accepts a, b, null, bad or stop.");
                }
            }
        }
        finally { if (b != 0) Marshal.FreeHGlobal(b); if (a != 0) Marshal.FreeHGlobal(a); if (root != 0) Marshal.FreeHGlobal(root); }
    }
    private static string? ReadCommand()
    {
        var text = new StringBuilder(16);
        while (true)
        {
            int c = Console.In.Read(); if (c < 0) return text.Length == 0 ? null : text.ToString();
            if (c == '\n') return text.ToString(); if (c == '\r') continue;
            if (text.Length >= 16) throw new ObservationException("fixture_command_limit", "Pointer fixture command is too long.");
            text.Append((char)c);
        }
    }
}
