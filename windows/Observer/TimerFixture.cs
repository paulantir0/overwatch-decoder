using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

namespace OverwatchDecoder.Observer;

/// <summary>Bounded synthetic child with a deliberately cross-page identity guard.</summary>
public static class TimerFixture
{
    public static void Run(int seconds)
    {
        if (seconds is < 1 or > 60) throw new ObservationException("invalid_arguments", "Timer fixture duration must be 1 to 60 seconds.");
        nint allocation = Marshal.AllocHGlobal(12288);
        try
        {
            ulong page = ((ulong)allocation + 4095) & ~4095UL;
            nint guard = (nint)(page + 4094), state = (nint)(page + 64), clockValue = (nint)(page + 96);
            Marshal.Copy(new byte[] { 1, 2, 3, 4 }, 0, guard, 4);
            Marshal.Copy(TimerTests.State(1000, 12, 1), 0, state, 16); Marshal.WriteInt64(clockValue, 2000);
            Program.Emit("timer_fixture_ready", new { schema = "overwatch-decoder.timer-fixture/1", pid = Environment.ProcessId,
                guard_address = (ulong)guard, state_address = (ulong)state, clock_address = (ulong)clockValue,
                private_address_trace = true, maximum_commands = 16, maximum_command_chars = 16, label = "SYNTHETIC FIXTURE" });
            Console.Out.Flush(); var elapsed = Stopwatch.StartNew(); Task<string?>? pending = null; int commands = 0;
            while (elapsed.Elapsed.TotalSeconds < seconds)
            {
                pending ??= Task.Run(ReadCommand);
                if (!pending.IsCompleted) { Thread.Sleep(20); continue; }
                string? command = pending.GetAwaiter().GetResult(); pending = null;
                if (command is null or "stop") break;
                if (++commands > 16) throw new ObservationException("fixture_command_limit", "Too many timer fixture commands.");
                switch (command)
                {
                    case "backstep": Marshal.WriteInt64(clockValue, 1985); break;
                    case "bad": Marshal.Copy(new byte[4], 0, guard, 4); break;
                    default: throw new ObservationException("invalid_fixture_command", "Timer fixture accepts backstep, bad or stop.");
                }
            }
        }
        finally { Marshal.FreeHGlobal(allocation); }
    }
    private static string? ReadCommand()
    {
        var text = new StringBuilder(16);
        while (true)
        {
            int c = Console.In.Read(); if (c < 0) return text.Length == 0 ? null : text.ToString();
            if (c == '\n') return text.ToString(); if (c == '\r') continue;
            if (text.Length == 16) throw new ObservationException("fixture_command_limit", "Timer fixture command is too long.");
            text.Append((char)c);
        }
    }
}
