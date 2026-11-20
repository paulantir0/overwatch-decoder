using System.Diagnostics;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;

namespace OverwatchDecoder.SessionRecorder;

/// <summary>Never makes a window-message callback wait for disk I/O.</summary>
public sealed class EventJournal : IAsyncDisposable
{
    private readonly Channel<object> queue = Channel.CreateBounded<object>(new BoundedChannelOptions(16384)
    { SingleReader = true, SingleWriter = false, FullMode = BoundedChannelFullMode.Wait });
    private readonly Task writer;
    private long dropped, written;
    private int closed;
    public long Dropped => Interlocked.Read(ref dropped);
    public long Written => Interlocked.Read(ref written);
    public string? Error { get; private set; }

    public EventJournal(string path)
    {
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read, 65536, FileOptions.SequentialScan);
        writer = Task.Run(async () =>
        {
            try
            {
                await using var gzip = new GZipStream(file, CompressionLevel.Fastest);
                await using var output = new StreamWriter(gzip, new UTF8Encoding(false), 65536);
                long flushed = Stopwatch.GetTimestamp();
                await foreach (object item in queue.Reader.ReadAllAsync())
                {
                    await output.WriteLineAsync(JsonSerializer.Serialize(item));
                    Interlocked.Increment(ref written);
                    if (Stopwatch.GetElapsedTime(flushed).TotalSeconds >= 1) { await output.FlushAsync(); flushed = Stopwatch.GetTimestamp(); }
                }
                await output.WriteLineAsync(JsonSerializer.Serialize(new { kind = "journal_end", qpc_ticks = Stopwatch.GetTimestamp(), written = Written, dropped = Dropped }));
                await output.FlushAsync();
            }
            catch (Exception ex) { Error = ex.Message; queue.Writer.TryComplete(ex); }
            finally { await file.DisposeAsync(); }
        });
    }

    public void Emit(object item)
    {
        if (Volatile.Read(ref closed) != 0 || !queue.Writer.TryWrite(item)) Interlocked.Increment(ref dropped);
    }

    public async ValueTask DisposeAsync()
    {
        if (Interlocked.Exchange(ref closed, 1) == 0) queue.Writer.TryComplete();
        await writer;
    }
}
