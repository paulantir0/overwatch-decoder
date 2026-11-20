using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace OverwatchDecoder.Observer;

internal static class NativeReadSetupTests
{
    internal static object? Benchmark { get; private set; }
    private sealed class Backend : INativeReadCalls
    {
        internal readonly byte[] Memory = new byte[1024 * 1024];
        internal readonly List<(ulong Address, int Size)> Requests = [];
        internal int Alive, Queries, Reads;
        internal bool Exited, Partial;
        internal uint Protection = 4;
        internal string? QueryError, ReadError;
        internal Action? AfterRead;
        public void EnsureAlive()
        { Alive++; if (Exited) throw new ObservationException("process_exited", "fixture exit"); }
        public MemoryRegion QueryRegion(ulong address)
        {
            Queries++;
            if (QueryError is not null) throw new ObservationException(QueryError, "fixture query");
            return new(address & ~4095UL, 4096, 0x1000, Protection, 0x20000);
        }
        public int ReadBytes(ulong address, byte[] buffer)
        {
            Reads++; Requests.Add((address, buffer.Length));
            if (ReadError is not null) throw new ObservationException(ReadError, "fixture read");
            Memory.AsSpan(checked((int)address), buffer.Length).CopyTo(buffer); AfterRead?.Invoke();
            return Partial ? buffer.Length - 1 : buffer.Length;
        }
        internal byte[] LegacyRead(ulong address, int size)
        {
            if (size <= 0 || size > NativeMemory.MaxRead) throw new ObservationException("invalid_read_size", "fixture size");
            EnsureAlive(); var region = QueryRegion(address);
            if (!region.Readable || !region.Contains(address, size)) throw new ObservationException("unreadable_range", "fixture region");
            var bytes = new byte[size];
            if (ReadBytes(address, bytes) != size) throw new ObservationException("partial_read", "fixture partial");
            EnsureAlive(); return bytes;
        }
    }
    private sealed class Source(Backend backend, bool optimized) : IMemorySource
    {
        public TargetIdentity Identity { get; } = new(27, "fixture.exe", "fixture", 33, new string('f',64), "x64");
        public byte[] Read(ulong address, int size) => optimized ? NativeReadSetup.Read(backend,address,size) : backend.LegacyRead(address,size);
        public void EnsureAlive() => backend.EnsureAlive();
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private static JsonNode Stable(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            var result = new JsonObject();
            foreach (var p in obj)
            {
                // Preserve every non-timing byte/value/status/dependency/address.
                // Each original timing bracket is checked separately below.
                if (p.Key.EndsWith("_ticks", StringComparison.Ordinal) || p.Key is "utc_origin" or "timestamp_utc") continue;
                result[p.Key] = p.Value is null ? null : Stable(p.Value);
            }
            return result;
        }
        if (node is JsonArray array) return new JsonArray(array.Select(x => x is null ? null : Stable(x)).ToArray());
        return node.DeepClone();
    }
    public static int Run()
    {
        int assertions = 0;
        void Check(bool ok, string reason) { assertions++; if (!ok) throw new ObservationException("self_test_failed", "native-read-setup:"+reason); }
        void Fails(Backend b, string code, ulong address = 0x1000, int size = 4)
        {
            try { NativeReadSetup.Read(b,address,size); Check(false,"failure returned bytes"); }
            catch (ObservationException e) { Check(e.Code == code,"expected "+code+" got "+e.Code); }
        }
        var simple = new Backend(); simple.Memory[0x1000]=13;
        Check(NativeReadSetup.Read(simple,0x1000,4)[0]==13 && simple.Alive==1 && simple.Queries==1 && simple.Reads==1,
            "one complete lifetime check, fresh query and exact read");
        foreach (uint protection in new uint[] { 1, 0x104, 0x10 })
        { var b=new Backend{Protection=protection}; Fails(b,"unreadable_range"); Check(b.Reads==0,"protection denied before RPM"); }
        var boundary=new Backend(); Fails(boundary,"unreadable_range",0x1fff,4); Check(boundary.Reads==0,"region boundary preserved");
        Fails(new Backend{Partial=true},"partial_read");
        Fails(new Backend{ReadError="permission_denied"},"permission_denied");
        Fails(new Backend{QueryError="native_error",Exited=true},"process_exited");
        var during=new Backend(); during.AfterRead=()=>during.Exited=true; Fails(during,"process_exited");
        var remap=new Backend(); NativeReadSetup.Read(remap,0x1000,4); remap.Protection=0x104;
        Fails(remap,"unreadable_range"); Check(remap.Queries==2 && remap.Reads==1,"no protection cache even between adjacent reads");
        var changed=new Backend(); NativeReadSetup.Read(changed,0x1000,4); changed.Memory[0x1000]=99;
        Check(NativeReadSetup.Read(changed,0x1000,4)[0]==99 && changed.Reads==2,"no byte cache");

        string directory=Path.Combine(Path.GetTempPath(),"overwatch-decoder-native-read-setup-"+Guid.NewGuid().ToString("N")); Directory.CreateDirectory(directory);
        try
        {
            (JsonNode Frame, Backend Backend) Capture(bool optimized, bool mismatch = false)
            {
                var backend=new Backend(); var source=new Source(backend,optimized);
                var guards=new JsonArray(); var fields=new JsonArray();
                for(int i=0;i<128;i++)
                {
                    int address=0x10000+i*16; BinaryPrimitives.WriteInt64LittleEndian(backend.Memory.AsSpan(address),i+1);
                    guards.Add(new JsonObject{["address"]=address,["bytes_hex"]=Convert.ToHexStringLower(backend.Memory.AsSpan(address,8))});
                }
                for(int i=0;i<75;i++)
                {
                    int address=0x20000+i*4; BinaryPrimitives.WriteInt32LittleEndian(backend.Memory.AsSpan(address),i+1);
                    fields.Add(new JsonObject{["name"]="scalar"+i,["type"]="i32",["address"]=address});
                }
                for(int i=0;i<6;i++)
                {
                    int address=0x30000+i*4096; var slots=new JsonArray();
                    for(int j=0;j<48;j++)
                    {
                        BinaryPrimitives.WriteUInt32LittleEndian(backend.Memory.AsSpan(address+j*24),1);
                        BinaryPrimitives.WriteInt32LittleEndian(backend.Memory.AsSpan(address+j*24+12),BitConverter.SingleToInt32Bits(1f));
                        slots.Add(new JsonObject{["membership_offset"]=j*24,["scalar_offset"]=j*24+12});
                    }
                    fields.Add(new JsonObject{["name"]="sum"+i,["type"]="f32",["address"]=address,["codec"]="pool_sum_f32",["pool_span"]=1152,["pool_slots"]=slots});
                }
                var profile=new JsonObject{["schema"]="overwatch-decoder.field-profile/4",["target"]=JsonSerializer.SerializeToNode(Snapshots.PublicIdentity(source.Identity)),["guards"]=guards,["fields"]=fields};
                string path=Path.Combine(directory,optimized?"optimized.json":"reference.json"); File.WriteAllText(path,profile.ToJsonString());
                if (mismatch) backend.Memory[0x10000] ^= 1;
                using var output=new StringWriter(); using var stop=new CancellationTokenSource();
                FieldStream.RunBounded(source,path,10,TimeSpan.FromSeconds(5),output,stop.Token,new(),_=>stop.Cancel());
                JsonNode frame=output.ToString().Split('\n',StringSplitOptions.RemoveEmptyEntries).Select(s=>JsonNode.Parse(s)!).Single(n=>n["kind"]!.GetValue<string>()=="frame");
                long start=frame["start_ticks"]!.GetValue<long>(),end=frame["end_ticks"]!.GetValue<long>();
                foreach(string phase in new[]{"guards_before","guards_after"})
                    foreach(var g in frame[phase]!.AsArray())
                    {
                        var read=g!["read"]!; long a=read["start_ticks"]!.GetValue<long>(),b=read["end_ticks"]!.GetValue<long>();
                        Check(start<=a && a<=b && b<=end,"actual exact guard read bracket preserved");
                    }
                foreach(var f in frame["fields"]!.AsObject())
                {
                    if (f.Value!["read_start_ticks"] is null)
                    { Check(f.Value["status"]!.GetValue<string>() == "unknown" && f.Value["value"] is null, "unattempted field remains unknown"); continue; }
                    long a=f.Value["read_start_ticks"]!.GetValue<long>(),b=f.Value["read_end_ticks"]!.GetValue<long>();
                    Check(start<=a && a<=b && b<=end,"field physical-read bracket preserved");
                }
                return(frame,backend);
            }
            var reference=Capture(false); var optimized=Capture(true);
            string referenceStable=Stable(reference.Frame).ToJsonString(),optimizedStable=Stable(optimized.Frame).ToJsonString();
            Check(referenceStable==optimizedStable,"whole v4 frame non-timing evidence exactly equivalent");
            Check(reference.Backend.Requests.SequenceEqual(optimized.Backend.Requests),"every physical address/size/order unchanged");
            var badReference=Capture(false,true); var badOptimized=Capture(true,true);
            Check(Stable(badReference.Frame).ToJsonString()==Stable(badOptimized.Frame).ToJsonString() &&
                badReference.Backend.Requests.SequenceEqual(badOptimized.Backend.Requests), "guard mismatch preserves every unknown and read envelope");
            Check(badOptimized.Frame["fields"]!.AsObject().All(f => f.Value!["status"]!.GetValue<string>() == "unknown" && f.Value["value"] is null),
                "failed guard still blocks all dependent fields");
            int reads=optimized.Backend.Reads;
            Check(reads==343 && reference.Backend.Reads==reads && optimized.Backend.Queries==reads && reference.Backend.Queries==reads,
                "343 separate physical reads and permission queries remain");
            Check(reference.Backend.Alive-optimized.Backend.Alive==reads,"one redundant lifetime check removed per exact read");
            int referenceCalls=2*reference.Backend.Alive+reference.Backend.Queries+reference.Backend.Reads;
            int optimizedCalls=2*optimized.Backend.Alive+optimized.Backend.Queries+optimized.Backend.Reads;
            Benchmark=new{schema="overwatch-decoder.native-read-setup-benchmark/1",synthetic=true,frames_per_variant=1,fields=81,guards=128,
                physical_reads=reads,virtual_query_calls=optimized.Backend.Queries,reference_lifetime_checks=reference.Backend.Alive,
                optimized_lifetime_checks=optimized.Backend.Alive,reference_native_calls=referenceCalls,optimized_native_calls=optimizedCalls,
                saved_native_calls=referenceCalls-optimizedCalls,non_timing_evidence_sha256=Convert.ToHexStringLower(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(optimizedStable))),
                note="Production pipeline with counted fake OS calls; not a Windows CPU or wall-time measurement. Every actual timing bracket remains independently validated."};
        }
        finally{Directory.Delete(directory,true);}
        return assertions;
    }
}
