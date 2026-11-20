using System.Diagnostics;
using System.Text.Json;

namespace OverwatchDecoder.Observer;

internal static class AcquisitionRetryTests
{
    private sealed class Memory : IMemorySource
    {
        internal bool AlwaysFail; internal string? Failure; internal int HeaderReads;
        public TargetIdentity Identity { get; } = new(21, "fixture.exe", "fixture", 31, new string('c',64), "x64");
        public byte[] Read(ulong address, int size)
        {
            if (Failure is not null) throw new ObservationException(Failure, "Synthetic failure.");
            if (address == 0x1000) return BitConverter.GetBytes(AlwaysFail || ++HeaderReads == 1 ? 0 : 123);
            return BitConverter.GetBytes(17);
        }
        public void EnsureAlive() { }
        public IEnumerable<MemoryRegion> Regions() => [];
        public void Dispose() { }
    }
    private sealed class StopAfterFrameWriter(CancellationTokenSource stop) : StringWriter
    {
        internal int Frames;
        public override void Write(string? value)
        {
            using var line = JsonDocument.Parse(value!);
            base.Write(value);
            if (line.RootElement.GetProperty("kind").GetString() == "frame")
            { Frames++; stop.Cancel(); }
        }
    }
    internal static int Run()
    {
        int assertions = 0;
        void Check(bool ok,string reason) { assertions++; if(!ok) throw new ObservationException("self_test_failed","acquisition-retry:"+reason); }
        Check(Program.AcquisitionRetryOption(new())==250,"CLI compatible default");
        foreach(int value in new[]{250,1000,2000,5000}) Check(Program.AcquisitionRetryOption(new(){["acquisition-retry-ms"]=value.ToString()})==value,"CLI configured delay");
        foreach(string value in new[]{"0","249","5001","-1","abc","1.5"})
        {
            try { Program.AcquisitionRetryOption(new(){["acquisition-retry-ms"]=value}); Check(false,"invalid CLI accepted"); }
            catch(ObservationException e) { Check(e.Code=="invalid_arguments","CLI rejected before target access"); }
        }
        string root=Path.Combine(Path.GetTempPath(),"overwatch-decoder-retry-"+Guid.NewGuid().ToString("N"));Directory.CreateDirectory(root);
        try
        {
            var memory=new Memory();string recipe=Path.Combine(root,"recipe.json");
            File.WriteAllText(recipe,JsonSerializer.Serialize(new {
                schema="overwatch-decoder.acquisition-recipe/1",target=new{image_name=memory.Identity.ImageName,executable_sha256=memory.Identity.ExecutableSha256,architecture="x64"},
                seconds=5,constants=new{},functions=new{},global_guards="g",stages=new[]{new{name="header",steps=new object[]{
                    new{op="read",name="h",address=4096,size=4},new{op="require",test=new object[]{"eq",new object[]{"load",new object[]{"var","h"},0,4},123}},
                    new{op="guard",set="g",value=new object[]{"var","h"}}}}},fields=new[]{new{name="value",type="i32",address=8192}}
            }));
            // Stop on the evidence this case needs, not a short wall-clock window
            // shared by JIT, filesystem publication, the retry delay and sampling.
            using var resumedStop = new CancellationTokenSource(TimeSpan.FromSeconds(20));
            using var live = new StopAfterFrameWriter(resumedStop);
            string resumedDirectory = Path.Combine(root,"resumed");
            var resumed=ObserveFields.Run(memory,new(0x1000,0x2000,"fixture.exe"),recipe,resumedDirectory,10,TimeSpan.FromSeconds(30),
                resumedStop.Token,liveOutput:live,maxAcquisitions:3,maxConsecutiveAcquisitionFailures:3,acquisitionRetryMs:600);
            Check(resumed.stop_reason=="cancelled" && resumed.acquisitions.Length==2 &&
                resumed.acquisitions[0].error=="acquisition_predicate_failed" && resumed.acquisitions[1].complete &&
                resumed.segments.Length==1 && resumed.segments[0].frames==1 && live.Frames==1,
                "retryable failure then fresh successful acquisition and fixture-requested frame stop");
            var resumedEvents = live.ToString().Split('\n',StringSplitOptions.RemoveEmptyEntries)
                .Select(line => JsonDocument.Parse(line).RootElement.Clone()).ToArray();
            var resumedValue = resumedEvents.Single(line => line.GetProperty("kind").GetString()=="frame").GetProperty("fields").GetProperty("value");
            Check(resumedValue.GetProperty("status").GetString()=="observed" && resumedValue.GetProperty("value").GetInt32()==17 &&
                FieldRecordingVerification.Verify(Path.Combine(resumedDirectory,resumed.segments[0].directory)).valid,
                "fresh successful retry yields a guarded strictly verified sample");
            Check((resumed.acquisitions[1].start_ticks-resumed.acquisitions[0].end_ticks)*1000d/resumed.monotonic_frequency>=600,"configured synchronous minimum retry delay");
            var limits=JsonSerializer.SerializeToElement(resumed.limits);
            Check(limits.GetProperty("retry_delay_ms").GetInt32()==600 && limits.GetProperty("maximum_acquisition_attempts").GetInt32()==3 &&
                limits.GetProperty("maximum_read_bytes").GetInt64()==FieldStream.MaximumReadBytes,"effective provenance and unchanged read budget");
            using(var first=JsonDocument.Parse(live.ToString().Split('\n')[0])) Check(first.RootElement.GetProperty("acquisition_retry_ms").GetInt32()==600,"live session-start option provenance");
            foreach(string scenario in new[]{"cancel","deadline","permission","attempts"})
            {
                memory=new(){AlwaysFail=true,Failure=scenario=="permission"?"permission_denied":null};using var stop=new CancellationTokenSource();
                if(scenario=="cancel")stop.CancelAfter(150);
                var clock=Stopwatch.StartNew();
                var result=ObserveFields.Run(memory,new(0x1000,0x2000,"fixture.exe"),recipe,Path.Combine(root,scenario),10,
                    TimeSpan.FromMilliseconds(scenario=="deadline"?150:2000),stop.Token,maxAcquisitions:2,maxConsecutiveAcquisitionFailures:2,
                    acquisitionRetryMs:scenario=="attempts"?250:5000);
                Check(result.acquisitions.Length==(scenario=="attempts"?2:1),scenario+" bounded attempts");
                Check(result.stop_reason==(scenario=="cancel"?"cancelled":scenario=="deadline"?"fields_never_observed":scenario=="permission"?"permission_denied":"acquisition_retry_limit"),scenario+" truthful terminal reason");
                Check(clock.Elapsed.TotalMilliseconds<1500,scenario+" no unnecessary long retry wait");
            }
            foreach(int invalid in new[]{0,249,5001})
            {
                try { ObserveFields.Run(memory,new(0x1000,0x2000,"fixture.exe"),recipe,Path.Combine(root,"invalid"+invalid),10,TimeSpan.FromSeconds(1),acquisitionRetryMs:invalid);Check(false,"public invalid delay accepted"); }
                catch(ObservationException e){Check(e.Code=="invalid_arguments","public range enforced");}
            }
        }
        finally { Directory.Delete(root,true); }
        return assertions;
    }
}
