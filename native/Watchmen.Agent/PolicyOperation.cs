using System.Text.Json;

// A streamed control channel keeps the UI informed even while a Windows RPC
// call is waiting. Counts describe staged work, not committed enforcement.
static class PolicyOperation
{
    static readonly object Gate=new();
    static CancellationTokenSource? cancellation,heartbeat;
    static Task? ticker;
    static bool enabled;
    static string stage="queued",message="Waiting to start…";
    static long completed,total;
    static bool canCancel=true;
    static DateTimeOffset advanced=DateTimeOffset.UtcNow,lastEmission=DateTimeOffset.MinValue;
    public static CancellationToken Token=>cancellation?.Token??CancellationToken.None;
    public static void Start(bool controlled)
    {
        enabled=controlled;cancellation=new CancellationTokenSource();
        if(!controlled)return;
        _=Task.Run(async()=>{try{while(true){string? line=await Console.In.ReadLineAsync();if(line==null||line=="cancel"){cancellation?.Cancel();return;}}}catch{cancellation?.Cancel();}});
        heartbeat=new CancellationTokenSource();
        ticker=Task.Run(async()=>{try{while(true){await Task.Delay(1000,heartbeat.Token);Emit();}}catch(OperationCanceledException){}});
        Report("queued",0,0,"Waiting to start…");
    }
    public static void Check()=>Token.ThrowIfCancellationRequested();
    public static void Report(string next,long done=0,long expected=0,string? detail=null,bool cancellable=true)
    {
        lock(Gate){bool changed=next!=stage||done!=completed;if(changed)advanced=DateTimeOffset.UtcNow;stage=next;completed=done;total=expected;message=detail??next;canCancel=cancellable;if(changed&&(DateTimeOffset.UtcNow-lastEmission).TotalMilliseconds>=200||done==expected&&expected>0)Emit();}
    }
    static void Emit()
    {
        if(!enabled)return;
        lock(Gate){lastEmission=DateTimeOffset.UtcNow;Console.WriteLine(JsonSerializer.Serialize(new{type="progress",stage,message,completed,total,canCancel,updatedAt=lastEmission,lastAdvancedAt=advanced},Firewall.Json));}
    }
    public static async Task Stop(){var timer=heartbeat;if(timer!=null){timer.Cancel();if(ticker!=null)await ticker;timer.Dispose();heartbeat=null;}enabled=false;/* The input reader may still be waiting until process exit. */}
}
