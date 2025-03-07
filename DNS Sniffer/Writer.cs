using System.Diagnostics;
using System.Net;
using System.Text;
using System.Text.Json;

namespace DNS_Sniffer;

internal static class Writer
{
    private const string HOSTS_PATH =  @"C:\Windows\System32\drivers\etc\hosts";

    private static readonly List<string> hosts = [];
    private static readonly List<string> missingHosts = [];

    private static FileStream hostsFileStream = null!;

    private static bool dirty;
    private static readonly Uri dnsUri = new("https://www.nslookup.io/api/v1/records");
    private static readonly HttpClient httpClient = new();

    public static void LoadDnsPairs()
    {
        hostsFileStream = new FileStream(HOSTS_PATH, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);

        using TextReader reader = new StreamReader(hostsFileStream, Encoding.UTF8, leaveOpen: true);

        string? line;
        while((line = reader.ReadLine()) is not null)
        {
            line = line.Trim();
            if (line.StartsWith('#'))
                continue;

            string[] parts = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
            if (parts.Length != 2)
                continue;

            hosts.Add(parts[1]);
        }
    }

    public static void AddHost(string host)
    {
        if (hosts.Contains(host))
            return;

        if (missingHosts.Contains(host))
            return;

        missingHosts.Add(host);
    }

    public static async Task ResolveDnsLoop()
    {
        while(true)
        {
            await ResolveMissingHosts();
            await Task.Delay(5_000);

            if (dirty)
            {
                Console.WriteLine();
                NativeMethods.DnsFlushResolverCache();
                dirty = false;
            }
        }
    }

    private static async Task ResolveMissingHosts()
    {
        Task<(string, IPAddress?)>[] tasks = new Task<(string, IPAddress?)>[missingHosts.Count];

        for (int i = 0; i < missingHosts.Count; i++)
            tasks[i] = ResolveHost(missingHosts[i]);

        await foreach(Task<(string, IPAddress?)> dnsResponse in Task.WhenEach(tasks))
        {
            if (!dnsResponse.IsCompletedSuccessfully)
            {
                Console.Write('X');
                continue;
            }

            var (host, address) = dnsResponse.Result;

            hosts.Add(host);
            missingHosts.Remove(host);

            if (address is null)
            {
                Console.Write(',');
                continue;
            }

            string appendage = $"\t{address}\t{host}\n";

            hostsFileStream.Position = hostsFileStream.Length - 1;
            if (hostsFileStream.ReadByte() != (byte)'\n')
                hostsFileStream.WriteByte((byte)'\n');

            hostsFileStream.Position = hostsFileStream.Length;
            await hostsFileStream.WriteAsync(Encoding.UTF8.GetBytes(appendage));
            dirty = true;
        }

        await hostsFileStream.FlushAsync();
    }

    private static async Task<(string, IPAddress?)> ResolveHost(string host)
    {
        Console.Write('?');
        HttpContent content = new StringContent($"{{\"domain\":\"{host}\",\"dnsServer\":\"thenetherlands\"}}");

        HttpResponseMessage message = await httpClient.PostAsync(dnsUri, content);
        JsonElement json = (await JsonDocument.ParseAsync(message.Content.ReadAsStream())).RootElement;

        if (!json.TryGetProperty("records", out JsonElement records))
            return (host, null);

        if (!records.TryGetProperty("a", out JsonElement ipv4Records))
            return (host, null);

        if (!ipv4Records.TryGetProperty("response", out JsonElement ipv4Responses))
            return (host, null);

        if (!ipv4Responses.TryGetProperty("answer", out JsonElement ipv4Answer))
            return (host, null);

        if (ipv4Answer.GetArrayLength() == 0)
            return (host, null);

        foreach(var ipv4AnserEnum in ipv4Answer.EnumerateArray())
        {
            if (!ipv4AnserEnum.TryGetProperty("ipInfo", out JsonElement ipInfo))
                continue;

            if (!ipInfo.TryGetProperty("query", out JsonElement ipQuery))
                continue;

            Console.Write('!');
            return (host, IPAddress.Parse(ipQuery.GetString()!));
        }

        return (host, null);
    }
}
