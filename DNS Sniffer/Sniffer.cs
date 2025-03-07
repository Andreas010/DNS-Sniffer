using PacketDotNet;
using PacketDotNet.Utils.Converters;
using SharpPcap;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace DNS_Sniffer;

internal static class Sniffer
{
    public static void Run()
    {
        ILiveDevice device = PickDevice();

        Console.WriteLine("Enter to switch device or stop\n\nSniffing");
        try
        {
            device.OnPacketArrival += OnPacket;
            device.Open(DeviceModes.Promiscuous);
            device.StartCapture();

            Console.ReadLine();
        } catch (Exception e)
        {
            Console.WriteLine("\n\n\nERRROR!!!:\n" + e);
        } finally
        {
            device.OnPacketArrival -= OnPacket;
            device.StopCapture();
            device.Close();
        }
    }

    private static void OnDns(string?[] hosts, IPAddress?[] addresses)
    {
        string? host = null;
        IPAddress? address = null;

        if (hosts.Length == 1 && hosts[0] is not null)
            host = hosts[0];

        foreach (IPAddress? ip in addresses)
        {
            if (ip is null)
                continue;

            if (ip.AddressFamily != AddressFamily.InterNetwork)
                continue;

            address = ip;
            break;
        }

        if (host is null || address is null)
            return;

        if (address.ToString() == "0.0.0.0")
            Writer.AddHost(host);
        else
            Console.Write('.');
    }

    private static void OnPacket(object device, PacketCapture packetCapture)
    {
        RawCapture rawPacket = packetCapture.GetPacket();
        Packet packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);

        UdpPacket? udpPacket = packet.Extract<UdpPacket?>();
        if (udpPacket is null)
            return;

        const int DNS_PORT = 53;
        if (udpPacket.SourcePort != DNS_PORT)
            return;

        HandleDnsPacket(udpPacket);
    }

    private static void HandleDnsPacket(UdpPacket udpPacket)
    {
        using MemoryStream memoryStream = new(udpPacket.PayloadData);
        using BinaryReader reader = new(memoryStream, Encoding.ASCII, false);

        string?[] questions = [];
        IPAddress?[] responses = [];

        try
        {
            reader.BaseStream.Seek(4, SeekOrigin.Current);
            ushort questionCount = EndianBitConverter.Big.ToUInt16(reader.ReadBytes(sizeof(ushort)), 0);
            ushort responseCount = EndianBitConverter.Big.ToUInt16(reader.ReadBytes(sizeof(ushort)), 0);
            reader.BaseStream.Seek(4, SeekOrigin.Current);

            questions = new string?[questionCount];
            ReadDnsQuestions(reader, questions, questionCount);

            responses = new IPAddress[responseCount];
            ReadDnsResponses(reader, responses, responseCount);

            if (questionCount == 0 || responseCount == 0)
                return;

            OnDns(questions, responses);
        }
        catch (Exception ex)
        {
            Console.WriteLine(ex.ToString());
        } finally
        {
            reader.Dispose();
            memoryStream.Dispose();
        }
    }

    private static string ReadString(BinaryReader reader)
    {
        StringBuilder builder = new();

        while (true)
        {
            byte length = reader.ReadByte();
            if (length == 0)
                break;

            if (builder.Length != 0)
                builder.Append('.');
            builder.Append(Encoding.ASCII.GetString(reader.ReadBytes(length)));
        }

        return builder.ToString();
    }

    private static void ReadDnsQuestions(BinaryReader reader, string?[] questions, ushort questionCount)
    {
        for (int i = 0; i < questionCount; i++)
        {
            questions[i] = ReadString(reader);
            ushort type = EndianBitConverter.Big.ToUInt16(reader.ReadBytes(sizeof(ushort)), 0);
            if (type != 1)
                questions[i] = null;

            reader.BaseStream.Seek(2, SeekOrigin.Current);
        }
    }

    private static void ReadDnsResponses(BinaryReader reader, IPAddress?[] responses, ushort responseCount)
    {
        for (int i = 0; i < responseCount; i++)
        {
            reader.BaseStream.Seek(2, SeekOrigin.Current);
            ushort type = EndianBitConverter.Big.ToUInt16(reader.ReadBytes(sizeof(ushort)), 0);
            reader.BaseStream.Seek(6, SeekOrigin.Current);
            ushort dataLength = EndianBitConverter.Big.ToUInt16(reader.ReadBytes(sizeof(ushort)), 0);

            if (type != 1 || dataLength != 4)
            {
                reader.BaseStream.Seek(dataLength, SeekOrigin.Current);
                continue;
            }

            byte[] addressBytes = new byte[4];
            addressBytes = reader.ReadBytes(4);
            IPAddress address = new(addressBytes);

            responses[i] = address;
        }
    }

    private static ILiveDevice PickDevice()
    {
        CaptureDeviceList devices = CaptureDeviceList.New();

        while (true)
        {
            devices.Refresh();

            Console.WriteLine("=== SELECT A DEVICE TO MONITOR ===");
            for (int i = 0; i < devices.Count; i++)
                Console.WriteLine($"{i}: {devices[i].Name} ({devices[i].Description})");
            Console.Write("\nDevice: ");

            string? readLine = Console.ReadLine();
            if (readLine is null || !int.TryParse(readLine, out int selectedIndex))
                continue;

            return devices[selectedIndex];
        }
    }
}
