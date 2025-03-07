using DNS_Sniffer;

Writer.LoadDnsPairs();
Task resolverTask = Writer.ResolveDnsLoop();
while (true)
    Sniffer.Run();
