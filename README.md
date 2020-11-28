# Sniffer-c-
O [sniffer escolhido](https://www.codeproject.com/Articles/17031/A-Network-Sniffer-in-C) já tinha desenvolvido os cabeçalhos dos protocolos IPv4, TCP, UDP cada um em sua respectiva classe IPHeaderV4, TCPHeader, UDPHeader. Porém, o sniffer não estava funcionando adequadamente através da implementação por sockets então tivemos que alterar o seu código para buscar os pacotes. Para isso foi utilizado 3 pacotes do NuGet, sendo eles: [SharpPcap](https://github.com/chmorgan/sharppcap), [Pcap.Net.x86 ](https://github.com/PcapDotNet/Pcap.Net) e o [PacketDotNet](https://www.nuget.org/packages/PacketDotNet/1.0.3?\_src=template). A funcionalidade acrescida ao programa foi o cabeçalho do protocolo IPv6, além de algumas mudanças de interface. Para isso foi criada a classe IPHeaderV6 contendo todas as informações do cabeçalho do protocolo. Adicionado cabeçalho do protocolo ICMP e ICMPv6, contendo todas as informações do cabeçalho.
## IP2Location
[Ip2Location](https://www.nuget.org/packages/IP2Location.IPGeolocation/) é uma biblioteca para pesquisar meta-informações sobre ips v4 e v6 é possivel baixar um banco de dados diretamente do [site](https://www.ip2location.com/database/ip2location) e adicionar na aplicação para a pesquisa de IPs, existem versões gratuitas e pagas, as gratuitas não são tao precisas quanto as pagas.
