using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Threading;
using System.Windows.Forms;

namespace PraisedSniffer
{
    public partial class PraisedSnifferForm : Form
    {
        List<LibPcapLiveDevice> interfaceList = new List<LibPcapLiveDevice>();
        Dictionary<int, Packet> capturedPackets_list = new Dictionary<int, Packet>();
        LibPcapLiveDevice device;
        Thread sniffing;
        int packetNumber;

        public PraisedSnifferForm()
        {
            InitializeComponent();
        }

        private void PraisedSnifferForm_Load(object sender, EventArgs e)
        {
            LibPcapLiveDeviceList devices = LibPcapLiveDeviceList.Instance;

            foreach (var device in devices)
            {
                if (!device.Interface.Addresses.Exists(a => a != null && a.Addr != null && a.Addr.ipAddress != null)) continue;
                var devInterface = device.Interface;
                var friendlyName = devInterface.FriendlyName;
                var description = devInterface.Description;

                interfaceList.Add(device);
                mInterfaces.Items.Add(friendlyName);
            }
            listPackets.Columns.Add("Item", 1);
            listPackets.Columns.Add("Origem", 200, HorizontalAlignment.Center);
            listPackets.Columns.Add("Destino", 200, HorizontalAlignment.Center);
            listPackets.Columns.Add("Protocolo", 70, HorizontalAlignment.Center);
        }

        private void buttonStartStop_Click(object sender, EventArgs e)
        {
            if (buttonStartStop.Text.Equals("Start"))
            {
                if (mInterfaces.SelectedIndex > 0 && mInterfaces.SelectedIndex < interfaceList.Count)
                {
                    buttonStartStop.Text = "Stop";
                    listPackets.Items.Clear();
                    capturedPackets_list.Clear();
                    textProperties.Text = "";
                    packetNumber = 1;

                    device = interfaceList[mInterfaces.SelectedIndex];
                    device.OnPacketArrival += new SharpPcap.PacketArrivalEventHandler(Device_OnPacketArrival);
                    sniffing = new Thread(new ThreadStart(sniffing_Proccess));
                    sniffing.Start();
                }
            }
            else
            {
                buttonStartStop.Text = "Start";
                sniffing.Abort();
                device.StopCapture();
                device.Close();
            }
        }

        private void sniffing_Proccess()
        {
            // Open the device for capturing
            int readTimeoutMilliseconds = 1000;
            device.Open(DeviceMode.Promiscuous, readTimeoutMilliseconds);

            // Start the capturing process
            if (device.Opened)
            {
                device.Capture();
            }
        }

        public void Device_OnPacketArrival(object sender, CaptureEventArgs e)
        {
            var packet = PacketDotNet.Packet.ParsePacket(e.Packet.LinkLayerType, e.Packet.Data);

            // add to the list
            capturedPackets_list.Add(packetNumber, packet);


            var ipPacket = (IpPacket)packet.Extract(typeof(IpPacket));


            if (ipPacket != null)
            {
                var protocol = ipPacket.Protocol.ToString();
                var source = ipPacket.SourceAddress.ToString();
                var destination = ipPacket.DestinationAddress.ToString();



                var protocolPacket = ipPacket.PayloadPacket;

                ListViewItem item = new ListViewItem(packetNumber.ToString());
                item.SubItems.Add(source);
                item.SubItems.Add(destination);
                item.SubItems.Add(protocol);

                Action action = () => listPackets.Items.Add(item);
                listPackets.Invoke(action);


            }
            packetNumber++;
        }

        private void listPackets_ItemSelectionChanged(object sender, ListViewItemSelectionChangedEventArgs e)
        {
            string protocol = e.Item.SubItems[3].Text;
            int key = Int32.Parse(e.Item.SubItems[0].Text);
            Packet packet;
            bool hasPacket = capturedPackets_list.TryGetValue(key, out packet);

            textProperties.Text = "";

            IIpHeader ipHeader;

            if (hasPacket)
            {
                MemoryStream memoryStream = new MemoryStream(packet.PayloadPacket.Header, 0, packet.PayloadPacket.Header.Length);
                BinaryReader binaryReader = new BinaryReader(memoryStream);

                if (((PacketDotNet.EthernetPacket)packet).Type == PacketDotNet.EthernetPacketType.IpV4)
                {
                    ipHeader = new IPHeaderV4(binaryReader);
                    MakeInformationIP(ipHeader);
                }
                else if (((PacketDotNet.EthernetPacket)packet).Type == PacketDotNet.EthernetPacketType.IpV6)
                {
                    ipHeader = new IPHeaderV6(binaryReader);
                    MakeInformationIP(ipHeader);
                }
                else
                {
                    textProperties.Text = "Desconhecido";
                }

                textProperties.Text += "\r\n";

                if (protocol.Equals("TCP"))
                {
                    var tcpPacket = (TcpPacket)packet.Extract(typeof(TcpPacket));
                    if (tcpPacket != null)
                    {
                        var tcpHeader = new TCPHeader(tcpPacket);
                        MakeInformationTCP(tcpHeader);
                    }
                }
                else if (protocol.Equals("UDP"))
                {
                    var udpPacket = (UdpPacket)packet.Extract(typeof(UdpPacket));
                    if (udpPacket != null)
                    {
                        var udpHeader = new UDPHeader(udpPacket);
                        MakeInformationUDP(udpHeader);
                    }
                }
            }
        }

        private void MakeInformationIP(IIpHeader ipHeader)
        {
            textProperties.Text = "IP";
            if (ipHeader is IPHeaderV4)
            {
                var ipHeaderv4 = (IPHeaderV4)ipHeader;
                textProperties.Text +=  "\r\n\tVersão: " + ipHeaderv4.Version +
                                        "\r\n\tTamanho do cabeçalho: " + ipHeaderv4.HeaderLength +
                                        "\r\n\tTipos de serviço: " + ipHeaderv4.DifferentiatedServices +
                                        "\r\n\tComprimento Total: " + ipHeaderv4.TotalLength +
                                        "\r\n\tIdentificação: " + ipHeaderv4.Identification +
                                        "\r\n\tFlags: " + ipHeaderv4.Flags +
                                        "\r\n\tDeslocamento do Fragmento: " + ipHeaderv4.FragmentOffset +
                                        "\r\n\tTempo de vida: " + ipHeaderv4.TimeToLive +
                                        "\r\n\tProtocolo: " + ipHeaderv4.Protocol +
                                        "\r\n\tChecksum: " + ipHeaderv4.Checksum +
                                        "\r\n\tIP Origem: " + ipHeaderv4.SourceAddress +
                                        "\r\n\tIP Destino: " + ipHeaderv4.DestinationAddress;
            }
            else if(ipHeader is IPHeaderV6)
            {
                var ipHeaderv6 = (IPHeaderV6)ipHeader;
                textProperties.Text +=  "\r\n\tVersão: " + ipHeaderv6.Version +
                                        "\r\n\tClasse de Tráfego: " + ipHeaderv6.TrafficClass +
                                        "\r\n\tIdentificação de Fluxo: " + ipHeaderv6.FlowLabel +
                                        "\r\n\tComprimento do Campo de Informação: " + ipHeaderv6.PayloadLength +
                                        "\r\n\tPróximo Cabeçalho: " + ipHeaderv6.NextHeader +
                                        "\r\n\tLimites de Saltos: " + ipHeaderv6.HopLimit +
                                        "\r\n\tIP Origem: " + ipHeaderv6.SourceAddress +
                                        "\r\n\tIP Destino: " + ipHeaderv6.DestinationAddress;
            }
        }

        private void MakeInformationTCP(TCPHeader tcpHeader)
        {
            textProperties.Text +=  "\r\nTCP" +
                                    "\r\n\tPorta Origem: " + tcpHeader.SourcePort +
                                    "\r\n\tPorta Destino: " + tcpHeader.DestinationPort +
                                    "\r\n\tNúmero da sequência: " + tcpHeader.SequenceNumber +
                                    "\r\n\tNúmero Acknowledgement: " + tcpHeader.AcknowledgementNumber +
                                    "\r\n\tTamanho do cabeçalho: " + tcpHeader.HeaderLength +
                                    "\r\n\tFlags: " + tcpHeader.Flags +
                                    "\r\n\tTamanho da janela: " + tcpHeader.WindowSize +
                                    "\r\n\tChecksum: " + tcpHeader.Checksum +
                                    "\r\n\tPonteiro Urgente: " + tcpHeader.UrgentPointer;
        }

        private void MakeInformationUDP(UDPHeader udpHeader)
        {
            textProperties.Text +=  "\r\nUDP" +
                                    "\r\n\tPorta Origem: " + udpHeader.SourcePort +
                                    "\r\n\tPorta Destino: " + udpHeader.DestinationPort +
                                    "\r\n\tTamanho: " + udpHeader.Length +
                                    "\r\n\tChecksum: " + udpHeader.Checksum;
        }
    }
}
