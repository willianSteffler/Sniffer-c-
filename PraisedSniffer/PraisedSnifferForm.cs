using PacketDotNet;
using SharpPcap;
using SharpPcap.LibPcap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Windows.Forms;

namespace PraisedSniffer
{
    public partial class PraisedSnifferForm : Form
    {
        List<LibPcapLiveDevice> interfaceList = new List<LibPcapLiveDevice>();
        Dictionary<int, Packet> capturedPackets_list = new Dictionary<int, Packet>();
        LibPcapLiveDevice device;
        IP2Location.Component ip2l = null;
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

            if(Properties.Settings.Default.DbFile == null || Properties.Settings.Default.DbFile == "")
            {
                if(MessageBox.Show("Nenhum arquivo de banco de dados foi carregado, deseja carrega-lo agora ?",
                    "Carregar arquivo",
                    MessageBoxButtons.YesNo,
                    MessageBoxIcon.Question) == DialogResult.Yes)
                {
                    LoadIp2l("");
                } else
                {
                    WarnIp2lNotLoadeded();
                }
            } else
            {
                LoadIp2l(Properties.Settings.Default.DbFile);
            }
        }

        private void buttonStartStop_Click(object sender, EventArgs e)
        {
            if (buttonStartStop.Text.Equals("Start"))
            {
                if (mInterfaces.SelectedIndex > -1 && mInterfaces.SelectedIndex < interfaceList.Count)
                {
                    buttonStartStop.Text = "Stop";
                    listPackets.Items.Clear();
                    capturedPackets_list.Clear();
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

            IIpHeader ipHeader;

            if (hasPacket)
            {
                MemoryStream memoryStream = new MemoryStream(packet.PayloadPacket.Header, 0, packet.PayloadPacket.Header.Length);
                BinaryReader binaryReader = new BinaryReader(memoryStream);
                treeView1.Nodes.Clear();

                if (((PacketDotNet.EthernetPacket)packet).Type == PacketDotNet.EthernetPacketType.IpV4)
                {
                    ipHeader = new IPHeaderV4(binaryReader,this.ip2l);
                    MakeInformationIP(ipHeader);
                }
                else if (((PacketDotNet.EthernetPacket)packet).Type == PacketDotNet.EthernetPacketType.IpV6)
                {
                    ipHeader = new IPHeaderV6(binaryReader,this.ip2l);
                    MakeInformationIP(ipHeader);
                }
                else
                {
                    treeView1.Nodes.Add("Desconhecido");
                }

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

                treeView1.ExpandAll();
            }
        }

        private void MakeInformationIP(IIpHeader ipHeader)
        {
            TreeNode ipNode = new TreeNode("IP");
            if (ipHeader is IPHeaderV4)
            {
                var ipHeaderv4 = (IPHeaderV4)ipHeader;

                ipNode.Nodes.AddRange(new TreeNode[]{
                    new TreeNode($"Versão: {ipHeaderv4.Version}"),
                    new TreeNode($"Tamanho do cabeçalho: {ipHeaderv4.HeaderLength}"),
                    new TreeNode($"Tipos de serviço: {ipHeaderv4.DifferentiatedServices}"),
                    new TreeNode($"Comprimento Total: {ipHeaderv4.TotalLength}"),
                    new TreeNode($"Identificação: {ipHeaderv4.Identification}"),
                    new TreeNode($"Flags: {ipHeaderv4.Flags}"),
                    new TreeNode($"Deslocamento do Fragmento: {ipHeaderv4.FragmentOffset}"),
                    new TreeNode($"Tempo de vida: {ipHeaderv4.TimeToLive}"),
                    new TreeNode($"Protocolo: {ipHeaderv4.Protocol}"),
                    new TreeNode($"Checksum: {ipHeaderv4.Checksum}")
                });

            }
            else if(ipHeader is IPHeaderV6)
            {
                var ipHeaderv6 = (IPHeaderV6)ipHeader;

                ipNode.Nodes.AddRange(new TreeNode[]{
                    new TreeNode($"Versão: {ipHeaderv6.Version}"),
                    new TreeNode($"Classe de Tráfego: {ipHeaderv6.TrafficClass}"),
                    new TreeNode($"Identificação de Fluxo: {ipHeaderv6.FlowLabel}"),
                    new TreeNode($"Comprimento do Campo de Informação: {ipHeaderv6.PayloadLength}"),
                    new TreeNode($"Próximo Cabeçalho: {ipHeaderv6.NextHeader}"),
                    new TreeNode($"Limites de Saltos: {ipHeaderv6.HopLimit}"),
                });
            }

            ipNode.Nodes.AddRange(new TreeNode[] {
            new TreeNode($"Origem: {ipHeader.SourceAddress.ToString()}", this.ip2l == null ? new TreeNode[] { } :
                        new TreeNode[] {
                            new TreeNode($"Cidade: {ipHeader.SourceAddress.City}"),
                            new TreeNode($"País: {ipHeader.SourceAddress.Country}"),
                            new TreeNode($"Região: {ipHeader.SourceAddress.Region}"),
                            new TreeNode($"Latitude: {ipHeader.SourceAddress.Latitude}"),
                            new TreeNode($"Longitude: {ipHeader.SourceAddress.Longitude}"),
                            new TreeNode($"Cod Postal: {ipHeader.SourceAddress.ZipCode}"),
                            new TreeNode($"Time-Zone: {ipHeader.SourceAddress.TimeZone}"),
                        }),
                    new TreeNode($"Destino: {ipHeader.DestinationAddress.ToString()}", this.ip2l == null ? new TreeNode[] { } :
                        new TreeNode[] {
                            new TreeNode($"Cidade: {ipHeader.DestinationAddress.City}"),
                            new TreeNode($"País: {ipHeader.DestinationAddress.Country}"),
                            new TreeNode($"Região: {ipHeader.DestinationAddress.Region}"),
                            new TreeNode($"Latitude: {ipHeader.DestinationAddress.Latitude}"),
                            new TreeNode($"Longitude: {ipHeader.DestinationAddress.Longitude}"),
                            new TreeNode($"Cod Postal: {ipHeader.DestinationAddress.ZipCode}"),
                            new TreeNode($"Time-Zone: {ipHeader.DestinationAddress.TimeZone}"),
                        })});


            treeView1.Nodes.Add(ipNode);
        }

        private void MakeInformationTCP(TCPHeader tcpHeader)
        {
            TreeNode tcpNode = new TreeNode("TCP", new TreeNode[]{
                    new TreeNode($"Porta Origem: {tcpHeader.SourcePort}"),
                    new TreeNode($"Porta Destino: {tcpHeader.DestinationPort}"),
                    new TreeNode($"Número da sequência: {tcpHeader.SequenceNumber}"),
                    new TreeNode($"Número Acknowledgement: {tcpHeader.AcknowledgementNumber}"),
                    new TreeNode($"Tamanho do cabeçalho: {tcpHeader.HeaderLength}"),
                    new TreeNode($"Flags: {tcpHeader.Flags.AllFlags}",new TreeNode [] {
                            new TreeNode($"NS: {tcpHeader.Flags.NS}"),
                            new TreeNode($"CWR: {tcpHeader.Flags.CWR}"),
                            new TreeNode($"ECN: {tcpHeader.Flags.ECN}"),
                            new TreeNode($"URG: {tcpHeader.Flags.URG}"),
                            new TreeNode($"ACK: {tcpHeader.Flags.Ack}"),
                            new TreeNode($"PSH: {tcpHeader.Flags.Psh}"),
                            new TreeNode($"RST: {tcpHeader.Flags.Rst}"),
                            new TreeNode($"SYN: {tcpHeader.Flags.Syn}"),
                            new TreeNode($"FIN: {tcpHeader.Flags.Fin}"),
                        }),
                    new TreeNode($"Tamanho da janela: {tcpHeader.WindowSize}"),
                    new TreeNode($"Checksum: {tcpHeader.Checksum}"),
                    new TreeNode($"Ponteiro Urgente: {tcpHeader.UrgentPointer}")
                });

            treeView1.Nodes.Add(tcpNode);
        }

        private void MakeInformationUDP(UDPHeader udpHeader)
        {
            TreeNode udpNode = new TreeNode("UDP", new TreeNode[]{
                    new TreeNode($"Porta Origem: {udpHeader.SourcePort}"),
                    new TreeNode($"Porta Destino: {udpHeader.DestinationPort}"),
                    new TreeNode($"Tamanho: {udpHeader.Length}"),
                    new TreeNode($"Checksum: {udpHeader.Checksum}")
                });

            treeView1.Nodes.Add(udpNode);
        }

        private void button1_Click(object sender, EventArgs e)
        {
            LoadIp2l("");
        }

        void LoadIp2l(string binFile)
        {
            IP2Location.Component ip2l;
            if(binFile == "" || binFile == null)
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    openFileDialog.Filter = "IP2L Database files (*.BIN)|*.BIN|All files (*.*)|*.*";
                    openFileDialog.FilterIndex = 1;
                    openFileDialog.RestoreDirectory = true;

                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        binFile = openFileDialog.FileName;
                    }
                }
            }

            if(binFile != "" && binFile != null)
            {
                ip2l = new IP2Location.Component();
                ip2l.UseMemoryMappedFile = true;
                ip2l.IPDatabasePath = binFile;
                if (ip2l.LoadBIN())
                {
                    this.ip2l = ip2l;
                    textBox1.Text = binFile;
                    Properties.Settings.Default.DbFile = binFile;
                    Properties.Settings.Default.Save();
                }
                else
                {
                    MessageBox.Show("Não foi possível abrir o arquivo do banco de dados", "Falha", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }

            WarnIp2lNotLoadeded();
        }

        void WarnIp2lNotLoadeded()
        {
            if (this.ip2l == null)
            {
                MessageBox.Show("Por favor selecione um arquivo válido para o banco de dados para ter acesso as informações do Geo-IP",
                    "Aviso", MessageBoxButtons.OK, MessageBoxIcon.Exclamation);
            }
        }
    }
}
