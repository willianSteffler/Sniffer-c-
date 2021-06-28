using PacketDotNet;
using System.Text;

namespace PraisedSniffer
{
    public class IGMPv2Header
    {
        private IGMPv2Packet _igmpv2Packet;

        public IGMPv2Header(IGMPv2Packet igmpv2Packet)
        {
            _igmpv2Packet = igmpv2Packet;
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _igmpv2Packet.Checksum);
            }
        }

        public string MaxResponseTime
        {
            get
            {
                return _igmpv2Packet.MaxResponseTime.ToString();
            }
        }

        public string GroupAddress
        {
            get
            {
                return _igmpv2Packet.GroupAddress.ToString();
            }
        }


        public string Tipo
        {
            get
            {
                return _igmpv2Packet.Type.ToString();
            }
        }
    }
}
