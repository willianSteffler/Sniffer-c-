using PacketDotNet;
using System.Text;

namespace PraisedSniffer
{
    public class ICMPv6Header
    {
        private ICMPv6Packet _icmpv6Packet;

        public ICMPv6Header(ICMPv6Packet icmpv6Packet)
        {
            _icmpv6Packet = icmpv6Packet;
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _icmpv6Packet.Checksum);
            }
        }

        public string Codigo
        {
            get
            {
                return _icmpv6Packet.Code.ToString();
            }
        }

        public string Dados
        {
            get
            {
                return Encoding.Default.GetString(_icmpv6Packet.Bytes).Substring(8);
            }
        }

        public string Tipo
        {
            get
            {
                return _icmpv6Packet.Type.ToString();
            }
        }
    }
}
