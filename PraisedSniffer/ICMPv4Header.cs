using PacketDotNet;
using System.Text;

namespace PraisedSniffer
{
    public class ICMPv4Header
    {
        private ICMPv4Packet _icmpv4Packet;

        public ICMPv4Header(ICMPv4Packet icmpv4Packet)
        {
            _icmpv4Packet = icmpv4Packet;
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _icmpv4Packet.Checksum);
            }
        }

        public string Dados
        {
            get
            {
                return Encoding.Default.GetString(_icmpv4Packet.Data);
            }
        }

        public string ID
        {
            get
            {
                return _icmpv4Packet.ID.ToString();
            }
        }

        public string TipoCodigo
        {
            get
            {
                return _icmpv4Packet.TypeCode.ToString();
            }
        }

        public string Sequencia
        {
            get
            {
                return _icmpv4Packet.Sequence.ToString();
            }
        }
    }
}
