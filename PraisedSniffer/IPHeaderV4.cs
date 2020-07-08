using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace PraisedSniffer
{
    public class IPHeaderV4 : IIpHeader
    {
        private byte _headerLength;
        private byte _differentiatedServices;
        private byte _timeToLive;
        private byte _protocol;

        private ushort _totalLength;
        private ushort _identification;
        private ushort _flagsAndOffset;

        private short _checksum;

        public IPHeaderV4(BinaryReader binaryReader,IP2Location.Component ip2l)
        {
            try
            {
                _headerLength = binaryReader.ReadByte();
                _headerLength <<= 4;
                _headerLength >>= 4;
                _headerLength *= 4;

                _differentiatedServices = binaryReader.ReadByte();

                _totalLength = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                _identification = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                _flagsAndOffset = (ushort)IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                _timeToLive = binaryReader.ReadByte();

                _protocol = binaryReader.ReadByte();

                _checksum = IPAddress.NetworkToHostOrder(binaryReader.ReadInt16());

                SourceAddress = new ExtendedIpAddress((uint)(binaryReader.ReadInt32()), ip2l);

                DestinationAddress = new ExtendedIpAddress((uint)(binaryReader.ReadInt32()), ip2l);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "PraisedSniffer", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        public string Version
        {
            get
            {
                return "IP v4";
            }
        }
        public string HeaderLength
        {
            get
            {
                return _headerLength.ToString();
            }
        }

        public string DifferentiatedServices
        {
            get
            {
                return string.Format("0x{0:x2} ({1})", _differentiatedServices, _differentiatedServices);
            }
        }

        public string TotalLength
        {
            get
            {
                return _totalLength.ToString();
            }
        }

        public string Identification
        {
            get
            {
                return _identification.ToString();
            }
        }

        public string Flags
        {
            get
            {
                int flags = _flagsAndOffset >> 13;
                if (flags == 2)
                {
                    return "Não fragmentado";
                }
                else if (flags == 1)
                {
                    return "Mais fragmentos";
                }
                else
                {
                    return flags.ToString();
                }
            }
        }

        public string FragmentOffset
        {
            get
            {
                int offset = _flagsAndOffset << 3;
                offset >>= 3;

                return offset.ToString();
            }
        }

        public string TimeToLive
        {
            get
            {
                return _timeToLive.ToString();
            }
        }

        public string Protocol
        {
            get
            {
                if (_protocol == 6)
                {
                    return "TCP";
                }
                else if (_protocol == 17)
                {
                    return "UDP";
                }
                else
                {
                    return "Desconhecido";
                }
            }
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _checksum);
            }
        }

        public ExtendedIpAddress SourceAddress { get; }

        public ExtendedIpAddress DestinationAddress { get; }
    }
}
