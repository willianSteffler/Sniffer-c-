using PacketDotNet;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PraisedSniffer
{
    public class TCPHeaderFlags
    {
        public string URG { get; set; }
        public string Ack {get;set;}
        public string Psh {get;set;}
        public string Rst {get;set;}
        public string Syn {get;set;}
        public string Fin {get;set;}
        public string ECN {get;set;}
        public string CWR { get; set;}
        public string NS { get; set;}
        public string AllFlags { get; set; }
    }

    public class TCPHeader
    {
        TcpPacket _tcpPacket;
        
        public TCPHeader(TcpPacket tcpPacket)
        {
            _tcpPacket = tcpPacket;
        }

        public string SourcePort
        {
            get
            {
                return _tcpPacket.SourcePort.ToString();
            }
        }

        public string DestinationPort
        {
            get
            {
                return _tcpPacket.DestinationPort.ToString();
            }
        }

        public string SequenceNumber
        {
            get
            {
                return _tcpPacket.SequenceNumber.ToString();
            }
        }

        public string AcknowledgementNumber
        {
            get
            {
                return _tcpPacket.AcknowledgmentNumber.ToString();
            }
        }

        public string HeaderLength
        {
            get
            {
                return _tcpPacket.DataOffset.ToString();
            }
        }

        public string WindowSize
        {
            get
            {
                return _tcpPacket.WindowSize.ToString();
            }
        }

        public string UrgentPointer
        {
            get
            {
                return _tcpPacket.UrgentPointer.ToString();
            }
        }

        public TCPHeaderFlags Flags
        {
            get
            {
                return new TCPHeaderFlags()
                {
                    NS = _tcpPacket.NS   ? "setado" : "não setado",
                    CWR = _tcpPacket.CWR ? "setado" : "não setado",
                    ECN = _tcpPacket.ECN ? "setado" : "não setado",
                    URG = _tcpPacket.Urg ? "Ssetado": "não setado",
                    Ack = _tcpPacket.Ack ? "setado" : "não setado",
                    Psh = _tcpPacket.Psh ? "setado" : "não setado",
                    Rst = _tcpPacket.Rst ? "setado" : "não setado",
                    Syn = _tcpPacket.Syn ? "setado" : "não setado",
                    Fin = _tcpPacket.Fin ? "setado" : "não setado",
                    AllFlags = string.Format("0x{0:x2}", _tcpPacket.AllFlags)
                };
            }
        }

        public string Checksum
        {
            get
            {
                return string.Format("0x{0:x2}", _tcpPacket.Checksum);
            }
        }
    }
}
