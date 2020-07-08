using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace PraisedSniffer
{
    interface IIpHeader
    {
        ExtendedIpAddress DestinationAddress { get; }
        ExtendedIpAddress SourceAddress { get; }
    }
}
