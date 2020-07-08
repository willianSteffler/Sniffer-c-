using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PraisedSniffer
{
    public class ExtendedIpAddress : IPAddress
    {

        public string City { get; set; }
        public string Country { get; set; }
        public string Region { get; set; }
        public float Latitude { get; set; }
        public float Longitude { get; set; }
        public string ZipCode { get; set; }
        public string TimeZone { get; set; }

        public ExtendedIpAddress(long newAddress,IP2Location.Component ip2l) : base(newAddress)
        {
            setMetaFields(ip2l);

        }

        public ExtendedIpAddress(byte[] address, IP2Location.Component ip2l) : base(address)
        {
            setMetaFields(ip2l);
        }

        public ExtendedIpAddress(byte[] address, long scopeid, IP2Location.Component ip2l) : base(address, scopeid)
        {
            setMetaFields(ip2l);
        }

        private void setMetaFields(IP2Location.Component ip2l)
        {
            if(ip2l != null)
            {
                var qr = ip2l.IPQuery(ToString());
                City = qr.City;
                Country = qr.CountryLong;
                Region = qr.Region;
                Latitude = qr.Latitude;
                Longitude = qr.Longitude;
                ZipCode = qr.ZipCode;
                TimeZone = qr.TimeZone;
            }
        }
    }
}
