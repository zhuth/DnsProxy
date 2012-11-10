using System;
using System.Runtime.InteropServices;
using System.Collections.Generic;
using System.Net;
using System.Linq;
using System.Text;

namespace dnsProxy
{
    public class UShortT
    {
        public ushort Value = 0;

        public bool this [int index] {
            get
            {
                index = 15 - index;
                return ((Value >> index) & 0x1) == 1;
            }
            set 
            {
                index = 15 - index;
                if (value)
                    Value |= (ushort)(1 << index);
                else
                    Value &= (ushort)~(1 << index);
            }
        }

        public ushort this [int offset, int length] {
            get {
                ushort result = 0;
                for (int i = offset; i < offset + length && i < 16; ++i)
                    result |= this[i] ? (ushort)(1 << (length - i - 1)) :(ushort)0;
                return result;
            }
            set {
                UShortT ut = new UShortT((ushort)(value << (16 - length)));
                for (int i = 0; i < length && i + offset < 16; ++i)
                {
                    this[i + offset] = ut[i];
                }
            }
        }

        public UShortT(ushort t)
        {
            Value = t;
        }

        public static implicit operator ushort(UShortT val)
        {
            return val.Value;
        }

        public static implicit operator UShortT(ushort t)
        {
            return new UShortT(t);
        }
                
        public byte HighByte
        {
            get { return (byte)(Value >> 8); }
        }

        public byte LowByte
        {
            get { return (byte)(Value & 0xff); }
        }

        public static UShortT FromBytes(byte[] data, int offset)
        {
            return new UShortT(BitConverter.ToUInt16(new byte[] { data[offset + 1], data[offset] }, 0));
        }
    }

    class DnsHeader
    {
        public UShortT id = 0, flags = 0, qdcount = 0, ancount = 0, nscount = 0, arcount = 0;

        public int Length
        {
            get { return 12; }
        }

        public bool IsResponse
        {
            get { return flags[0]; }
            set { flags[0] = value; }
        }

        public bool AA
        {
            get { return flags[5]; }
            set { flags[5] = value; }
        }

        public bool TC
        {
            get { return flags[6]; }
            set { flags[6] = value; }
        }
        
        public bool RD
        {
            get { return flags[7]; }
            set { flags[7] = value; }
        }

        public bool RA
        {
            get { return flags[8]; }
            set { flags[8] = value; }
        }

        public ushort OpCode
        {
            get { return flags[1, 4]; }
            set { flags[1, 4] = value; }
        }

        public ushort RCode
        {
            get { return flags[12, 4]; }
            set { flags[12, 4] = value; }
        }

        public DnsHeader()
        {
        }
        
        public DnsHeader(byte[] data)
        {
            id = UShortT.FromBytes(data, 0);
            flags = UShortT.FromBytes(data, 2);
            qdcount = UShortT.FromBytes(data, 4); 
            ancount = UShortT.FromBytes(data, 6);
            nscount = UShortT.FromBytes(data, 8);
            arcount = UShortT.FromBytes(data, 10);
        }

        public byte[] GetBytes()
        {
            byte[] buf = new byte[this.Length];
            buf[0] = id.HighByte; buf[1] = id.LowByte;
            buf[2] = flags.HighByte; buf[3] = flags.LowByte;
            buf[4] = qdcount.HighByte; buf[5] = qdcount.LowByte;
            buf[6] = ancount.HighByte; buf[7] = ancount.LowByte;
            buf[8] = nscount.HighByte; buf[9] = nscount.LowByte;
            buf[10] = arcount.HighByte; buf[11] = arcount.LowByte;
            return buf;
        }
    }

    class DnsQuery
    {
        public UShortT qtype = 0, qclass = 0;
        public string qname = "";
        public byte[] qnameBytes = null;

        private int length = 0;

        public int Length
        {
            get { return length; }
        }

        public static string ParseName(byte[] data, int offset, out byte[] qnameBytes, out int n)
        {
            n = 0;
            for (; n < data.Length - offset; ++n)
                if (data[n + offset] == 0) break;

            qnameBytes = new byte[n + 1];

            for (int i = 0; i < n; ++i)
            {
                qnameBytes[i] = data[i + offset];
                if (data[offset + i] < 0x2d) data[offset + i] = 0x2e;
            }

            string tmp = Encoding.ASCII.GetString(data, offset, n);
            while (tmp[0] == '.') tmp = tmp.Substring(1);
            return tmp;
        }

        public DnsQuery(byte[] data, int offset)
        {
            int n = 0;
            qname = ParseName(data, offset, out qnameBytes, out n);
            qtype = UShortT.FromBytes(data, offset + n);
            qclass = UShortT.FromBytes(data, offset + n + 2);
            length = n + 4;
        }
    }

    class DnsResponse
    {
        public byte[] name = null;
        public UShortT type1 = 1,
            class1 = 1,
            ttl = 600,
            length = 4;

        public byte[] data = null;

        public DnsResponse(byte[] nameBytes, string ip, ushort Length = 4, ushort Type = 1, ushort Class1 = 1, ushort Ttl = 600)
        {
            name = nameBytes; length = Length; type1 = Type; class1 = Class1; ttl = Ttl;
            IPAddress ipa = IPAddress.Parse(ip);
            byte[] ipab = ipa.GetAddressBytes();
            data = new byte[name.Length + 10 + 4];
            
            for (int i = 0; i < name.Length; ++i) data[i] = name[i];
            
            data[name.Length + 0] = type1.HighByte;
            data[name.Length + 1] = type1.LowByte;

            data[name.Length + 2] = class1.HighByte;
            data[name.Length + 3] = class1.LowByte;

            data[name.Length + 4] = ttl.HighByte;
            data[name.Length + 5] = ttl.LowByte;

            data[name.Length + 6] = ttl.HighByte;
            data[name.Length + 7] = ttl.LowByte;

            data[name.Length + 8] = length.HighByte;
            data[name.Length + 9] = length.LowByte;

            for (int i = 0; i < ipab.Length; ++i) data[name.Length + 10 + i] = ipab[i];
        }

        public byte[] ToBytes()
        {
            return data;
        }
    }
}
