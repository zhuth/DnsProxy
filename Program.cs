using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Text;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Windows.Forms;

namespace dnsProxy
{
    struct CacheEntry
    {
        public string ip;
        public DateTime timeStamp;

        public CacheEntry(string Ip)
        {
            ip = Ip; timeStamp = DateTime.Now;
        }
    }

    static class Program
    {
        internal static Dictionary<string, CacheEntry> dnsCache = new Dictionary<string, CacheEntry>();

        public const int MaxCacheCount = 1 << 16;

        /// <summary>
        /// 应用程序的主入口点。
        /// </summary>
        [STAThread]
        static void Main()
        {
            Thread thrListener = new Thread(new ThreadStart(udpListening));
            thrListener.Start();

            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            Application.Run(new Form1());
        }        

        static string[] fetchDnsIpResult(string domain)
        {
            Form1.instance.Invoke(new Action(() => { Form1.instance.addItem(domain); }));
            string ip = "";
            if (domain == Properties.Settings.Default.dnsServerName) return new string[] { Properties.Settings.Default.dnsServerIp };
            if (dnsCache.ContainsKey(domain))
            {
                ip = dnsCache[domain].ip;
                dnsCache[domain] = new CacheEntry(ip);
                return splitIps(ip);
            }

            string url = string.Format(Properties.Settings.Default.dnsServer, domain);
            WebRequest wr = WebRequest.Create(url);
            try
            {
                var sr = new System.IO.StreamReader(wr.GetResponse().GetResponseStream(), true);
                ip = sr.ReadToEnd();
            }
            catch(Exception) 
            {
                throw new NetworkInformationException();
            }
            if (ip == "" || ip == domain) throw new NetworkInformationException();

            if (dnsCache.Count > MaxCacheCount)
            {
                DateTime stamp = DateTime.Now; string victim = "";
                foreach (KeyValuePair<string, CacheEntry> pair in dnsCache)
                {
                    if (pair.Value.timeStamp < stamp) stamp = pair.Value.timeStamp; victim = pair.Key;
                }
                if (dnsCache.ContainsKey(victim)) dnsCache.Remove(victim);
            }

            try
            {
                dnsCache.Add(domain, new CacheEntry(ip));
            }
            catch { }

            return splitIps(ip);
        }

        private static string[] splitIps(string ip)
        {
            if (ip == "") throw new NetworkInformationException();
            List<string> p = new List<string>(ip.Split('\r'));
            p.RemoveAll(new Predicate<string>((str) => { return str.Length == 0; }));
            return p.ToArray();
        }

        static void udpListening()
        {
            UdpClient uc = new UdpClient(53);
            while (true)
            {
                try
                {
                    IPEndPoint remoteEP = null;
                    byte[] data_buf = uc.Receive(ref remoteEP);
                    new Thread(new ParameterizedThreadStart((o_data) =>
                    {
                        byte[] data = (byte[])o_data;
                        int n = data.Length;
                        byte[] buf = new byte[data.Length];
                        Array.Copy(data, buf, data.Length);

                        DnsHeader dHeader = new DnsHeader(data);
                        if (!dHeader.IsResponse)
                        {
                            DnsHeader dHResponse = new DnsHeader(data);
                            dHResponse.IsResponse = true;
                            dHResponse.ancount = dHeader.qdcount;
                            dHResponse.RA = dHResponse.RD = false;

                            byte[] tmp = dHResponse.GetBytes();
                            Array.Copy(tmp, buf, tmp.Length);

                            int offset = dHeader.Length;
                            try
                            {
                                for (int i = 0; i < dHeader.qdcount; ++i)
                                {
                                    DnsQuery dQuery = new DnsQuery(data, offset);
                                    string[] ips = fetchDnsIpResult(dQuery.qname);
                                    string ip = selectIps(ips);
                                    DnsResponse dResponse = new DnsResponse(dQuery.qnameBytes, ip);
                                    buf = mergeBytes(buf, dResponse.data);
                                    offset += dQuery.Length;
                                }
                            }
                            catch (NetworkInformationException)
                            {
                                dHResponse.ancount = dHResponse.qdcount = 0;
                                dHResponse.RCode = 2;
                                buf = dHResponse.GetBytes();
                            }
                            uc.Send(buf, buf.Length, remoteEP);
                        }
                    })).Start(data_buf);
                }
                catch (Exception) { }
            }
        }

        private static byte[] mergeBytes(byte[] buf, byte[] after, int offset, int length)
        {
            byte[] result = new byte[buf.Length + after.Length];
            Array.Copy(buf, result, buf.Length);
            Array.Copy(after, offset, result, buf.Length, length);
            return result;
        }

        private static byte[] mergeBytes(byte[] buf, byte[] after)
        {
            return mergeBytes(buf, after, 0, after.Length);
        }

        private static string selectIps(string[] ips)
        {
            if (ips.Length < 2) return ips[0];
            PingOptions options = new PingOptions();
            options.DontFragment = true;
            byte[] buffer = Encoding.ASCII.GetBytes("aaaaaaaaaaaaaaaaa");
            int timeout = 255;
            
            int finalId = -1, threads = ips.Length;
            for (int i = 0; i < ips.Length; ++i)
            {
                new Thread(new ParameterizedThreadStart((o_index) =>
                {
                    Ping ping = new Ping();
                    int index = (int)o_index;
                    PingReply reply = ping.Send(ips[index], timeout, buffer, options);
                    if (reply.Status == IPStatus.Success)
                    {
                        if (finalId < 0) finalId = index;
                    }
                    --threads;
                })).Start(i);
            }

            while (threads > 0 && finalId < 0) Thread.Sleep(5);

            if (finalId < 0) finalId = new Random().Next(ips.Length);
            return ips[finalId];
        }
    }
}
