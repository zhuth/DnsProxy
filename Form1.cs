using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.IO;
using System.Net;
using System.Windows.Forms;

namespace dnsProxy
{
    public partial class Form1 : Form
    {
        internal static Form1 instance;

        public Form1()
        {
            InitializeComponent();
            instance = this;
        }

        internal void addItem(string text)
        {
            if (listBox1.Items.Count >= 10) listBox1.Items.RemoveAt(9);
            listBox1.Items.Insert(0, text);
        }

        private void Form1_Load(object sender, EventArgs e)
        {
        }

        private void notifyIcon1_MouseDoubleClick(object sender, MouseEventArgs e)
        {
            this.Visible = !this.Visible;
        }

        private void Form1_FormClosing(object sender, FormClosingEventArgs e)
        {
            this.Visible = false;
            e.Cancel = true;
        }

        private void button1_Click(object sender, EventArgs e)
        {
            Environment.Exit(0);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            new System.Threading.Thread(new System.Threading.ThreadStart(() =>
            {
                Dictionary<string, string> hostsRecords = new Dictionary<string, string>();
                foreach (string url in Properties.Settings.Default.hostsUpdate.Split('|'))
                {
                    WebRequest wr = WebRequest.Create(url);
                    try
                    {
                        StreamReader sr = new StreamReader(wr.GetResponse().GetResponseStream());
                        while (!sr.EndOfStream)
                        {
                            string line = sr.ReadLine().Trim();
                            if (line.StartsWith("#")) continue;
                            string[] cols = line.Split(' ', '\t');
                            if (cols.Length < 2) continue;
                            string domain = cols[cols.Length - 1];
                            if (!hostsRecords.ContainsKey(domain))
                                hostsRecords.Add(domain, "");
                            if (!hostsRecords[domain].Contains(cols[0] + "\r"))
                                hostsRecords[domain] += cols[0] + "\r";
                        }
                    }
                    catch (Exception) { }
                }

                foreach (KeyValuePair<string, string> pair in hostsRecords)
                {
                    CacheEntry entry = new CacheEntry(pair.Value); entry.timeStamp = DateTime.MaxValue;
                    if (Program.dnsCache.ContainsKey(pair.Key))
                        Program.dnsCache[pair.Key] = entry;
                    else
                        Program.dnsCache.Add(pair.Key, entry);
                }

                MessageBox.Show("更新完毕！");
            })).Start();
        }
    }
}
