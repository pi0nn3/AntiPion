using System;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Forms;
using System.Xml.Linq;
using Newtonsoft.Json.Linq;

namespace AntiPion
{
    public partial class Form1 : Form
    {
        private const string apiKey = "c8872c9505c853032e67eea96c22439721096e0641f04a19967308f7bfaa712c";

        public Form1()
        {
            InitializeComponent();
        }

        private void Form1_Load(object sender, EventArgs e)
        {
            string[] klasorler = {
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                Environment.GetFolderPath(Environment.SpecialFolder.MyPictures),
                Environment.GetFolderPath(Environment.SpecialFolder.MyMusic),
            };

            foreach (string klasor in klasorler)
            {
                ListeleDosyalar(klasor);
            }
        }

        private void ListeleDosyalar(string dizinYolu)
        {
            try
            {
                string[] dosyalar = Directory.GetFiles(dizinYolu);

                foreach (string dosya in dosyalar)
                {
                    listBox1.Items.Add(dosya);
                }

                string[] altDizinler = Directory.GetDirectories(dizinYolu);

                foreach (string altDizin in altDizinler)
                {
                    ListeleDosyalar(altDizin);
                }
            }
            catch (UnauthorizedAccessException ex)
            {
                
                listBox1.Items.Add($"Klasör erişim reddedildi: {dizinYolu}");
                listBox1.Items.Add($"Hata: {ex.Message}");
            }
            catch (Exception ex)
            {
                
                listBox1.Items.Add($"Hata: {ex.Message}");
            }
        }

        private string CalculateMD5(string filename)
        {
            using (var md5 = MD5.Create())
            {
                using (var stream = File.OpenRead(filename))
                {
                    var hashBytes = md5.ComputeHash(stream);
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < hashBytes.Length; i++)
                    {
                        sb.Append(hashBytes[i].ToString("x2"));
                    }
                    return sb.ToString();
                }
            }
        }

        private void button1_Click(object sender, EventArgs e)
        {
            if (listBox1.SelectedIndex != -1)
            {
                string selectedFile = listBox1.SelectedItem.ToString();
                if (File.Exists(selectedFile))
                {
                    string fileHash = CalculateMD5(selectedFile);
                    ScanFile(fileHash);
                }
                else
                {
                    MessageBox.Show("Seçilen dosya bulunamadı.");
                }
            }
            else
            {
                MessageBox.Show("Lütfen bir dosya seçin.");
            }
        }

        private void ScanFile(string fileHash)
        {
            string url = "https://www.virustotal.com/vtapi/v2/file/report";
            string parameters = $"?apikey={apiKey}&resource={fileHash}";

            WebClient client = new WebClient();
            client.Encoding = Encoding.UTF8;

            try
            {
                string response = client.DownloadString(url + parameters);
                ShowScanResults(response);
            }
            catch (WebException ex)
            {
                MessageBox.Show("Hata: " + ex.Message);
            }
        }

        private void ShowScanResults(string response)
        {
            
            JObject json = JObject.Parse(response);
            int responseCode = (int)json["response_code"];
            if (responseCode == 1)
            {
                JToken positives = json["positives"];
                JToken total = json["total"];
                string result = $"Dosya zararlıdır. {positives} / {total} tarama motoru tarafından algılandı.";
                MessageBox.Show(result, "Tarama Sonuçları", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            else if (responseCode == 0)
            {
                MessageBox.Show("Dosya zararsızdır.", "Tarama Sonuçları", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                MessageBox.Show("Tarama sonuçları alınamadı.", "Tarama Sonuçları", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }
    }
}
