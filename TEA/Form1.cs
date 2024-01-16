using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Configuration;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Timers;
using System.Windows.Forms;



namespace prviKlijent
{
    public partial class Form1 : Form
    {

        private int fileCounter = 0;
        private int i = 0;
        string key = "";
        string directoryPath;
        private FileSystemWatcher watcher;
        private CustomTEA customTEA;
        private Random random;
        private string randomNum;
        public string filePath1;
        public string poruka = "";
        public string encryptedContent = "";
        public string Sha1Hash = "";
        public string algoritam = "LEA";
        public bool file = false;
        byte[] LEAkey;
        byte[] iv;
        public Form1()
        {
            InitializeComponent();
            random = new Random();
            customTEA = new CustomTEA();
            string line1;
            string fileName1 = "communication.txt";
            string baseDirectory1 = Path.GetDirectoryName(AppDomain.CurrentDomain.BaseDirectory);
            filePath1 = Path.Combine(baseDirectory1, fileName1);
            filePath1 = filePath1.Replace("\\TEA\\bin\\Debug\\", "\\");

            using (StreamReader file1 = new StreamReader(filePath1))
            {
                line1 = file1.ReadToEnd();
            }

            randomNum = random.Next(0, 10000 + 1).ToString();
            if (line1.Contains(randomNum))
                randomNum += 1;


            string apiKey = System.Configuration.ConfigurationManager.AppSettings["ApiKey"];

            if (apiKey != null) key = apiKey;


            LEAkey = LEA.GenerateRandomKey();
            iv = LEA.GenerateRandomIV();


            directoryPath = filePath1.Replace("\\communication.txt", "");
            InitializeWatcher();

        }

        private void InitializeWatcher()
        {
            try
            {
                watcher = new FileSystemWatcher();
                watcher.Path = directoryPath;
                watcher.NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.FileName | NotifyFilters.DirectoryName;

                watcher.Changed += OnChanged;
                watcher.Deleted += OnChanged;
                watcher.Created += OnChanged;
                watcher.Renamed += OnChanged;

                watcher.EnableRaisingEvents = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Error setting up FileSystemWatcher: " + ex.Message);
            }
        }
        private static Mutex fileMutex = new Mutex(false, "MyFileMutex");

        private void OnChanged(object sender, FileSystemEventArgs e)
        {
            try
            {


                using (FileStream fs = new FileStream(filePath1, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    using (StreamReader reader = new StreamReader(fs))
                    {

                        encryptedContent = reader.ReadToEnd();
                        poruka = encryptedContent;
                        string decryptedContent = "";
                        if (algoritam == "TEA")
                            decryptedContent = customTEA.DecryptData(encryptedContent, key);
                        else
                            decryptedContent = LEA.LEADecryptionCTR(LEAkey, iv, encryptedContent);

                        if (decryptedContent != null)
                        {
                            if (!decryptedContent.StartsWith(randomNum))
                            {
                                if (!decryptedContent.Contains("-sha") && !decryptedContent.Contains("sha-"))
                                {
                                    richTextBox3.Invoke((MethodInvoker)delegate
                                    {
                                        richTextBox3.Text = ($"{encryptedContent}" + "\n");
                                    });


                                    richTextBox4.Invoke((MethodInvoker)delegate
                                    {
                                        if (key != "")
                                        {
                                            richTextBox4.Text = ($"{decryptedContent}" + "\n");
                                        }
                                    });
                                }
                                else
                                {
                                    string capturedTextSha = "";
                                    string remainingText = "";
                                    int indexShaStart = decryptedContent.IndexOf("-sha") + 4; 
                                    int indexShaEnd = decryptedContent.IndexOf("sha-", indexShaStart);

                                    if (indexShaStart >= 4 && indexShaEnd > indexShaStart)
                                    {
                                         capturedTextSha = decryptedContent.Substring(indexShaStart+1, indexShaEnd - indexShaStart-2);
                                    }
                                    if (indexShaEnd != -1)
                                    {

                                         remainingText = decryptedContent.Substring(indexShaEnd + 4);
                                    }

                                    string shaPrimljenog= Sha1.ComputeSHA1(Encoding.UTF8.GetBytes(remainingText));
                                    if (capturedTextSha == shaPrimljenog)
                                    {
                                        label1.Invoke((MethodInvoker)delegate
                                        {
                                            label1.Text = "Hash-ovi su jednaki! Datoteka je primljena uspesno!";
                                        });
                                    }
                                    else
                                    {
                                        label1.Invoke((MethodInvoker)delegate
                                        {
                                            label1.Text = "Hash-ovi nisu jednaki! Datoteka nije primljena uspesno!";
                                        });
                                    }

                                    richTextBox3.Invoke((MethodInvoker)delegate
                                    {
                                        richTextBox3.Text = ($"{encryptedContent}" + "\n");
                                    });


                                    richTextBox4.Invoke((MethodInvoker)delegate
                                    {
                                        if (key != "")
                                        {
                                            richTextBox4.Text = ($"{decryptedContent.Substring(indexShaEnd + 4)}" + "\n");
                                        }
                                    });


                                }
                                }
                        }

                    }
                }
            }
            catch (Exception ex)
            {

                Console.WriteLine($"Error processing encrypted message: {ex.Message}");
            }
        }






        private void checkBox2_CheckedChanged_1(object sender, EventArgs e)
        {
            if (checkBox2.Checked)
            {
                richTextBox4.Visible = true;
            }
            else
            {
                richTextBox4.Visible = false;
            }
        }


        private void button2_Click(object sender, EventArgs e)
        {    try
                {
                    string message = richTextBox5.Text.ToString();
                    string encryptedChangeInfo;

                    BeginInvoke(new Action(() =>
                    {
                        if (key != "")
                        {
                            if (file == false)
                            {
                                if (algoritam == "TEA")
                                {
                                    encryptedChangeInfo = customTEA.EncryptData($"{randomNum}-{message}", key);
                                }
                                else encryptedChangeInfo = LEA.LEAEncryptionCTR(LEAkey, iv, $"{randomNum}-{message}");
                            }
                            else
                            {

                                encryptedChangeInfo = encryptedContent;
                                File.WriteAllText(filePath1, encryptedChangeInfo + Environment.NewLine);
                                richTextBox5.Text = "";
                                return;
                            }
                        }
                        else encryptedChangeInfo = message;

                        File.WriteAllText(filePath1, encryptedChangeInfo + Environment.NewLine);
                        richTextBox5.Text = "";
                    }));
                }
                catch (Exception ex)
                {
                    MessageBox.Show($"An error occurred: {ex.Message}");
                }
            }


            private void richTextBox3_TextChanged(object sender, EventArgs e)
        {

        }



        private void radioButton1_CheckedChanged(object sender, EventArgs e)
        {
            algoritam = "LEA";
            string decryptedContent = "";

            decryptedContent = LEA.LEADecryptionCTR(LEAkey, iv, poruka);

            if (decryptedContent != null)
            {
                if (!decryptedContent.StartsWith(randomNum))
                {
                    richTextBox3.Invoke((MethodInvoker)delegate
                    {
                        richTextBox3.Text = ($"{poruka}" + "\n");
                    });


                    richTextBox4.Invoke((MethodInvoker)delegate
                    {
                        if (key != "")
                        {
                            richTextBox4.Text = ($"{decryptedContent}" + "\n");
                        }
                    });
                }
            }

        }

        private void radioButton2_CheckedChanged(object sender, EventArgs e)
        {
            algoritam = "TEA";
            string decryptedContent = "";

            decryptedContent = customTEA.DecryptData(poruka, key);


            if (!decryptedContent.StartsWith(randomNum))
            {
                richTextBox3.Invoke((MethodInvoker)delegate
                {
                    richTextBox3.Text = ($"{poruka}" + "\n");
                });


                richTextBox4.Invoke((MethodInvoker)delegate
                {
                    if (key != "")
                    {
                        richTextBox4.Text = ($"{decryptedContent}" + "\n");
                    }
                });
            }

        }
        private  string ReadAndEncryptFile(string filePath)
        {
            try
            {
                string Content = File.ReadAllText(filePath);

                Sha1Hash = Sha1.ComputeSHA1(Encoding.UTF8.GetBytes(Content));
                string fileContent = $"{randomNum}-sha {Sha1Hash} sha-{Content}";
                file = false;
         

                if (algoritam == "LEA")
                {
                    encryptedContent = LEA.LEAEncryptionCTR(LEAkey, iv, fileContent);
                }
                else if (algoritam == "TEA")
                {
                    CustomTEA customTEA = new CustomTEA();
                   encryptedContent = customTEA.EncryptData(fileContent, key);
                }

                    return encryptedContent;
                
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error reading and encrypting file: {ex.Message}");
                return null;
            }
        }



        private void buttonChooseFile_Click(object sender, EventArgs e)
        {
            try
            {
                using (OpenFileDialog openFileDialog = new OpenFileDialog())
                {
                    if (openFileDialog.ShowDialog() == DialogResult.OK)
                    {
                        string selectedFilePath = openFileDialog.FileName;
                        richTextBox5.Text = selectedFilePath;

                        encryptedContent = ReadAndEncryptFile(selectedFilePath);
                        file = true;
                  
                    }
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"An error occurred: {ex.Message}");
            }
        }

        private void Form1_Load(object sender, EventArgs e)
        {

        }
    }
}
