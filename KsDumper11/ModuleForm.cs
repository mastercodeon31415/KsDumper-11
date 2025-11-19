// Relative Path: KsDumper11\ModuleForm.cs
using DarkControls;
using KsDumper11.Driver;
using KsDumper11.PE;
using KsDumper11.Utility;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace KsDumper11
{
    public partial class ModuleForm : Form
    {
        private KsDumperDriverInterface _driver;
        private ProcessDumper _dumper;
        private ProcessSummary _targetProcess;

        protected override CreateParams CreateParams
        {
            get
            {
                CreateParams cp = base.CreateParams;
                cp.ExStyle |= 33554432;
                return cp;
            }
        }

        public ModuleForm(KsDumperDriverInterface driver, ProcessDumper dumper, ProcessSummary targetProcess)
        {
            InitializeComponent();
            _driver = driver;
            _dumper = dumper;
            _targetProcess = targetProcess;

            this.FormBorderStyle = FormBorderStyle.None;
            this.Region = Region.FromHrgn(Utils.CreateRoundRectRgn(0, 0, Width, Height, 10, 10));
        }

        private void ModuleForm_Load(object sender, EventArgs e)
        {
            string arch = _targetProcess.IsWOW64 ? "x86" : "x64";
            string type = _targetProcess.IsDotNet ? ".NET" : "Native";
            titleLbl.Text = $"Modules: {_targetProcess.ProcessName} ({_targetProcess.ProcessId}) [{arch}] [{type}]";
            RefreshModules();
        }

        private void RefreshModules()
        {
            moduleList.Items.Clear();
            moduleList.BeginUpdate();
            try
            {
                var modules = _driver.GetProcessModules(_targetProcess.ProcessId);

                foreach (var mod in modules)
                {
                    if (mod.BaseAddress == 0) continue;

                    string fullPath = PathUtils.NormalizePath(mod.FullPathName ?? "");
                    string fileName = "Unknown";

                    bool isManualMap = false;
                    bool isUnlinked = false;
                    bool isDotNet = false;
                    bool isInMemoryDotNet = false;

                    string dotNetVersion = "";

                    if (fullPath.Contains("ManualMap_Region"))
                    {
                        fileName = "Manual Map Region";
                        isManualMap = true;
                    }
                    else if (fullPath.Contains("Unlinked_Module"))
                    {
                        var dnInfo = DotNetResolver.GetDotNetInfo(
                            _driver,
                            _targetProcess.ProcessId,
                            mod.BaseAddress,
                            mod.SizeOfImage);

                        if (dnInfo.IsValid)
                        {
                            fileName = dnInfo.Name + ".dll";
                            fullPath = $"{fileName} (In-Memory)";
                            isInMemoryDotNet = true;
                            isDotNet = true;
                            dotNetVersion = dnInfo.Version;
                        }
                        else
                        {
                            fileName = "Unlinked Module";
                            isUnlinked = true;
                        }
                    }
                    else if (!string.IsNullOrEmpty(fullPath))
                    {
                        fileName = Path.GetFileName(fullPath);
                        string lowerName = fileName.ToLower();

                        if (lowerName == "mscorlib.dll" || lowerName == "clr.dll" || lowerName == "mscoree.dll" ||
                            lowerName.StartsWith("system.") || lowerName.StartsWith("microsoft.") || lowerName.EndsWith(".ni.dll"))
                        {
                            isDotNet = true;
                        }
                        else if (_targetProcess.IsDotNet)
                        {
                            if (lowerName != "kernel32.dll" && lowerName != "ntdll.dll" && lowerName != "user32.dll")
                            {
                                var dnInfo = DotNetResolver.GetDotNetInfo(_driver, _targetProcess.ProcessId, mod.BaseAddress, mod.SizeOfImage);
                                if (dnInfo.IsValid)
                                {
                                    isDotNet = true;
                                    dotNetVersion = dnInfo.Version;
                                }
                            }
                        }
                    }

                    ListViewItem item = new ListViewItem(fileName);
                    item.SubItems.Add($"0x{mod.BaseAddress:X8}");
                    item.SubItems.Add($"0x{mod.SizeOfImage:X}");
                    item.SubItems.Add(fullPath);

                    if (isManualMap)
                    {
                        item.ForeColor = Color.Red;
                        item.ToolTipText = "Region found via VAD Scan";
                    }
                    else if (isInMemoryDotNet)
                    {
                        item.ForeColor = Color.LimeGreen;
                        item.ToolTipText = $"In-Memory .NET Assembly ({dotNetVersion})";
                    }
                    else if (isUnlinked)
                    {
                        item.ForeColor = Color.Orange;
                        item.ToolTipText = "Unlinked Native PE Module";
                    }
                    else if (isDotNet)
                    {
                        item.ForeColor = Color.Cyan;
                        if (!string.IsNullOrEmpty(dotNetVersion))
                            item.ToolTipText = $".NET Managed Assembly ({dotNetVersion})";
                    }
                    else
                    {
                        item.ForeColor = Color.Silver;
                    }

                    var fixedModInfo = mod;
                    fixedModInfo.FullPathName = fullPath;
                    item.Tag = fixedModInfo;

                    moduleList.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error enumerating modules: " + ex.Message);
            }
            finally
            {
                moduleList.EndUpdate();
            }
        }

        private void closeBtn_Click(object sender, EventArgs e)
        {
            this.Close();
        }

        private void refreshBtn_Click(object sender, EventArgs e)
        {
            RefreshModules();
        }

        private void dumpModuleToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (moduleList.SelectedItems.Count == 0) return;

            var item = moduleList.SelectedItems[0];
            var modInfo = (KsDumper11.Driver.Operations.KERNEL_MODULE_INFO)item.Tag;

            string fullPath = modInfo.FullPathName;
            if (string.IsNullOrEmpty(fullPath) || fullPath.Contains("Unlinked_") || fullPath.Contains("ManualMap_") || fullPath.Contains("(In-Memory)"))
                fullPath = item.Text;

            // Check if we detected this specific module as .NET (Cyan or Green color)
            bool isDotNetModule = (item.ForeColor == Color.Cyan || item.ForeColor == Color.LimeGreen);

            ProcessSummary moduleSummary = new ProcessSummary(
                _targetProcess.ProcessId,
                modInfo.BaseAddress,
                fullPath,
                modInfo.SizeOfImage,
                0,
                _targetProcess.IsWOW64,
                isDotNetModule // Pass true if .NET to help dumper logic
            );

            Task.Run(() =>
            {
                Logger.Log($"Dumping module {item.Text} (Base: 0x{modInfo.BaseAddress:X})...");
                PEFile peFile;

                if (_dumper.DumpProcess(moduleSummary, out peFile))
                {
                    this.Invoke(new Action(() =>
                    {
                        using (SaveFileDialog sfd = new SaveFileDialog())
                        {
                            string safeName = Path.GetFileNameWithoutExtension(item.Text);
                            if (string.IsNullOrEmpty(safeName) || safeName.Contains(" ")) safeName = $"Module_{modInfo.BaseAddress:X}";

                            string ext = "dll"; // Default extension

                            sfd.FileName = safeName + "_dump." + ext;
                            sfd.Filter = "DLL File (*.dll)|*.dll|Executable File (*.exe)|*.exe|All Files (*.*)|*.*";

                            if (sfd.ShowDialog() == DialogResult.OK)
                            {
                                peFile.SaveToDisk(sfd.FileName);
                                Logger.Log($"Module saved to {sfd.FileName}");
                                MessageBox.Show("Module Dumped Successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            }
                        }
                    }));
                }
                else
                {
                    this.Invoke(new Action(() =>
                    {
                        MessageBox.Show("Failed to dump module!", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }));
                }
            });
        }

        // ... (CopyAddress and WndProc unchanged)
        private void copyAddressToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (moduleList.SelectedItems.Count > 0) Clipboard.SetText(moduleList.SelectedItems[0].SubItems[1].Text);
        }
        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == Utils.WM_NCHITTEST) m.Result = (IntPtr)Utils.HT_CAPTION;
        }
    }
}