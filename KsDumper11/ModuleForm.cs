// Relative Path: ModuleForm.cs
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
                cp.ExStyle |= 33554432; // WS_EX_COMPOSITED for anti-flicker
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
            try
            {
                var modules = _driver.GetProcessModules(_targetProcess.ProcessId);

                foreach (var mod in modules)
                {
                    if (mod.BaseAddress == 0) continue;

                    string fileName = "Unknown";
                    string fullPath = mod.FullPathName ?? "";
                    bool isManualMap = false;
                    bool isDotNetRuntime = false;

                    // Check for Manual Map (Flagged by Driver)
                    if (fullPath.Contains("ManualMap_Region"))
                    {
                        fileName = "Manual Map";
                        isManualMap = true;
                    }
                    else if (!string.IsNullOrEmpty(fullPath))
                    {
                        fileName = Path.GetFileName(fullPath);

                        // Check for .NET Runtime DLLs
                        string lowerName = fileName.ToLower();
                        if (lowerName == "clr.dll" || lowerName == "coreclr.dll" || lowerName == "mscoree.dll")
                        {
                            isDotNetRuntime = true;
                        }
                    }

                    ListViewItem item = new ListViewItem(fileName);
                    item.SubItems.Add($"0x{mod.BaseAddress:X8}");
                    item.SubItems.Add($"0x{mod.SizeOfImage:X}");
                    item.SubItems.Add(fullPath);

                    // Color Coding
                    if (isManualMap)
                    {
                        item.ForeColor = Color.Red;
                        item.ToolTipText = "Detected via Memory Scan (VAD)";
                    }
                    else if (isDotNetRuntime)
                    {
                        item.ForeColor = Color.Cyan;
                        item.ToolTipText = ".NET Runtime Module";
                    }

                    // Tag the item with the raw module info for dumping
                    item.Tag = mod;

                    moduleList.Items.Add(item);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show("Error enumerating modules: " + ex.Message);
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

            // Create a temporary ProcessSummary to trick the ProcessDumper
            string fullPath = modInfo.FullPathName;
            if (string.IsNullOrEmpty(fullPath) || fullPath.Contains("ManualMap_Region"))
                fullPath = item.Text;

            // Note: We pass isDotNet=false here for the module dump itself as it treats it as a generic PE
            ProcessSummary moduleSummary = new ProcessSummary(
                _targetProcess.ProcessId,
                modInfo.BaseAddress,
                fullPath,
                modInfo.SizeOfImage,
                0, // EntryPoint unknown for modules via this method usually
                _targetProcess.IsWOW64, // Inherit architecture
                false
            );

            Task.Run(() =>
            {
                Logger.Log($"Dumping module {item.Text} (Base: 0x{modInfo.BaseAddress:X})...");
                PEFile peFile;

                // ProcessDumper will now use IATReconstructor which handles in-memory export resolution
                if (_dumper.DumpProcess(moduleSummary, out peFile))
                {
                    this.Invoke(new Action(() =>
                    {
                        using (SaveFileDialog sfd = new SaveFileDialog())
                        {
                            string safeName = Path.GetFileNameWithoutExtension(item.Text);
                            if (string.IsNullOrEmpty(safeName)) safeName = $"Module_{modInfo.BaseAddress:X}";

                            sfd.FileName = safeName + "_dump.dll";
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

        private void copyAddressToolStripMenuItem_Click(object sender, EventArgs e)
        {
            if (moduleList.SelectedItems.Count > 0)
            {
                Clipboard.SetText(moduleList.SelectedItems[0].SubItems[1].Text);
            }
        }

        protected override void WndProc(ref Message m)
        {
            base.WndProc(ref m);
            if (m.Msg == Utils.WM_NCHITTEST)
                m.Result = (IntPtr)Utils.HT_CAPTION;
        }
    }
}