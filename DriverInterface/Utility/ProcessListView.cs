// Relative Path: Utility\ProcessListView.cs
using System;
using System.Collections;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Forms;

namespace KsDumper11.Utility
{
    public class ProcessListView : ListView
    {
        public bool SystemProcessesHidden { get; set; } = true;

        public ProcessListView()
        {
            base.OwnerDraw = true;
            this.DoubleBuffered = true;
            base.Sorting = SortOrder.Ascending;
        }

        public void LoadProcesses(ProcessSummary[] processSummaries)
        {
            this.processCache = processSummaries;
            this.ReloadItems();
        }

        public void ShowSystemProcesses()
        {
            this.SystemProcessesHidden = false;
            this.ReloadItems();
        }

        public void HideSystemProcesses()
        {
            this.SystemProcessesHidden = true;
            this.ReloadItems();
        }

        protected override void OnDrawItem(DrawListViewItemEventArgs e)
        {
            e.DrawDefault = true;
        }

        protected override void OnDrawColumnHeader(DrawListViewColumnHeaderEventArgs e)
        {
            e.DrawBackground();
            using (StringFormat sf = new StringFormat())
            {
                sf.Alignment = StringAlignment.Center;
                using (Font headerFont = new Font("Microsoft Sans Serif", 9f, FontStyle.Bold))
                {
                    e.Graphics.FillRectangle(new SolidBrush(this.BackColor), e.Bounds);
                    e.Graphics.DrawString(e.Header.Text, headerFont, new SolidBrush(this.ForeColor), e.Bounds, sf);
                }
            }
        }

        private void ReloadItems()
        {
            base.BeginUpdate();
            int idx = 0;
            bool flag = base.SelectedIndices.Count > 0;
            if (flag)
            {
                idx = base.SelectedIndices[0];
                bool flag2 = idx == -1;
                if (flag2)
                {
                    idx = 0;
                }
            }
            base.Items.Clear();
            string systemRootFolder = Environment.GetFolderPath(Environment.SpecialFolder.Windows).ToLower();
            foreach (ProcessSummary processSummary in this.processCache)
            {
                bool flag3 = this.SystemProcessesHidden && (processSummary.MainModuleFileName.ToLower().StartsWith(systemRootFolder) || processSummary.MainModuleFileName.StartsWith("\\"));
                if (!flag3)
                {
                    ListViewItem lvi = new ListViewItem(processSummary.ProcessId.ToString());
                    lvi.BackColor = this.BackColor;
                    lvi.ForeColor = this.ForeColor;
                    lvi.SubItems.Add(Path.GetFileName(processSummary.MainModuleFileName));
                    lvi.SubItems.Add(processSummary.MainModuleFileName);
                    lvi.SubItems.Add(string.Format("0x{0:x8}", processSummary.MainModuleBase));
                    lvi.SubItems.Add(string.Format("0x{0:x8}", processSummary.MainModuleEntryPoint));
                    lvi.SubItems.Add(string.Format("0x{0:x4}", processSummary.MainModuleImageSize));
                    lvi.SubItems.Add(processSummary.IsWOW64 ? "x86" : "x64");

                    // New: Framework Column
                    if (processSummary.IsDotNet)
                    {
                        lvi.SubItems.Add(".NET");
                        lvi.ForeColor = Color.Cyan; // Highlight .NET processes
                    }
                    else
                    {
                        lvi.SubItems.Add("Native");
                    }

                    lvi.Tag = processSummary;
                    base.Items.Add(lvi);
                }
            }
            base.ListViewItemSorter = new ProcessListView.ProcessListViewItemComparer(this.sortColumnIndex, base.Sorting);
            base.Sort();

            if (base.Items.Count > 0 && idx < base.Items.Count)
            {
                base.Items[idx].Selected = true;
            }

            base.EndUpdate();
        }

        protected override void OnColumnClick(ColumnClickEventArgs e)
        {
            bool flag = e.Column != this.sortColumnIndex;
            if (flag)
            {
                this.sortColumnIndex = e.Column;
                base.Sorting = SortOrder.Ascending;
            }
            else
            {
                bool flag2 = base.Sorting == SortOrder.Ascending;
                if (flag2)
                {
                    base.Sorting = SortOrder.Descending;
                }
                else
                {
                    base.Sorting = SortOrder.Ascending;
                }
            }
            base.ListViewItemSorter = new ProcessListView.ProcessListViewItemComparer(e.Column, base.Sorting);
            base.Sort();
        }

        protected override void WndProc(ref Message m)
        {
            bool flag = m.Msg == 1;
            if (flag)
            {
            }
            base.WndProc(ref m);
        }

        [DllImport("uxtheme.dll", CharSet = CharSet.Unicode)]
        private static extern int SetWindowTheme(IntPtr hWnd, string pszSubAppName, string pszSubIdList);

        private int sortColumnIndex = 1;

        private ProcessSummary[] processCache;

        private class ProcessListViewItemComparer : IComparer
        {
            public ProcessListViewItemComparer(int columnIndex, SortOrder sortOrder)
            {
                this.columnIndex = columnIndex;
                this.sortOrder = sortOrder;
            }

            public int Compare(object x, object y)
            {
                bool flag = x is ListViewItem && y is ListViewItem;
                if (flag)
                {
                    ProcessSummary p = ((ListViewItem)x).Tag as ProcessSummary;
                    ProcessSummary p2 = ((ListViewItem)y).Tag as ProcessSummary;
                    bool flag2 = p != null && p2 != null;
                    if (flag2)
                    {
                        int result = 0;
                        switch (this.columnIndex)
                        {
                            case 0:
                                result = p.ProcessId.CompareTo(p2.ProcessId);
                                break;
                            case 1:
                                result = p.ProcessName.CompareTo(p2.ProcessName);
                                break;
                            case 2:
                                result = p.MainModuleFileName.CompareTo(p2.MainModuleFileName);
                                break;
                            case 3:
                                result = p.MainModuleBase.CompareTo(p2.MainModuleBase);
                                break;
                            case 4:
                                result = p.MainModuleEntryPoint.CompareTo(p2.MainModuleEntryPoint);
                                break;
                            case 5:
                                result = p.MainModuleImageSize.CompareTo(p2.MainModuleImageSize);
                                break;
                            case 6:
                                result = p.IsWOW64.CompareTo(p2.IsWOW64);
                                break;
                            case 7: // New Sort for Framework
                                result = p.IsDotNet.CompareTo(p2.IsDotNet);
                                break;
                        }
                        bool flag3 = this.sortOrder == SortOrder.Descending;
                        if (flag3)
                        {
                            result = -result;
                        }
                        return result;
                    }
                }
                return 0;
            }

            private readonly int columnIndex;
            private readonly SortOrder sortOrder;
        }
    }
}