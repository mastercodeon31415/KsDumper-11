﻿namespace KsDumper11
{
	public partial class DumperForm : global::System.Windows.Forms.Form
	{
		protected override void Dispose(bool disposing)
		{
			bool flag = disposing && this.components != null;
			if (flag)
			{
				this.components.Dispose();
			}
			base.Dispose(disposing);
		}

		private void InitializeComponent()
		{
            this.components = new System.ComponentModel.Container();
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(DumperForm));
            this.groupBox1 = new System.Windows.Forms.GroupBox();
            this.logsTextBox = new System.Windows.Forms.RichTextBox();
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.dumpMainModuleToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.toolStripSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.openInExplorerToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.suspendProcessToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.resumeProcessToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.killProcessToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.fileDumpBtn = new System.Windows.Forms.Button();
            this.titleLbl = new DarkControls.Controls.TransparentLabel();
            this.closeBtn = new DarkControls.Controls.WindowsDefaultTitleBarButton();
            this.refreshBtn = new System.Windows.Forms.Button();
            this.autoRefreshCheckBox = new DarkControls.Controls.DarkCheckBox();
            this.hideSystemProcessBtn = new System.Windows.Forms.Button();
            this.closeDriverOnExitBox = new DarkControls.Controls.DarkCheckBox();
            this.appIcon1 = new DarkControls.Controls.AppIcon();
            this.processList = new KsDumper11.Utility.ProcessListView();
            this.PIDHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.NameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.PathHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.BaseAddressHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.EntryPointHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ImageSizeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.ImageTypeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.providerBtn = new DarkControls.Controls.DarkButton();
            this.trigger1 = new KsDumper11.Trigger();
            this.debuggerTrigger = new KsDumper11.Trigger();
            this.antiantiDebuggerToolsBox = new DarkControls.Controls.DarkCheckBox();
            this.groupBox1.SuspendLayout();
            this.contextMenuStrip1.SuspendLayout();
            ((System.ComponentModel.ISupportInitialize)(this.appIcon1)).BeginInit();
            this.SuspendLayout();
            // 
            // groupBox1
            // 
            this.groupBox1.Controls.Add(this.logsTextBox);
            this.groupBox1.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.groupBox1.Location = new System.Drawing.Point(12, 512);
            this.groupBox1.Name = "groupBox1";
            this.groupBox1.Size = new System.Drawing.Size(987, 222);
            this.groupBox1.TabIndex = 5;
            this.groupBox1.TabStop = false;
            this.groupBox1.Text = "Logs";
            // 
            // logsTextBox
            // 
            this.logsTextBox.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.logsTextBox.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.logsTextBox.ForeColor = System.Drawing.Color.Silver;
            this.logsTextBox.Location = new System.Drawing.Point(12, 19);
            this.logsTextBox.Name = "logsTextBox";
            this.logsTextBox.ReadOnly = true;
            this.logsTextBox.ScrollBars = System.Windows.Forms.RichTextBoxScrollBars.Vertical;
            this.logsTextBox.Size = new System.Drawing.Size(967, 197);
            this.logsTextBox.TabIndex = 0;
            this.logsTextBox.Text = "";
            this.logsTextBox.TextChanged += new System.EventHandler(this.logsTextBox_TextChanged);
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.ImageScalingSize = new System.Drawing.Size(20, 20);
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dumpMainModuleToolStripMenuItem,
            this.toolStripSeparator1,
            this.openInExplorerToolStripMenuItem,
            this.suspendProcessToolStripMenuItem,
            this.resumeProcessToolStripMenuItem,
            this.killProcessToolStripMenuItem});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(163, 120);
            this.contextMenuStrip1.Opening += new System.ComponentModel.CancelEventHandler(this.contextMenuStrip1_Opening);
            // 
            // dumpMainModuleToolStripMenuItem
            // 
            this.dumpMainModuleToolStripMenuItem.Name = "dumpMainModuleToolStripMenuItem";
            this.dumpMainModuleToolStripMenuItem.Size = new System.Drawing.Size(162, 22);
            this.dumpMainModuleToolStripMenuItem.Text = "Dump Process";
            this.dumpMainModuleToolStripMenuItem.Click += new System.EventHandler(this.dumpMainModuleToolStripMenuItem_Click);
            // 
            // toolStripSeparator1
            // 
            this.toolStripSeparator1.Name = "toolStripSeparator1";
            this.toolStripSeparator1.Size = new System.Drawing.Size(159, 6);
            // 
            // openInExplorerToolStripMenuItem
            // 
            this.openInExplorerToolStripMenuItem.Name = "openInExplorerToolStripMenuItem";
            this.openInExplorerToolStripMenuItem.Size = new System.Drawing.Size(162, 22);
            this.openInExplorerToolStripMenuItem.Text = "Open In Explorer";
            this.openInExplorerToolStripMenuItem.Click += new System.EventHandler(this.openInExplorerToolStripMenuItem_Click);
            // 
            // suspendProcessToolStripMenuItem
            // 
            this.suspendProcessToolStripMenuItem.Name = "suspendProcessToolStripMenuItem";
            this.suspendProcessToolStripMenuItem.Size = new System.Drawing.Size(162, 22);
            this.suspendProcessToolStripMenuItem.Text = "Suspend process";
            this.suspendProcessToolStripMenuItem.Click += new System.EventHandler(this.suspendProcessToolStripMenuItem_Click);
            // 
            // resumeProcessToolStripMenuItem
            // 
            this.resumeProcessToolStripMenuItem.Name = "resumeProcessToolStripMenuItem";
            this.resumeProcessToolStripMenuItem.Size = new System.Drawing.Size(162, 22);
            this.resumeProcessToolStripMenuItem.Text = "Resume process";
            this.resumeProcessToolStripMenuItem.Click += new System.EventHandler(this.resumeProcessToolStripMenuItem_Click);
            // 
            // killProcessToolStripMenuItem
            // 
            this.killProcessToolStripMenuItem.Name = "killProcessToolStripMenuItem";
            this.killProcessToolStripMenuItem.Size = new System.Drawing.Size(162, 22);
            this.killProcessToolStripMenuItem.Text = "Kill process";
            this.killProcessToolStripMenuItem.Click += new System.EventHandler(this.killProcessToolStripMenuItem_Click);
            // 
            // fileDumpBtn
            // 
            this.fileDumpBtn.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.fileDumpBtn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.fileDumpBtn.ForeColor = System.Drawing.Color.Silver;
            this.fileDumpBtn.Location = new System.Drawing.Point(227, 49);
            this.fileDumpBtn.Name = "fileDumpBtn";
            this.fileDumpBtn.Size = new System.Drawing.Size(75, 23);
            this.fileDumpBtn.TabIndex = 1;
            this.fileDumpBtn.Text = "Dump File";
            this.fileDumpBtn.UseVisualStyleBackColor = false;
            this.fileDumpBtn.Click += new System.EventHandler(this.fileDumpBtn_Click);
            // 
            // titleLbl
            // 
            this.titleLbl.AutoSize = true;
            this.titleLbl.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.titleLbl.Location = new System.Drawing.Point(32, 7);
            this.titleLbl.Name = "titleLbl";
            this.titleLbl.Size = new System.Drawing.Size(106, 20);
            this.titleLbl.TabIndex = 8;
            this.titleLbl.Text = "KsDumper 11";
            // 
            // closeBtn
            // 
            this.closeBtn.ButtonType = DarkControls.Controls.WindowsDefaultTitleBarButton.Type.Close;
            this.closeBtn.ClickColor = System.Drawing.Color.Red;
            this.closeBtn.ClickIconColor = System.Drawing.Color.Black;
            this.closeBtn.HoverColor = System.Drawing.Color.OrangeRed;
            this.closeBtn.HoverIconColor = System.Drawing.Color.Black;
            this.closeBtn.IconColor = System.Drawing.Color.Black;
            this.closeBtn.IconLineThickness = 2;
            this.closeBtn.Location = new System.Drawing.Point(969, 1);
            this.closeBtn.Name = "closeBtn";
            this.closeBtn.Size = new System.Drawing.Size(40, 40);
            this.closeBtn.TabIndex = 7;
            this.closeBtn.Text = "windowsDefaultTitleBarButton1";
            this.closeBtn.UseVisualStyleBackColor = true;
            // 
            // refreshBtn
            // 
            this.refreshBtn.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.refreshBtn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.refreshBtn.ForeColor = System.Drawing.Color.Silver;
            this.refreshBtn.Location = new System.Drawing.Point(12, 49);
            this.refreshBtn.Name = "refreshBtn";
            this.refreshBtn.Size = new System.Drawing.Size(75, 23);
            this.refreshBtn.TabIndex = 10;
            this.refreshBtn.Text = "Refresh";
            this.refreshBtn.UseVisualStyleBackColor = false;
            this.refreshBtn.Click += new System.EventHandler(this.refreshBtn_Click);
            // 
            // autoRefreshCheckBox
            // 
            this.autoRefreshCheckBox.Appearance = System.Windows.Forms.Appearance.Button;
            this.autoRefreshCheckBox.BoxBorderColor = System.Drawing.Color.DarkSlateBlue;
            this.autoRefreshCheckBox.BoxFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.autoRefreshCheckBox.CheckColor = System.Drawing.Color.CornflowerBlue;
            this.autoRefreshCheckBox.FlatAppearance.BorderSize = 0;
            this.autoRefreshCheckBox.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.autoRefreshCheckBox.Location = new System.Drawing.Point(93, 49);
            this.autoRefreshCheckBox.Name = "autoRefreshCheckBox";
            this.autoRefreshCheckBox.Size = new System.Drawing.Size(98, 23);
            this.autoRefreshCheckBox.TabIndex = 11;
            this.autoRefreshCheckBox.Text = "Auto Refresh";
            this.autoRefreshCheckBox.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.autoRefreshCheckBox.UseVisualStyleBackColor = true;
            this.autoRefreshCheckBox.CheckedChanged += new System.EventHandler(this.autoRefreshCheckBox_CheckedChanged);
            // 
            // hideSystemProcessBtn
            // 
            this.hideSystemProcessBtn.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.hideSystemProcessBtn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.hideSystemProcessBtn.ForeColor = System.Drawing.Color.Silver;
            this.hideSystemProcessBtn.Location = new System.Drawing.Point(750, 49);
            this.hideSystemProcessBtn.Name = "hideSystemProcessBtn";
            this.hideSystemProcessBtn.Size = new System.Drawing.Size(137, 23);
            this.hideSystemProcessBtn.TabIndex = 12;
            this.hideSystemProcessBtn.Text = "Show System Processes";
            this.hideSystemProcessBtn.UseVisualStyleBackColor = false;
            this.hideSystemProcessBtn.Click += new System.EventHandler(this.hideSystemProcessBtn_Click);
            // 
            // closeDriverOnExitBox
            // 
            this.closeDriverOnExitBox.Appearance = System.Windows.Forms.Appearance.Button;
            this.closeDriverOnExitBox.BoxBorderColor = System.Drawing.Color.DarkSlateBlue;
            this.closeDriverOnExitBox.BoxFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.closeDriverOnExitBox.CheckColor = System.Drawing.Color.CornflowerBlue;
            this.closeDriverOnExitBox.FlatAppearance.BorderSize = 0;
            this.closeDriverOnExitBox.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.closeDriverOnExitBox.Location = new System.Drawing.Point(361, 48);
            this.closeDriverOnExitBox.Name = "closeDriverOnExitBox";
            this.closeDriverOnExitBox.Size = new System.Drawing.Size(133, 23);
            this.closeDriverOnExitBox.TabIndex = 13;
            this.closeDriverOnExitBox.Text = "Close Driver on Exit";
            this.closeDriverOnExitBox.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.closeDriverOnExitBox.UseVisualStyleBackColor = true;
            this.closeDriverOnExitBox.CheckedChanged += new System.EventHandler(this.closeDriverOnExitBox_CheckedChanged);
            // 
            // appIcon1
            // 
            this.appIcon1.AppIconImage = global::KsDumper11.Properties.Resources.icons8_crossed_axes_100;
            this.appIcon1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.appIcon1.DragForm = this;
            this.appIcon1.Image = ((System.Drawing.Image)(resources.GetObject("appIcon1.Image")));
            this.appIcon1.Location = new System.Drawing.Point(5, 4);
            this.appIcon1.Name = "appIcon1";
            this.appIcon1.Scale = 3.5F;
            this.appIcon1.Size = new System.Drawing.Size(28, 28);
            this.appIcon1.TabIndex = 9;
            this.appIcon1.TabStop = false;
            // 
            // processList
            // 
            this.processList.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.processList.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.processList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.PIDHeader,
            this.NameHeader,
            this.PathHeader,
            this.BaseAddressHeader,
            this.EntryPointHeader,
            this.ImageSizeHeader,
            this.ImageTypeHeader});
            this.processList.ContextMenuStrip = this.contextMenuStrip1;
            this.processList.ForeColor = System.Drawing.Color.Silver;
            this.processList.FullRowSelect = true;
            this.processList.HideSelection = false;
            this.processList.Location = new System.Drawing.Point(12, 78);
            this.processList.MultiSelect = false;
            this.processList.Name = "processList";
            this.processList.OwnerDraw = true;
            this.processList.Size = new System.Drawing.Size(987, 428);
            this.processList.Sorting = System.Windows.Forms.SortOrder.Ascending;
            this.processList.SystemProcessesHidden = true;
            this.processList.TabIndex = 2;
            this.processList.UseCompatibleStateImageBehavior = false;
            this.processList.View = System.Windows.Forms.View.Details;
            // 
            // PIDHeader
            // 
            this.PIDHeader.Text = "PID";
            this.PIDHeader.Width = 76;
            // 
            // NameHeader
            // 
            this.NameHeader.Text = "Name";
            this.NameHeader.Width = 143;
            // 
            // PathHeader
            // 
            this.PathHeader.Text = "Path";
            this.PathHeader.Width = 375;
            // 
            // BaseAddressHeader
            // 
            this.BaseAddressHeader.Text = "Base Address";
            this.BaseAddressHeader.Width = 106;
            // 
            // EntryPointHeader
            // 
            this.EntryPointHeader.Text = "Entry Point";
            this.EntryPointHeader.Width = 106;
            // 
            // ImageSizeHeader
            // 
            this.ImageSizeHeader.Text = "Image Size";
            this.ImageSizeHeader.Width = 88;
            // 
            // ImageTypeHeader
            // 
            this.ImageTypeHeader.Text = "Image Type";
            this.ImageTypeHeader.Width = 76;
            // 
            // providerBtn
            // 
            this.providerBtn.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.providerBtn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.providerBtn.ForeColor = System.Drawing.Color.Silver;
            this.providerBtn.Location = new System.Drawing.Point(893, 49);
            this.providerBtn.Name = "providerBtn";
            this.providerBtn.Size = new System.Drawing.Size(106, 23);
            this.providerBtn.TabIndex = 17;
            this.providerBtn.Text = "Provider Selector";
            this.providerBtn.UseVisualStyleBackColor = true;
            this.providerBtn.Click += new System.EventHandler(this.providerBtn_Click);
            // 
            // trigger1
            // 
            this.trigger1.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.trigger1.Location = new System.Drawing.Point(443, 28);
            this.trigger1.Margin = new System.Windows.Forms.Padding(4);
            this.trigger1.Name = "trigger1";
            this.trigger1.Size = new System.Drawing.Size(35, 24);
            this.trigger1.TabIndex = 16;
            // 
            // debuggerTrigger
            // 
            this.debuggerTrigger.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.debuggerTrigger.Location = new System.Drawing.Point(484, 28);
            this.debuggerTrigger.Margin = new System.Windows.Forms.Padding(4);
            this.debuggerTrigger.Name = "debuggerTrigger";
            this.debuggerTrigger.Size = new System.Drawing.Size(15, 13);
            this.debuggerTrigger.TabIndex = 15;
            // 
            // antiantiDebuggerToolsBox
            // 
            this.antiantiDebuggerToolsBox.Appearance = System.Windows.Forms.Appearance.Button;
            this.antiantiDebuggerToolsBox.BoxBorderColor = System.Drawing.Color.DarkSlateBlue;
            this.antiantiDebuggerToolsBox.BoxFillColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.antiantiDebuggerToolsBox.CheckColor = System.Drawing.Color.CornflowerBlue;
            this.antiantiDebuggerToolsBox.FlatAppearance.BorderSize = 0;
            this.antiantiDebuggerToolsBox.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.antiantiDebuggerToolsBox.Location = new System.Drawing.Point(500, 48);
            this.antiantiDebuggerToolsBox.Name = "antiantiDebuggerToolsBox";
            this.antiantiDebuggerToolsBox.Size = new System.Drawing.Size(244, 23);
            this.antiantiDebuggerToolsBox.TabIndex = 18;
            this.antiantiDebuggerToolsBox.Text = "Enable Anti Anti Debugger Tools Detection";
            this.antiantiDebuggerToolsBox.TextAlign = System.Drawing.ContentAlignment.MiddleRight;
            this.antiantiDebuggerToolsBox.UseVisualStyleBackColor = true;
            this.antiantiDebuggerToolsBox.CheckedChanged += new System.EventHandler(this.antiantiDebuggerToolsBox_CheckedChanged);
            // 
            // DumperForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.ClientSize = new System.Drawing.Size(1009, 746);
            this.Controls.Add(this.antiantiDebuggerToolsBox);
            this.Controls.Add(this.providerBtn);
            this.Controls.Add(this.trigger1);
            this.Controls.Add(this.debuggerTrigger);
            this.Controls.Add(this.closeDriverOnExitBox);
            this.Controls.Add(this.hideSystemProcessBtn);
            this.Controls.Add(this.autoRefreshCheckBox);
            this.Controls.Add(this.refreshBtn);
            this.Controls.Add(this.closeBtn);
            this.Controls.Add(this.fileDumpBtn);
            this.Controls.Add(this.groupBox1);
            this.Controls.Add(this.processList);
            this.Controls.Add(this.appIcon1);
            this.Controls.Add(this.titleLbl);
            this.DoubleBuffered = true;
            this.ForeColor = System.Drawing.Color.Silver;
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.MaximizeBox = false;
            this.Name = "DumperForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Actions";
            this.Load += new System.EventHandler(this.Dumper_Load);
            this.groupBox1.ResumeLayout(false);
            this.contextMenuStrip1.ResumeLayout(false);
            ((System.ComponentModel.ISupportInitialize)(this.appIcon1)).EndInit();
            this.ResumeLayout(false);
            this.PerformLayout();

		}

		private System.ComponentModel.IContainer components = null;
		private KsDumper11.Utility.ProcessListView processList;
		private System.Windows.Forms.ColumnHeader PIDHeader;
		private System.Windows.Forms.ColumnHeader NameHeader;
		private System.Windows.Forms.ColumnHeader PathHeader;
		private System.Windows.Forms.ColumnHeader BaseAddressHeader;
		private System.Windows.Forms.ColumnHeader EntryPointHeader;
		private System.Windows.Forms.ColumnHeader ImageSizeHeader;
		private System.Windows.Forms.ColumnHeader ImageTypeHeader;
		private System.Windows.Forms.GroupBox groupBox1;
		private System.Windows.Forms.RichTextBox logsTextBox;
		private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
		private System.Windows.Forms.ToolStripMenuItem dumpMainModuleToolStripMenuItem;
		private System.Windows.Forms.ToolStripSeparator toolStripSeparator1;
		private System.Windows.Forms.ToolStripMenuItem openInExplorerToolStripMenuItem;
		private System.Windows.Forms.ToolStripMenuItem suspendProcessToolStripMenuItem;
		private System.Windows.Forms.ToolStripMenuItem resumeProcessToolStripMenuItem;
		private System.Windows.Forms.ToolStripMenuItem killProcessToolStripMenuItem;
		private System.Windows.Forms.Button fileDumpBtn;
		private DarkControls.Controls.WindowsDefaultTitleBarButton closeBtn;
		private DarkControls.Controls.TransparentLabel titleLbl;
		private DarkControls.Controls.AppIcon appIcon1;
		private System.Windows.Forms.Button refreshBtn;
		private DarkControls.Controls.DarkCheckBox autoRefreshCheckBox;
		private System.Windows.Forms.Button hideSystemProcessBtn;
        private DarkControls.Controls.DarkCheckBox closeDriverOnExitBox;
        private Trigger debuggerTrigger;
        private Trigger trigger1;
        private DarkControls.Controls.DarkButton providerBtn;
        private DarkControls.Controls.DarkCheckBox antiantiDebuggerToolsBox;
    }
}
