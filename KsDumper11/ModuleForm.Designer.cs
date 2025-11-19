namespace KsDumper11
{
    public partial class ModuleForm : global::System.Windows.Forms.Form
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
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(ModuleForm));
            this.moduleList = new DarkControls.Controls.DarkListView();
            this.NameHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.BaseHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.SizeHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.PathHeader = ((System.Windows.Forms.ColumnHeader)(new System.Windows.Forms.ColumnHeader()));
            this.contextMenuStrip1 = new System.Windows.Forms.ContextMenuStrip(this.components);
            this.dumpModuleToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.copyAddressToolStripMenuItem = new System.Windows.Forms.ToolStripMenuItem();
            this.closeBtn = new DarkControls.Controls.WindowsDefaultTitleBarButton();
            this.titleLbl = new DarkControls.Controls.TransparentLabel();
            this.refreshBtn = new System.Windows.Forms.Button();
            this.contextMenuStrip1.SuspendLayout();
            this.SuspendLayout();
            // 
            // moduleList
            // 
            this.moduleList.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.moduleList.Columns.AddRange(new System.Windows.Forms.ColumnHeader[] {
            this.NameHeader,
            this.BaseHeader,
            this.SizeHeader,
            this.PathHeader});
            this.moduleList.ContextMenuStrip = this.contextMenuStrip1;
            this.moduleList.ForeColor = System.Drawing.Color.Silver;
            this.moduleList.FullRowSelect = true;
            this.moduleList.HideSelection = false;
            this.moduleList.Location = new System.Drawing.Point(0, 47);
            this.moduleList.Name = "moduleList";
            this.moduleList.OwnerDraw = true;
            this.moduleList.Size = new System.Drawing.Size(778, 699);
            this.moduleList.TabIndex = 0;
            this.moduleList.UseCompatibleStateImageBehavior = false;
            this.moduleList.View = System.Windows.Forms.View.Details;
            // 
            // NameHeader
            // 
            this.NameHeader.Text = "Module";
            this.NameHeader.Width = 150;
            // 
            // BaseHeader
            // 
            this.BaseHeader.Text = "Base Address";
            this.BaseHeader.Width = 120;
            // 
            // SizeHeader
            // 
            this.SizeHeader.Text = "Size";
            this.SizeHeader.Width = 80;
            // 
            // PathHeader
            // 
            this.PathHeader.Text = "Path";
            this.PathHeader.Width = 400;
            // 
            // contextMenuStrip1
            // 
            this.contextMenuStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.dumpModuleToolStripMenuItem,
            this.copyAddressToolStripMenuItem});
            this.contextMenuStrip1.Name = "contextMenuStrip1";
            this.contextMenuStrip1.Size = new System.Drawing.Size(152, 48);
            // 
            // dumpModuleToolStripMenuItem
            // 
            this.dumpModuleToolStripMenuItem.Name = "dumpModuleToolStripMenuItem";
            this.dumpModuleToolStripMenuItem.Size = new System.Drawing.Size(151, 22);
            this.dumpModuleToolStripMenuItem.Text = "Dump Module";
            this.dumpModuleToolStripMenuItem.Click += new System.EventHandler(this.dumpModuleToolStripMenuItem_Click);
            // 
            // copyAddressToolStripMenuItem
            // 
            this.copyAddressToolStripMenuItem.Name = "copyAddressToolStripMenuItem";
            this.copyAddressToolStripMenuItem.Size = new System.Drawing.Size(151, 22);
            this.copyAddressToolStripMenuItem.Text = "Copy Address";
            this.copyAddressToolStripMenuItem.Click += new System.EventHandler(this.copyAddressToolStripMenuItem_Click);
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
            this.closeBtn.Location = new System.Drawing.Point(738, 0);
            this.closeBtn.Name = "closeBtn";
            this.closeBtn.Size = new System.Drawing.Size(40, 40);
            this.closeBtn.TabIndex = 8;
            this.closeBtn.UseVisualStyleBackColor = true;
            this.closeBtn.Click += new System.EventHandler(this.closeBtn_Click);
            // 
            // titleLbl
            // 
            this.titleLbl.AutoSize = true;
            this.titleLbl.Font = new System.Drawing.Font("Microsoft Sans Serif", 12F, System.Drawing.FontStyle.Regular, System.Drawing.GraphicsUnit.Point, ((byte)(0)));
            this.titleLbl.ForeColor = System.Drawing.Color.Silver;
            this.titleLbl.Location = new System.Drawing.Point(12, 9);
            this.titleLbl.Name = "titleLbl";
            this.titleLbl.Size = new System.Drawing.Size(130, 20);
            this.titleLbl.TabIndex = 9;
            this.titleLbl.Text = "Process Modules";
            // 
            // refreshBtn
            // 
            this.refreshBtn.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.refreshBtn.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.refreshBtn.ForeColor = System.Drawing.Color.Silver;
            this.refreshBtn.Location = new System.Drawing.Point(642, 18);
            this.refreshBtn.Name = "refreshBtn";
            this.refreshBtn.Size = new System.Drawing.Size(75, 23);
            this.refreshBtn.TabIndex = 11;
            this.refreshBtn.Text = "Refresh";
            this.refreshBtn.UseVisualStyleBackColor = false;
            this.refreshBtn.Click += new System.EventHandler(this.refreshBtn_Click);
            // 
            // ModuleForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.BackColor = System.Drawing.Color.FromArgb(((int)(((byte)(33)))), ((int)(((byte)(33)))), ((int)(((byte)(33)))));
            this.ClientSize = new System.Drawing.Size(778, 746);
            this.Controls.Add(this.refreshBtn);
            this.Controls.Add(this.titleLbl);
            this.Controls.Add(this.closeBtn);
            this.Controls.Add(this.moduleList);
            this.FormBorderStyle = System.Windows.Forms.FormBorderStyle.None;
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "ModuleForm";
            this.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen;
            this.Text = "Modules";
            this.Load += new System.EventHandler(this.ModuleForm_Load);
            this.contextMenuStrip1.ResumeLayout(false);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        private System.ComponentModel.IContainer components = null;
        private DarkControls.Controls.DarkListView moduleList;
        private System.Windows.Forms.ColumnHeader NameHeader;
        private System.Windows.Forms.ColumnHeader BaseHeader;
        private System.Windows.Forms.ColumnHeader SizeHeader;
        private System.Windows.Forms.ColumnHeader PathHeader;
        private DarkControls.Controls.WindowsDefaultTitleBarButton closeBtn;
        private DarkControls.Controls.TransparentLabel titleLbl;
        private System.Windows.Forms.ContextMenuStrip contextMenuStrip1;
        private System.Windows.Forms.ToolStripMenuItem dumpModuleToolStripMenuItem;
        private System.Windows.Forms.ToolStripMenuItem copyAddressToolStripMenuItem;
        private System.Windows.Forms.Button refreshBtn;
    }
}