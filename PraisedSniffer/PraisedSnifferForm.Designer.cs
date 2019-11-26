namespace PraisedSniffer
{
    partial class PraisedSnifferForm
    {
        /// <summary>
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Windows Form Designer generated code

        /// <summary>
        /// Required method for Designer support - do not modify
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            System.ComponentModel.ComponentResourceManager resources = new System.ComponentModel.ComponentResourceManager(typeof(PraisedSnifferForm));
            this.mInterfaces = new System.Windows.Forms.ComboBox();
            this.buttonStartStop = new System.Windows.Forms.Button();
            this.listPackets = new System.Windows.Forms.ListView();
            this.textProperties = new System.Windows.Forms.TextBox();
            this.label1 = new System.Windows.Forms.Label();
            this.SuspendLayout();
            // 
            // mInterfaces
            // 
            this.mInterfaces.FormattingEnabled = true;
            this.mInterfaces.Location = new System.Drawing.Point(13, 13);
            this.mInterfaces.Name = "mInterfaces";
            this.mInterfaces.Size = new System.Drawing.Size(389, 21);
            this.mInterfaces.TabIndex = 1;
            // 
            // buttonStartStop
            // 
            this.buttonStartStop.Location = new System.Drawing.Point(408, 11);
            this.buttonStartStop.Name = "buttonStartStop";
            this.buttonStartStop.Size = new System.Drawing.Size(75, 23);
            this.buttonStartStop.TabIndex = 2;
            this.buttonStartStop.Text = "Start";
            this.buttonStartStop.UseVisualStyleBackColor = true;
            this.buttonStartStop.Click += new System.EventHandler(this.buttonStartStop_Click);
            // 
            // listPackets
            // 
            this.listPackets.FullRowSelect = true;
            this.listPackets.GridLines = true;
            this.listPackets.HideSelection = false;
            this.listPackets.Location = new System.Drawing.Point(13, 40);
            this.listPackets.MultiSelect = false;
            this.listPackets.Name = "listPackets";
            this.listPackets.Size = new System.Drawing.Size(494, 289);
            this.listPackets.TabIndex = 3;
            this.listPackets.UseCompatibleStateImageBehavior = false;
            this.listPackets.View = System.Windows.Forms.View.Details;
            this.listPackets.ItemSelectionChanged += new System.Windows.Forms.ListViewItemSelectionChangedEventHandler(this.listPackets_ItemSelectionChanged);
            // 
            // textProperties
            // 
            this.textProperties.Location = new System.Drawing.Point(513, 40);
            this.textProperties.Multiline = true;
            this.textProperties.Name = "textProperties";
            this.textProperties.ScrollBars = System.Windows.Forms.ScrollBars.Both;
            this.textProperties.Size = new System.Drawing.Size(451, 289);
            this.textProperties.TabIndex = 4;
            // 
            // label1
            // 
            this.label1.AutoSize = true;
            this.label1.Location = new System.Drawing.Point(510, 21);
            this.label1.Name = "label1";
            this.label1.Size = new System.Drawing.Size(120, 13);
            this.label1.TabIndex = 5;
            this.label1.Text = "Informações do Pacote:";
            // 
            // PraisedSnifferForm
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(976, 341);
            this.Controls.Add(this.label1);
            this.Controls.Add(this.textProperties);
            this.Controls.Add(this.listPackets);
            this.Controls.Add(this.buttonStartStop);
            this.Controls.Add(this.mInterfaces);
            this.Icon = ((System.Drawing.Icon)(resources.GetObject("$this.Icon")));
            this.Name = "PraisedSnifferForm";
            this.Text = "PraisedSniffer";
            this.Load += new System.EventHandler(this.PraisedSnifferForm_Load);
            this.ResumeLayout(false);
            this.PerformLayout();

        }

        #endregion
        private System.Windows.Forms.ComboBox mInterfaces;
        private System.Windows.Forms.Button buttonStartStop;
        private System.Windows.Forms.ListView listPackets;
        private System.Windows.Forms.TextBox textProperties;
        private System.Windows.Forms.Label label1;
    }
}

