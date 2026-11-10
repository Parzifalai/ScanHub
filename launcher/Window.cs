// Окно ScanHub без рамки Edge: WebView2 (движок Edge, встроенный в Windows 11) в своём окне.
// ScanHub.exe --window <адрес> <папка профиля> — так его открывает сервер (scanhub.open_window).
// Системной полосы заголовка нет: её место занимает тёмная шапка ScanHub, кнопки «свернуть / развернуть / закрыть» —
// в ней же (index.html, .wincaps), перетаскивание — за пустое место шапки. Края окна, тень, Snap и Win+стрелки — как у обычного окна.
// Библиотеки WebView2 (Microsoft, BSD) лежат в папке window рядом с ScanHub.exe.
// Если движка нет или окно не поднялось — сервер сам откроет ScanHub через Edge, как раньше.
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Windows.Forms;
using Microsoft.Web.WebView2.Core;
using Microsoft.Web.WebView2.WinForms;

static class WindowHost
{
    static string libDir;

    // AssemblyResolve — до первого обращения к типам WebView2, поэтому само окно — в отдельном методе
    public static int Run(string url, string dataDir)
    {
        libDir = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "window");
        AppDomain.CurrentDomain.AssemblyResolve += delegate (object s, ResolveEventArgs e)
        {
            string p = Path.Combine(libDir, new AssemblyName(e.Name).Name + ".dll");
            return File.Exists(p) ? Assembly.LoadFrom(p) : null;
        };
        try { SetProcessDpiAwarenessContext(new IntPtr(-4)); } catch (Exception) { }     // per-monitor v2: чёткий текст на 125–150 %
        return Show(url, dataDir);
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    static int Show(string url, string dataDir)
    {
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        var f = new HostForm(url, dataDir, libDir);
        Application.Run(f);
        return f.ExitCode;
    }

    [DllImport("user32.dll")] static extern bool SetProcessDpiAwarenessContext(IntPtr value);
}

class HostForm : Form
{
    public int ExitCode;
    readonly string url, dataDir, libDir, boundsFile;
    readonly WebView2 web;

    public HostForm(string url, string dataDir, string libDir)
    {
        this.url = url; this.dataDir = dataDir; this.libDir = libDir;
        boundsFile = Path.Combine(dataDir, "window-bounds.txt");
        Text = "ScanHub";
        BackColor = Color.FromArgb(7, 12, 27);
        try { Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath); } catch (Exception) { }
        AutoScaleMode = AutoScaleMode.None;
        StartPosition = FormStartPosition.Manual;
        MinimumSize = new Size(760, 520);
        LoadBounds();
        web = new WebView2();
        web.Dock = DockStyle.Fill;
        web.DefaultBackgroundColor = BackColor;
        web.CreationProperties = new CoreWebView2CreationProperties
        {
            UserDataFolder = dataDir,
            // свёрнутое окно не «засыпает»: иначе оно перестаёт подавать сигнал «я открыто» и сервер ScanHub закрывается сам
            AdditionalBrowserArguments = "--disable-background-timer-throttling --disable-renderer-backgrounding " +
                "--disable-backgrounding-occluded-windows --disable-features=IntensiveWakeUpThrottling --disk-cache-size=20000000"
        };
        Controls.Add(web);
        Load += OnLoad;
        FormClosing += delegate { SaveBounds(); };
        Resize += delegate { Tell(); };
    }

    async void OnLoad(object sender, EventArgs e)
    {
        try
        {
            CoreWebView2Environment.SetLoaderDllFolderPath(libDir);
            await web.EnsureCoreWebView2Async();
        }
        catch (Exception)
        {
            ExitCode = 10;          // движка нет или он сломан — сервер откроет окно через Edge
            Close();
            return;
        }
        var cw = web.CoreWebView2;
        cw.Settings.IsStatusBarEnabled = false;
        cw.Settings.IsZoomControlEnabled = false;
        cw.Settings.AreDevToolsEnabled = false;
        cw.Settings.IsPasswordAutosaveEnabled = false;
        cw.Settings.IsGeneralAutofillEnabled = false;
        cw.DocumentTitleChanged += delegate { Text = cw.DocumentTitle; };
        cw.WebMessageReceived += OnMessage;
        cw.NavigationCompleted += delegate { Tell(); };
        // ссылки «открыть на сайте» — в обычном браузере, а не новым окном внутри ScanHub
        cw.NewWindowRequested += delegate (object s, CoreWebView2NewWindowRequestedEventArgs a)
        {
            a.Handled = true;
            if (a.Uri.StartsWith("https://", StringComparison.OrdinalIgnoreCase)) Process.Start(a.Uri);
        };
        cw.Navigate(url);
    }

    void OnMessage(object sender, CoreWebView2WebMessageReceivedEventArgs e)
    {
        string m;
        try { m = e.TryGetWebMessageAsString(); } catch (Exception) { return; }
        if (m == "min") WindowState = FormWindowState.Minimized;
        else if (m == "max") WindowState = WindowState == FormWindowState.Maximized ? FormWindowState.Normal : FormWindowState.Maximized;
        else if (m == "close") Close();
        else if (m == "drag") { ReleaseCapture(); SendMessage(Handle, 0xA1, new IntPtr(2), IntPtr.Zero); }    // WM_NCLBUTTONDOWN, HTCAPTION
    }

    // окно сообщает странице, развёрнуто ли оно — меняется значок кнопки «развернуть»
    void Tell()
    {
        try { if (web != null && web.CoreWebView2 != null) web.CoreWebView2.PostWebMessageAsString(WindowState == FormWindowState.Maximized ? "state:max" : "state:normal"); }
        catch (Exception) { }
    }

    // ---- рамка: убираем только полосу заголовка; края для изменения размера, тень и Snap остаются системными
    const int WM_NCCALCSIZE = 0x83;
    [StructLayout(LayoutKind.Sequential)] struct RECT { public int L, T, R, B; }
    [StructLayout(LayoutKind.Sequential)] struct NCCALCSIZE_PARAMS { public RECT r0, r1, r2; public IntPtr pos; }

    protected override void WndProc(ref Message m)
    {
        if (m.Msg == WM_NCCALCSIZE && m.WParam != IntPtr.Zero)
        {
            var p = (NCCALCSIZE_PARAMS)Marshal.PtrToStructure(m.LParam, typeof(NCCALCSIZE_PARAMS));
            int top = p.r0.T;
            base.WndProc(ref m);
            p = (NCCALCSIZE_PARAMS)Marshal.PtrToStructure(m.LParam, typeof(NCCALCSIZE_PARAMS));
            // развёрнутое окно Windows выдвигает за край экрана на толщину рамки — иначе верх шапки обрезался бы
            p.r0.T = top + (WindowState == FormWindowState.Maximized ? FrameThickness() : 0);
            Marshal.StructureToPtr(p, m.LParam, false);
            m.Result = IntPtr.Zero;
            return;
        }
        base.WndProc(ref m);
    }

    protected override void OnHandleCreated(EventArgs e)
    {
        base.OnHandleCreated(e);
        try
        {
            int on = 1;
            DwmSetWindowAttribute(Handle, 20, ref on, 4);                  // тёмная рамка и тень (DWMWA_USE_IMMERSIVE_DARK_MODE)
            int border = 0x47261A;                                          // тонкая граница окна — тёмно-синяя (COLORREF 0x00BBGGRR)
            DwmSetWindowAttribute(Handle, 34, ref border, 4);
        }
        catch (Exception) { }
        SetWindowPos(Handle, IntPtr.Zero, 0, 0, 0, 0, 0x0001 | 0x0002 | 0x0004 | 0x0020);   // NOSIZE|NOMOVE|NOZORDER|FRAMECHANGED
    }

    int FrameThickness()
    {
        int dpi = 96;
        try { dpi = (int)GetDpiForWindow(Handle); } catch (Exception) { }
        try { return GetSystemMetricsForDpi(33, dpi) + GetSystemMetricsForDpi(92, dpi); }   // SM_CYFRAME + SM_CXPADDEDBORDER
        catch (Exception) { return 8; }
    }

    // ---- размер и место окна между запусками
    void LoadBounds()
    {
        var wa = Screen.PrimaryScreen.WorkingArea;
        int w = Math.Min(1360, wa.Width - 40), h = Math.Min(900, wa.Height - 40);
        Bounds = new Rectangle(wa.Left + (wa.Width - w) / 2, wa.Top + (wa.Height - h) / 2, w, h);
        try
        {
            var a = File.ReadAllText(boundsFile).Split(',');
            var r = new Rectangle(int.Parse(a[0]), int.Parse(a[1]), int.Parse(a[2]), int.Parse(a[3]));
            foreach (var s in Screen.AllScreens)
                if (s.WorkingArea.IntersectsWith(r) && r.Width >= 600 && r.Height >= 400) { Bounds = r; break; }
            if (a.Length > 4 && a[4] == "max") WindowState = FormWindowState.Maximized;
        }
        catch (Exception) { }
    }

    void SaveBounds()
    {
        try
        {
            Directory.CreateDirectory(dataDir);
            var r = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;
            File.WriteAllText(boundsFile, string.Format("{0},{1},{2},{3},{4}", r.X, r.Y, r.Width, r.Height,
                WindowState == FormWindowState.Maximized ? "max" : "normal"));
        }
        catch (Exception) { }
    }

    [DllImport("user32.dll")] static extern bool ReleaseCapture();
    [DllImport("user32.dll")] static extern IntPtr SendMessage(IntPtr h, int msg, IntPtr w, IntPtr l);
    [DllImport("user32.dll")] static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int cx, int cy, uint flags);
    [DllImport("user32.dll")] static extern uint GetDpiForWindow(IntPtr h);
    [DllImport("user32.dll")] static extern int GetSystemMetricsForDpi(int index, int dpi);
    [DllImport("dwmapi.dll")] static extern int DwmSetWindowAttribute(IntPtr h, int attr, ref int value, int size);
}
