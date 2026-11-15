// ScanHub.exe — запускалка: открывает ScanHub без консольного окна.
// Ищет Python: сначала встроенный (папка python рядом — портативная версия), потом установленный (pythonw в PATH).
// Все аргументы передаёт дальше (например, --check "файл" из меню «Проверить в ScanHub»).
// Сборка (из папки launcher): csc /target:winexe /win32icon:..\ui\scanhub.ico /out:..\ScanHub.exe
//   /r:..\window\Microsoft.Web.WebView2.Core.dll /r:..\window\Microsoft.Web.WebView2.WinForms.dll ScanHub.cs Window.cs
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("ScanHub")]
[assembly: AssemblyDescription("ScanHub — проверка и обслуживание Windows")]
[assembly: AssemblyCompany("parzifaal")]
[assembly: AssemblyProduct("ScanHub")]
[assembly: AssemblyCopyright("MIT License")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

static class Launcher
{
    // окна ошибок — на языке Windows: русский для русской Windows, английский для остальных
    static readonly bool Ru = CultureInfo.CurrentUICulture.TwoLetterISOLanguageName == "ru";
    static string T(string ru, string en) { return Ru ? ru : en; }

    static string Quote(string a)
    {
        if (a.Length > 0 && a.IndexOfAny(new[] { ' ', '\t', '"' }) < 0) return a;
        var sb = new StringBuilder("\"");
        foreach (var ch in a) { if (ch == '"') sb.Append('\\'); sb.Append(ch); }
        return sb.Append('"').ToString();
    }

    static string FindOnPath(string exe)
    {
        foreach (var dir in (Environment.GetEnvironmentVariable("PATH") ?? "").Split(';'))
        {
            try
            {
                var p = Path.Combine(dir.Trim().Trim('"'), exe);
                if (File.Exists(p) && !p.ToLowerInvariant().Contains("\\windowsapps\\")) return p;   // заглушка Microsoft Store — не Python
            }
            catch (ArgumentException) { }
        }
        return null;
    }

    [STAThread]
    static int Main(string[] args)
    {
        string root = AppDomain.CurrentDomain.BaseDirectory;
        // окно ScanHub (его открывает сервер): ScanHub.exe --window <адрес> <папка профиля> — Window.cs
        if (args.Length >= 2 && args[0] == "--window")
            return WindowHost.Run(args[1], args.Length > 2 ? args[2] : Path.Combine(root, "data", "webview"));
        string script = Path.Combine(root, "scanhub.py");
        if (!File.Exists(script))
        {
            MessageBox.Show(T("Рядом с ScanHub.exe нет файла scanhub.py.\n\nРаспакуй архив ScanHub целиком и запускай ScanHub.exe из этой папки.",
                              "scanhub.py is missing next to ScanHub.exe.\n\nUnpack the whole ScanHub archive and run ScanHub.exe from that folder."),
                            "ScanHub", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        string py = Path.Combine(root, "python", "pythonw.exe");
        if (!File.Exists(py)) py = FindOnPath("pythonw.exe");
        if (py == null)
        {
            var r = MessageBox.Show(T("Не найден Python.\n\nПроще всего скачать портативную версию ScanHub (ScanHub-Windows.zip) — в ней Python уже есть. Открыть страницу загрузки?",
                                      "Python was not found.\n\nThe easiest fix is the portable ScanHub (ScanHub-Windows.zip) — Python is already inside. Open the download page?"),
                                    "ScanHub", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (r == DialogResult.Yes) Process.Start("https://github.com/Parzifalai/ScanHub/releases/latest");
            return 2;
        }
        var line = new StringBuilder(Quote(script));
        foreach (var a in args) line.Append(' ').Append(Quote(a));
        var psi = new ProcessStartInfo(py, line.ToString()) { WorkingDirectory = root, UseShellExecute = false };
        try { Process.Start(psi); }
        catch (Exception e)
        {
            MessageBox.Show(T("Не удалось запустить ScanHub: ", "Couldn't start ScanHub: ") + e.Message, "ScanHub", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 3;
        }
        return 0;
    }
}
