// ScanHub.exe — запускалка: открывает ScanHub без консольного окна.
// Ищет Python: сначала встроенный (папка python рядом — портативная версия), потом установленный (pythonw в PATH).
// Все аргументы передаёт дальше (например, --check "файл" из меню «Проверить в ScanHub»).
// Сборка: csc /target:winexe /win32icon:..\ui\scanhub.ico /out:..\ScanHub.exe ScanHub.cs
using System;
using System.Diagnostics;
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
        string script = Path.Combine(root, "scanhub.py");
        if (!File.Exists(script))
        {
            MessageBox.Show("Рядом с ScanHub.exe нет файла scanhub.py.\n\nРаспакуй архив ScanHub целиком и запускай ScanHub.exe из этой папки.",
                            "ScanHub", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 1;
        }
        string py = Path.Combine(root, "python", "pythonw.exe");
        if (!File.Exists(py)) py = FindOnPath("pythonw.exe");
        if (py == null)
        {
            var r = MessageBox.Show("Не найден Python.\n\nПроще всего скачать портативную версию ScanHub — в ней Python уже есть. Открыть страницу загрузки?",
                                    "ScanHub", MessageBoxButtons.YesNo, MessageBoxIcon.Information);
            if (r == DialogResult.Yes) Process.Start("https://www.python.org/downloads/windows/");
            return 2;
        }
        var line = new StringBuilder(Quote(script));
        foreach (var a in args) line.Append(' ').Append(Quote(a));
        var psi = new ProcessStartInfo(py, line.ToString()) { WorkingDirectory = root, UseShellExecute = false };
        try { Process.Start(psi); }
        catch (Exception e)
        {
            MessageBox.Show("Не удалось запустить ScanHub: " + e.Message, "ScanHub", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return 3;
        }
        return 0;
    }
}
