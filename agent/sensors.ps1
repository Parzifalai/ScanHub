# ScanHub — агент датчиков Lenovo (температуры и вентиляторы).
# Запускается задачей планировщика «ScanHub\Датчики» с правами администратора, потому что
# WMI-классы Lenovo (LENOVO_GAMEZONE_DATA, LENOVO_FAN_METHOD) недоступны обычному пользователю.
# Только ЧИТАЕТ датчики и пишет числа в %ProgramData%\ScanHub\sensors.json.
# Сам завершается, если ScanHub не обновлял файл «want» дольше 45 секунд (окно закрыто).
$ErrorActionPreference = 'SilentlyContinue'
$dir  = Join-Path $env:ProgramData 'ScanHub'
$out  = Join-Path $dir 'sensors.json'
$want = Join-Path $dir 'want'
New-Item -ItemType Directory -Force -Path $dir | Out-Null

$gz = Get-CimInstance -Namespace root\WMI -ClassName LENOVO_GAMEZONE_DATA | Select-Object -First 1
$fm = Get-CimInstance -Namespace root\WMI -ClassName LENOVO_FAN_METHOD | Select-Object -First 1
# новые Legion/LOQ: датчики по номерам возможностей (как в Lenovo Legion Toolkit)
$om = Get-CimInstance -Namespace root\WMI -ClassName LENOVO_OTHER_METHOD | Select-Object -First 1
$OM_IDS = [ordered]@{ om_fan1 = 0x04030001; om_fan2 = 0x04030002; om_fan3 = 0x04030004
                      om_cpu = 0x05040000; om_gpu = 0x05050000; om_pch = 0x05010000 }

function Read-Num($obj, [string]$method, [hashtable]$arg) {
    if (-not $obj) { return $null }
    try {
        $r = if ($arg) { Invoke-CimMethod -InputObject $obj -MethodName $method -Arguments $arg -ErrorAction Stop }
             else      { Invoke-CimMethod -InputObject $obj -MethodName $method -ErrorAction Stop }
        foreach ($p in $r.PSObject.Properties) {
            if ($p.Name -in 'ReturnValue', 'PSComputerName') { continue }
            if ($p.Value -is [ValueType]) { return [double]$p.Value }
        }
    } catch { }
    return $null
}

function Read-Acpi {
    # запасной вариант: зоны ACPI (десятые доли кельвина)
    $z = Get-CimInstance -Namespace root\WMI -ClassName MSAcpi_ThermalZoneTemperature
    @($z | ForEach-Object { [math]::Round($_.CurrentTemperature / 10 - 273.15, 1) })
}

$t0 = Get-Date
while ($true) {
    if (-not (Test-Path $want)) { break }
    if (((Get-Date) - (Get-Item $want).LastWriteTime).TotalSeconds -gt 45) { break }
    if (((Get-Date) - $t0).TotalHours -gt 12) { break }
    $o = [ordered]@{ t = [DateTimeOffset]::Now.ToUnixTimeSeconds() }
    if ($gz) {
        $o.gz_cpu   = Read-Num $gz 'GetCPUTemp'
        $o.gz_gpu   = Read-Num $gz 'GetGPUTemp'
        $o.gz_fan1  = Read-Num $gz 'GetFan1Speed'
        $o.gz_fan2  = Read-Num $gz 'GetFan2Speed'
        $o.gz_fanmax = Read-Num $gz 'GetFanMaxSpeed'
        $o.gz_mode  = Read-Num $gz 'GetSmartFanMode'
    }
    if ($fm) {
        $o.fm_fan1 = Read-Num $fm 'Fan_GetCurrentFanSpeed' @{ FanID = [uint32]1 }
        $o.fm_fan2 = Read-Num $fm 'Fan_GetCurrentFanSpeed' @{ FanID = [uint32]2 }
        $o.fm_cpu  = Read-Num $fm 'Fan_GetCurrentSensorTemperature' @{ SensorID = [uint32]3 }
        $o.fm_gpu  = Read-Num $fm 'Fan_GetCurrentSensorTemperature' @{ SensorID = [uint32]4 }
    }
    if ($om) {
        foreach ($k in $OM_IDS.Keys) { $o[$k] = Read-Num $om 'GetFeatureValue' @{ IDs = [uint32]$OM_IDS[$k] } }
    }
    $o.acpi = @(Read-Acpi)
    $o.has_gz = [bool]$gz; $o.has_fm = [bool]$fm; $o.has_om = [bool]$om
    $o.v = 2
    $tmp = "$out.tmp"
    ($o | ConvertTo-Json -Compress) | Set-Content -Encoding UTF8 -Path $tmp
    Move-Item -Force -Path $tmp -Destination $out
    Start-Sleep -Seconds 2
}
