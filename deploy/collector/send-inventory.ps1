<#
  Отправка автовыгрузки инвентаризации в «Реестр ПО».
  Запускается задачей планировщика каждый день в 21:00 (см. install-task.ps1).

  Токен берётся из файла token.txt рядом со скриптом (создаётся на сайте: Импорт → «Создать токен»).
  Журнал отправок — send-inventory.log рядом со скриптом.
#>
param(
    [Parameter(Mandatory = $true)] [string] $ZipPath,
    [Parameter(Mandatory = $true)] [string] $Url,
    [int] $MaxAgeHours = 20,
    [int] $Retries = 3
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$log = Join-Path $here 'send-inventory.log'

function Write-Log([string] $msg) {
    $line = '{0}  {1}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
    Add-Content -Path $log -Value $line -Encoding UTF8
    Write-Output $line
}

# Журнал не разрастается: храним последние 1000 строк.
if ((Test-Path $log) -and ((Get-Item $log).Length -gt 200KB)) {
    Get-Content $log -Encoding UTF8 | Select-Object -Last 1000 | Set-Content $log -Encoding UTF8
}

try {
    $tokenFile = Join-Path $here 'token.txt'
    if (-not (Test-Path $tokenFile)) { throw "Нет файла токена: $tokenFile" }
    $token = (Get-Content $tokenFile -Raw).Trim()
    if (-not $token) { throw 'Файл токена пустой' }

    if (-not (Test-Path $ZipPath)) { throw "Архив не найден: $ZipPath" }
    $zip = Get-Item $ZipPath
    $age = (Get-Date) - $zip.LastWriteTime
    if ($age.TotalHours -gt $MaxAgeHours) {
        throw ("Архив устарел: изменён {0:yyyy-MM-dd HH:mm}, старше {1} ч. Сбор данных сегодня не отработал?" -f $zip.LastWriteTime, $MaxAgeHours)
    }

    # Копия, чтобы сборщик мог перезаписать архив во время отправки.
    $tmp = Join-Path $env:TEMP ('inventory_send_{0}.zip' -f [guid]::NewGuid())
    Copy-Item $zip.FullName $tmp
    $resp = Join-Path $env:TEMP ('inventory_resp_{0}.txt' -f [guid]::NewGuid())

    $sent = $false
    try {
        for ($i = 1; $i -le $Retries -and -not $sent; $i++) {
            # curl.exe есть в Windows 10 1803+ и Windows 11; при сетевой ошибке печатает код 000
            $code = & curl.exe -s -o $resp -w '%{http_code}' --max-time 120 `
                -H "Authorization: Bearer $token" -F "file=@$tmp;type=application/zip" $Url
            $body = if (Test-Path $resp) { Get-Content $resp -Raw -Encoding UTF8 } else { '' }
            if ($code -eq '200') {
                $msg = try { ($body | ConvertFrom-Json).message } catch { $body }
                Write-Log "OK: $msg"
                $sent = $true
            }
            elseif ($code -eq '401') { throw 'Сервер отклонил токен (401). Создайте новый токен на сайте и запишите в token.txt' }
            elseif ($code -eq '422') {
                $msg = try { ($body | ConvertFrom-Json).message } catch { $body }
                throw "Сервер не принял архив: $msg"
            }
            else {
                Write-Log "Попытка $i из $Retries не удалась (код: $code)"
                if ($i -lt $Retries) { Start-Sleep -Seconds 60 }
            }
        }
    }
    finally {
        Remove-Item $tmp, $resp -ErrorAction SilentlyContinue
    }
    if (-not $sent) { throw 'Сервер недоступен, все попытки исчерпаны' }
}
catch {
    Write-Log "ОШИБКА: $($_.Exception.Message)"
    exit 1
}
exit 0
