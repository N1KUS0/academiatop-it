<#
  Создаёт задачу планировщика «Реестр ПО — отправка инвентаризации»: каждый день в 21:00.
  Запускать в PowerShell от имени администратора на ПК, где создаётся inventory_latest.zip:

    .\install-task.ps1 -ZipPath "D:\Inventory\inventory_latest.zip" -Url "https://academiatop-blg.ru/api/inventory"
#>
param(
    [Parameter(Mandatory = $true)] [string] $ZipPath,
    [Parameter(Mandatory = $true)] [string] $Url,
    [string] $At = '21:00',
    [string] $TaskName = 'Реестр ПО — отправка инвентаризации'
)

$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$script = Join-Path $here 'send-inventory.ps1'
$tokenFile = Join-Path $here 'token.txt'

if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Запустите PowerShell от имени администратора'
}
if (-not (Test-Path $ZipPath)) { Write-Warning "Архив пока не найден: $ZipPath (задача всё равно будет создана)" }

if (-not (Test-Path $tokenFile)) {
    $secure = Read-Host 'Вставьте токен с сайта (Импорт → «Создать токен»)' -AsSecureString
    $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    Set-Content -Path $tokenFile -Value $plain.Trim() -Encoding ASCII -NoNewline
}
# Токен читают только SYSTEM и администраторы.
icacls $tokenFile /inheritance:r /grant:r '*S-1-5-18:R' '*S-1-5-32-544:F' | Out-Null

$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -ExecutionPolicy Bypass -File "{0}" -ZipPath "{1}" -Url "{2}"' -f $script, $ZipPath, $Url)
$trigger = New-ScheduledTaskTrigger -Daily -At $At
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
$principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
    -Principal $principal -Force | Out-Null

Write-Output "Задача «$TaskName» создана: каждый день в $At."
Write-Output "Проверить сейчас:  Start-ScheduledTask -TaskName '$TaskName'"
Write-Output "Журнал:            $(Join-Path $here 'send-inventory.log')"
