param(
    [Parameter(Mandatory = $true)]
    [string]$SamplePath,
    [Parameter(Mandatory = $true)]
    [string]$OutputPath,
    [string]$TimeoutSeconds = "30"
)

$ErrorActionPreference = "Stop"
$sample = Get-Item -LiteralPath $SamplePath
if (-not $sample) { throw "sample not found: $SamplePath" }
$hash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SamplePath).Hash.ToLower()
$start = Get-Date -Format o
$process = Start-Process -FilePath $SamplePath -PassThru
Start-Sleep -Seconds ([int]$TimeoutSeconds)
$end = Get-Date -Format o
$events = @()
try {
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 2000 |
        Where-Object { $_.TimeCreated -ge (Get-Date $start) -and $_.TimeCreated -le (Get-Date $end) } |
        ForEach-Object {
            $message = $_.Message
            [PSCustomObject]@{
                id = $_.Id
                provider = $_.ProviderName
                target = $message
                action = switch ($_.Id) {
                    1 { "process_start" }
                    3 { "network_connect" }
                    5 { "process_exit" }
                    7 { "image_load" }
                    11 { "file_create" }
                    12 { "registry_create" }
                    13 { "registry_set" }
                    14 { "registry_delete" }
                    default { "other" }
                }
                category = switch ($_.Id) {
                    1 { "process" }
                    5 { "process" }
                    7 { "pe" }
                    3 { "network" }
                    11 { "file" }
                    12 { "registry" }
                    13 { "registry" }
                    14 { "registry" }
                    default { "other" }
                }
                process_id = [string]$_.Properties[0].Value
            }
        }
} catch {
    Write-Warning "Sysmon log not available or not configured: $_"
}
$report = [PSCustomObject]@{
    schema_version = "0.1"
    sample = @{
        file_name = $sample.Name
        sha256 = $hash
        path = $SamplePath
    }
    environment = @{
        vm_name = $env:COMPUTERNAME
        os = (Get-CimInstance Win32_OperatingSystem).Caption
        isolated = $true
    }
    started_at = $start
    ended_at = $end
    exit_code = $process.ExitCode
    events = $events
    dropped_files = @()
}
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $OutputPath -Encoding utf8
