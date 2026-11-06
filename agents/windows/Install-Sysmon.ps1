# Install a minimal Sysmon configuration for GlassBox lab telemetry.
# Run in an isolated lab VM only.
param(
    [string]$InstallerPath = "Sysmon64.exe"
)

$ErrorActionPreference = "Stop"
$config = @(
    '<Sysmon schemaversion="4.90">'
    '  <EventFiltering>'
    '    <ProcessCreate onmatch="exclude" />'
    '    <ProcessChangeControl onmatch="exclude" />'
    '    <ProcessTerminate onmatch="exclude" />'
    '    <ProcessAccess onmatch="exclude" />'
    '    <FileCreate onmatch="exclude" />'
    '    <NetworkConnect onmatch="exclude" />'
    '    <RegistryEvent onmatch="exclude" />'
    '  </EventFiltering>'
    '</Sysmon>'
)
$config | Set-Content .\glassbox-sysmon.xml -Encoding utf8
& $InstallerPath -accepteula -i .\glassbox-sysmon.xml
