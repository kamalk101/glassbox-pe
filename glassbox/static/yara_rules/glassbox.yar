/*
 * GlassBox PE built-in YARA rules.
 *
 * These rules deliberately target concrete, high-signal strings rather than
 * broad capability words. Python rules describe capabilities; YARA adds
 * artifact-level matches with byte offsets.
 */

rule GB_YARA_CREDENTIAL_THEFT
{
    meta:
        gb_rule_id = "GB-YARA-001"
        title = "Credential theft tooling strings"
        severity = "critical"
        category = "process"
        technique = "T1003.001"
        confidence = "0.9"
        description = "Strings associated with credential dumping tools such as Mimikatz were found."
    strings:
        $a1 = "sekurlsa::logonpasswords" ascii wide nocase
        $a2 = "mimikatz" ascii wide nocase
        $a3 = "lsadump::sam" ascii wide nocase
        $a4 = "kerberos::golden" ascii wide nocase
    condition:
        $a1 or $a2 or $a3 or $a4
}

rule GB_YARA_PROCESS_DUMP
{
    meta:
        gb_rule_id = "GB-YARA-002"
        title = "Process memory dumping strings"
        severity = "medium"
        category = "process"
        technique = "T1003.001"
        confidence = "0.7"
        description = "The sample references LSASS and process-memory dump APIs together."
    strings:
        $a1 = "lsass.exe" ascii wide nocase
        $a2 = "MiniDumpWriteDump" ascii wide nocase
        $a3 = "dbghelp.dll" ascii wide nocase
        $a4 = "PssCaptureSnapshot" ascii wide nocase
    condition:
        $a1 and any of ($a2, $a3, $a4)
}

rule GB_YARA_ENCODED_POWERSHELL
{
    meta:
        gb_rule_id = "GB-YARA-003"
        title = "Encoded PowerShell execution"
        severity = "critical"
        category = "process"
        technique = "T1059.001"
        confidence = "0.8"
        description = "The sample contains encoded or dynamically downloaded PowerShell content."
    strings:
        $a1 = "-encodedcommand" ascii wide nocase
        $a2 = "-enc " ascii wide nocase
        $a3 = "FromBase64String" ascii wide nocase
        $a4 = "DownloadString" ascii wide nocase
        $a5 = "IEX(" ascii wide nocase
        $a6 = "Invoke-Expression" ascii wide nocase
    condition:
        2 of them
}

rule GB_YARA_RANSOMWARE_NOTE
{
    meta:
        gb_rule_id = "GB-YARA-004"
        title = "Ransomware note language"
        severity = "high"
        category = "file"
        technique = "T1486"
        confidence = "0.75"
        description = "The sample contains language commonly used in ransomware notes."
    strings:
        $a1 = "your files have been encrypted" ascii wide nocase
        $a2 = "your files are encrypted" ascii wide nocase
        $a3 = "bitcoin" ascii wide nocase
        $a4 = "decrypt your files" ascii wide nocase
        $a5 = "recover your files" ascii wide nocase
    condition:
        $a1 or $a2 or ($a4 and $a5) or ($a3 and $a4)
}

rule GB_YARA_COINMINER
{
    meta:
        gb_rule_id = "GB-YARA-005"
        title = "Cryptocurrency miner strings"
        severity = "critical"
        category = "network"
        technique = "T1496"
        confidence = "0.85"
        description = "The sample contains mining-pool or miner identifiers."
    strings:
        $a1 = "stratum+tcp://" ascii wide nocase
        $a2 = "stratum+ssl://" ascii wide nocase
        $a3 = "xmrig" ascii wide nocase
        $a4 = "monero" ascii wide nocase
        $a5 = "minerd" ascii wide nocase
        $a6 = "cryptonight" ascii wide nocase
    condition:
        any of them
}

rule GB_YARA_ANTI_VM_STRINGS
{
    meta:
        gb_rule_id = "GB-YARA-006"
        title = "Virtual-machine detection strings"
        severity = "medium"
        category = "pe"
        technique = "T1497.001"
        confidence = "0.65"
        description = "The sample contains multiple virtual-machine or sandbox artifact names."
    strings:
        $a1 = "VMware" ascii wide nocase
        $a2 = "VirtualBox" ascii wide nocase
        $a3 = "VBoxService" ascii wide nocase
        $a4 = "vmtoolsd" ascii wide nocase
        $a5 = "SbieDll.dll" ascii wide nocase
        $a6 = "sandboxie" ascii wide nocase
        $a7 = "qemu" ascii wide nocase
    condition:
        2 of them
}

rule GB_YARA_DOWNLOAD_AND_RUN
{
    meta:
        gb_rule_id = "GB-YARA-007"
        title = "Download-and-run API combination"
        severity = "medium"
        category = "network"
        technique = "T1105"
        confidence = "0.7"
        description = "The import or string table combines URL download and process execution APIs."
    strings:
        $a1 = "URLDownloadToFile" ascii wide nocase
        $a2 = "WinExec" ascii wide nocase
        $a3 = "ShellExecute" ascii wide nocase
        $a4 = "http://" ascii wide nocase
        $a5 = "https://" ascii wide nocase
    condition:
        $a1 and any of ($a2, $a3) and any of ($a4, $a5)
}

rule GB_YARA_SERVICE_PERSISTENCE
{
    meta:
        gb_rule_id = "GB-YARA-008"
        title = "Service or scheduled-task persistence strings"
        severity = "medium"
        category = "registry"
        technique = "T1543.003"
        confidence = "0.65"
        description = "The sample references service creation and hidden execution paths together."
    strings:
        $a1 = "CreateService" ascii wide nocase
        $a2 = "schtasks" ascii wide nocase
        $a3 = "sc create" ascii wide nocase
        $a4 = "CurrentVersion\\Run" ascii wide nocase
        $a5 = "powershell" ascii wide nocase
    condition:
        ($a1 and any of ($a2, $a3)) or ($a4 and $a5)
}
