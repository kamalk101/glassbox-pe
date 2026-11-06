"""Synthetic Speakeasy reports for unit tests.

These are data structures only. They are never executed and are not PE files.
"""


def network_registry_report():
    return {
        "emu_version": "test",
        "arch": "x64",
        "os_run": "windows.6_1",
        "emulation_total_runtime": 1.25,
        "entry_points": [
            {
                "apis": [
                    {"api_name": "KERNEL32.CreateRemoteThread", "args": ["0x1"], "ret_val": "0x0", "pc": "0x1000"},
                    {"api_name": "KERNEL32.WriteProcessMemory", "args": ["0x2"], "ret_val": "0x1", "pc": "0x1010"},
                    {"api_name": "KERNEL32.CreateFileA", "args": ["C:\\Users\\Public\\svchost.exe"], "ret_val": "0x3", "pc": "0x1020"},
                    {"api_name": "KERNEL32.WriteFile", "args": ["0x3", "0x2000"], "ret_val": "0x1", "pc": "0x1030"},
                    {"api_name": "KERNEL32.InternetOpenA", "args": ["http://bad.example/gate.php"], "ret_val": "0x4", "pc": "0x1040"},
                    {"api_name": "KERNEL32.connect", "args": ["0x5", "192.0.2.10", "16"], "ret_val": "0x0", "pc": "0x1050"},
                    {"api_name": "ADVAPI32.RegSetValueExA", "args": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "GlassBoxSyntheticValue", "0", "1", "synthetic-data", "15"], "ret_val": "0x0", "pc": "0x1060"},
                    {"api_name": "ADVAPI32.RegOpenKeyExA", "args": ["HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"], "ret_val": "0x0", "pc": "0x1070"},
                    {"api_name": "KERNEL32.CreateProcessA", "args": ["cmd.exe"], "ret_val": "0x1", "pc": "0x1080"},
                    {"api_name": "KERNEL32.LoadLibraryA", "args": ["kernel32.dll"], "ret_val": "0x1", "pc": "0x1090"},
                    {"api_name": "KERNEL32.IsDebuggerPresent", "args": [], "ret_val": "0x0", "pc": "0x10a0"},
                    {"api_name": "USER32.GetAsyncKeyState", "args": ["0x1"], "ret_val": "0x0", "pc": "0x10b0"},
                    {"api_name": "GDI32.BitBlt", "args": ["0x1"], "ret_val": "0x0", "pc": "0x10c0"},
                    {"api_name": "ADVAPI32.RegCloseKey", "args": ["0x5"], "ret_val": "0x0", "pc": "0x10d0"},
                    {"api_name": "KERNEL32.GetStartupInfoA", "args": [], "ret_val": "0x1", "pc": "0x10e0"},
                ],
                "dynamic_code_segments": [{"addr": "0x3000", "size": 128}],
            }
        ],
        "strings": {"in_memory": {"ansi": ["synthetic"], "unicode": []}},
    }
