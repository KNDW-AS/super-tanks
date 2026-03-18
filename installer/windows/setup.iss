; Super Tanks Windows Installer — Inno Setup Script
; Compile with Inno Setup 6.x: iscc setup.iss
; Output: install.exe

[Setup]
AppName=Super Tanks
AppVersion=3.1
AppPublisher=KNDW Shelter Solutions AS
AppPublisherURL=https://aeris.no
DefaultDirName={autopf}\SuperTanks
DefaultGroupName=Super Tanks
OutputBaseFilename=install
SetupIconFile=..\..\dashboard-static\assets\icon.ico
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"
Name: "norwegian"; MessagesFile: "compiler:Languages\Norwegian.isl"

[Tasks]
Name: "autostart"; Description: "Start Super Tanks when Windows starts"; GroupDescription: "Additional options:"
Name: "desktopicon"; Description: "Create desktop shortcut"; GroupDescription: "Additional options:"

[Files]
Source: "..\..\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs; Excludes: "venv\*,__pycache__\*,.git\*,data\*.db,*.pyc"
Source: "start.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "stop.bat"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Super Tanks"; Filename: "{app}\start.bat"; IconFilename: "{app}\dashboard-static\assets\icon.ico"
Name: "{group}\Stop Super Tanks"; Filename: "{app}\stop.bat"
Name: "{group}\Uninstall Super Tanks"; Filename: "{uninstallexe}"
Name: "{autodesktop}\Super Tanks"; Filename: "{app}\start.bat"; Tasks: desktopicon

[Run]
Filename: "{app}\start.bat"; Description: "Start Super Tanks now"; Flags: nowait postinstall skipifsilent

[Code]
// Check for Docker on install
function InitializeSetup(): Boolean;
begin
  Result := True;
  // Will be extended to check/install Docker and Ollama
end;
