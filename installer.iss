#define MyInstallerName "Open Paging Server Desktop"
#define MyShortcutName "Open Paging Server"
#define MyAppVersion "0.7.9"
#define MyAppPublisher "Open Paging Server"
#define MyAppExeName "OpenPagingServerClient.exe"

[Setup]
AppId={{7C1B9A64-52D4-4E7B-9F3A-0E8A2C6D51B0}
AppName={#MyInstallerName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyInstallerName}
DefaultGroupName={#MyShortcutName}
DisableProgramGroupPage=yes
OutputDir=dist
OutputBaseFilename=OpenPagingServerClientSetup
Compression=lzma
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
UsePreviousPrivileges=yes
CloseApplications=force
RestartApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "startupicon"; Description: "Launch the client when Windows starts"; GroupDescription: "Additional options:"

[Files]
Source: "dist\{#MyAppExeName}"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyShortcutName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyShortcutName}"; Filename: "{app}\{#MyAppExeName}"

[Registry]
Root: HKA; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "OpenPagingServerClient"; ValueData: """{app}\{#MyAppExeName}"" -background"; Flags: uninsdeletevalue; Tasks: startupicon
Root: HKLM; Subkey: "Software\Policies\OpenPagingServer\DesktopClient"; ValueType: string; ValueName: "ServerAddress"; ValueData: "{code:GetServerAddress}"; Check: HasServerAddress

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Launch {#MyShortcutName}"; Flags: nowait postinstall skipifsilent; Check: not IsUnattendedInstall

[UninstallRun]
Filename: "{cmd}"; Parameters: "/C taskkill /IM ""{#MyAppExeName}"" /T >nul 2>&1 || exit /B 0"; Flags: runhidden
Filename: "{cmd}"; Parameters: "/C taskkill /IM ""{#MyAppExeName}"" /F /T >nul 2>&1 || exit /B 0"; Flags: runhidden

[Code]
var
  ExistingInstallPage: TInputOptionWizardPage;
  ExistingInstallVersion: String;

function ReadInstalledVersion(RootKey: Integer; var Version: String): Boolean;
begin
  Result := RegQueryStringValue(
    RootKey,
    'Software\Microsoft\Windows\CurrentVersion\Uninstall\{7C1B9A64-52D4-4E7B-9F3A-0E8A2C6D51B0}_is1',
    'DisplayVersion',
    Version);
end;

function ExistingInstallDetected: Boolean;
begin
  Result := ReadInstalledVersion(HKLM, ExistingInstallVersion) or
            ReadInstalledVersion(HKCU, ExistingInstallVersion);
end;

procedure InitializeWizard;
begin
  if ExistingInstallDetected then
  begin
    ExistingInstallPage := CreateInputOptionPage(
      wpWelcome,
      'Existing Installation Detected',
      'Choose how to continue',
      'Open Paging Server Desktop ' + ExistingInstallVersion + ' is already installed. ' +
      'Upgrade installs this version and preserves settings. Repair reinstalls all program files.',
      True,
      False);
    ExistingInstallPage.Add('Upgrade the existing installation');
    ExistingInstallPage.Add('Repair the existing installation');
    ExistingInstallPage.SelectedValueIndex := 0;
  end;
end;

procedure RegisterExtraCloseApplicationsResources;
begin
  RegisterExtraCloseApplicationsResource(ExpandConstant('{app}\{#MyAppExeName}'));
end;

function HasCommandLineSwitch(Value: String): Boolean;
var
  I: Integer;
begin
  Result := False;
  for I := 1 to ParamCount do
    if CompareText(ParamStr(I), Value) = 0 then
    begin
      Result := True;
      Exit;
    end;
end;

function IsUnattendedInstall: Boolean;
begin
  Result := WizardSilent or HasCommandLineSwitch('/UNATTENDED');
end;

function GetServerAddress(Param: String): String;
begin
  Result := Trim(ExpandConstant('{param:SERVERADDRESS|}'));
end;

function HasServerAddress: Boolean;
begin
  Result := GetServerAddress('') <> '';
end;

function ExpandProfileEnvironment(ProfilePath: String): String;
begin
  StringChangeEx(ProfilePath, '%SystemDrive%', ExpandConstant('{sd}'), False);
  StringChangeEx(ProfilePath, '%SystemRoot%', ExpandConstant('{win}'), False);
  StringChangeEx(ProfilePath, '%WINDIR%', ExpandConstant('{win}'), False);
  Result := ProfilePath;
end;

procedure RemoveAllUserAppData;
var
  RootKey: Integer;
  ProfileSids: TArrayOfString;
  ProfilePath: String;
  AppDataPath: String;
  I: Integer;
begin
  { Remove the interactive account first, then every locally registered profile. }
  DelTree(ExpandConstant('{userappdata}\OpenPagingServerClient'), True, True, True);

  if IsWin64 then
    RootKey := HKLM64
  else
    RootKey := HKLM;

  if not RegGetSubkeyNames(
    RootKey,
    'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList',
    ProfileSids) then
    Exit;

  for I := 0 to GetArrayLength(ProfileSids) - 1 do
  begin
    ProfilePath := '';
    if RegQueryStringValue(
      RootKey,
      'SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + ProfileSids[I],
      'ProfileImagePath',
      ProfilePath) then
    begin
      ProfilePath := RemoveBackslashUnlessRoot(ExpandProfileEnvironment(Trim(ProfilePath)));
      if ProfilePath <> '' then
      begin
        AppDataPath := AddBackslash(ProfilePath) + 'AppData\Roaming\OpenPagingServerClient';
        DelTree(AppDataPath, True, True, True);
      end;
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    RemoveAllUserAppData;
end;
