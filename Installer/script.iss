[Setup]
AppName=Zoom Custom Installer
AppVersion=1.0
DefaultDirName={pf}\Zoom
DefaultGroupName=Zoom
OutputDir=.
OutputBaseFilename=NewZoomInstaller
Compression=lzma
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64

[Files]
Source: "ZoomInstaller.exe"; DestDir: "{tmp}"
Source: "WrapperPKCS11.dll"; DestDir: "{app}"; DestName: "WrapperPKCS11.dll"

[Run]
Filename: "{tmp}\ZoomInstaller.exe"; Parameters: "/silent /install"; Flags: waituntilterminated

[Code]


var
  Dummy: Integer;

function IsETPKCS11Referenced: Boolean;
var
  i: Integer;
  regSubKey: String;
  valueName: String;
  valueData: String;
begin
  Result := False;
  regSubKey := 'Software\Adobe\Adobe Acrobat\DC\Security\cASPKI\cAdobe_P11CredentialProvider\cModules';

  for i := 0 to 99 do
  begin
    valueName := 't' + IntToStr(i);
    if RegQueryStringValue(HKCU, regSubKey, valueName, valueData) then
    begin
      if Pos('etpkcs11.dll', LowerCase(valueData)) > 0 then
      begin
        Result := True;
        Exit; 
      end;
    end;
  end;
end;

procedure MoveLibraryFile();
var
  SourceFile, DestFile: string;
  WinDir: string;
begin
  SourceFile := ExpandConstant('{app}\WrapperPKCS11.dll');
  WinDir := ExpandConstant('{win}');
  DestFile := WinDir + '\System32\WrapperPKCS11.dll';

  if FileCopy(SourceFile, DestFile, False) then
    Log('WrapperPKCS11.dll copiat cu succes în ' + DestFile)
  else
    Log('Eroare la copierea WrapperPKCS11.dll în ' + DestFile);
end;

procedure CreateAndRunPowerShellScript();
var
  PowerShellScript: string;
  PSFilePath, DLLPath: string;
begin
  PSFilePath := ExpandConstant('{tmp}\modify_registry.ps1');
  DLLPath := 'C:\Windows\System32\WrapperPKCS11.dll';

  PowerShellScript :=
    '$registryPath = "HKCU:\Software\Adobe\Adobe Acrobat\DC\Security\cASPKI\cAdobe_P11CredentialProvider\cModules";' +
    '$values = Get-ItemProperty -Path $registryPath | Select-Object -Property * | Where-Object { $_.PSObject.Properties.Name -match "^t\d+$" };' +
    'foreach ($value in $values.PSObject.Properties) {' +
    '    if ($value.Value -like "*\eTPKCS11.dll") {' +
    '        Set-ItemProperty -Path $registryPath -Name $value.Name -Value "' + DLLPath + '";' +
    '    }' +
    '}';

  SaveStringToFile(PSFilePath, PowerShellScript, False);

  Exec('powershell.exe',
    '-NoProfile -ExecutionPolicy Bypass -File "' + PSFilePath + '"',
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    Dummy);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    if IsETPKCS11Referenced then
    begin
      MoveLibraryFile();
      CreateAndRunPowerShellScript();
    end
  end;
end;
