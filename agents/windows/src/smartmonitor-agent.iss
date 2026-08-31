; SmartMonitor v3 - Instalador grafico (Inno Setup) del agente Windows.
;
; Reemplaza a install-agent-windows.bat/uninstall-agent-windows.bat con un
; asistente "Siguiente > Siguiente > Finalizar" - esos .bat viejos se
; mantienen aparte, en agents/windows/legacy/antiguos/, junto al agente viejo en
; PowerShell (smartmonitor-push.ps1), como respaldo por-equipo durante la
; transicion.
;
; TODO lo que corre en este instalador (agente, y los pasos de instalacion/
; desinstalacion) esta en Python, compilado con PyInstaller - CERO
; PowerShell en todo el flujo (decision explicita del usuario). Este .iss en
; si esta en Pascal Script (el lenguaje propio de Inno Setup para el
; asistente grafico) - eso no cambia, solo se elimino cualquier invocacion a
; powershell.exe desde aca:
;   - smartmonitor-agent.exe: el agente (metricas, bloqueo via cloudflared).
;   - smartmonitor-installer-helper.exe: TODO lo que antes se armaba al vuelo
;     como scripts .ps1 temporales (RunPS) o vivia en uninstall-cleanup.ps1/
;     validate-uninstall-code.ps1 - un solo binario con subcomandos
;     (cleanup-previous, write-config, install-tailscale, install-ca-cert,
;     register-service, register-tray, validate-uninstall-code,
;     uninstall-cleanup), invocado
;     aca solo via Exec() - igual que ya se invocaba netsh.exe/sc.exe/
;     schtasks.exe nativos, ninguno de esos es PowerShell tampoco.
;
; Para compilar: ver agents/windows/src/BUILD.md (primero smartmonitor_agent.py
; y smartmonitor_installer_helper.py con PyInstaller, despues este .iss).

#define MyAppName "SmartMonitor Agent"
#define MyAppVersion "2026.08.07-2"
#define MyDefaultServerIp "monitoreo.smarthrlatam.com"

[Setup]
AppId={{B4205850-0F75-404B-8535-A8E06EDB13AE}}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName=C:\SmartMonitor
DisableDirPage=yes
DisableProgramGroupPage=yes
DisableReadyPage=yes
DisableWelcomePage=no
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
OutputBaseFilename=SmartMonitor-Agent-Setup
OutputDir=dist
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName={#MyAppName}
SetupIconFile=icon.ico

[Files]
Source: "dist\smartmonitor-agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\smartmonitor-installer-helper\*"; DestDir: "{app}\smartmonitor-installer-helper"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "dist\smartmonitor-tray\*"; DestDir: "{app}\smartmonitor-tray"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "icon.ico"; DestDir: "{app}"; Flags: ignoreversion

[Code]
var
  ServerPage: TInputQueryWizardPage;
  ProgressPage: TOutputProgressWizardPage;

procedure InitializeWizard;
begin
  ServerPage := CreateInputQueryPage(wpSelectDir,
    'Configuracion del servidor', 'Direccion del servidor SmartMonitor',
    'Ingresa la IP o dominio del servidor SmartMonitor. Si no la conoces, deja el valor por defecto.');
  ServerPage.Add('IP/dominio del servidor:', False);
  ServerPage.Values[0] := '{#MyDefaultServerIp}';

  ProgressPage := CreateOutputProgressPage('Instalando SmartMonitor Agent', 'Espera mientras se configura el equipo...');
end;

function GetServerIp(Param: String): String;
begin
  Result := ServerPage.Values[0];
end;

function HelperPath(): String;
begin
  Result := ExpandConstant('{app}\smartmonitor-installer-helper\smartmonitor-installer-helper.exe');
end;

function RunHelper(Args: String): Integer;
var
  ResultCode: Integer;
begin
  if not Exec(HelperPath(), Args, '', SW_HIDE, ewWaitUntilTerminated, ResultCode) then
    ResultCode := -1;
  Result := ResultCode;
end;

procedure StepMsg(Msg: String);
begin
  ProgressPage.SetText(Msg, '');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if FileExists(HelperPath()) then
    Exec(HelperPath(), 'cleanup-previous', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

function AskForUninstallCode(): String;
var
  Form: TForm;
  Lbl: TNewStaticText;
  Edit: TNewEdit;
  BtnOk, BtnCancel: TNewButton;
begin
  Result := '';
  Form := TForm.Create(nil);
  try
    Form.ClientWidth := ScaleX(380);
    Form.ClientHeight := ScaleY(140);
    Form.Caption := 'Codigo de desinstalacion requerido';
    Form.Position := poScreenCenter;
    Form.BorderStyle := bsDialog;

    Lbl := TNewStaticText.Create(Form);
    Lbl.Parent := Form;
    Lbl.Left := ScaleX(16);
    Lbl.Top := ScaleY(16);
    Lbl.Width := Form.ClientWidth - ScaleX(32);
    Lbl.AutoSize := False;
    Lbl.Height := ScaleY(32);
    Lbl.WordWrap := True;
    Lbl.Caption := 'Ingresa el codigo de desinstalacion de un solo uso (pidelo al administrador de SmartMonitor):';

    Edit := TNewEdit.Create(Form);
    Edit.Parent := Form;
    Edit.Left := ScaleX(16);
    Edit.Top := Lbl.Top + Lbl.Height + ScaleY(8);
    Edit.Width := Form.ClientWidth - ScaleX(32);

    BtnOk := TNewButton.Create(Form);
    BtnOk.Parent := Form;
    BtnOk.Caption := 'Aceptar';
    BtnOk.ModalResult := mrOk;
    BtnOk.Default := True;
    BtnOk.Width := ScaleX(90);
    BtnOk.Height := ScaleY(23);
    BtnOk.Top := Edit.Top + Edit.Height + ScaleY(16);
    BtnOk.Left := Form.ClientWidth - ScaleX(16) - (BtnOk.Width * 2) - ScaleX(8);

    BtnCancel := TNewButton.Create(Form);
    BtnCancel.Parent := Form;
    BtnCancel.Caption := 'Cancelar';
    BtnCancel.ModalResult := mrCancel;
    BtnCancel.Cancel := True;
    BtnCancel.Width := ScaleX(90);
    BtnCancel.Height := ScaleY(23);
    BtnCancel.Top := BtnOk.Top;
    BtnCancel.Left := BtnOk.Left + BtnOk.Width + ScaleX(8);

    if Form.ShowModal() = mrOk then
      Result := Edit.Text;
  finally
    Form.Free;
  end;
end;

function InitializeUninstall(): Boolean;
var
  Code: String;
  ExitCode: Integer;
begin
  Result := False;
  if not FileExists(HelperPath()) then begin
    MsgBox('No se encuentra smartmonitor-installer-helper.exe - no se puede verificar el codigo. Desinstalacion cancelada.', mbError, MB_OK);
    Exit;
  end;

  Code := AskForUninstallCode();
  if Code = '' then
    Exit;

  ExitCode := RunHelper('validate-uninstall-code --code "' + Code + '"');
  if ExitCode = 0 then
    Result := True
  else
    MsgBox('Codigo invalido, expirado, o no se pudo contactar al servidor. La desinstalacion se cancelo.', mbError, MB_OK);
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  AppDir, ServerIp: String;
begin
  if CurStep <> ssPostInstall then
    Exit;

  AppDir := ExpandConstant('{app}');
  ServerIp := GetServerIp('');

  ProgressPage.Show;
  try
   try
    StepMsg('Limpiando una instalacion previa (si habia)...');
    RunHelper('cleanup-previous');

    StepMsg('Configurando direccion del servidor...');
    RunHelper('write-config --server "http://' + ServerIp + ':8000"');

    StepMsg('Instalando Tailscale (tunel WireGuard)...');
    RunHelper('install-tailscale');

    StepMsg('Instalando certificado de la CA...');
    RunHelper('install-ca-cert --server "' + ServerIp + '"');

    StepMsg('Registrando el servicio de Windows...');
    RunHelper('register-service --app-dir "' + AppDir + '"');

    StepMsg('Registrando el ícono de pausa...');
    RunHelper('register-tray --app-dir "' + AppDir + '"');

    StepMsg('Finalizando instalación...');
    RunHelper('hide-folder --app-dir "' + AppDir + '"');
   except
    MsgBox('Ocurrio un error durante la configuracion del agente: ' + GetExceptionMessage + #13#10#13#10 +
           'La instalacion de archivos ya se completo, pero revisa este paso a mano.', mbError, MB_OK);
   end;
  finally
    ProgressPage.Hide;
  end;
end;

[UninstallRun]
Filename: "{app}\smartmonitor-installer-helper\smartmonitor-installer-helper.exe"; Parameters: "uninstall-cleanup"; Flags: runhidden waituntilterminated
