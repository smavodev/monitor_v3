; SmartMonitor v3 - Instalador grafico (Inno Setup) del agente Windows.
;
; Reemplaza a install-agent-windows.bat/uninstall-agent-windows.bat con un
; asistente "Siguiente > Siguiente > Finalizar" - esos .bat viejos se
; mantienen aparte, en agents/windows/antiguos/, junto al agente viejo en
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
; Para compilar: ver agents/windows/BUILD.md (primero smartmonitor_agent.py
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
; Sin firma digital todavia - SmartScreen va a avisar "Editor desconocido" la
; primera vez que se ejecute, en cualquier equipo, hasta que se compre y
; configure un certificado de code-signing (ver BUILD.md).

[Files]
; smartmonitor-agent.exe se compila con PyInstaller --onedir (NO --onefile) -
; ver BUILD.md. Un Servicio de Windows tiene que ser el MISMO proceso que el
; Administrador de Servicios arranca; el bootloader --onefile arranca un
; proceso "lanzador" que a su vez lanza un hijo real, y el Administrador de
; Servicios rechaza eso ("El Administrador de control de servicios inicio el
; proceso X pero el proceso Y se conecto en su lugar") - confirmado con un
; build real, el servicio nunca terminaba de arrancar bien con --onefile.
; --onedir no tiene ese problema (el .exe final ES el proceso, sin relanzar
; nada) a cambio de quedar como carpeta (con una subcarpeta _internal) en vez
; de un solo archivo - por eso aca se empaqueta la carpeta entera
; (recursesubdirs), no un unico Source. cloudflared.exe sigue embebido
; (PyInstaller --add-data lo deja en _internal\cloudflared.exe).
Source: "smartmonitor-agent\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
; smartmonitor-installer-helper.exe y smartmonitor-tray.exe TAMBIEN pasaron de
; --onefile a --onedir (ver BUILD.md, "Notas de diseño"): Kaspersky detecto y
; mato smartmonitor-installer-helper.exe como "Malicious object" durante una
; instalacion real - el bootloader --onefile se auto-extrae a una carpeta
; temporal en cada arranque, patron que coincide con como se comportan
; muchos droppers de malware, y dispara la heuristica de varios antivirus
; (no solo Kaspersky) independientemente de que el .exe este firmado o no.
; Cada uno queda en su propia subcarpeta (no se aplanan junto al agente en
; {app} directamente) para que sus respectivas carpetas _internal no
; choquen entre si.
Source: "smartmonitor-installer-helper\*"; DestDir: "{app}\smartmonitor-installer-helper"; Flags: ignoreversion recursesubdirs createallsubdirs
; Icono de bandeja para pausar el bloqueo con codigo (tipo Kaspersky) - corre
; en la sesion del usuario logueado, no en el Servicio (Session 0, sin
; escritorio). Ver register-tray en smartmonitor_installer_helper.py.
Source: "smartmonitor-tray\*"; DestDir: "{app}\smartmonitor-tray"; Flags: ignoreversion recursesubdirs createallsubdirs
; Icono de la app (ventana del instalador, notificaciones, bandeja) - ver
; smartmonitor_tray.py, que lo carga de aca en vez del icono generico de Windows.
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

// Unico punto por el que este instalador ejecuta un proceso externo para
// hacer trabajo real (fuera de herramientas nativas de Windows como
// icacls.exe) - siempre smartmonitor-installer-helper.exe con un
// subcomando, nunca powershell.exe.
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

// Corre ANTES de que el paso [Files] copie nada. Necesario para reinstalar
// sobre una instalacion existente que sigue corriendo: el Servicio (o, en
// versiones viejas, la Tarea Programada) mantiene bloqueado
// smartmonitor-agent.exe, y RestartManager no puede cerrarlo solo (corre
// sin ventana, como SYSTEM) - confirmado en pruebas reales, el instalador
// abortaba con "Setup was unable to automatically close all applications".
// El resto de la limpieza (cleanup-previous completo) se vuelve a correr
// despues igual, en CurStepChanged(ssPostInstall), ya con el helper
// actualizado - esto solo destraba el archivo para que el paso [Files]
// pueda sobrescribirlo.
function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  if FileExists(HelperPath()) then
    Exec(HelperPath(), 'cleanup-previous', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
end;

// InitializeUninstall corre ANTES de que exista el asistente grafico del
// desinstalador (no hay wizard todavia en esa etapa) - las funciones de
// "pagina" (CreateInputQueryPage, etc.) no sirven aca. Se arma un formulario
// propio, minimo, con TForm (no TSetupForm: ese depende de un recurso que el
// compilador solo embebe en Setup.exe, no en unins000.exe - usarlo en el
// desinstalador tira "Resource TSetupForm not found" en tiempo de ejecucion,
// confirmado corriendo el desinstalador real). TNewEdit/TNewButton/
// TNewStaticText si estan disponibles en cualquier etapa, esos no cambian.
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

// --- Desinstalacion: exige el codigo de un solo uso generado desde el panel
// (Feature 1 del plan) ANTES de tocar cualquier cosa. Sin bypass si el
// servidor no responde - ver el comentario en smartmonitor_installer_helper.py
// (cmd_validate_uninstall_code).
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
    Exit; // el usuario cancelo o no escribio nada

  ExitCode := RunHelper('validate-uninstall-code --code "' + Code + '"');
  if ExitCode = 0 then
    Result := True
  else
    MsgBox('Codigo invalido, expirado, o no se pudo contactar al servidor. La desinstalacion se cancelo.', mbError, MB_OK);
end;

// --- Instalacion: todos los pasos, cada uno delegado a un subcomando de
// smartmonitor-installer-helper.exe (ver ese archivo para el detalle real).
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

    // ── Servicio nativo de Windows (Feature 3, reemplaza la Tarea
    // Programada de una version anterior): sin ningun binario de terceros
    // (NSSM se probo primero, pero Kaspersky - y probablemente otros
    // antivirus - bloqueo el patron "descargar y ejecutar un .exe de
    // terceros" que eso implica). smartmonitor-agent.exe ES el servicio
    // (win32serviceutil.ServiceFramework); "sc.exe create" (invocado desde
    // Python dentro de smartmonitor-installer-helper.exe, nunca PowerShell)
    // solo lo registra ante el Administrador de Servicios, igual que
    // cualquier otro servicio nativo - mucho menos probable que un
    // antivirus corporativo lo marque que envolverlo con un binario de
    // terceros. "sc.exe failure" reinicia el proceso a los pocos segundos
    // si muere o si lo terminan a mano (antes, con Tarea Programada, el
    // reintento mas rapido era ~1 minuto). Un Servicio con dueno LocalSystem
    // ya rechaza por defecto que un usuario sin permisos de administrador
    // lo detenga/deshabilite/borre (Windows lo aplica via el Security
    // Descriptor propio del servicio, sin necesitar un icacls aparte) - un
    // administrador local de verdad SIEMPRE puede, igual que con la Tarea
    // Programada; no existe forma de evitar eso sin un driver de kernel,
    // que no se construye aca. ───────
    StepMsg('Registrando el servicio de Windows...');
    RunHelper('register-service --app-dir "' + AppDir + '"');

    // Icono de bandeja para pausar el bloqueo con codigo (tipo Kaspersky) -
    // ver register-tray/smartmonitor_tray.py. Autoarranca para CUALQUIER
    // usuario que inicie sesion (HKLM Run, no HKCU); ademas se lanza de
    // inmediato en la sesion interactiva activa (si hay alguien logueado en
    // consola en este momento) para no obligar a cerrar sesion/reiniciar
    // solo para ver el icono - bug real reportado: quedaba sin aparecer
    // hasta el proximo login.
    StepMsg('Registrando el ícono de pausa...');
    RunHelper('register-tray --app-dir "' + AppDir + '"');

    // Oculta C:\SmartMonitor del Explorador (no es un rootkit, sigue
    // visible con "Elementos ocultos" activado) - bug real reportado:
    // quedaba visible sin mas, a diferencia de otras herramientas de
    // monitoreo/control parental.
    StepMsg('Finalizando instalación...');
    RunHelper('hide-folder --app-dir "' + AppDir + '"');
   except
    // Sin este bloque, cualquier excepcion durante los pasos de arriba
    // tumbaba el instalador entero sin ningun mensaje (visto en pruebas:
    // "Installation process succeeded" seguido de un crash silencioso,
    // codigo de salida 0x40000015 / STATUS_FATAL_APP_EXIT). Ahora se
    // atrapa y se muestra que fallo en vez de morir en silencio.
    MsgBox('Ocurrio un error durante la configuracion del agente: ' + GetExceptionMessage + #13#10#13#10 +
           'La instalacion de archivos ya se completo, pero revisa este paso a mano.', mbError, MB_OK);
   end;
  finally
    ProgressPage.Hide;
  end;
end;

[UninstallRun]
Filename: "{app}\smartmonitor-installer-helper\smartmonitor-installer-helper.exe"; Parameters: "uninstall-cleanup"; Flags: runhidden waituntilterminated
