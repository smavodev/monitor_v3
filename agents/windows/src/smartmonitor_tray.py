#!/usr/bin/env python3
"""SmartMonitor v3 - icono de bandeja para pausar el bloqueo con codigo
(tipo Kaspersky).

Corre en la sesion del usuario logueado (autoarranque via
HKLM\...\\Run, registrado por el instalador - ver register-tray en
smartmonitor_installer_helper.py) - a diferencia del agente principal (ahora
un Servicio de Windows en Session 0, sin acceso a escritorio, ver
smartmonitor_agent.py), este SI necesita sesion interactiva para mostrar el
icono/dialogo. Corre con los permisos del usuario que inicio sesion (sin
privilegios de administrador) y a proposito: cualquier usuario del equipo,
tenga o no permisos de administrador, puede intentar pausar - lo que protege
la pausa es el CODIGO (lo entrega un administrador desde el panel), no el
nivel de permisos de Windows.

No habla con el agente ni necesita tocar nada del sistema: solo hace un POST
HTTP a /api/agents/pause-code/validate (misma categoria sin-autenticacion-de-
panel que /api/agents/blocklist) - la decision real de "bloquear o no" sigue
viviendo 100% del lado servidor (resolve_should_block(), que ya respeta
agent.paused_until sin ningun cambio adicional).
"""
import sys; sys.dont_write_bytecode = True
import os, json, threading
import urllib.request, urllib.error

try:
    import win32gui, win32con, win32api
except ImportError:
    win32gui = win32con = win32api = None

import tkinter as tk
from tkinter import messagebox

CONFIG_FILE = r"C:\SmartMonitor\config.json"
ICON_FILE = r"C:\SmartMonitor\icon.ico"


def _load_tray_icon():
    if os.path.exists(ICON_FILE):
        try:
            return win32gui.LoadImage(
                0, ICON_FILE, win32con.IMAGE_ICON, 0, 0,
                win32con.LR_LOADFROMFILE | win32con.LR_DEFAULTSIZE)
        except Exception:
            pass
    return win32gui.LoadIcon(0, win32con.IDI_APPLICATION)

DURATION_OPTIONS = [
    ("5 minutos", 5, False),
    ("15 minutos", 15, False),
    ("30 minutos", 30, False),
    ("1 hora", 60, False),
    ("Hasta reiniciar el equipo", None, True),
]


def _load_server():
    try:
        with open(CONFIG_FILE, encoding="utf-8") as f:
            return json.load(f).get("server") or ""
    except Exception:
        return ""


def _hostname():
    return os.environ.get("COMPUTERNAME") or ""


def _call_pause(code, duration_minutes=None, until_reboot=False):
    server = _load_server()
    if not server:
        raise RuntimeError("No se encontró la configuración del agente (C:\\SmartMonitor\\config.json).")
    body = {"hostname": _hostname(), "code": code}
    if until_reboot:
        body["until_reboot"] = True
    else:
        body["duration_minutes"] = duration_minutes
    req = urllib.request.Request(
        f"{server}/api/agents/pause-code/validate",
        data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=8) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = "Código inválido o expirado."
        try:
            detail = json.loads(e.read()).get("detail", detail)
        except Exception:
            pass
        raise RuntimeError(detail)
    except Exception as e:
        raise RuntimeError(f"No se pudo contactar al servidor: {e}")


def show_pause_dialog():
    root = tk.Tk()
    root.title("SmartMonitor - Pausar bloqueo")
    root.resizable(False, False)
    root.attributes("-topmost", True)

    tk.Label(root, text="Código de pausa (pedíselo al administrador):").grid(
        row=0, column=0, columnspan=2, sticky="w", padx=12, pady=(12, 4))
    code_var = tk.StringVar()
    entry = tk.Entry(root, textvariable=code_var, width=24)
    entry.grid(row=1, column=0, columnspan=2, padx=12, pady=(0, 10))
    entry.focus_set()

    tk.Label(root, text="Duración:").grid(row=2, column=0, sticky="w", padx=12)
    duration_var = tk.IntVar(value=0)
    for i, (label, _minutes, _reboot) in enumerate(DURATION_OPTIONS):
        tk.Radiobutton(root, text=label, variable=duration_var, value=i).grid(
            row=3 + i, column=0, columnspan=2, sticky="w", padx=24)

    status_var = tk.StringVar()
    tk.Label(root, textvariable=status_var, fg="red", wraplength=280, justify="left").grid(
        row=3 + len(DURATION_OPTIONS), column=0, columnspan=2, padx=12, pady=(6, 0))

    def on_submit():
        code = code_var.get().strip()
        if not code:
            status_var.set("Ingresá el código.")
            return
        _label, minutes, until_reboot = DURATION_OPTIONS[duration_var.get()]
        try:
            _call_pause(code, duration_minutes=minutes, until_reboot=until_reboot)
            messagebox.showinfo("SmartMonitor", f"Bloqueo pausado ({_label}).")
            root.destroy()
        except RuntimeError as e:
            status_var.set(str(e))

    btn_row = 4 + len(DURATION_OPTIONS)
    btn_frame = tk.Frame(root)
    btn_frame.grid(row=btn_row, column=0, columnspan=2, pady=12)
    tk.Button(btn_frame, text="Pausar", command=on_submit, width=12).pack(side="left", padx=6)
    tk.Button(btn_frame, text="Cancelar", command=root.destroy, width=12).pack(side="left", padx=6)

    root.mainloop()


# ── Icono de bandeja (win32gui - Shell_NotifyIcon) ───────────────────────────
class TrayIcon:
    ID_PAUSE = 1
    ID_EXIT = 2

    def __init__(self):
        self.hinst = win32api.GetModuleHandle(None)
        wc = win32gui.WNDCLASS()
        wc.hInstance = self.hinst
        wc.lpszClassName = "SmartMonitorTrayWndClass"
        wc.lpfnWndProc = self._wnd_proc
        try:
            win32gui.RegisterClass(wc)
        except win32gui.error:
            pass

        self.hwnd = win32gui.CreateWindow(
            wc.lpszClassName, "SmartMonitorTray", 0, 0, 0, 0, 0, 0, 0, self.hinst, None)
        win32gui.UpdateWindow(self.hwnd)

        self.WM_TRAY_NOTIFY = win32con.WM_USER + 20
        hicon = _load_tray_icon()
        win32gui.Shell_NotifyIcon(win32gui.NIM_ADD, (
            self.hwnd, 0,
            win32gui.NIF_ICON | win32gui.NIF_MESSAGE | win32gui.NIF_TIP,
            self.WM_TRAY_NOTIFY, hicon, "SmartMonitor Agent"))

    def _wnd_proc(self, hwnd, msg, wparam, lparam):
        if msg == self.WM_TRAY_NOTIFY:
            if lparam in (win32con.WM_RBUTTONUP, win32con.WM_LBUTTONUP):
                self._show_menu(hwnd)
            return 0
        if msg == win32con.WM_COMMAND:
            cmd_id = win32api.LOWORD(wparam)
            if cmd_id == self.ID_PAUSE:
                threading.Thread(target=show_pause_dialog, daemon=True).start()
            elif cmd_id == self.ID_EXIT:
                win32gui.DestroyWindow(hwnd)
            return 0
        if msg == win32con.WM_DESTROY:
            win32gui.Shell_NotifyIcon(win32gui.NIM_DELETE, (hwnd, 0))
            win32gui.PostQuitMessage(0)
            return 0
        return win32gui.DefWindowProc(hwnd, msg, wparam, lparam)

    def _show_menu(self, hwnd):
        menu = win32gui.CreatePopupMenu()
        win32gui.AppendMenu(menu, win32con.MF_STRING, self.ID_PAUSE, "Pausar bloqueo...")
        win32gui.AppendMenu(menu, win32con.MF_SEPARATOR, 0, "")
        win32gui.AppendMenu(menu, win32con.MF_STRING, self.ID_EXIT, "Salir")
        pos = win32gui.GetCursorPos()
        win32gui.SetForegroundWindow(hwnd)
        win32gui.TrackPopupMenu(menu, win32con.TPM_LEFTALIGN, pos[0], pos[1], 0, hwnd, None)
        win32gui.PostMessage(hwnd, win32con.WM_NULL, 0, 0)


def main():
    if win32gui is None:
        return
    try:
        TrayIcon()
        win32gui.PumpMessages()
    except Exception:
        import traceback
        try:
            with open(r"C:\SmartMonitor\tray_error.log", "a", encoding="utf-8") as f:
                f.write(traceback.format_exc() + "\n")
        except Exception:
            pass


if __name__ == "__main__":
    main()
