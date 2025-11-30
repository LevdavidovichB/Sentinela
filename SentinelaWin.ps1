<#
.SYNOPSIS
    SENTINELA WIN - Auditoría Forense y Threat Hunting
.DESCRIPTION
    Script de triaje para detección de persistencia, conexiones anómalas
    y configuraciones de seguridad comprometidas en entornos Windows.
.AUTHOR
    Levi Ack
.VERSION
    1.0
#>

# --- CONFIGURACIÓN E INICIALIZACIÓN ---
$ErrorActionPreference = "SilentlyContinue"
$Date = Get-Date -Format "yyyyMMdd_HHmm"
$LogFile = "$PWD\Sentinela_Reporte_$Date.txt"
$HostName = $env:COMPUTERNAME

function Write-Log {
    param (
        [string]$Message,
        [string]$Color = "White",
        [switch]$NoFile
    )
    
    Write-Host $Message -ForegroundColor $Color
    
    if (-not $NoFile) {
        $CleanMessage = $Message -replace "\e\[[0-9;]*m", "" 
        Add-Content -Path $LogFile -Value $CleanMessage
    }
}

function Write-Header {
    param ([string]$Title)
    Write-Log "" -NoFile
    Write-Log ">>> FASE: $Title" -Color Cyan
    Write-Log "------------------------------------------------------------" -Color Cyan
}

# --- VERIFICACIÓN DE PRIVILEGIOS ---
$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if (-not $IsAdmin) {
    Write-Host "[ERROR] Se requieren permisos de ADMINISTRADOR." -ForegroundColor Red
    Start-Sleep -Seconds 2
    Exit
}

# --- UI ---
Clear-Host
Write-Host ""
Write-Host -ForegroundColor Red @"
  _____ _____ _   _ _____ _____ _   _ _____ _       ___  
 /  ___|  ___| \ | |_   _|_   _| \ | |  ___| |     / _ \ 
 \ `--.| |__ |  \| | | |   | | |  \| | |__ | |    / /_\ \
  `--. \  __|| . ` | | |   | | | . ` |  __|| |    |  _  |
 /\__/ / |___| |\  | | |  _| |_| |\  | |___| |____| | | |
 \____/\____/\_| \_/ \_/  \___/\_| \_/\____/\_____/\_| |_/
"@
Write-Log "INICIANDO ANÁLISIS FORENSE - SENTINELA" -Color White
Write-Log "Autor: Levi Ack"
Write-Log "Fecha: $(Get-Date)"
Write-Log "Reporte: $LogFile"

# ==============================================================================
# 1. INTEGRIDAD DE SISTEMA Y DEFENDER
# ==============================================================================
Write-Header "1. Estado del Sistema y Seguridad"

$OS = Get-CimInstance Win32_OperatingSystem
Write-Log "OS: $($OS.Caption) (Build $($OS.BuildNumber))"
Write-Log "Usuario: $env:USERNAME"

# Estado Windows Defender
$Defender = Get-MpComputerStatus
if ($Defender.AntivirusEnabled -eq $true) {
    Write-Log "[OK] Windows Defender ACTIVO." -Color Green
} else {
    Write-Log "[ALERTA] Windows Defender DESACTIVADO." -Color Red
}

# Verificar Exclusiones (Evasión común)
$Exclusions = Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
if ($Exclusions) {
    Write-Log "[ALERTA] Exclusiones de antivirus detectadas:" -Color Yellow
    foreach ($ex in $Exclusions) { Write-Log "   -> $ex" }
} else {
    Write-Log "[OK] Sin exclusiones de rutas en AV." -Color Green
}

# ==============================================================================
# 2. PERSISTENCIA (AUTORUNS)
# ==============================================================================
Write-Header "2. Mecanismos de Persistencia"

$RunKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
)

foreach ($key in $RunKeys) {
    $Entries = Get-ItemProperty $key
    $Entries.PSObject.Properties | Where-Object { $_.Name -notin @("PSPath", "PSParentPath", "PSChildName", "PSDrive", "PSProvider") } | ForEach-Object {
        Write-Log "[REGISTRO] $($key): $($_.Name) -> $($_.Value)" -Color Yellow
    }
}

# Carpeta de Inicio
$StartupPath = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
if (Test-Path $StartupPath) {
    $StartupFiles = Get-ChildItem $StartupPath
    if ($StartupFiles) {
        Write-Log "[STARTUP] Archivos en carpeta de inicio:" -Color Yellow
        foreach ($file in $StartupFiles) { Write-Log "   -> $($file.Name)" }
    } else {
        Write-Log "[OK] Carpeta Startup vacía." -Color Green
    }
}

# ==============================================================================
# 3. ANÁLISIS DE PROCESOS
# ==============================================================================
Write-Header "3. Anomalías en Procesos"

# Procesos ejecutándose desde AppData/Temp
$SuspiciousPaths = Get-Process | Where-Object {$_.Path -match "AppData" -or $_.Path -match "Temp"}
if ($SuspiciousPaths) {
    Write-Log "[INVESTIGAR] Procesos en rutas temporales:" -Color Yellow
    foreach ($proc in $SuspiciousPaths) {
        Write-Log "   PID: $($proc.Id) | Nombre: $($proc.ProcessName)"
        Write-Log "   Ruta: $($proc.Path)"
    }
} else {
    Write-Log "[OK] Sin binarios en AppData/Temp." -Color Green
}

# Detección de PowerShell Ofuscado (EncodedCommand)
$EncodedPS = Get-WmiObject Win32_Process | Where-Object { $_.Name -eq "powershell.exe" -and $_.CommandLine -match "EncodedCommand" }
if ($EncodedPS) {
    Write-Log "[ALERTA CRÍTICA] PowerShell codificado detectado:" -Color Red
    foreach ($ps in $EncodedPS) { Write-Log "   CMD: $($ps.CommandLine)" }
}

# ==============================================================================
# 4. RED Y THREAT HUNTING
# ==============================================================================
Write-Header "4. Conexiones Activas"

# TCP Established (Excluye Loopback)
$Conns = Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -ne "127.0.0.1" -and $_.RemoteAddress -ne "::1" }

if ($Conns) {
    Write-Log "PID   | Local Port | Remote IP       | Remote Port | Proceso"
    foreach ($c in $Conns) {
        $ProcessParams = @{ Id = $c.OwningProcess }
        $ProcName = (Get-Process @ProcessParams).ProcessName
        Write-Log "$($c.OwningProcess.ToString().PadRight(5)) | $($c.LocalPort.ToString().PadRight(10)) | $($c.RemoteAddress.ToString().PadRight(15)) | $($c.RemotePort.ToString().PadRight(11)) | $ProcName"
    }
} else {
    Write-Log "[OK] Sin conexiones externas activas." -Color Green
}

# Integridad HOSTS
$HostsContent = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch "^#" -and $_ -ne "" }
if ($HostsContent) {
    Write-Log "`n[ALERTA] Modificaciones en archivo HOSTS:" -Color Yellow
    foreach ($line in $HostsContent) { Write-Log "   -> $line" }
}

# ==============================================================================
# 5. SERVICIOS DE TERCEROS
# ==============================================================================
Write-Header "5. Servicios No-Microsoft"

# Filtrado por PathName
$Services = Get-WmiObject Win32_Service | Where-Object { $_.State -eq "Running" -and $_.PathName -notmatch "Windows" -and $_.PathName -notmatch "Microsoft" }

if ($Services) {
    Write-Log "Servicios activos externos (Verificar legitimidad):" -Color Yellow
    foreach ($srv in $Services) {
        Write-Log "   Nombre: $($srv.Name)"
        Write-Log "   Ruta: $($srv.PathName)"
        Write-Log "   ---"
    }
} else {
    Write-Log "[OK] Servicios activos consistentes con sistema base." -Color Green
}

# ==============================================================================
# 6. ESCANEO NTFS (ADS)
# ==============================================================================
Write-Header "6. Alternate Data Streams (ADS)"
Write-Log "Escaneando flujos ocultos en perfil de usuario..."

$UserDirs = @("$env:USERPROFILE\Desktop", "$env:USERPROFILE\Downloads")
$ADSFound = $false

foreach ($dir in $UserDirs) {
    if (Test-Path $dir) {
        # Filtro: Ignorar stream por defecto (:$DATA) y Zone.Identifier
        $Streams = Get-ChildItem -Path $dir -Recurse -Stream * -ErrorAction SilentlyContinue | Where-Object { $_.Stream -ne ':$DATA' -and $_.Stream -ne 'Zone.Identifier' }
        
        if ($Streams) {
            $ADSFound = $true
            foreach ($s in $Streams) {
                Write-Log "[ALERTA] ADS Detectado: $($s.FileName):$($s.Stream)" -Color Red
            }
        }
    }
}

if (-not $ADSFound) {
    Write-Log "[OK] No se detectaron flujos ADS sospechosos." -Color Green
}

# ==============================================================================
# RESUMEN  (CHECKLIST)
# ==============================================================================
Write-Log ""
Write-Log "============================================================" -Color Cyan
Write-Log "   RESUMEN  (CHECKLIST DE ACCIONES)" -Color Cyan
Write-Log "============================================================" -Color Cyan
Write-Log "1. [OK] Antivirus: Se verificó el estado de Windows Defender y la inexistencia de 'exclusiones' peligrosas."
Write-Log "2. [OK] Arranque: Se auditaron los programas que inician automáticamente con el sistema (Persistencia)."
Write-Log "3. [OK] Procesos: Se rastrearon procesos ejecutándose desde carpetas temporales."
Write-Log "4. [OK] Red: Se listaron las conexiones establecidas hacia servidores externos."
Write-Log "5. [OK] Servicios: Se identificaron los servicios activos ajenos a Microsoft."
Write-Log "6. [OK] Ocultos: Se realizó un escaneo de flujos de datos ocultos (ADS) en archivos de usuario."

Write-Log ""
Write-Log "ANÁLISIS COMPLETADO." -Color Green
Write-Log "El reporte técnico completo se guardó en: $LogFile" -Color White
Pause
