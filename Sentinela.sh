#!/bin/bash

# ==============================================================================
# SENTINELA v1.0 - Auditoría Forense y Threat Hunting
# Autor: Levi Ack
# ==============================================================================

# --- CONFIGURACIÓN VISUAL ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Nombre del reporte con fecha
LOGFILE="sentinela_reporte_$(date +%Y%m%d_%H%M).txt"

# --- FUNCIONES AUXILIARES ---
log() {
    echo -e "$1"
    # Eliminar códigos de color ANSI para guardar en texto plano limpio
    echo -e "$1" | sed 's/\x1b\[[0-9;]*m//g' >> "$LOGFILE"
}

header() {
    echo ""
    log "${CYAN}${BOLD}>>> FASE $1${NC}"
    log "${CYAN}------------------------------------------------------------${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}[ERROR] Se requieren permisos de root (sudo) para auditar el sistema.${NC}"
        exit 1
    fi
}

# --- INICIO ---
check_root
clear
echo -e "${RED}"
cat << "EOF"
  _____ _____ _   _ _____ _____ _   _ _____ _        ___
 /  ___|  ___| \ | |_   _|_   _| \ | |  ___| |      / _ \
 \ `--.| |__ |  \| | | |   | | |  \| | |__ | |     / /_\ \
  `--. \  __|| . ` | | |   | | | . ` |  __|| |     |  _  |
 /\__/ / |___| |\  | | |  _| |_| |\  | |___| |____ | | | |
 \____/\____/\_| \_/ \_/  \___/\_| \_/\____/\_____/\_| |_/
EOF
echo -e "${NC}"
log "${BOLD}INICIANDO ANÁLISIS FORENSE - SENTINELA ${NC}"

# ==============================================================================
# 1. CONTEXTO DEL KERNEL Y USUARIOS
# ==============================================================================
header "1. Integridad del Kernel y Usuarios"

KERNEL=$(uname -r)
log "Kernel: $KERNEL"

# Verificar Tainted Kernel
TAINT=$(cat /proc/sys/kernel/tainted 2>/dev/null)
if [ "$TAINT" -ne 0 ]; then
    log "[${YELLOW}WARNING${NC}] Kernel Tainted (Valor: $TAINT). Módulos no firmados cargados."
else
    log "[${GREEN}OK${NC}] Kernel limpio (0)."
fi

# Buscar usuarios con UID 0 que no sean root
ROOT_CLONES=$(awk -F: '($3 == 0) {print $1}' /etc/passwd | grep -v '^root$')
if [ -n "$ROOT_CLONES" ]; then
    log "[${RED}ALERTA CRÍTICA${NC}] Usuarios adicionales con privilegios de ROOT detectados:"
    log "$ROOT_CLONES"
else
    log "[${GREEN}OK${NC}] Solo 'root' tiene UID 0."
fi

# ==============================================================================
# 2. ANÁLISIS DE RED.
# ==============================================================================
header "2. Conexiones Activas y Interfaces"

# Verificación de Modo Promiscuo (Sniffers)
PROMISC=$(ip link | grep -i "PROMISC")
if [ -n "$PROMISC" ]; then
    log "[${RED}ALERTA${NC}] Interfaz en modo PROMISCUO (Posible sniffing activo):"
    log "$PROMISC"
else
    log "[${GREEN}OK${NC}] Interfaces en modo normal."
fi

log "\n${BOLD}[*] Conexiones Establecidas hacia el exterior (Excluyendo localhost):${NC}"

# Filtrar localhost y mostrar PID/Programa.
CONNS=$(ss -tunap | grep ESTAB | grep -v "127.0.0.1" | grep -v "\[::1\]")

if [ -z "$CONNS" ]; then
    log "No hay conexiones externas activas."
else
    # Formato simple para lectura rápida
    echo "$CONNS" | awk '{print $7, "->", $6, "Proc:", $NF}' | while read line; do
        log "   $line"
    done
fi

# ==============================================================================
# 3. PROCESOS Y MEMORIA.
# ==============================================================================
header "3. Anomalías en Procesos"

# Procesos Fileless (Binario borrado del disco)
DELETED=$(ls -l /proc/*/exe 2>/dev/null | grep '(deleted)' | awk '{print $9, $10, $11}')
if [ -n "$DELETED" ]; then
    log "[${YELLOW}INVESTIGAR${NC}] Procesos ejecutándose con binario eliminado:"
    log "$DELETED"
else
    log "[${GREEN}OK${NC}] No se detectan procesos huérfanos/fileless."
fi

# ==============================================================================
# 4. PERSISTENCIA.
# ==============================================================================

header "4. Mecanismos de Persistencia Reciente"

log "${BOLD}[*] Cambios recientes en Cron (Tareas programadas):${NC}"
find /etc/cron* /var/spool/cron -mtime -1 -ls 2>/dev/null | while read line; do
    log "[!] Modificado hace <24h: $line"
done

log "\n${BOLD}[*] Cambios recientes en Systemd (Servicios):${NC}"
find /etc/systemd/system -mtime -1 -name "*.service" 2>/dev/null | while read line; do
    log "[!] Nuevo servicio detectado: $line"
done

log "\n${BOLD}[*] Archivos RC de usuario modificados:${NC}"
find /home -maxdepth 2 -name ".bashrc" -o -name ".zshrc" -o -name ".profile" -mtime -1 2>/dev/null | while read line; do
    log "[!] Configuración de shell modificada: $line"
done

# ==============================================================================
# 5. INTEGRIDAD DE PAQUETES
# ==============================================================================

header "5. Verificación de Integridad de Binarios"

if command -v dpkg >/dev/null; then
    log "[INFO] Sistema Debian/Kali detectado. Verificando con dpkg."

    # Busca cambios en /bin, /sbin, /usr/bin, /usr/sbin
    INTEGRITY=$(dpkg --verify | grep -E "5......\s+/(bin|sbin|usr/bin|usr/sbin)")
    if [ -n "$INTEGRITY" ]; then
        log "[${RED}ALERTA${NC}] Hash MD5 alterado en binarios del sistema:"
        log "$INTEGRITY"
    else
        log "[${GREEN}OK${NC}] Binarios del sistema verificados correctamente."
    fi

elif command -v rpm >/dev/null; then
    log "[INFO] Sistema RHEL/Fedora detectado. Verificando con rpm."
    # rpm -Va verifica todo. Filtramos por binarios comunes.
    INTEGRITY=$(rpm -Va | grep -E "^..5" | grep -E "/bin/|/sbin/")
    if [ -n "$INTEGRITY" ]; then
        log "[${RED}ALERTA${NC}] Hash MD5 alterado en binarios:"
        log "$INTEGRITY"
    else
        log "[${GREEN}OK${NC}] Binarios verificados correctamente."
    fi
else
    log "[AVISO] Gestor de paquetes no soportado para verificación automática."
fi

# ==============================================================================
# 6. ESCANEO DE MALWARE.
# ==============================================================================
header "6. Threat Hunting con ClamAV"

if command -v clamscan >/dev/null; then
    log "Iniciando motor de escaneo (va a tardar unos minutos...)."

    # Exclusiones inteligentes para no borrar herramientas de pentesting
    EXC=(
        "--exclude-dir=^/sys" "--exclude-dir=^/proc" "--exclude-dir=^/dev" 
        "--exclude-dir=^/var/lib/docker" "--exclude-dir=^/snap"
        "--exclude-dir=exploitdb" "--exclude-dir=metasploit"
        "--exclude-dir=seclists" "--exclude-dir=webshells"
        "--exclude-dir=mimikatz" "--exclude-dir=empire"
    )
    
    # Escaneo recursivo solo infectados (-i) y bell (-r)
    RESULTADO=$(clamscan -r -i "${EXC[@]}" /boot /tmp /etc /bin /sbin /home --max-filesize=100M 2>/dev/null | grep "FOUND")
    
    if [ -n "$RESULTADO" ]; then
        log "[${RED}ALERTA${NC}] Amenazas detectadas:"
        log "$RESULTADO"
    else
        log "[${GREEN}OK${NC}] No se encontraron firmas de malware conocidas en rutas críticas."
    fi
else
    log "[SKIP] ClamAV no está instalado. Se omite esta fase."
    log "Para instalar: sudo apt install clamav (Debian) o sudo dnf install clamav (RHEL)"
fi

log "\n============================================================"
log "${BOLD}ANÁLISIS COMPLETADO.${NC}"
log "Por favor revise el archivo detallado: ${BOLD}$LOGFILE${NC}"
log "============================================================"


