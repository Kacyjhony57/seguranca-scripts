#!/usr/bin/env bash
#
# auditoria_linux.sh
# ------------------
# Checklist rápido de segurança para um servidor/estação Linux (SOMENTE LEITURA).
# Não altera nenhuma configuração: apenas consulta e mostra [OK] / [ALERTA] / [INFO].
#
# Verifica:
#   1. Sistema operacional e kernel
#   2. Contas com UID 0 além do root
#   3. Contas com senha vazia (precisa de root para ler /etc/shadow)
#   4. Configuração do SSH (login de root e autenticação por senha)
#   5. Portas TCP/UDP em escuta
#   6. Arquivos graváveis por qualquer usuário dentro de /etc
#   7. Usuários com privilégio sudo
#   8. Atualizações pendentes (Debian/Ubuntu/Kali)
#
# Uso:
#   chmod +x auditoria_linux.sh
#   ./auditoria_linux.sh            # funciona sem root, com algumas verificações limitadas
#   sudo ./auditoria_linux.sh       # verificação completa

set -u

ok()     { printf '  [OK]     %s\n' "$1"; }
alerta() { printf '  [ALERTA] %s\n' "$1"; }
info()   { printf '  [INFO]   %s\n' "$1"; }
titulo() { printf '\n== %s ==\n' "$1"; }

# --- 1. Sistema ---------------------------------------------------------------
titulo "1. Sistema"
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    info "Distribuição: ${PRETTY_NAME:-desconhecida}"
fi
info "Kernel: $(uname -r)"

# --- 2. UID 0 -----------------------------------------------------------------
titulo "2. Contas com UID 0 (equivalentes a root)"
uid0=$(awk -F: '($3 == 0 && $1 != "root") {print $1}' /etc/passwd)
if [ -z "$uid0" ]; then
    ok "Apenas o root possui UID 0"
else
    alerta "Contas extras com UID 0: $(echo "$uid0" | tr '\n' ' ')"
fi

# --- 3. Senhas vazias ---------------------------------------------------------
titulo "3. Contas com senha vazia"
if [ "$(id -u)" -eq 0 ]; then
    vazias=$(awk -F: '($2 == "") {print $1}' /etc/shadow)
    if [ -z "$vazias" ]; then
        ok "Nenhuma conta com senha vazia"
    else
        alerta "Contas sem senha: $(echo "$vazias" | tr '\n' ' ')"
    fi
else
    info "Execute com sudo para verificar /etc/shadow"
fi

# --- 4. SSH -------------------------------------------------------------------
titulo "4. Configuração do SSH"
SSHD_CONFIG="${SSHD_CONFIG:-/etc/ssh/sshd_config}"   # pode ser sobrescrito para testes
# O sshd usa o PRIMEIRO valor encontrado. Em Debian/Ubuntu/Kali o arquivo principal
# faz "Include sshd_config.d/*.conf" no topo, então a pasta .d vem antes do principal.
arquivos_ssh=""
[ -d "${SSHD_CONFIG}.d" ] && arquivos_ssh="$(ls "${SSHD_CONFIG}.d"/*.conf 2>/dev/null | tr '\n' ' ')"
arquivos_ssh="$arquivos_ssh $SSHD_CONFIG"

if [ -r "$SSHD_CONFIG" ]; then
    # Pega o primeiro valor definido para a diretiva (ignora comentários).
    # shellcheck disable=SC2086
    valor() { grep -hiE "^\s*$1\s+" $arquivos_ssh 2>/dev/null | head -n1 | awk '{print tolower($2)}'; }

    root_login=$(valor PermitRootLogin)
    case "${root_login:-padrao}" in
        no|prohibit-password|without-password) ok "PermitRootLogin: ${root_login}" ;;
        *) alerta "PermitRootLogin está '${root_login:-padrão do sistema}' (recomendado: no ou prohibit-password)" ;;
    esac

    senha_login=$(valor PasswordAuthentication)
    if [ "${senha_login:-padrao}" = "no" ]; then
        ok "PasswordAuthentication desativado (apenas chaves)"
    else
        alerta "PasswordAuthentication '${senha_login:-padrão (yes)}' (recomendado: no, usar chaves SSH)"
    fi
else
    info "SSH server não instalado ou arquivo de configuração ilegível"
fi

# --- 5. Portas em escuta ------------------------------------------------------
titulo "5. Portas em escuta"
if command -v ss >/dev/null 2>&1; then
    ss -tulnH 2>/dev/null | awk '{printf "  %-5s %s\n", $1, $5}' | sort -u
else
    info "Comando 'ss' não encontrado"
fi

# --- 6. Arquivos graváveis por todos em /etc ---------------------------------
titulo "6. Arquivos em /etc graváveis por qualquer usuário"
graveis=$(find /etc -xdev -type f -perm -0002 2>/dev/null)
if [ -z "$graveis" ]; then
    ok "Nenhum arquivo de /etc com permissão de escrita para 'outros'"
else
    alerta "Arquivos com escrita para qualquer usuário:"
    echo "$graveis" | sed 's/^/             /'
fi

# --- 7. Sudo ------------------------------------------------------------------
titulo "7. Usuários com privilégio sudo"
for grupo in sudo wheel; do
    membros=$(getent group "$grupo" 2>/dev/null | cut -d: -f4)
    [ -n "$membros" ] && info "Grupo '$grupo': $membros"
done

# --- 8. Atualizações ----------------------------------------------------------
titulo "8. Atualizações pendentes"
if command -v apt >/dev/null 2>&1; then
    pendentes=$(apt list --upgradable 2>/dev/null | grep -vc '^Listing')
    if [ "$pendentes" -eq 0 ]; then
        ok "Sistema atualizado (com base na última sincronização do apt)"
    else
        alerta "$pendentes pacote(s) com atualização disponível (rode: sudo apt update && sudo apt upgrade)"
    fi
else
    info "Gerenciador apt não encontrado; verifique atualizações manualmente"
fi

printf '\nAuditoria concluída.\n'
