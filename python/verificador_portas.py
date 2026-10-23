#!/usr/bin/env python3
"""
verificador_portas.py
---------------------
Verificador simples de portas TCP abertas (técnica "TCP connect").
Serve para conferir quais serviços estão expostos em máquinas SUAS ou de
laboratório e entender como ferramentas como o Nmap funcionam por dentro.

USO ÉTICO E LEGAL
  Só escaneie sistemas que você possui ou tem autorização por escrito para testar.
  Por segurança, o script recusa alvos fora de redes locais/privadas, a menos que
  você informe --confirmo-autorizacao (assumindo a responsabilidade).

Uso:
  python3 verificador_portas.py                          # 127.0.0.1, portas comuns
  python3 verificador_portas.py 192.168.0.1 --portas 1-1024
  python3 verificador_portas.py 10.0.0.5 --portas 22,80,443,3389 --timeout 0.5

Apenas biblioteca padrão do Python 3.
"""

import argparse
import ipaddress
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

PORTAS_COMUNS = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445,
                 993, 995, 1433, 3306, 3389, 5432, 8080]


def interpretar_portas(texto):
    """Converte '22,80,443' ou '1-1024' (ou mistura) em uma lista de portas."""
    portas = set()
    for parte in texto.split(","):
        parte = parte.strip()
        if "-" in parte:
            inicio, fim = parte.split("-", 1)
            portas.update(range(int(inicio), int(fim) + 1))
        elif parte:
            portas.add(int(parte))
    invalidas = [p for p in portas if not 1 <= p <= 65535]
    if invalidas:
        raise ValueError(f"Portas fora do intervalo 1-65535: {sorted(invalidas)}")
    return sorted(portas)


def alvo_e_local(host):
    """True se o host resolve para um IP loopback ou de rede privada."""
    ip = ipaddress.ip_address(socket.gethostbyname(host))
    return ip.is_loopback or ip.is_private


def testar_porta(host, porta, timeout):
    """Tenta abrir uma conexão TCP. Retorna a porta se estiver aberta."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        if s.connect_ex((host, porta)) == 0:
            return porta
    return None


def nome_servico(porta):
    try:
        return socket.getservbyport(porta, "tcp")
    except OSError:
        return "desconhecido"


def main():
    parser = argparse.ArgumentParser(description="Verificador de portas TCP abertas.")
    parser.add_argument("host", nargs="?", default="127.0.0.1", help="IP ou nome do alvo (padrão: 127.0.0.1)")
    parser.add_argument("--portas", help="Ex.: 22,80,443 ou 1-1024 (padrão: portas comuns)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Segundos de espera por porta (padrão: 1.0)")
    parser.add_argument("--threads", type=int, default=100, help="Conexões em paralelo (padrão: 100)")
    parser.add_argument("--confirmo-autorizacao", action="store_true",
                        help="Confirma que você tem autorização para escanear um alvo fora de rede privada")
    args = parser.parse_args()

    try:
        portas = interpretar_portas(args.portas) if args.portas else PORTAS_COMUNS
        local = alvo_e_local(args.host)
    except (ValueError, socket.gaierror) as erro:
        sys.exit(f"Erro: {erro}")

    if not local and not args.confirmo_autorizacao:
        sys.exit("Alvo fora de rede privada. Escaneie apenas sistemas autorizados; "
                 "se for o caso, use --confirmo-autorizacao.")

    print(f"Verificando {args.host} ({len(portas)} portas)...\n")
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        resultados = pool.map(lambda p: testar_porta(args.host, p, args.timeout), portas)
        abertas = [p for p in resultados if p is not None]

    if abertas:
        print(f"{'PORTA':<8}{'SERVIÇO'}")
        print("-" * 25)
        for porta in abertas:
            print(f"{porta:<8}{nome_servico(porta)}")
    else:
        print("Nenhuma porta aberta encontrada.")
    print(f"\nTotal de portas abertas: {len(abertas)}")


if __name__ == "__main__":
    main()
