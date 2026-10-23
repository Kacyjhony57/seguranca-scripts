#!/usr/bin/env python3
"""
analisador_logs_ssh.py
----------------------
Analisa um arquivo de log de autenticação do Linux (ex.: /var/log/auth.log)
e identifica possíveis tentativas de força bruta contra o serviço SSH.

O que o script faz:
  1. Conta tentativas de login que falharam, agrupadas por IP de origem.
  2. Lista quais usuários foram testados em cada IP.
  3. Marca como SUSPEITO o IP que atinge o limite de falhas.
  4. Aponta IPs que tiveram um login BEM-SUCEDIDO depois de atingir o limite
     de falhas (cenário clássico de credencial adivinhada, o mais perigoso).

Uso:
  python3 analisador_logs_ssh.py /var/log/auth.log
  python3 analisador_logs_ssh.py exemplos/auth.log.exemplo --limite 3
  python3 analisador_logs_ssh.py exemplos/auth.log.exemplo --csv resultado.csv

Apenas biblioteca padrão do Python 3 (sem dependências externas).
"""

import argparse
import csv
import re
import sys
from collections import defaultdict

# Exemplos de linhas reconhecidas:
#   Failed password for root from 203.0.113.5 port 52344 ssh2
#   Failed password for invalid user admin from 203.0.113.5 port 52344 ssh2
#   Accepted password for deploy from 203.0.113.5 port 52400 ssh2
RE_FALHA = re.compile(
    r"Failed password for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)
RE_SUCESSO = re.compile(
    r"Accepted (?:password|publickey) for (?P<usuario>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def analisar(caminho, limite):
    """Lê o arquivo linha a linha e devolve as estatísticas por IP.

    Um login bem-sucedido só é sinalizado se o mesmo IP já tinha acumulado
    pelo menos `limite` falhas ANTES do sucesso (evita alarme falso para quem
    apenas errou a senha uma vez).
    """
    falhas = defaultdict(int)             # ip -> quantidade de falhas
    usuarios = defaultdict(set)           # ip -> usuários testados
    sucesso_apos_falha = defaultdict(set)  # ip -> usuários que logaram após falhar

    with open(caminho, "r", encoding="utf-8", errors="replace") as arquivo:
        for linha in arquivo:
            m = RE_FALHA.search(linha)
            if m:
                ip = m.group("ip")
                falhas[ip] += 1
                usuarios[ip].add(m.group("usuario"))
                continue

            m = RE_SUCESSO.search(linha)
            if m and falhas[m.group("ip")] >= limite:
                # O mesmo IP já tinha falhado várias vezes antes de conseguir entrar.
                sucesso_apos_falha[m.group("ip")].add(m.group("usuario"))

    return falhas, usuarios, sucesso_apos_falha


def main():
    parser = argparse.ArgumentParser(
        description="Detecta possível força bruta em SSH a partir de um log de autenticação."
    )
    parser.add_argument("arquivo", help="Caminho do log (ex.: /var/log/auth.log)")
    parser.add_argument(
        "--limite",
        type=int,
        default=5,
        help="Nº de falhas a partir do qual o IP é marcado como suspeito (padrão: 5)",
    )
    parser.add_argument("--csv", help="Salva o resultado também em um arquivo CSV")
    args = parser.parse_args()

    try:
        falhas, usuarios, sucesso = analisar(args.arquivo, args.limite)
    except FileNotFoundError:
        sys.exit(f"Erro: arquivo '{args.arquivo}' não encontrado.")
    except PermissionError:
        sys.exit(f"Erro: sem permissão para ler '{args.arquivo}' (tente com sudo).")

    if not falhas:
        print("Nenhuma tentativa de login falha encontrada.")
        return

    ordenado = sorted(falhas.items(), key=lambda item: item[1], reverse=True)

    print(f"{'IP':<18}{'FALHAS':>7}  {'STATUS':<10} USUÁRIOS TESTADOS")
    print("-" * 70)
    linhas_csv = []
    for ip, total in ordenado:
        status = "SUSPEITO" if total >= args.limite else "normal"
        lista = ", ".join(sorted(usuarios[ip]))
        print(f"{ip:<18}{total:>7}  {status:<10} {lista}")
        linhas_csv.append([ip, total, status, lista])

    if sucesso:
        print("\n[!] ATENÇÃO: login bem-sucedido APÓS falhas (possível credencial comprometida):")
        for ip, lista in sucesso.items():
            print(f"    {ip} -> usuário(s): {', '.join(sorted(lista))}")

    if args.csv:
        with open(args.csv, "w", newline="", encoding="utf-8") as saida:
            escritor = csv.writer(saida)
            escritor.writerow(["ip", "falhas", "status", "usuarios_testados"])
            escritor.writerows(linhas_csv)
        print(f"\nResultado salvo em {args.csv}")


if __name__ == "__main__":
    main()
