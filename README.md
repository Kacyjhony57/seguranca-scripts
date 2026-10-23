# Scripts de Segurança da Informação

Coleção de scripts que escrevi durante meus estudos de Segurança da Informação (formação na GoHacking, prática no TryHackMe e rotina de estágio em TI com Active Directory e redes). O foco é **auditoria e detecção** (visão Blue Team), sempre em modo somente leitura.

## Conteúdo

| Script | Linguagem | O que faz |
|---|---|---|
| [`python/analisador_logs_ssh.py`](python/analisador_logs_ssh.py) | Python | Analisa `auth.log` e aponta IPs com tentativas de força bruta em SSH e logins bem-sucedidos após várias falhas |
| [`python/verificador_portas.py`](python/verificador_portas.py) | Python | Verificador de portas TCP abertas (TCP connect) com recusa automática de alvos fora de rede privada |
| [`powershell/Auditoria-AD.ps1`](powershell/Auditoria-AD.ps1) | PowerShell | Relatório de AD: contas inativas, senhas que nunca expiram e membros de grupos privilegiados |
| [`bash/auditoria_linux.sh`](bash/auditoria_linux.sh) | Bash | Checklist de hardening básico em Linux: UID 0, senhas vazias, SSH, portas, permissões e atualizações |
| [`ctf-writeups/`](ctf-writeups/) | Markdown | Template e writeups das salas de CTF que resolvo no TryHackMe |

## Como usar

```bash
# Analisador de logs SSH (há um log de exemplo para testar)
python3 python/analisador_logs_ssh.py python/exemplos/auth.log.exemplo --limite 3

# Verificador de portas na própria máquina
python3 python/verificador_portas.py 127.0.0.1 --portas 1-1024

# Auditoria de hardening em Linux
sudo bash bash/auditoria_linux.sh
```

```powershell
# Auditoria de AD (requer módulo ActiveDirectory / RSAT)
.\powershell\Auditoria-AD.ps1 -DiasInativo 90
```

Os scripts em Python usam apenas a biblioteca padrão (Python 3.8+), sem instalar dependências.

## Uso ético

Estes scripts são para estudo e para auditar sistemas **próprios ou com autorização**. O verificador de portas recusa, por padrão, alvos fora de redes privadas. Não utilize em sistemas de terceiros sem permissão.

## Autor

**Kacy Jhony Rezende Parreiras**: estudante de Sistemas de Informação (PUC Minas), em formação em Segurança da Informação.
[LinkedIn](https://www.linkedin.com/in/kacy-jhony-5702b5302/)

## Licença

MIT
