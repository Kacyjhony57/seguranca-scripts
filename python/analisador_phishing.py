#!/usr/bin/env python3
"""
analisador_phishing.py
----------------------
Triagem automática de um e-mail suspeito (arquivo .eml), no estilo do que um
analista de SOC faz ao receber um "reporte de phishing" de um colaborador.

O script NÃO abre links nem executa anexos: ele só lê o arquivo e aplica
verificações heurísticas, somando pontos de risco:

  Cabeçalhos
    - Domínio do "From" diferente do "Return-Path", "Reply-To" ou "Message-ID"
    - Resultado de SPF, DKIM e DMARC no cabeçalho Authentication-Results
    - Palavras de urgência no assunto ("urgente", "bloqueada", "verifique"...)
    - IP de origem provável (a partir dos cabeçalhos Received)

  Links (texto e HTML)
    - Host que é um endereço IP, domínio com punycode (xn--), encurtadores,
      TLDs muito abusados, excesso de subdomínios e links sem HTTPS
    - Texto do link mostrando um domínio, mas apontando para outro

  Anexos
    - Extensões executáveis/scripts, dupla extensão (fatura.pdf.exe), macros
    - Hash SHA-256 de cada anexo (para consultar em VirusTotal, por exemplo)

No final, lista os IOCs (indicadores de comprometimento) encontrados, já
"defanged" (hxxp://exemplo[.]com) para você não clicar sem querer.

IMPORTANTE: é uma ferramenta de apoio baseada em regras simples. Ela não
substitui a análise de um profissional nem garante que um e-mail é seguro.

Uso:
  python3 analisador_phishing.py exemplos/phishing.eml
  python3 analisador_phishing.py exemplos/legitimo.eml
  python3 analisador_phishing.py mensagem.eml --json > resultado.json

  (No JSON os IOCs saem SEM defang, para uso em ferramentas. Não clique neles.)

Dica: para salvar um e-mail como .eml, use "Salvar como" / "Baixar mensagem"
no Outlook ou "Mostrar original" no Gmail. Apenas biblioteca padrão do Python 3.
"""

import argparse
import hashlib
import ipaddress
import json
import re
import sys
from email import policy
from email.parser import BytesParser
from email.utils import parseaddr
from html.parser import HTMLParser
from urllib.parse import urlparse

ENCURTADORES = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "cutt.ly",
                "ow.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "buff.ly"}
TLDS_SUSPEITOS = {".zip", ".top", ".xyz", ".click", ".icu", ".work",
                  ".gq", ".tk", ".cf", ".ml", ".monster"}
EXT_PERIGOSAS = {".exe", ".scr", ".js", ".vbs", ".bat", ".cmd", ".ps1", ".iso",
                 ".img", ".lnk", ".jar", ".hta", ".msi", ".com", ".pif", ".wsf"}
EXT_DOCUMENTOS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg",
                  ".png", ".txt", ".ppt", ".pptx"}
EXT_MACRO = {".docm", ".xlsm", ".pptm"}
EXT_COMPACTADOS = {".zip", ".rar", ".7z", ".gz", ".tar"}
RE_URGENCIA = re.compile(
    r"\b(urgente|urgent|imediat\w*|immediately|bloquead\w*|suspens\w*|suspended|"
    r"verifique|verify|confirme|expira\w*|pendente|[úu]ltimo aviso|"
    r"atualize seus dados|action required)\b", re.I)
REDES_PRIVADAS = [ipaddress.ip_network(n) for n in
                  ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                   "127.0.0.0/8", "169.254.0.0/16")]

RE_URL = re.compile(r"https?://[^\s<>\"'\\)\]]+", re.I)
RE_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
RE_AUTH = re.compile(r"\b(spf|dkim|dmarc)=([a-z]+)", re.I)
RE_TEXTO_PARECE_DOMINIO = re.compile(r"^(https?://)?(www\.)?[\w-]+(\.[\w-]+)+(/\S*)?$", re.I)
GRAVIDADE_AUTH = {"fail": 3, "softfail": 2, "none": 1, "neutral": 1,
                  "temperror": 1, "permerror": 1, "pass": 0}


# ----------------------------------------------------------------- utilidades
def defang(texto):
    """Torna URLs/domínios/IPs inofensivos para exibição: http -> hxxp, . -> [.]"""
    return texto.replace("http", "hxxp").replace(".", "[.]")


def dominio_de(endereco):
    """Extrai o domínio de um endereço de e-mail (ou '' se não houver)."""
    _, addr = parseaddr(str(endereco or ""))
    return addr.rsplit("@", 1)[1].lower() if "@" in addr else ""


def dominio_base(dominio):
    """Aproximação do domínio registrável (mail.empresa.com.br -> empresa.com.br).

    Não usa a Public Suffix List; cobre o caso comum de sufixos como .com.br.
    """
    partes = dominio.lower().strip(".").split(".")
    if len(partes) >= 3 and partes[-2] in {"com", "org", "net", "gov", "edu"} and len(partes[-1]) == 2:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def ip_publico(ip_texto):
    try:
        ip = ipaddress.ip_address(ip_texto)
    except ValueError:
        return False
    return ip.version == 4 and not any(ip in rede for rede in REDES_PRIVADAS)


def nivel_por_pontos(pontos):
    if pontos >= 3:
        return "ALTO"
    if pontos == 2:
        return "MÉDIO"
    if pontos == 1:
        return "BAIXO"
    return "INFO"


class Analise:
    """Guarda achados e IOCs de um e-mail."""

    def __init__(self):
        self.achados = []
        self.dominios, self.urls, self.ips = set(), set(), set()
        self.hashes = []

    def add(self, pontos, texto):
        self.achados.append({"pontos": pontos, "nivel": nivel_por_pontos(pontos), "texto": texto})

    @property
    def pontuacao(self):
        return sum(a["pontos"] for a in self.achados)

    @property
    def classificacao(self):
        if self.pontuacao >= 7:
            return "ALTO RISCO: muito provável phishing/e-mail malicioso"
        if self.pontuacao >= 3:
            return "SUSPEITO: requer análise manual antes de qualquer ação"
        return "BAIXO RISCO: nenhum indício forte encontrado (não garante que seja seguro)"


class ExtratorLinks(HTMLParser):
    """Coleta pares (href, texto visível) de cada <a> do HTML."""

    def __init__(self):
        super().__init__()
        self.links = []
        self._href = None
        self._texto = []

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            self._href = dict(attrs).get("href")
            self._texto = []

    def handle_data(self, dados):
        if self._href is not None:
            self._texto.append(dados)

    def handle_endtag(self, tag):
        if tag == "a" and self._href is not None:
            self.links.append((self._href, "".join(self._texto).strip()))
            self._href = None


# ------------------------------------------------------------- verificações
def verificar_cabecalhos(msg, a):
    dom_from = dominio_de(msg["From"])
    if not dom_from:
        a.add(1, "Cabeçalho 'From' ausente ou sem endereço válido")
        return
    a.dominios.add(dom_from)
    base_from = dominio_base(dom_from)

    for cabecalho, pontos in (("Return-Path", 2), ("Reply-To", 2)):
        outro = dominio_de(msg[cabecalho])
        if outro:
            a.dominios.add(outro)
            if dominio_base(outro) != base_from:
                a.add(pontos, f"{cabecalho} ({defang(outro)}) é de domínio diferente do remetente "
                              f"({defang(dom_from)})")

    dom_id = dominio_de(str(msg["Message-ID"] or "").strip("<>"))
    if dom_id and dominio_base(dom_id) != base_from:
        a.add(1, f"Message-ID gerado por domínio diferente do remetente ({defang(dom_id)})")

    # SPF / DKIM / DMARC
    texto_auth = " ".join(str(h) for h in msg.get_all("Authentication-Results", []))
    if not texto_auth:
        a.add(1, "Sem cabeçalho Authentication-Results: não dá para confirmar SPF/DKIM/DMARC")
    else:
        resultados = {}
        for mecanismo, valor in RE_AUTH.findall(texto_auth):
            mecanismo, valor = mecanismo.upper(), valor.lower()
            atual = resultados.get(mecanismo)
            if atual is None or GRAVIDADE_AUTH.get(valor, 1) > GRAVIDADE_AUTH.get(atual, 1):
                resultados[mecanismo] = valor
        for mecanismo in ("SPF", "DKIM", "DMARC"):
            valor = resultados.get(mecanismo)
            if valor is None:
                a.add(1, f"{mecanismo}: sem resultado informado")
            else:
                a.add(GRAVIDADE_AUTH.get(valor, 1), f"{mecanismo}: {valor}")

    # Assunto
    assunto = str(msg["Subject"] or "")
    achadas = sorted({p.lower() for p in RE_URGENCIA.findall(assunto)})
    if achadas:
        a.add(min(len(achadas), 3), "Assunto com linguagem de urgência/ameaça: " + ", ".join(achadas))

    # Origem provável: o Received mais antigo (último da lista) com IP público
    recebidos = msg.get_all("Received", [])
    if recebidos:
        a.add(0, f"Mensagem passou por {len(recebidos)} servidor(es) (cabeçalhos Received)")
        for salto in reversed(recebidos):
            for ip in RE_IPV4.findall(str(salto)):
                if ip_publico(ip):
                    a.ips.add(ip)
                    a.add(0, f"IP de origem provável: {defang(ip)}")
                    return


def verificar_links(textos, htmls, base_remetente, a):
    urls = set()
    for bloco in textos + htmls:
        for u in RE_URL.findall(bloco):
            urls.add(u.rstrip(".,;:!?"))

    sem_achado = 0
    for url in sorted(urls):
        a.urls.add(url)
        host = (urlparse(url).hostname or "").lower()
        if not host:
            continue
        motivos, pontos = [], 0
        try:
            ipaddress.ip_address(host)
            motivos.append("usa endereço IP em vez de domínio"); pontos += 3
            a.ips.add(host)
        except ValueError:
            a.dominios.add(host)
            if any(parte.startswith("xn--") for parte in host.split(".")):
                motivos.append("domínio com punycode (pode imitar outro com caracteres parecidos)"); pontos += 3
            if dominio_base(host) in ENCURTADORES:
                motivos.append("encurtador de URL (destino real escondido)"); pontos += 1
            if any(host.endswith(tld) for tld in TLDS_SUSPEITOS):
                motivos.append("TLD muito usado em campanhas maliciosas"); pontos += 1
            if len(host.split(".")) >= 5:
                motivos.append("excesso de subdomínios"); pontos += 1
        if url.lower().startswith("http://"):
            motivos.append("sem HTTPS"); pontos += 1
        if motivos:
            a.add(pontos, f"Link {defang(url)}: " + "; ".join(motivos))
        else:
            sem_achado += 1
    if urls:
        a.add(0, f"{len(urls)} link(s) encontrado(s) no corpo ({sem_achado} sem indícios)")

    # Texto do link x destino real
    for html in htmls:
        extrator = ExtratorLinks()
        extrator.feed(html)
        for href, texto in extrator.links:
            if not href or not RE_TEXTO_PARECE_DOMINIO.match(texto):
                continue
            destino = (urlparse(href).hostname or "").lower()
            mostrado = (urlparse(texto if "://" in texto else "http://" + texto).hostname or "").lower()
            if destino and mostrado and dominio_base(destino) != dominio_base(mostrado):
                a.add(3, f"Link enganoso: texto mostra {defang(mostrado)} mas leva para {defang(destino)}")


def verificar_anexos(msg, a):
    for parte in msg.walk():
        nome = parte.get_filename()
        if not nome:
            continue
        dados = parte.get_payload(decode=True) or b""
        sha = hashlib.sha256(dados).hexdigest()
        a.hashes.append({"arquivo": nome, "sha256": sha})

        partes = nome.lower().split(".")
        ext = "." + partes[-1] if len(partes) > 1 else ""
        penultima = "." + partes[-2] if len(partes) > 2 else ""

        if ext in EXT_PERIGOSAS and penultima in EXT_DOCUMENTOS:
            a.add(4, f"Anexo '{nome}': DUPLA EXTENSÃO ({penultima}{ext}) disfarçando executável")
        elif ext in EXT_PERIGOSAS:
            a.add(4, f"Anexo '{nome}': extensão executável/script ({ext})")
        elif ext in EXT_MACRO:
            a.add(2, f"Anexo '{nome}': documento com macros ({ext})")
        elif ext in EXT_COMPACTADOS:
            a.add(1, f"Anexo '{nome}': arquivo compactado (pode esconder conteúdo)")
        else:
            a.add(0, f"Anexo '{nome}'")
        a.add(0, f"SHA-256 de '{nome}': {sha} ({len(dados)} bytes)")


def extrair_corpo(msg):
    textos, htmls = [], []
    for parte in msg.walk():
        if parte.is_multipart() or parte.get_content_disposition() == "attachment":
            continue
        tipo = parte.get_content_type()
        if tipo not in ("text/plain", "text/html"):
            continue
        try:
            conteudo = parte.get_content()
        except (LookupError, UnicodeDecodeError):
            conteudo = (parte.get_payload(decode=True) or b"").decode("utf-8", errors="replace")
        (htmls if tipo == "text/html" else textos).append(conteudo)
    return textos, htmls


def analisar(caminho):
    with open(caminho, "rb") as arquivo:
        msg = BytesParser(policy=policy.default).parse(arquivo)

    # Um e-mail real tem ao menos algum destes cabeçalhos; senão, não é um .eml válido.
    if not any(msg[h] for h in ("From", "Subject", "Received", "Date", "Message-ID")):
        raise ValueError("o arquivo não parece ser um e-mail (.eml) válido")

    a = Analise()
    verificar_cabecalhos(msg, a)
    textos, htmls = extrair_corpo(msg)
    verificar_links(textos, htmls, dominio_base(dominio_de(msg["From"])), a)
    verificar_anexos(msg, a)
    return msg, a


# ------------------------------------------------------------------- saída
def imprimir_relatorio(caminho, msg, a):
    print("=" * 70)
    print(" ANÁLISE DE E-MAIL SUSPEITO")
    print("=" * 70)
    print(f"Arquivo : {caminho}")
    print(f"De      : {msg['From'] or '(ausente)'}")
    print(f"Assunto : {msg['Subject'] or '(sem assunto)'}\n")

    for achado in sorted(a.achados, key=lambda x: x["pontos"], reverse=True):
        marca = f"+{achado['pontos']}" if achado["pontos"] else "  "
        print(f"[{achado['nivel']:<5}] {marca:>3}  {achado['texto']}")

    print("\n" + "-" * 70)
    print(f"PONTUAÇÃO: {a.pontuacao}  ->  {a.classificacao}")
    print("-" * 70)

    if a.dominios or a.urls or a.ips or a.hashes:
        print("\nIOCs (defanged, seguros para copiar em relatório):")
        for dom in sorted(a.dominios):
            print(f"  domínio : {defang(dom)}")
        for ip in sorted(a.ips):
            print(f"  ip      : {defang(ip)}")
        for url in sorted(a.urls):
            print(f"  url     : {defang(url)}")
        for h in a.hashes:
            print(f"  sha256  : {h['sha256']}  ({h['arquivo']})")

    if a.pontuacao >= 3:
        print("\nPróximos passos sugeridos: não clicar nem abrir anexos; isolar o e-mail; "
              "bloquear/monitorar os IOCs; avisar o remetente interno e registrar o incidente.")


def main():
    parser = argparse.ArgumentParser(description="Triagem de e-mails suspeitos (.eml) por heurísticas.")
    parser.add_argument("arquivo", help="Arquivo .eml a ser analisado")
    parser.add_argument("--json", action="store_true", help="Saída em JSON (IOCs sem defang)")
    args = parser.parse_args()

    try:
        msg, a = analisar(args.arquivo)
    except FileNotFoundError:
        sys.exit(f"Erro: arquivo '{args.arquivo}' não encontrado.")
    except IsADirectoryError:
        sys.exit(f"Erro: '{args.arquivo}' é uma pasta, informe um arquivo .eml.")
    except ValueError as erro:
        sys.exit(f"Erro: {erro}.")

    if args.json:
        print(json.dumps({
            "arquivo": args.arquivo,
            "pontuacao": a.pontuacao,
            "classificacao": a.classificacao,
            "achados": a.achados,
            "iocs": {"dominios": sorted(a.dominios), "ips": sorted(a.ips),
                     "urls": sorted(a.urls), "hashes": a.hashes},
        }, ensure_ascii=False, indent=2))
    else:
        imprimir_relatorio(args.arquivo, msg, a)


if __name__ == "__main__":
    main()
