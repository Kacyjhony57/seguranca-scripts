<#
.SYNOPSIS
    Auditoria básica de segurança do Active Directory (somente leitura).

.DESCRIPTION
    Gera relatórios com os pontos que mais interessam em uma revisão rápida de AD:
      1. Contas habilitadas sem logon há X dias (contas esquecidas = superfície de ataque).
      2. Contas habilitadas com "senha nunca expira".
      3. Membros dos grupos privilegiados (Domain Admins, Enterprise Admins,
         Schema Admins e Administrators).

    O script NÃO altera nada no domínio: apenas consulta e exporta CSVs.
    Os grupos privilegiados são localizados pelo SID conhecido (RID 512, 518, 519 e
    S-1-5-32-544), por isso funciona em AD em qualquer idioma (ex.: "Admins. do domínio").

.PARAMETER DiasInativo
    Quantidade de dias sem logon para considerar a conta inativa. Padrão: 90.

.PARAMETER PastaRelatorio
    Pasta onde os CSVs serão salvos. Padrão: .\relatorio-ad

.EXAMPLE
    .\Auditoria-AD.ps1
    .\Auditoria-AD.ps1 -DiasInativo 60 -PastaRelatorio C:\Temp\auditoria

.NOTES
    Requer o módulo ActiveDirectory (RSAT) e permissão de leitura no domínio.
    Execute em um PowerShell com conta que consulte o AD. Teste primeiro em ambiente
    de laboratório ou com autorização de quem administra o domínio.
    Atenção: o atributo LastLogonDate é replicado entre controladores de domínio com
    atraso de até ~14 dias, então trate o resultado como lista de contas a REVISAR,
    não como prova definitiva de inatividade.
#>

#Requires -Modules ActiveDirectory

[CmdletBinding()]
param(
    [int]$DiasInativo = 90,
    [string]$PastaRelatorio = ".\relatorio-ad"
)

$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory

if (-not (Test-Path $PastaRelatorio)) {
    New-Item -ItemType Directory -Path $PastaRelatorio | Out-Null
}

$dataCorte = (Get-Date).AddDays(-$DiasInativo)
$sidDominio = (Get-ADDomain).DomainSID.Value

Write-Host "== Auditoria de AD ($((Get-ADDomain).DNSRoot)) ==" -ForegroundColor Cyan
Write-Host "Critério de inatividade: sem logon desde $($dataCorte.ToString('dd/MM/yyyy'))`n"

# --- 1. Contas inativas -------------------------------------------------------
$usuarios = Get-ADUser -Filter 'Enabled -eq $true' `
    -Properties LastLogonDate, PasswordLastSet, PasswordNeverExpires, Description

$inativos = $usuarios |
    Where-Object { -not $_.LastLogonDate -or $_.LastLogonDate -lt $dataCorte } |
    Select-Object SamAccountName, Name, LastLogonDate, PasswordLastSet, Description

$inativos | Export-Csv "$PastaRelatorio\contas_inativas.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[1] Contas habilitadas inativas há mais de $DiasInativo dias: $(@($inativos).Count)"

# --- 2. Senha nunca expira ---------------------------------------------------
$semExpiracao = $usuarios |
    Where-Object { $_.PasswordNeverExpires } |
    Select-Object SamAccountName, Name, PasswordLastSet

$semExpiracao | Export-Csv "$PastaRelatorio\senha_nunca_expira.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[2] Contas com 'senha nunca expira': $(@($semExpiracao).Count)"

# --- 3. Grupos privilegiados -------------------------------------------------
$gruposPrivilegiados = [ordered]@{
    "Domain Admins"     = "$sidDominio-512"
    "Schema Admins"     = "$sidDominio-518"
    "Enterprise Admins" = "$sidDominio-519"
    "Administrators"    = "S-1-5-32-544"
}

$privilegiados = foreach ($nome in $gruposPrivilegiados.Keys) {
    try {
        Get-ADGroupMember -Identity $gruposPrivilegiados[$nome] -Recursive |
            Select-Object @{n = "Grupo"; e = { $nome } }, SamAccountName, Name, objectClass
    }
    catch {
        # Alguns grupos (ex.: Enterprise Admins) só existem no domínio raiz da floresta.
        Write-Warning "Não foi possível ler o grupo '$nome': $($_.Exception.Message)"
    }
}

$privilegiados | Export-Csv "$PastaRelatorio\grupos_privilegiados.csv" -NoTypeInformation -Encoding UTF8
Write-Host "[3] Membros em grupos privilegiados: $(@($privilegiados).Count)"
$privilegiados | Format-Table Grupo, SamAccountName, Name -AutoSize

Write-Host "`nRelatórios salvos em: $((Resolve-Path $PastaRelatorio).Path)" -ForegroundColor Green
