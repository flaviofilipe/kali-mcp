# kali-security-bridge

Servidor [MCP](https://modelcontextprotocol.io) que expõe um ciclo completo de
testes de segurança ofensivos — reconhecimento, enumeração, análise web e
exploração — executados dentro de um container Kali Linux isolado, com
allowlist obrigatória, rate limiting e audit log.

> ⚠️ Leia [`SECURITY.md`](./SECURITY.md) antes de usar. Este projeto executa
> ferramentas ofensivas reais (`hydra`, `sqlmap`, upload de arquivo malicioso
> como PoC, etc.) — só contra alvos que você tem autorização explícita para
> testar.

## Índice

- [Arquitetura e infraestrutura](#arquitetura-e-infraestrutura)
- [Requisitos mínimos](#requisitos-mínimos)
- [Ferramentas disponíveis no container](#ferramentas-disponíveis-no-container)
- [Iniciando a imagem Docker](#iniciando-a-imagem-docker)
- [Conectando no Claude Code (local, stdio)](#conectando-no-claude-code-local-stdio)
- [Conectando no Claude Desktop (remoto, via Cloudflare Tunnel)](#conectando-no-claude-desktop-remoto-via-cloudflare-tunnel)
- [Tools MCP — referência e exemplos de uso](#tools-mcp--referência-e-exemplos-de-uso)
- [Dados locais](#dados-locais-fora-do-repositório)

## Arquitetura e infraestrutura

```
Claude (Code / Desktop)
        │  MCP — stdio local, OU HTTP remoto com OAuth
        ▼
   server.py (FastMCP)  ──docker exec (sem shell)──▶  container kali-mcp-box
        │                                              (Kali Linux + ferramentas)
        ▼
  ~/.kali-mcp/findings.db (SQLite) + audit.log + relatórios
```

O projeto usa duas topologias, dependendo de quem conecta:

| Peça | Uso | Papel |
|---|---|---|
| **Docker** | sempre | Isola as ferramentas ofensivas num container próprio (`kali-mcp-box`), com `NET_ADMIN`/`NET_RAW` só ali dentro — nunca no host |
| **FastMCP** (Python) | sempre | Implementa o protocolo MCP e expõe as tools; roda em `stdio` (local) ou `http` (remoto) |
| **systemd (`--user`)** | modo remoto | Mantém o servidor HTTP no ar como serviço persistente, com restart automático e sobrevivência a reboot (`loginctl enable-linger`) |
| **AWS Cognito** | modo remoto | Authorization Server OAuth 2.1 — exige login antes de qualquer tool call quando exposto via HTTP. Nunca é usado no modo stdio local |
| **Cloudflare Tunnel** (`cloudflared`) | modo remoto | Expõe o servidor num domínio público real com TLS válido. **Necessário mesmo pra uso pessoal remoto**: o registro OAuth do Claude Desktop é feito pelo *back-end da Anthropic*, que não alcança domínios que só existem em DNS privado/VPN (ex. `.ts.net` do Tailscale) |

Não há GPU/CUDA envolvido em nada disso — ver seção de requisitos.

## Requisitos mínimos

### Para rodar localmente (stdio, uso com Claude Code)

- **Docker** + **Docker Compose v2**
- **[uv](https://docs.astral.sh/uv/)** (gerencia o Python 3.13 automaticamente)
- **CPU:** 2 núcleos (limite aplicado ao container via `docker-compose.yml`)
- **RAM:** 4 GB livres (2 GB reservados ao container + host + processo Python)
- **Disco:** ~6 GB livres (imagem final ~3 GB; durante o build multi-stage, picos maiores por causa do stage de compilação Go)
- **SO:** Linux ou macOS com Docker Desktop. Windows funciona via WSL2
- Usuário com permissão no socket Docker (grupo `docker` ou root)

### Adicional, só para expor remotamente (HTTP + OAuth)

- Uma conta **AWS** (Cognito tem free tier — 50k MAUs/mês grátis, suficiente pra uso pessoal/pequenas equipes)
- **AWS CLI** configurado, para criar o User Pool/App Client
- **`cloudflared`** instalado ([Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/)) — não precisa de domínio próprio pra testar (Quick Tunnel gera uma URL `*.trycloudflare.com` na hora); domínio próprio é recomendado pra uso permanente
- **systemd** (`systemctl --user`) se for rodar como serviço persistente em Linux — em outro SO, adapte para o gerenciador de processos equivalente (launchd, etc.)

### GPU / CUDA

**Não é usado neste projeto.** Nenhuma ferramenta do container (nmap, sqlmap,
hydra, nuclei, etc.) depende de GPU — todo o trabalho é CPU-bound. O
`docker-compose.yml` não reserva nenhum device de GPU, e o Dockerfile não
instala CUDA/drivers NVIDIA. Se a máquina host tiver uma GPU, ela fica
ociosa para os fins deste projeto.

## Ferramentas disponíveis no container

Instaladas via `apt` (imagem final `kalilinux/kali-rolling`):

| Ferramenta | Categoria |
|---|---|
| `nmap` | Varredura de portas/serviços |
| `nikto` | Vulnerabilidades web |
| `testssl.sh` | Análise SSL/TLS |
| `wpscan` | Auditoria WordPress |
| `sqlmap` | SQL Injection |
| `hydra` | Brute force de credenciais |
| `gobuster`, `dirb` | Enumeração de diretórios |
| `ffuf` | Fuzzing rápido |
| `mariadb-client` | Enumeração direta de MySQL/MariaDB |
| `curl`, `wget`, `chromium` | Requisições HTTP / renderização |

Compiladas de fonte em um stage builder Go separado (`golang:1.24-bookworm`),
e só os binários finais copiados pra imagem (mantém a imagem final enxuta):

| Ferramenta | Categoria |
|---|---|
| `subfinder` | Enumeração de subdomínios |
| `katana` | Crawling de aplicação web |
| `nuclei` | Detecção de CVEs via templates (atualizados no build) |
| `dalfox` | Detecção de XSS |
| `gowitness` | Screenshot de evidências |
| `httpx` | Probing HTTP em lote |

Wordlists incluídas: `rockyou.txt` (descompactada no build), wordlists padrão
do Kali (`dirb`, `dirbuster`), e uma lista própria de paths sensíveis
(`config/sensitive-paths.txt`, 60+ entradas — `.env`, backups de banco,
`wp-config.php.bak` etc.) usada por `verificar_arquivos_expostos`.

## Iniciando a imagem Docker

```bash
git clone <este-repositório>
cd kali-mcp

# builda a imagem (primeira vez ou após atualizar o Dockerfile)
docker compose build

# sobe o container em background, fica vivo aguardando exec do MCP server
docker compose up -d

# confirma que subiu
docker ps --filter name=kali-mcp-box
```

Para forçar uma imagem 100% nova (pacotes/templates atualizados, sem cache):

```bash
docker compose build --no-cache
docker compose up -d   # recria o container a partir da imagem nova
```

Recomendado rodar o rebuild periodicamente — a imagem não se atualiza
sozinha, e os templates do Nuclei/pacotes `apt` ficam parados na data do
build.

## Conectando no Claude Code (local, stdio)

1. Instale as dependências Python:
   ```bash
   uv sync
   ```
2. Confirme que o container está rodando (`docker ps --filter name=kali-mcp-box`).
3. Registre o servidor em `~/.mcp.json`:
   ```json
   {
     "mcpServers": {
       "kali-security-bridge": {
         "command": "uv",
         "args": ["run", "--project", "/caminho/absoluto/para/kali-mcp", "/caminho/absoluto/para/kali-mcp/server.py"]
       }
     }
   }
   ```
4. Reinicie o Claude Code. As 27 tools devem aparecer disponíveis.

Nesse modo, **não há autenticação** — o próprio SO controla quem consegue
spawnar o processo, e o `KALI_MCP_TRANSPORT` fica em `stdio` (padrão, não
precisa setar nada).

## Conectando no Claude Desktop (remoto, via Cloudflare Tunnel)

Use este caminho quando o Claude Desktop roda numa máquina diferente de onde
o servidor/container estão. O fluxo nativo de "Connectors" do Desktop exige
que o servidor: (a) esteja em HTTPS com domínio publicamente resolvível, e
(b) implemente OAuth com registro dinâmico de cliente (RFC 7591) — os dois
já vêm prontos aqui via FastMCP + AWS Cognito.

### 1. Criar a infraestrutura de auth (uma vez)

```bash
# User Pool com self-signup desabilitado — só você (ou quem for adicionado
# manualmente) consegue logar
aws cognito-idp create-user-pool \
  --pool-name kali-mcp-bridge \
  --auto-verified-attributes email \
  --admin-create-user-config AllowAdminCreateUserOnly=true \
  --region us-east-1

# domínio da Hosted UI (login)
aws cognito-idp create-user-pool-domain \
  --domain <prefixo-unico-seu> \
  --user-pool-id <POOL_ID> \
  --region us-east-1

# App Client com secret
aws cognito-idp create-user-pool-client \
  --user-pool-id <POOL_ID> \
  --client-name kali-mcp-bridge-client \
  --generate-secret \
  --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid email profile \
  --allowed-o-auth-flows-user-pool-client \
  --callback-urls "https://<seu-dominio-cloudflare>/auth/callback" \
  --supported-identity-providers COGNITO \
  --region us-east-1

# seu usuário (self-signup está desligado, então só admin cria)
aws cognito-idp admin-create-user \
  --user-pool-id <POOL_ID> \
  --username seu-email@exemplo.com \
  --user-attributes Name=email,Value=seu-email@exemplo.com Name=email_verified,Value=true \
  --message-action SUPPRESS --region us-east-1

aws cognito-idp admin-set-user-password \
  --user-pool-id <POOL_ID> --username seu-email@exemplo.com \
  --password '<senha-forte>' --permanent --region us-east-1
```

### 2. Subir o túnel Cloudflare

```bash
# teste rápido, sem conta/domínio (URL temporária *.trycloudflare.com)
cloudflared tunnel --url http://127.0.0.1:8765

# para produção: crie um tunnel nomeado com domínio próprio
# https://developers.cloudflare.com/cloudflare-one/connections/connect-apps/
```

Anote a URL gerada (ex. `https://algo-aleatorio.trycloudflare.com`) — ela vai
mudar toda vez que um Quick Tunnel for reiniciado. Pra uso permanente, use um
tunnel nomeado com domínio fixo.

### 3. Configurar e subir o servidor em modo HTTP

Variáveis de ambiente (via `.env` local, ou diretamente no ambiente):

```bash
KALI_MCP_TRANSPORT=http
KALI_MCP_HOST=127.0.0.1        # bind só em loopback — o Cloudflare Tunnel expõe pra fora
KALI_MCP_PORT=8765
KALI_MCP_PUBLIC_URL=https://<url-do-tunnel>
COGNITO_USER_POOL_ID=<POOL_ID>
COGNITO_REGION=us-east-1
COGNITO_CLIENT_ID=<CLIENT_ID>
COGNITO_CLIENT_SECRET=<CLIENT_SECRET>
```

```bash
uv run --project . server.py
```

Pra manter no ar de forma persistente em Linux, use um serviço `systemd
--user` com `EnvironmentFile` apontando pro `.env` e `Restart=on-failure` —
veja o exemplo comentado no repositório (não versionado, específico de cada
deploy).

### 4. Adicionar o conector no Claude Desktop

Nas configurações do Desktop, seção de Connectors → **Add custom connector**:

- **Nome:** `kali-security-bridge`
- **URL:** `https://<url-do-tunnel>/mcp`
- Deixe as configurações avançadas em branco — o registro OAuth é automático
  (dynamic client registration), não precisa de Client ID manual

Você será redirecionado pra tela de login hospedada do Cognito. Depois de
autenticar, as 27 tools ficam disponíveis normalmente.

## Tools MCP — referência e exemplos de uso

Fluxo obrigatório: **adicione o alvo na allowlist antes de qualquer scan.**
Nenhuma tool executa contra um alvo não autorizado.

### Governança

**`gerenciar_allowlist`** — adiciona/remove/lista alvos autorizados
```python
gerenciar_allowlist(action="add", entry="192.168.1.10", note="VM de lab — autorizado em 2026-05-18")
gerenciar_allowlist(action="list")
gerenciar_allowlist(action="remove", entry="192.168.1.10")
```

**`verificar_alvo_online`** — ping antes de qualquer scan
```python
verificar_alvo_online(target="192.168.1.10")
```

**`retomar_sessao`** — retoma um pentest interrompido, listando scans salvos
```python
retomar_sessao(target="exemplo.com.br")
```

**`listar_findings`** — consulta o histórico de findings no SQLite
```python
listar_findings(target="192.168.1.10", limit=20)
```

**`gerar_relatorio`** — consolida todos os findings de um alvo num relatório
```python
gerar_relatorio(target="192.168.1.10", formato="markdown")
```

### Reconhecimento

**`scan_portas_nmap`** — varredura de portas, sempre a primeira fase
```python
scan_portas_nmap(target="192.168.1.10", flags="-sV -F")
scan_portas_nmap(target="192.168.1.10", flags="-p 1-65535 -sV", stealth=True)
```

**`enum_subdominios_subfinder`** — reconhecimento passivo de subdomínios
```python
enum_subdominios_subfinder(domain="exemplo.com.br")
```

**`scan_diretorios_gobuster`** — diretórios/arquivos ocultos via força bruta
```python
scan_diretorios_gobuster(target_url="http://192.168.1.10", extensions="php,html,js,txt,bak,zip,env")
scan_diretorios_gobuster(target_url="https://app.local", evasion=True)  # alvo com WAF
```

**`crawl_aplicacao_katana`** — crawling pra descobrir endpoints/parâmetros
```python
crawl_aplicacao_katana(target_url="http://192.168.1.10", depth=3)
```

**`scan_fuzzing_ffuf`** — fuzzing rápido de diretórios, parâmetros ou APIs
```python
scan_fuzzing_ffuf(target_url="http://192.168.1.10/FUZZ")                      # diretórios
scan_fuzzing_ffuf(target_url="http://192.168.1.10/page", param_name="id")     # parâmetro GET
scan_fuzzing_ffuf(target_url="http://192.168.1.10/login", param_name="user", method="POST")
```

### Análise de vulnerabilidades

**`scan_vulnerabilidades_nikto`** — varredura geral de vulnerabilidades web
```python
scan_vulnerabilidades_nikto(target_url="http://192.168.1.10")
```

**`scan_ssl_testssl`** — protocolos/cifras fracas, certificados, HEARTBLEED etc.
```python
scan_ssl_testssl(target="app.exemplo.com", port=443)
```

**`scan_nuclei`** — CVEs conhecidos via templates
```python
scan_nuclei(target_url="http://192.168.1.10", severity="high,critical")
scan_nuclei(target_url="http://192.168.1.10", tags="wordpress")
```

**`scan_xss_dalfox`** — XSS refletido/DOM
```python
scan_xss_dalfox(target_url="http://app.local/search?q=test")
```

**`scan_wordpress_wpscan`** — auditoria completa de WordPress
```python
scan_wordpress_wpscan(target_url="http://192.168.1.10", enumerate="vp,vt,u")
```

**`scan_xmlrpc_wordpress`** — vetores de ataque no xmlrpc.php
```python
scan_xmlrpc_wordpress(target_url="http://192.168.1.10")
```

### Exploração

**`scan_sql_injection_sqlmap`** — SQL Injection, sempre escalando o risco aos poucos
```python
scan_sql_injection_sqlmap(target_url="http://app.local/user?id=1", risk=1, level=1)  # comece aqui
```

**`brute_force_hydra`** — credenciais fracas em serviços de autenticação
```python
brute_force_hydra(target="192.168.1.10", service="ssh", port=22)
brute_force_hydra(
    target="192.168.1.10", service="http-post-form", port=80,
    http_form_path="/wp-login.php",
    http_form_data="log=^USER^&pwd=^PASS^&wp-submit=Log+In",
    http_form_fail="ERROR",
)
```

**`testar_upload_arquivo`** — PoC de upload irrestrito (CWE-434)
```python
testar_upload_arquivo(upload_url="http://192.168.1.10/upload.php", field_name="file")
```

**`enumerar_banco_mysql`** — enumera bancos/tabelas/hashes com credenciais conhecidas
```python
enumerar_banco_mysql(host="192.168.1.10", user="root", password="root", database="wordpress")
```

### Utilitários web

**`fazer_requisicao_http`** — requisição HTTP customizada
```python
fazer_requisicao_http(url="http://192.168.1.10/.env")
fazer_requisicao_http(url="http://192.168.1.10/api/login", method="POST", body="user=admin&pass=test")
```

**`verificar_headers_seguranca`** — CSP, HSTS, cookies, CORS, com severidade
```python
verificar_headers_seguranca(target_url="https://app.local")
```

**`verificar_arquivos_expostos`** — `.env`, backups, `phpinfo.php` etc.
```python
verificar_arquivos_expostos(target_url="http://192.168.1.10")
```

**`screenshot_gowitness`** — evidência visual da aplicação
```python
screenshot_gowitness(target_url="http://192.168.1.10/admin")
```

### Orquestração

**`pentest_completo`** — pipeline autônomo de ponta a ponta (16 fases)
```python
pentest_completo(target="192.168.1.10")
pentest_completo(target="exemplo.com.br", target_url="https://exemplo.com.br", include_brute_force=True, evasion=True)
```

## Dados locais (fora do repositório)

| Caminho | Conteúdo |
|---|---|
| `~/.kali-mcp/findings.db` | SQLite com todos os findings por alvo |
| `~/.kali-mcp/audit.log` | Log de auditoria de toda execução |
| `~/.kali-mcp/workspaces/` | Relatórios gerados por `gerar_relatorio` |
| `~/mcps/outputs/kali-mcp/<alvo>/` | Output bruto de cada scan + `session.json` (permite retomar via `retomar_sessao`) |

## Licença

[MIT](./LICENSE)
