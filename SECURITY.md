# Aviso de uso responsável

O `kali-security-bridge` expõe, via MCP, ferramentas ofensivas reais —
`nmap`, `sqlmap`, `hydra`, `nuclei`, `ffuf`, entre outras — executadas dentro
de um container Kali Linux. Isso não é um brinquedo: usado contra um alvo sem
autorização, é crime na maioria das jurisdições (no Brasil, entre outros,
pode se enquadrar na Lei 12.737/2012 e no Marco Civil da Internet).

## Use apenas em

- Sistemas que você possui, **ou**
- Ambientes com autorização explícita e por escrito (contrato de pentest,
  bug bounty com escopo definido, laboratório próprio)

## Controles já implementados no projeto

- **Allowlist obrigatória** (`gerenciar_allowlist`) — nenhum scan roda contra
  um alvo que não tenha sido explicitamente adicionado antes
- **Rate limiting** por ferramenta, pra evitar disparo acidental de carga
- **Audit log** local (`~/.kali-mcp/audit.log`) de toda execução
- Execução via `docker exec` com lista de argumentos (sem `/bin/sh`),
  eliminando injeção de shell nos parâmetros repassados às ferramentas

Esses controles reduzem risco de **uso acidental**, mas não substituem
autorização explícita — a allowlist só impede repetir o alvo errado, não
valida se você tem permissão para testá-lo.

## Reportando vulnerabilidades no próprio projeto

Se você encontrar uma falha de segurança no código deste servidor (ex.: bypass
da allowlist, escape do container, injeção via parâmetros de tool), abra uma
issue privada ou entre em contato diretamente com o mantenedor — não abra uma
issue pública com detalhes de exploração antes de haver uma correção.
