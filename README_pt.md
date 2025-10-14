
# Gmail Toolbox (CLI em um único arquivo)

CLI Python para **buscar**, **rotular**, **arquivar**, **excluir**, **visualizar**, **baixar** e **gerenciar filtros** no Gmail, com **logs ao vivo** e opção de salvar.

## Requisitos
- `credentials.json` (OAuth Desktop) na mesma pasta.
- Python 3.9+ recomendado.
- Instalação:
  ```bash
  pip install --upgrade google-api-python-client google-auth-httplib2 google-auth-oauthlib
  ```

## Padrões
- **Timezone:** `America/Sao_Paulo` (mude com `--timezone`).
- **Print ao vivo:** `Counter | email | date | subject`.

## Início rápido
```bash
python gmail_toolbox.py --list-labels
python gmail_toolbox.py --search 'from:boss@example.com newer_than:1y' --save-log
```

## Busca
```bash
python gmail_toolbox.py --search 'in:inbox has:attachment' --limit 200
python gmail_toolbox.py --search @criteria.json
```
`criteria.json`:
```json
{"criteria": {"from": "alerts@example.com", "query": "in:anywhere", "hasAttachment": false}}
```

### Limites de data
```bash
python gmail_toolbox.py --search 'in:inbox' --since 2025-01-01 --until 2025-03-01
```
Observações:
- `--since` → `after:YYYY/MM/DD` (inclusivo).
- `--until` → `before:YYYY/MM/DD` (exclusivo).

### Saída & exportações
- `--save-log` grava `./output/search_<date>_<time>.log` em tempo real.
- `--export-json resultados.json` / `--export-csv resultados.csv`
- `--skip-live-print` oculta as linhas por mensagem; mantém totais e sumários.

## Agrupar por remetente
```bash
python gmail_toolbox.py --search 'in:anywhere' --group-by-email
```
- Mostra cada match ao vivo (a menos que use `--skip-live-print`) e, ao final, o sumário `Qty | E-mail` (desc).
- Com export, grava arquivos extras com prefixo `grouped_`.

## Ações (exigem `--search`)
```bash
python gmail_toolbox.py --search 'from:news@list.com' --archive
python gmail_toolbox.py --search 'subject:"Invoice"' --apply-label automated_hide
python gmail_toolbox.py --search 'label:automated_hide' --unarchive
python gmail_toolbox.py --search 'older_than:3y' --delete --yes-i-know    # destrutivo
```
Extras: `--batch-size`, `--dry-run`.

## Criar/Excluir filtros (Gmail Settings)
Criar (requer `--search` via `@criteria.json`):
```bash
python gmail_toolbox.py --search @criteria.json \
  --create-filter 'addLabel=automated_hide,removeLabel=INBOX,markRead=true'
```
Aplicar a mesma ação retroativamente:
```bash
python gmail_toolbox.py --search @criteria.json \
  --create-filter @action.json \
  --retroactive-filter-action --yes-i-know
```
Excluir filtro (destrutivo):
```bash
python gmail_toolbox.py --delete-filter 1234567890 --yes-i-know
```

## Mostrar / Baixar
```bash
# Mostrar mensagem
python gmail_toolbox.py --show-message <id>            # full
python gmail_toolbox.py --show-message-metadata <id>   # metadata
python gmail_toolbox.py --show-raw <id>                # base64url RFC822

# Baixar anexos
python gmail_toolbox.py --download-attachments <id> --dir ./anexos

# Opções de download
--download-inline                        # baixar também partes inline (body.data)
--download-prefix export_                # prefixar nomes de arquivos
--download-mime-contains image/          # filtrar por MIME (ex.: image/, pdf)
--download-filename-contains nota-fiscal # filtrar por trecho no filename
```

Observações:
- Partes inline sem filename viram `inline_part.<ext>` (quando possível).
- Se o arquivo já existir, um sufixo numérico é adicionado.
