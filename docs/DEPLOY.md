# Deploy dell'istanza pubblica

Procedura per pubblicare la demo su `insurai.aicorelabs.io`, dietro Nginx Proxy Manager.

## Modello di esposizione

```
Internet → Nginx Proxy Manager (443, TLS) → 127.0.0.1:8501 → container
```

Il container pubblica la porta **solo su loopback** (`127.0.0.1:8501:8501`). È deliberato: i limiti
di frequenza identificano il visitatore tramite `X-Forwarded-For`, header che ha valore solo se
impostato dal proxy. Se il servizio fosse raggiungibile direttamente dall'esterno, chiunque potrebbe
inviare quell'header a piacere e girare intorno ai limiti.

## 1. DNS

Record **A** presso il gestore del dominio:

| Tipo | Nome | Valore |
| :--- | :--- | :--- |
| A | `insurai` | indirizzo IP pubblico della VPS |

Verifica prima di procedere, perché Let's Encrypt fallisce se il nome non risolve:

```bash
dig +short insurai.aicorelabs.io
```

## 2. Configurazione sulla VPS

```bash
git clone https://github.com/filipposemilia/secure-insurance-rag-ai.git
cd secure-insurance-rag-ai
cp .env.example .env
```

In `.env`:

```ini
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...              # non finisce mai nell'immagine: passa da env_file a runtime
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_IP_HOUR=10
RATE_LIMIT_GLOBAL_DAY=300
```

`RATE_LIMIT_GLOBAL_DAY` è il tetto di spesa: superato, l'istanza **continua a rispondere** usando il
motore deterministico offline invece di rifiutare le richieste. Con `gpt-4o-mini` e un contesto di 4
chunk, 300 richieste sono nell'ordine di poche decine di centesimi al giorno; regolalo sul budget che
sei disposto a lasciare scoperto.

## 3. Avvio

```bash
docker compose up -d --build
docker compose logs -f          # al primo avvio: ingestion con anonimizzazione, poi Streamlit
```

Il primo avvio indicizza il corpus (14 chunk, ~17 entità PII rimosse) e paga gli embedding una volta
sola: l'indice sta su un volume, quindi i riavvii successivi lo saltano.

Verifica locale prima di esporre:

```bash
curl -sf http://127.0.0.1:8501/_stcore/health && echo OK
docker compose ps              # lo stato deve essere "healthy"
```

## 4. Nginx Proxy Manager

**Hosts → Proxy Hosts → Add Proxy Host**

*Scheda Details*

| Campo | Valore |
| :--- | :--- |
| Domain Names | `insurai.aicorelabs.io` |
| Scheme | `http` |
| Forward Hostname / IP | IP del container o `host.docker.internal` |
| Forward Port | `8501` |
| Cache Assets | off |
| Block Common Exploits | on |
| **Websockets Support** | **ON** |

> **Websockets Support è obbligatorio.** Streamlit tiene una connessione WebSocket aperta per tutta
> la sessione: senza, la pagina si carica e resta bloccata su "Please wait…" o si scollega di
> continuo. È il singolo errore di configurazione più frequente con Streamlit dietro proxy.

Se NPM gira in Docker sulla stessa macchina, `127.0.0.1` punterebbe al container del proxy, non
all'host: usa l'IP dell'host sulla rete Docker (`ip addr show docker0`) oppure metti i due servizi
sulla stessa rete Docker e indirizza il container per nome (`secure-rag`).

*Scheda SSL*

| Campo | Valore |
| :--- | :--- |
| SSL Certificate | Request a new SSL Certificate (Let's Encrypt) |
| Force SSL | on |
| HTTP/2 Support | on |
| HSTS Enabled | on |

## 5. Verifica finale

```bash
curl -sI https://insurai.aicorelabs.io | head -1        # atteso: 200
```

Poi dal browser:

1. La chat risponde (se resta in "Please wait…", i WebSocket non sono attivi).
2. L'intestazione mostra la quota residua del visitatore.
3. Nella scheda **Sicurezza**, l'audit trail registra l'indirizzo reale del visitatore e non
   `127.0.0.1`: se compare l'indirizzo del proxy, `X-Forwarded-For` non arriva e i limiti di
   frequenza varrebbero per tutti i visitatori insieme.

## Manutenzione

```bash
docker compose pull && docker compose up -d --build     # aggiornamento
docker compose logs --tail=100                          # log applicativi
docker compose exec secure-rag cat /app/logs/audit.jsonl | tail -20   # audit trail
docker compose down                                     # arresto (i volumi restano)
```

Per reindicizzare da zero, per esempio dopo aver cambiato i documenti o il modello di embedding:

```bash
docker compose down
docker volume rm secure-insurance-rag-ai_chroma-index
docker compose up -d --build
```

## Problemi frequenti

| Sintomo | Causa | Rimedio |
| :--- | :--- | :--- |
| Pagina ferma su "Please wait…" | WebSocket non inoltrati | Websockets Support ON nel Proxy Host |
| `AxiosError` / errori XSRF | Origine non coerente | Force SSL attivo e accesso solo via HTTPS |
| L'audit mostra sempre lo stesso IP | `X-Forwarded-For` assente | Verificare che il traffico passi dal proxy e che la porta non sia esposta pubblicamente |
| Il container riparte in ciclo | Ingestion fallita | `docker compose logs`: quasi sempre `OPENAI_API_KEY` mancante o senza credito |
| Ingestion a ogni riavvio | Volume non montato | Verificare `chroma-index` in `docker volume ls` |
| Emissione del certificato fallita | DNS non propagato | `dig +short insurai.aicorelabs.io` e riprovare |

## Limiti dichiarati di questo deployment

- **I contatori di frequenza vivono nella memoria del processo.** Corretto per un container singolo;
  con più repliche ogni istanza avrebbe i propri contatori e il tetto complessivo sarebbe il loro
  multiplo. Servirebbe uno store condiviso (Redis).
- **Il riavvio azzera i contatori.** Un riavvio ripetuto azzererebbe anche il tetto giornaliero.
- **Non c'è autenticazione.** Il ruolo è dichiarato dal visitatore, non verificato da un identity
  provider: è una scelta della demo, che serve a mostrare l'effetto dell'RBAC sul retrieval.
- **L'audit trail è un file su volume**, non un flusso verso un SIEM.
