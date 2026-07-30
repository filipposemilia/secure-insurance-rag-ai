# Deploy dell'istanza pubblica

Procedura per pubblicare la demo su `insurag.aicorelabs.io`, dietro Nginx Proxy Manager.

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
| A | `insurag` | indirizzo IP pubblico della VPS |

Verifica prima di procedere, perché Let's Encrypt fallisce se il nome non risolve:

```bash
dig +short insurag.aicorelabs.io
```

## 2. Configurazione sulla VPS

```bash
git clone https://github.com/filipposemilia/secure-insurance-rag-ai.git
cd secure-insurance-rag-ai
cp .env.example .env
```

In `.env` — **`LLM_PROVIDER` va cambiato**: l'esempio contiene `fake`, che fa rispondere l'istanza
offline senza mai interrogare il modello.

```ini
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-...              # non finisce mai nell'immagine: passa da env_file a runtime
PUBLIC_MODE=true                   # nasconde i controlli da amministratore
RATE_LIMIT_ENABLED=true
RATE_LIMIT_PER_IP_HOUR=10
RATE_LIMIT_GLOBAL_DAY=300
```

`PUBLIC_MODE=true` rimuove dall'interfaccia la scelta del modello e il pulsante di
reindicizzazione. Non è solo una questione di ordine: **la reindicizzazione costa embedding e non è
coperta dai limiti di frequenza**, che valgono per le domande. Lasciata in pagina, chiunque
potrebbe premerla ripetutamente a spese di chi ospita l'istanza. In locale va tenuta a `false`, così
la demo dal vivo può cambiare modello e ricostruire l'archivio.

`RATE_LIMIT_GLOBAL_DAY` è il tetto di spesa: superato, l'istanza **continua a rispondere** usando il
motore deterministico offline invece di rifiutare le richieste. Con `gpt-4o-mini` e un contesto di 4
chunk, 300 richieste sono nell'ordine di poche decine di centesimi al giorno; regolalo sul budget che
sei disposto a lasciare scoperto.

`PII_NER_ENABLED` **non va impostato**: il compose lo porta a `true` da sé, perché il livello 2
dell'anonimizzazione fa parte di ciò che l'istanza pubblica dimostra. Metterlo a `false` in `.env` lo
disattiva e provoca una reindicizzazione al riavvio successivo (i segnaposto di un livello non sono
quelli dell'altro).

## 3. Avvio

```bash
docker compose up -d --build
docker compose logs -f          # al primo avvio: ingestion con anonimizzazione, poi Streamlit
```

Il primo avvio indicizza il corpus (14 chunk, ~22 entità PII rimosse) e paga gli embedding una volta
sola: l'indice sta su un volume, quindi i riavvii successivi lo saltano.

**Cosa cambia con il livello 2 dell'anonimizzazione attivo.** L'immagine contiene Presidio e il
modello `it_core_news_lg`, e questo ha tre effetti da conoscere prima di lanciare la build:

| | Effetto |
| :--- | :--- |
| Immagine | **+~700 MB** (di cui 541 il solo modello). La prima build scarica il wheel del modello: serve rete sulla VPS e qualche minuto in più |
| RAM a regime | **+~870 MB di RSS** sul processo, caricati una volta sola e condivisi da tutte le sessioni: non è un costo per visitatore. Su una VPS da 12 GB il margine resta ampio |
| Primo avvio | Il caricamento del modello aggiunge ~3 s prima dell'ingestion. `start_period` dell'healthcheck è 90 s, quindi non serve toccarlo |

**Reindicizzazione automatica al cambio di livello.** L'indice porta una marca (`.anonymization`) con
i livelli usati per costruirlo. All'avvio il container la confronta con la configurazione attiva e
reindicizza se non coincidono, o se manca — è il caso di un volume creato da una versione precedente.
Nei log lo vedi così:

```
→ Eseguo l'ingestion con anonimizzazione dei dati personali: livelli cambiati: indice «1 (regex)», configurazione «1+2 (regex + NER it_core_news_lg)».
✓ Livelli attivi       : 1+2 (regex + NER it_core_news_lg)
```

Senza questo controllo un volume esistente conserverebbe l'indice di livello 1 mentre l'interfaccia
dichiara il livello 2: l'indice non avrebbe i segnaposto che il sistema afferma di avere prodotto.
**Aggiornando un'istanza già in esercizio, quindi, aspettati una reindicizzazione al primo avvio** —
14 chunk di embedding, frazioni di centesimo.

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
| Domain Names | `insurag.aicorelabs.io` |
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
curl -sI https://insurag.aicorelabs.io | head -1        # atteso: 200
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
| `Cartella documenti non trovata: /opt/venv/...` | Percorsi non dichiarati | Nell'immagine il pacchetto è installato in `site-packages`, quindi la root dedotta dal modulo cade dentro il venv. Il Dockerfile dichiara `POLICIES_DIR`, `CHROMA_BASE_DIR` e `AUDIT_LOG_PATH`: verifica di non averli sovrascritti con valori errati |
| Il container riparte in ciclo | Ingestion fallita | `docker compose logs`: quasi sempre `OPENAI_API_KEY` mancante o senza credito |
| Nei log compare `Provider attivo: fake` | `.env` copiato da `.env.example` | L'esempio contiene `LLM_PROVIDER=fake`: va cambiato in `openai`, altrimenti l'istanza risponde offline |
| Ingestion a ogni riavvio | Volume non montato | Verificare `chroma-index` in `docker volume ls`. Se il volume c'è, leggere il motivo nei log: `livelli cambiati` o `provenienza ignota` indicano un cambio di configurazione, non un volume perduto |
| Build interrotta su `it_core_news_lg` | Wheel del modello non raggiungibile | Il Dockerfile lo scarica dalle release di spaCy su GitHub: serve rete in fase di build. Per una build senza rete, pre-scaricare il wheel e installarlo da file |
| Nei log `NER level 2 requested but ... not installed` | Immagine costruita senza l'extra | Ricostruire con `--build`: l'installazione di `.[presidio]` sta nel primo stadio del Dockerfile. L'istanza continua a funzionare a sole regex e lo dichiara in pagina |
| Emissione del certificato fallita | DNS non propagato | `dig +short insurag.aicorelabs.io` e riprovare |

## Limiti dichiarati di questo deployment

- **I contatori di frequenza vivono nella memoria del processo.** Corretto per un container singolo;
  con più repliche ogni istanza avrebbe i propri contatori e il tetto complessivo sarebbe il loro
  multiplo. Servirebbe uno store condiviso (Redis).
- **Il riavvio azzera i contatori.** Un riavvio ripetuto azzererebbe anche il tetto giornaliero.
- **Non c'è autenticazione.** Il ruolo è dichiarato dal visitatore, non verificato da un identity
  provider: è una scelta della demo, che serve a mostrare l'effetto dell'RBAC sul retrieval.
- **L'audit trail è un file su volume**, non un flusso verso un SIEM.
