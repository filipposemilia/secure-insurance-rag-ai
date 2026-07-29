"""Vault dei dati personali: la mappa segnaposto → valore reale, cifrata su disco.

Il masking sostituisce `Mario Rossi` con `[NOME_001]` prima che il testo raggiunga l'indice e il
modello. Perché quella sostituzione sia **pseudonimizzazione** e non anonimizzazione irreversibile —
la distinzione è del GDPR, non terminologica — la mappa inversa deve sopravvivere: è ciò che permette
di rimettere il nome vero nella risposta mostrata all'operatore autorizzato.

Il problema pratico che questo modulo risolve: ingestion e interrogazione sono **processi diversi**.
`secure-rag ingest` gira da riga di comando, l'interfaccia gira altrove; un vault tenuto solo in
memoria muore con il processo che l'ha creato, e i segnaposto assegnati durante l'indicizzazione non
corrisponderebbero a quelli calcolati a runtime.

**Il vault è un archivio di dati personali**, e va trattato di conseguenza:

- è cifrato con Fernet (AES-128 in CBC con autenticazione HMAC), chiave da `PII_VAULT_KEY`;
- **senza chiave non viene scritto nulla** e il ripristino resta disattivato: il comportamento
  predefinito è quello irreversibile, cioè il più prudente;
- non entra mai nel vector store, nel prompt o nell'audit trail.

`cryptography` è una dipendenza opzionale (`pip install -e ".[vault]"`): se manca, il modulo si
comporta come se la chiave fosse assente, senza rompere nulla.
"""

from __future__ import annotations

import json
from pathlib import Path

try:  # dipendenza opzionale: senza, il vault è semplicemente non disponibile
    from cryptography.fernet import Fernet, InvalidToken

    CIFRATURA_DISPONIBILE = True
except ImportError:  # pragma: no cover - dipende dall'ambiente, non dalla logica
    Fernet = None  # type: ignore[assignment]
    InvalidToken = Exception  # type: ignore[assignment,misc]
    CIFRATURA_DISPONIBILE = False


class VaultStore:
    """Lettura e scrittura cifrata della mappa segnaposto → valore originale."""

    def __init__(self, path: Path, key: str = "") -> None:
        self._path = path
        self._key = key.strip()

    @property
    def available(self) -> bool:
        """True solo se il ripristino è effettivamente possibile.

        Serve una chiave **e** la libreria di cifratura: senza una delle due il vault non viene
        scritto, invece di essere scritto in chiaro.
        """
        return bool(self._key) and CIFRATURA_DISPONIBILE

    @property
    def path(self) -> Path:
        return self._path

    def save(self, mapping: dict[str, str]) -> bool:
        """Scrive la mappa cifrata. Restituisce False se il vault non è disponibile."""
        if not self.available or not mapping:
            return False

        payload = json.dumps(mapping, ensure_ascii=False).encode("utf-8")
        cifrato = self._fernet().encrypt(payload)

        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_bytes(cifrato)
        # Leggibile solo dall'utente che esegue il processo: un archivio di dati personali non
        # deve essere accessibile agli altri account della macchina.
        self._path.chmod(0o600)
        return True

    def load(self) -> dict[str, str]:
        """Legge la mappa. Restituisce un dizionario vuoto se assente o illeggibile.

        Una chiave errata non deve interrompere il servizio: senza mappa il sistema continua a
        funzionare in modalità irreversibile, che è il comportamento predefinito.
        """
        if not self.available or not self._path.exists():
            return {}
        try:
            decifrato = self._fernet().decrypt(self._path.read_bytes())
            return json.loads(decifrato.decode("utf-8"))
        except (InvalidToken, ValueError, OSError):
            return {}

    def clear(self) -> None:
        """Elimina il vault dal disco."""
        self._path.unlink(missing_ok=True)

    def _fernet(self) -> "Fernet":
        return Fernet(self._key.encode("utf-8"))


def genera_chiave() -> str:
    """Chiave nuova da incollare in `PII_VAULT_KEY`.

    Richiede `cryptography`; senza, solleva un errore esplicito invece di restituire un valore
    inutilizzabile.
    """
    if not CIFRATURA_DISPONIBILE:
        raise RuntimeError(
            "Per generare una chiave serve la dipendenza opzionale: "
            'uv pip install -e ".[vault]"'
        )
    return Fernet.generate_key().decode("utf-8")
