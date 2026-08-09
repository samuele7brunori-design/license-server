# TapeSense licensing v2 — runbook di sicurezza

## Proprietà garantite

- Le chiavi di attivazione sono generate con entropia crittografica, normalizzate e
  conservate sul server esclusivamente come HMAC-SHA-256 con pepper segreto.
- Il client non conserva la chiave di attivazione. Conserva una chiave dispositivo
  Ed25519 e un lease firmato, cifrati con Windows DPAPI per l'utente corrente.
- Ogni rinnovo richiede una challenge monouso firmata dal dispositivo. Challenge
  scadute, riutilizzate o firmate con una chiave diversa sono rifiutate.
- Lease e manifest di aggiornamento sono firmati Ed25519 e verificati contro chiavi
  pubbliche incorporate nel client. Il server non può essere sostituito modificando
  semplicemente DNS o URL.
- Download e version check usano `Authorization: Bearer`; nessun segreto appare in
  query string. Il file viene accettato soltanto se dimensione e SHA-256 coincidono
  con il manifest firmato.

Queste misure rendono la copia e la falsificazione sensibilmente più difficili, ma
nessun software eseguito sul computer dell'utente è matematicamente impossibile da
patchare. Le difese efficaci sono stratificate: protocollo, firma del codice,
telemetria minima di abuso, revoca, aggiornamenti rapidi e protezione legale.

## Prima chiave di firma

Generare la coppia su una macchina amministrativa, con destinazione privata fuori
dal repository:

```powershell
python license_server/generate_signing_key.py `
  --key-id license-signing-2026-01 `
  --private-out C:\Secure\TapeSense\license-signing.private-key `
  --public-out C:\Secure\TapeSense\license-signing.public.json
```

La chiave privata va nel secret manager del server come
`LICENSE_SIGNING_PRIVATE_KEY_B64`. Il JSON pubblico va copiato in
`EMBEDDED_LICENSE_PUBLIC_KEYS` in `license_trust.py`. La pipeline blocca una build
se questa mappa è vuota o contiene una chiave non valida.

Generare separatamente un pepper casuale di almeno 32 byte e conservarlo soltanto
nel secret manager come `LICENSE_KEY_PEPPER`. La perdita del pepper non consente di
ricostruire chiavi ad alta entropia già emesse, ma richiede comunque rotazione e
audit.

## Operazioni server

### Health check e contenimento costi

`/health` e' un controllo di sola liveness e non deve mai aprire PostgreSQL. Render
lo interroga ogni pochi secondi: una query in questo endpoint impedirebbe a Neon di
raggiungere lo scale-to-zero e produrrebbe compute fatturabile continuo. La relativa
regressione e' coperta dai test.

La disponibilita' del database viene verificata dalle vere richieste di licensing,
che continuano a fallire in modo chiuso se PostgreSQL non e' raggiungibile. Per una
diagnostica manuale usare la console Neon o il client amministrativo; non collegare
monitor periodici a endpoint che eseguono query. Configurare inoltre gli avvisi di
spesa Neon come segnalazione preventiva, ricordando che una soglia di notifica non e'
un limite automatico alla spesa.

Il deploy VPS richiede `DOMAIN`, `CERTBOT_EMAIL`, `LICENSE_KEY_PEPPER`,
`LICENSE_SIGNING_PRIVATE_KEY_B64` e `LICENSE_SIGNING_KEY_ID`. Non contiene password
predefinite, espone Gunicorn solo su loopback, configura HTTPS obbligatorio, header
proxy fidati, sandbox systemd e rate limit Nginx.

Esempi dopo il deploy:

```bash
tapesense-license-manage create --plan yearly --days 365 --max-devices 2
tapesense-license-manage list
tapesense-license-manage revoke lic_0123456789abcdef
tapesense-license-manage revoke-device dev_0123456789abcdef
tapesense-license-manage publish-release --file /percorso/TapeSense.exe \
  --version 1.2.3 --notes "Correzioni di sicurezza"
```

`publish-release` copia prima in un file temporaneo, forza il flush su disco e usa
una sostituzione atomica; versione e note vengono aggiornate soltanto dopo che il
binario è completo. Il server calcola e firma il manifest a ogni richiesta.

La chiave grezza compare una sola volta durante `create`: consegnarla tramite un
canale distinto dall'email dell'account quando il rischio lo giustifica. Backup del
database e del pepper devono essere cifrati e testati periodicamente.

## Rotazione

1. Generare una nuova coppia con un nuovo `key-id`.
2. Distribuire prima un client che incorpora chiave pubblica vecchia e nuova.
3. Impostare sul server la nuova privata/ID e mantenere la vecchia pubblica in
   `LICENSE_VERIFY_PUBLIC_KEYS_JSON` finché tutti i lease precedenti sono scaduti.
4. Rimuovere la vecchia trust anchor soltanto dopo la finestra massima di lease.

Non riutilizzare una chiave privata compromessa e non inserirla mai in repository,
artifact CI, log, ticket o build client.

## Release Windows

Le build di produzione richiedono un certificato Authenticode (`WINDOWS_SIGNING_PFX`
e `WINDOWS_SIGNING_PASSWORD`). L'eseguibile viene firmato e verificato prima di
essere incluso nell'installer; anche l'installer viene firmato e verificato. In CI,
configurare `WINDOWS_SIGNING_PFX_B64` e `WINDOWS_SIGNING_PASSWORD` come secret.

## Migrazione legacy

Le API e il pannello legacy sono disabilitati di default. Un client esistente può
leggere localmente la vecchia chiave una sola volta per attivare v2; il vecchio file
viene eliminato solo dopo il salvataggio DPAPI riuscito. Abilitare temporaneamente
`ENABLE_LEGACY_LICENSE_API=1` esclusivamente durante una finestra di migrazione
monitorata, poi riportarlo a `0`. Non abilitare il pannello legacy in produzione.

Se il database SQLite legacy è disponibile sulla nuova macchina, importare prima le
chiavi nello schema v2 senza ristamparle né conservarle in chiaro nella nuova tabella:

```bash
tapesense-license-manage migrate-legacy
```

Il comando non elimina le tabelle legacy: conservarne un backup cifrato, verificare
il campione migrato e rimuoverle soltanto in una manutenzione successiva. Per un
vecchio database PostgreSQL occorre un export controllato e temporaneo; non copiare
le chiavi in ticket, chat o fogli condivisi.
