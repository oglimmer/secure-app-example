# Secure Vault — zero-knowledge encrypted file store with searchable tags

A prototype that lets a user upload files and attach arbitrary tags, where
**both the files and the tags are encrypted with the user's password**. A
returning user can search their files by tag — but only after entering the
correct password. The server never sees the password, the keys, or any
plaintext.

The hard part is **searching encrypted tags without downloading them all** to
the client. This is solved with **blind indexes** — and, for substring
("contains") search, **trigram blind indexes**.

- **Frontend:** Vue 3 (Composition API) + Vite + Pinia + Vue Router
- **Backend:** Spring Boot 4.0.6 (Java 25) + Spring Data JPA + in-memory H2

## How the encryption & search work

All cryptography happens in the browser (`frontend/src/crypto.js`). This is a
**zero-knowledge** design — the server is a dumb encrypted blob store.

1. **Key derivation.** The password + a per-user random salt go through
   PBKDF2-HMAC-SHA256 (310k iterations) to produce a master key. HKDF then
   expands it into three independent sub-keys:
   - `encKey` — AES-GCM-256 for encrypting file bytes, metadata, and tag text
   - `indexKey` — HMAC-SHA256 for blind indexes
   - `verifier` — sent to the server at login to prove password knowledge
     (separate from the encryption keys, so it leaks nothing)

   `encKey`/`indexKey` are **non-extractable** `CryptoKey`s — they cannot be
   read out of memory or serialized, and they never leave the browser.

2. **Encryption.** Each file, its metadata (name/type/size), and each tag's
   text are encrypted with AES-GCM under a fresh random IV. The server stores
   only the ciphertext + IV.

3. **Searchable tags (trigram blind index).** To support substring
   ("contains") search, we split each normalized tag into its length-3
   substrings (trigrams) and store `base64(HMAC-SHA256(indexKey, trigram))` for
   each, one row per trigram in `tag_gram`. Because HMAC is deterministic, the
   *same trigram under the same password* always yields the *same* blind index.

   To search for "contains Q", the client breaks Q into trigrams and sends their
   blind indexes; the server returns files whose stored trigrams are a
   **superset** of the query's (`GROUP BY file HAVING count(distinct idx) = N`).
   That condition is *necessary but not sufficient* — trigrams can recombine
   across positions or across different tags on the same file — so the client
   re-checks the real substring after decrypting, dropping any false positives.
   Multiple comma-separated terms are `AND`-ed, and each term needs ≥3
   characters (a trigram index can't accelerate shorter queries, same as
   Postgres `pg_trgm`).

   This is why it scales: the server-side filter is
   `WHERE owner_id = ? AND blind_index IN (…)` against a B-tree index on
   `(owner_id, blind_index)` — indexed, not a full scan, even with millions of
   trigram rows.

### What this protects — and what it leaks

A server operator (or anyone who dumps the database) sees only ciphertext and
blind indexes. They **cannot** read file contents, filenames, or tag text, and
cannot run a dictionary attack on the blind indexes because `indexKey` never
leaves the client.

Like all practical searchable symmetric encryption, the deterministic blind
index **leaks equality and frequency**. Indexing *trigrams* rather than whole
tags leaks more: the server sees per-file trigram multisets and can mount
frequency / co-occurrence analysis to guess tag contents (and learns roughly
how long tags are). This is the inherent trade-off of trigram-based searchable
encryption — it's what buys server-side substring search. (Search-pattern
hiding needs ORAM/PIR, which is out of scope for a prototype.)

## Project layout

```
backend/   Spring Boot 4 API (auth, files, encrypted-tag search)
frontend/  Vue 3 SPA (all crypto in src/crypto.js, orchestrated in src/stores/vault.js)
```

### Key backend files
- `domain/TagEntry.java` — the encrypted tag text (one row per tag), no blind index
- `domain/TagGram.java` — the searchable trigram blind-index rows + indexes
- `repo/TagGramRepository.java` — the indexed `findFileIdsContainingAll` query
- `file/FileService.java` — upload / list / search / download / delete
- `auth/AuthController.java` — register / params / login (verifier-based)

## Running it

### Docker Compose (whole stack)
```bash
docker compose up --build
```
Then open **http://localhost:8088**. nginx serves the built SPA and proxies
`/api` to the backend container, so the app is single-origin (no CORS).
The backend is also exposed directly at **http://localhost:8090** (handy for the
H2 console / raw API). Stop with `docker compose down`.

> Host ports are 8088/8090 rather than 80/8080 because 8080 is already in use on
> this machine. Change the `ports:` mappings in `docker-compose.yml` if you want
> different ones.

To run the e2e test against the running stack:
```bash
sed 's#localhost:8090#localhost:8088#' e2e/vault-e2e.mjs > e2e/_tmp.mjs && node e2e/_tmp.mjs; rm e2e/_tmp.mjs
```

### Local dev (hot reload)

#### Backend (port 8080)
```bash
cd backend
mvn spring-boot:run
# If 8080 is busy: mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8090
```
H2 console (dev only): http://localhost:8080/h2-console — JDBC URL
`jdbc:h2:mem:vault`, user `sa`, no password. Useful to *confirm* that
`tag_entry` holds only ciphertext and `tag_gram` holds only trigram blind
indexes — no plaintext anywhere.

#### Frontend (port 5173)
```bash
cd frontend
npm install
npm run dev
```
Open http://localhost:5173. Vite proxies `/api/*` to the backend on `:8080`
(adjust `frontend/vite.config.js` if you changed the backend port).

### End-to-end test
Start the backend on `:8090`
(`mvn spring-boot:run -Dspring-boot.run.arguments=--server.port=8090`), then
from the repo root:
```bash
node e2e/vault-e2e.mjs
```
It exercises register → login (incl. wrong-password rejection) → encrypted
upload → trigram substring ("contains") search (case-insensitive, multi-term
AND, with false-positive verification) → download round-trip → per-user
isolation, all against the live API using the real browser crypto module.

## Prototype limitations (not production-ready)

- **In-memory H2** — all data is lost when the backend stops.
- **In-memory sessions** — bearer tokens live in a `ConcurrentHashMap` with no
  expiry; restarting the backend invalidates them. Swap for JWT/Redis.
- **File bytes are base64'd into the DB** — fine for a prototype, not for large
  files. Use object storage (still client-encrypted) in production.
- **No password recovery** — by design. Forgetting the password means the data
  is unrecoverable.
- **`/auth/params` allows username enumeration** — acceptable for a prototype.
- **Trigram search has a 3-character floor** — terms shorter than 3 chars can't
  be accelerated by the trigram index (same as Postgres `pg_trgm`).
- **Trigram indexing trades leakage for substring search** — see "What this
  protects — and what it leaks" above; the server can attempt co-occurrence
  analysis on per-file trigram sets.
