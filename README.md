# Secure Vault — zero-knowledge encrypted file store with searchable tags

A prototype that lets a user upload files and attach arbitrary tags, where
**both the files and the tags are encrypted with the user's password**. A
returning user can search their files by tag — but only after entering the
correct password. The server never sees the password, the keys, or any
plaintext.

The hard part is **searching encrypted tags without downloading them all** to
the client. This is solved with **blind indexes** — and, for substring
("contains") search, **trigram blind indexes**.

Files can also be **shared with other users** without re-encrypting them or
revealing your password, using per-file data keys wrapped to each recipient's
OpenPGP public key (see "Sharing" below). The server stays a dumb blob store.

- **Frontend:** Vue 3 (Composition API) + Vite + Pinia + Vue Router
- **Backend:** Spring Boot 4.0.6 (Java 25) + Spring Data JPA + in-memory H2

## How the encryption & search work

All cryptography happens in the browser (`frontend/src/crypto.js`). This is a
**zero-knowledge** design — the server is a dumb encrypted blob store.

1. **Key derivation.** The password + a per-user random salt go through
   PBKDF2-HMAC-SHA256 (310k iterations) to produce a master key. HKDF then
   expands it into three independent sub-keys:
   - `encKey` — AES-GCM-256 that wraps each file's data key (and the user's
     OpenPGP private key)
   - `indexKey` — HMAC-SHA256 for blind indexes
   - `verifier` — sent to the server at login to prove password knowledge
     (separate from the encryption keys, so it leaks nothing)

   `encKey`/`indexKey` are **non-extractable** `CryptoKey`s — they cannot be
   read out of memory or serialized, and they never leave the browser.

2. **Envelope encryption.** Each upload gets a fresh random **per-file data key
   (DEK)**. The file bytes, metadata (name/type/size), and each tag's text are
   encrypted with AES-GCM under that DEK. The DEK itself is then *wrapped* in a
   `file_access` envelope row — for the owner, symmetrically under `encKey`. The
   server stores only ciphertext + IVs and wrapped DEKs; it never sees a data
   key. The indirection (DEK, not `encKey`, encrypts the bytes) is what lets a
   file be shared by re-wrapping its small DEK rather than re-encrypting it.

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

4. **Sharing (OpenPGP key envelopes).** Every user generates an OpenPGP keypair
   (Curve25519) at registration. The public key is stored in cleartext (it's
   public); the private key is itself AES-GCM-encrypted under `encKey` and stored
   as just another ciphertext blob, recovered and decrypted client-side at login.

   To share a file, the owner fetches the recipient's public key, unwraps the
   file's DEK from their own envelope, re-encrypts that ~32-byte DEK to the
   recipient's public key (an armored OpenPGP message), and stores it as a new
   `file_access` row (`role = READER`, `wrap_type = OPENPGP`). The recipient
   decrypts the DEK with their private key, then decrypts the file/metadata/tags
   under it. **The file bytes are never re-encrypted or copied** — one tiny
   envelope per recipient is all that's added. OpenPGP is used *only* to wrap the
   DEK; all bulk crypto stays WebCrypto AES-GCM.

   **Public-key authenticity** is the hard part: the untrusted server could serve
   an attacker's key in place of the recipient's, so a new share would be
   encrypted to the attacker. The UI surfaces each key's **fingerprint** for
   out-of-band verification (TOFU); "the server can misdirect a *new* share" is an
   accepted residual risk in this prototype (same posture as `/auth/params`
   username enumeration).

   **Tag search works across shared files too — client-side.** The owner-keyed
   trigram blind index can't help a recipient (they don't have the owner's
   `indexKey`, and handing it over would leak the searchability of the owner's
   *whole* vault). But the recipient already holds the DEK for every file shared
   with them, and that set is bounded, so the client simply fetches the shared
   set (`GET /files/shared`) and filters it locally. This leaks **nothing** to the
   server (the query never leaves the browser) and has no trigram false positives
   (it matches decrypted tag text directly). Owned files keep using the scalable
   server-side index; only the bounded shared set is filtered in the browser. (If
   a user ever had so many shared-in files that fetching them all was prohibitive,
   you'd instead need a per-file search key inside the envelope, with a per-file
   server query — deliberately out of scope here.)

   **Revocation** removes server-side access (`DELETE …/shares/{user}`) but
   cannot retract a DEK a recipient has already unwrapped. Cryptographic
   un-sharing would require rotating the file's DEK and re-wrapping for the
   remaining recipients.

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

Sharing adds its own metadata leakage: the server learns the **social graph**
(which `file_access` rows link which users to which files, and who owns what) and
holds every user's **public key** in the clear. It still cannot read any file,
filename, tag, or data key. The wrapped private keys and wrapped DEKs are opaque
ciphertext to it.

## Project layout

```
backend/   Spring Boot 4 API (auth, files, encrypted-tag search)
frontend/  Vue 3 SPA (all crypto in src/crypto.js, orchestrated in src/stores/vault.js)
```

### Key backend files
- `domain/TagEntry.java` — the encrypted tag text (one row per tag), no blind index
- `domain/TagGram.java` — the searchable trigram blind-index rows + indexes
- `domain/FileAccess.java` — the key-envelope rows (owner = symmetric, share = OpenPGP)
- `repo/TagGramRepository.java` — the indexed `findFileIdsContainingAll` query
- `file/FileService.java` — upload / list / search / download / delete / share / revoke
- `user/UserController.java` — public-key lookup for sharing
- `auth/AuthController.java` — register / params / login (carries the OpenPGP identity)

All crypto helpers live in `frontend/src/crypto.js`; the DEK + OpenPGP envelope
helpers are at the bottom. `frontend/src/stores/vault.js` orchestrates upload,
list, search, download, and the share/revoke flow.

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
It exercises register → login (incl. wrong-password rejection, plus recovering
the OpenPGP identity) → encrypted upload → trigram substring ("contains") search
(case-insensitive, multi-term AND, with false-positive verification) → download
round-trip → per-user isolation → **sharing** (alice shares with bob via an
OpenPGP key envelope; bob decrypts, downloads, and tag-searches it client-side,
but cannot delete it) → revocation, all against the live API using the real
browser crypto module.

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
- **Share-key authenticity is TOFU at best** — the untrusted server serves the
  public keys, so it can misdirect a *new* share to an attacker's key. The UI
  shows fingerprints for out-of-band verification but there is no key-transparency
  log or signed directory.
- **Revocation isn't cryptographic** — revoking only deletes server-side access;
  a recipient who already unwrapped the DEK keeps it. Real un-sharing needs DEK
  rotation + re-wrap.
- **Shared-file search is client-side** — the recipient fetches the whole shared
  set and filters locally (fine here because that set is bounded and already
  resident). Server-side shared search would need a per-file search key in the
  envelope; deliberately out of scope.
