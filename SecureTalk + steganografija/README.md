# SecureTalk + Steganografija — README.md

Kompletan vodič: kako da postaviš, pokreneš i testiraš projekat (`server`, `GUI client`, CLI za stego). Kopiraj ovaj sadržaj u `README.md` u root direktorijumu projekta.

---

## Sadržaj projekta (preporučena struktura)

```
steganography_project/
├── README.md                <- ovaj fajl
├── requirements.txt
├── main.py
├── server.py
├── client.py
├── stego.py
├── crypto_utils.py
├── utils.py
├── users/                   <- automatski pravi klijent (users/<username>/received)
├── logs/                    <- (opciono) logs/events.log ako koristite utils.write_log
├── examples/
│   ├── sample.png
│   └── msg.txt
└── output/                  <- opciono za CLI stego
```

> Napomena: u `users/` se stvaraju foldere za svakog korisnika (npr. `users/milan/received/`) — primljeni fajlovi od drugih korisnika se spremaju tamo.

---

## Zahtevi / instalacija

**Preporuka:** koristi `venv` (izolovano okruženje).

### 1) Napravi i aktiviraj virtuelno okruženje

**Windows — PowerShell**

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Windows — CMD**

```cmd
python -m venv venv
venv\Scripts\activate
```

**Linux / macOS**

```bash
python3 -m venv venv
source venv/bin/activate
```

### 2) `requirements.txt` (kopiraj u svoj projekat)

```text
fastapi>=0.95.0
uvicorn>=0.22.0
websockets>=11.0
pynacl>=1.5.0
Pillow>=9.0.0
cryptography>=41.0.0
```

Instaliraj:

```bash
pip install --upgrade pip
pip install -r requirements.txt
```

---

## Koji fajlovi ti trebaju (kratko objašnjenje)

* **server.py** — signaling WebSocket server (FastAPI + uvicorn). Prosleđuje poruke i fajl-čankove između klijenata.
* **client.py** — tkinter GUI klijent (registrovanje, roster, slanje poruka, slanje fajlova/stego u chunkovima, prijem i skladištenje u `users/<username>/received/`).
* **main.py** — CLI wrapper (može startovati server, pokrenuti GUI, i sadrži CLI `embed`/`extract` komande).
* **stego.py** — LSB embedding/extraction + paket (MAGIC, verzija, meta, payload). (Obavezno: koristi PNG/BMP; ne JPEG)
* **crypto_utils.py** — PBKDF2 + AES-GCM enkripcija/dekripcija za payload-ove.
* **utils.py** — pomoćne funkcije (npr. `now_iso`, `write_log`), opcionalno.
* **requirements.txt** — zavisnosti (gore).

Ako ti nedostaju `stego.py` ili `crypto_utils.py` — obavezno ih dodaš (ili tražiš od mene kompletan kod).

---

## Brzi start

1. Aktiviraj venv i instaliraj zavisnosti (vide gore).
2. Pokreni server (u jednom terminalu):

```bash
python main.py server --port 8765
# ili direktno:
uvicorn server:app --host 0.0.0.0 --port 8765
```

3. Pokreni dva klijenta (u dva različita terminala ili na dve mašine). Primer:

```bash
python main.py gui --username milan
python main.py gui --username ana
```

4. U GUI:

   * klikni **Join sobu** (oba korisnika u istoj sobi),
   * pošiljalac: **Pošalji fajl (stego)** ili **Pošalji fajl (raw)** → izaberi primaoca iz liste,
   * primalac će dobiti fajl i fajl će biti sačuvan u `users/<recipient>/received/`.

---

## Kako radi slanje fajlova (važne tačke)

* Fajlovi se **svaki** šalju samo jednom (po jednoj destinaciji) — izaberi primaoca iz roster-a.
* Fajlovi se **šifruju per-peer** pomoću PyNaCl `Box` (E2E) pre nego što se šalju (metapodaci + svaki chunk).
* Veliki fajlovi / slike se **rade u chunkovima** (podrazumevano `CHUNK_SIZE = 128 KB`) i šalju se kao više `file` poruka sa poljima:

  * `msg_id` — jedinstveni ID poruke (svi chunkovi iste poruke imaju isti `msg_id`),
  * `chunk_index`, `chunk_total`, `is_last`.
* Server je "dumb forwarder" — prima poruke i prosleđuje ih primaocu (ne skladišti fajl).
* Primalac sklapa chunkove u `users/<recipient>/received/` privremeno i finalizuje fajl kad stigne poslednji chunk ili kad broj primljenih chunkova == `chunk_total`.

---

## Kako koristiti CLI stego (ako želiš iz komandne linije)

### Embed (bez enkripcije)

```bash
python main.py embed --image examples/sample.png --infile examples/msg.txt --out output/stego_sample.png --sender milan
```

### Embed (sa AES-GCM enkripcijom)

```bash
python main.py embed --image examples/sample.png --infile examples/msg.txt --out output/stego_enc.png --password tajnal0zinka --sender milan
```

### Extract

```bash
python main.py extract --image output/stego_enc.png --out output/ --password tajnal0zinka
```

> Napomena: CLI `embed`/`extract` koristi iste `stego.py` i `crypto_utils.py`. Ako GUI koristi stego, koristi se ista logika.

---

## Folder za primljene fajlove

Svi primljeni fajlovi se čuvaju u:

```
users/<username>/received/
```

Primedbe:

* Novi folder se kreira pri pokretanju klijenta (`os.makedirs(..., exist_ok=True)`).
* Pri zapisu se koristi sigurna funkcija `_safe_filename` (basename) — nema path traversal.
* Ako postoji konflikt imena, prvo se generiše jedinstveno ime sa sufiksom `_1`, `_2`, ...

---

## Logs i forenzika

Ako koristiš `utils.write_log` u `stego.py` i drugim mestima, očekuj logove u:

```
logs/events.log
```

Logovi sadrže JSON linije sa `time`, `event` i detaljima (embed, extract, received, sent).

---

## Troubleshooting — česte greške i rešenja

* **`ConnectionClosedError: received 1009 (message too big)`**
  Rešenje: koristimo chunking; ako još uvek imaš grešku (ako koristiš custom server ili neopterećen environment), možeš podići WebSocket limit pri pokretanju uvicorn-a:

  ```bash
  uvicorn server:app --host 0.0.0.0 --port 8765 --ws-max-size 33554432
  ```

  Ali chunking je preporučeno rešenje jer radi i kroz reverse-proxy.

* **Fajl završava u folderu pošiljaoca**
  Uzrok: raniji bug (klijent nije pravilno slao `to` ili je primalac koristio pogrešan path). Rešenje: koristi najnovije `client.py` koje pravi i čuva fajl u `users/<recipient>/received/` (primaoc sklapa chunkove lokalno).

* **GUI se ruši pri otvaranju fajla (tkinter crash)**
  Rešenje: najnovije verzije vrše sve UI pozive unutar glavnog GUI thread-a (`root.after(...)`) i hvataju greške. Ako se ruši i dalje, proveri trace u terminalu za konkretnu grešku i prosledi mi.

* **Problemi sa aktivacijom venv u PowerShell-u**
  Ako dobiješ poruku o blokiranim skriptama, pokreni:

  ```powershell
  Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
  ```

  (ili koristi CMD `venv\Scripts\activate`).

* **Port je zauzet**
  Promeni port prilikom startanja servera:

  ```bash
  python main.py server --port 9000
  ```

* **`ModuleNotFoundError`**
  Uveri se da si aktivirao virtualno okruženje i instalirao `requirements.txt`.

---

## Sigurnosne napomene

* LSB steganografija nije robustna protiv detekcije i nije pogodno za sigurnu komunikaciju samostalno. Koristi enkripciju (AES-GCM) za tajne podatke.
* Lozinke ne čuvamo — ako izgubiš lozinku, ne možeš dekriptovati AES-GCM payload.
* Ne koristite JPEG za LSB embedding (kompresija uništava skrivene podatke). Koristi **PNG** ili **BMP**.
* Ne prihvataj fajlove iz nepouzdanih izvora bez dodatne provere — fajl može sadržati zlonamerni sadržaj.

---

## Testni scenario (korak-po-korak)

1. Pokreni server:

   ```bash
   python main.py server --port 8765
   ```

2. Pokreni dva klijenta:

   ```bash
   python main.py gui --username milan
   python main.py gui --username ana
   ```

3. U GUI oba: klik `Join sobu`.

4. Ana šalje fajl Milanu:

   * Ana → **Pošalji fajl (stego)** → izaberi cover PNG → izaberi `examples/msg.txt` → izaberi primaoca (`milan`) → potvrdi enkripciju ako želiš.
   * Ana će videti log „Poslat stego fajl ... (chunks=N)“.

5. Milan će primiti poruke (chunkove), prikazati log „Kompletan fajl primljen ...“ i fajl će se naći u `users/milan/received/`.

6. Milan može u GUI izabrati `Prikaži primljene` → `Extract stego` → uneti lozinku (ako je enkriptovano) → fajl će biti dekriptovan i sačuvan.

---

## Dodatne opcije i unapređenja (predlozi)

* ACK + retransmisija: potvrde po chunk-u za pouzdanost (trenutno nema retransmisije ako neki chunk izgubiš).
* Multi-recipient send: omogućiti pošiljanje istog fajla paralelno više korisnika (trenutno po jednom primaocu).
* Verifikacija integriteta: uključivanje HMAC-a nad celim fajlom ili niza chunkova.
* DCT/DWT stego: umesto LSB, za veću otpornost protiv detekcije (zahteva drugačiju implementaciju).

---

