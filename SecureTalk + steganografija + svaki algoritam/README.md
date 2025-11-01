# SecureTalk — steganografija + end-to-end šifrovanje

**Opis (kratko)**
SecureTalk je edukativni/studentski projekat za bezbednu razmenu tekstualnih poruka i fajlova preko WebSocket servera. Kombinuje:

* End-to-end enkripciju transporta poruka i chunkova fajlova (NaCl `Box`),
* Podršku za više steganografskih algoritama (npr. `LSB`, `PVD`, `DCT`) za skrivanje fajlova unutar slika,
* Opcionu AES-GCM enkripciju za sam *payload* (sadržaj) koji je ugrađen u stego sliku,
* Tkinter GUI klijent (chat + kontrola slanja/primanja + poseban log panel).

Ovaj README je spreman za skidanje i direktnu upotrebu.

---

## Sadržaj repo-a (primer)

```
.
├── server.py                # WebSocket / FastAPI server (uvicorn)
├── main.py                  # Entrypoint (gui / cli) — pokretanje klijenta
├── client.py                # GUI klijent (Tkinter) — možeš copy/paste-ovati
├── stego.py                 # Implementacija embed/extract i API funkcije
├── crypto_utils.py          # AES-GCM util funkcije
├── requirements.txt         # Preporučene biblioteke
├── README.md                # Ovaj fajl
└── users/                   # (generiše se) users/<username> + received/
```

---

## Glavne osobine

* E2E enkriptovane chat poruke koristeći NaCl `Box` (Curve25519).
* Slanje fajlova chunk-ovano preko WebSocket-a (svaki chunk zasebno šifrovan Box-om).
* Izrada stego slika iz cover slike + input fajla (`embed_file`).
* Prefiks od 3 slova u imenu izlazne stego slike (npr. `LSBcover.png`, `DCTphoto.jpg`) — koristi se kao hint za automatsku ekstrakciju na prijemu.
* GUI ima dva panela: lijevo *chat* (samo stvarne poruke) i desno *log* (debug/status) — logovi ne zatrpavaju chat.

---

## Primjer workflowa (kako zapravo radi)

1. **Registracija/Parovi:**

   * Klijent se povezuje na server (`ws://<host>:<port>/ws`).
   * Generišu se lokalni ključevi (DH/NaCl i Signing).
   * Server distribuira javne ključeve ostalim članovima sobe → svaki klijent stvara `Box` sesiju prema drugima.

2. **Slanje tekstualne poruke (E2E):**

   * Poruka se enkriptuje zasebno za svakog primaoca koristeći njihov `Box`.
   * Poslata poruka na server sadrži `cipher` za svakog primaoca.

3. **Slanje raw fajla (bez stega):**

   * Fajl se čita i deli u CHUNK_SIZE (default 128 KB).
   * Svaki chunk se `box.encrypt` i šalje kao `file` tip poruke zajedno sa `cipher_meta` (meta je isto `box.encrypt`-ovana): meta sadrži barem `filename`.

4. **Slanje stego fajla:**

   * Sender poziva `embed_file(cover_image, input_file, output_image, algorithm=...)`.
   * Output image se daje imenu sa prefiksom kojim se označava algoritam: `ALG + original_cover_basename` (npr. `PVDwallpaper.png`).
   * Taj output image se šalje chunk-ovano iste kao raw fajl. Meta sadrži `filename` i `algorithm` (najbolje).

5. **Priemanje fajla i ekstrakcija:**

   * Primljeni chunkovi se sastave u `users/<username>/received/recv_<filename>`.
   * Kada je kompletan fajl, klijent:

     * prvo pokuša ekstrakciju koristeći `meta['algorithm']` (ako postoji),
     * ako ne postoji, proveri **prefix** prvih 3 slova datog imena (pretvori u velika slova) i ako je u listi poznatih algoritama — koristi ga,
     * ako ni to ne pomogne, pokuša autodetect (ako `stego.extract_bytes_from_image(..., algorithm=None)` podržava autodetect).
   * Nakon uspešne ekstrakcije vraća se metapodatak unutar stego-paketa: `{sender_id, algorithm, original_filename, payload_size, stego_algorithm, crypto, ...}` i payload bajtovi.
   * Ako je `crypto == 'AES-GCM'`, payload je enkriptovan i treba tražiti lozinku za dekripciju.

---

## Konvencija imena fajlova i algoritamski hint

* **Format:** `XXX<cover_filename>`, gde `XXX` = prva tri slova skraćenice algoritma, velika slova (npr. `LSB`, `PVD`, `DCT`).
* Sender treba da poštuje ovu konvenciju kada kreira izlaznu stego sliku. Primatelj će:

  1. prvo pokušati `meta['algorithm']`,
  2. ako nema meta, uzeti prvih 3 znaka imena primljenog fajla i uporediti s listom poznatih algoritama,
  3. ako je validan prefix → pokušati ekstrakciju sa tim algoritmom.

---

## Zahtevi i instalacija

Preporučeno: **Python 3.10+**

### Preporučeni `requirements.txt` (primer)

```
websockets>=10.0
pynacl>=1.5.0
uvicorn
fastapi
pillow
numpy
scipy
cryptography
```

### Koraci

```bash
# 1) kloniraj projekat
git clone <repo-url>
cd SecureTalk

# 2) virtualenv (preporučeno)
python -m venv venv
# Windows:
venv\Scripts\activate
# macOS / Linux:
source venv/bin/activate

# 3) instaliraj zavisnosti
pip install -r requirements.txt
```

Ako nemaš `requirements.txt`, instaliraj ručno:

```bash
pip install websockets pynacl pillow numpy scipy cryptography uvicorn fastapi
```

---

## Pokretanje

### Server

Server je WebSocket forwarder / room manager (najčešće FastAPI + websockets).
Ako `server.py` izlaže `app` objekt (FastAPI) — koristi uvicorn:

```bash
uvicorn server:app --host 0.0.0.0 --port 8765 --reload
```

Ili upravo:

```bash
python server.py
```

U logu treba biti:

```
[SERVER] Starting uvicorn on 0.0.0.0:8765
Uvicorn running on http://0.0.0.0:8765
```

### GUI klijent (preko `main.py`)

U logovima si ranije koristio:

```bash
python main.py gui --username milan
```

ili:

```bash
python main.py gui --username ana
```

Ako koristiš direktno `client.py` (ako `main.py` samo kreće GUI iz tog fajla), možeš uraditi:

```bash
python client.py
# (ili izmeniti __main__ u client.py da prihvati args)
```

**Napomena:** GUI klijent automatski kreira folder `users/<username>/received/` i `users/<username>/` za privremene fajlove i izlazne stego slike.

---

## Konfiguracije (bitne varijable)

* `SERVER_WS_TEMPLATE = "ws://{host}:{port}/ws"` — promeni host/port po potrebi.
* `CHUNK_SIZE = 128 * 1024` — veličina chunk-a; možeš povećati smanjiti zavisno od mreže.
* `ALGORITHMS` — lista podržanih algoritama u `stego.py`. Preporuka: `{"LSB":..., "PVD":..., "DCT":...}`

---

## Example: poruka tipa `file` (meta + chunk)

Meta (pre enkripcije sa Box-om) — JSON:

```json
{
  "filename": "DCTwallhaven-9djgpk.png",
  "algorithm": "DCT"
}
```

Server prima potpuno šifrovane chunkove i samo ih preusmerava — server ne vidi sadržaj.

---

## Troubleshooting — često viđeni problemi

### 1) `Extraction with DCT failed: 'utf-8' codec can't decode byte ...`

Mogući uzroci:

* **Payload je enkriptovan AES-GCM** → ekstrakcija vraća bajtove koji nisu UTF-8. Proveri `md_inner['crypto']`. Ako je `AES-GCM`, moraš dekriptovati pomoću salt/iv/lozinke.
* **DCT očekuje JPEG**: Implementacije koje koriste block-DCT (8x8) uglavnom rade nad JPEG kodiranim podacima. Ako šalješ **PNG** cover slike a DCT implementacija u `stego.py` radi kao za JPEG, može doći do greške. Rešenje: koristite JPEG cover za DCT ili izmeni implementaciju tako da radi nad raster podacima pravilno.
* **Nije ubačen stego paket DCT algoritmom** — proveri da li sender stvarno koristio `DCT` kada je embedovao (meta / filename prefix treba da to potvrdi).

### 2) File chunkovi se ne sastave / nedostaju chunkovi

* Proveri server log (treba da vidiš `Forwarded file chunk` za svaki chunk).
* Proveri `chunk_total` i `chunk_index` koje šalješ.
* Proveri `max_size` parametar prilikom `websockets.connect()` u klijentu/serveru.

### 3) Želim da logovi ne idu u chat (samo u konzolu / poseban panel)

* Po defaultu klijent koji ti je poslan stavlja debug/log poruke u **log panel** (desno) i u konzolu (`print`). Chat polje sadrži isključivo dekriptovane poruke i sistemske kratke notifikacije.
* Ako želiš da potpuno ukloniš log panel, izbriši UI element koji prikazuje log ili zameni `_log()` sa običnim `print()` i obriši upis u chat widget.

---

## Provera kompatibilnosti DCT <-> PNG/JPEG

* Ako implementacija DCT u `stego.py` radi sa block DCT / JPEG-like transformacijama, onda:

  * **Koristi JPEG kao cover** prilikom embedovanja DCT stega.
  * Ako želiš rad sa PNG, trebа refaktorisati DCT embed/extract da radi nad pixel matricama (i obezbediti invertibilnost).
* Brzo testiranje: lokalno pozovi `embed_file(...)` i odmah `extract_bytes_from_image(...)` nad istom slikom — ako radi lokalno, problem nije mreža.

---

## Sigurnosne napomene

* Projekat je edukativan — ne koristi ga kao jedinu zaštitu za izrazito osetljive podatke bez dodatnih mera.
* NaCl Box osigurava transportnu enkripciju, ali:

  * Server i klijenti ne vrše dodatnu autentifikaciju korisnika (može se proširiti).
  * Ključevi su generisani i drže se u procesu — po potrebi dodaj perzistentno skladištenje.

---

## Kako doprineti / razvoj

1. Fork → branch → PR.
2. Dodaj/uredi `stego.py` algoritme, pazi na API:

   ```py
   embed_file(cover_path, infile_path, out_img_path, algorithm='DCT', encrypt_password=None, metadata_extra={})
   md, payload_bytes = extract_bytes_from_image(path, algorithm=None)
   ```
3. Testiraj lokalno uz dva klijenta i server.

---

## Primeri komandi (kratko)

**Pokreni server**

```bash
uvicorn server:app --host 0.0.0.0 --port 8765 --reload
```

**Pokreni dva GUI klijenta (u dve terminal sesije)**

```bash
python main.py gui --username milan
python main.py gui --username ana
```

**Pošalji stego fajl iz GUI-a**

1. `Pošalji fajl (stego)` → izaberi cover (PNG/JPEG) → izaberi fajl za skrivanje (npr. `msg.txt`) → izaberi algoritam (LSB/PVD/DCT) → izaberi recipient → fajl će biti poslat.

---

## FAQ (kratko)

**Kako klijent zna koji algoritam da upotrebi za ekstrakciju?**

1. `meta['algorithm']` (šifrovana meta u `cipher_meta`) — NAJPOUZDANIJE.
2. Ako nema, proveri **prvih 3 slova imena fajla** (pretvoreno u velika slova) i uporedi sa `ALGORITHMS`.
3. Ako ni to ne uspe, pokušaj autodetect (ako implementirano).

**DCT ne radi samo kod mene — šta da radim?**

* Probaj cover u JPEG formatu.
* Testiraj embed+extract lokalno (bez mreže) — ako ne radi lokalno, problem je u DCT implementaciji ili u formatu slike.

---

## Licence


---
