```markdown
# SecureTalk — steganografija + end-to-end šifrovanje

**Opis (kratko)**
SecureTalk je edukativni/studentski projekat za bezbednu razmenu tekstualnih poruka i fajlova preko WebSocket servera. Kombinuje:

* End-to-end enkripciju transporta poruka i chunkova fajlova (NaCl `Box`),
* Podršku za više steganografskih algoritama (npr. `LSB`, `LSB2`, `PVD`, `DCT`, `DWT`) za skrivanje fajlova unutar slika,
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
├── stego_debug.py           # Debug alat za proveru embedovanih podataka
├── crypto_utils.py          # AES-GCM util funkcije
├── utils.py                 # Pomoćne funkcije (logovi, itd.)
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
* Dodati novi algoritmi: LSB2 (2 bita po kanalu) i DWT (Discrete Wavelet Transform za bolju robustnost).
* Ispravke za DCT i PVD: Bolji clamping, scale, i fallback da se smanji korupcija podataka.

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

* **Format:** `XXX<cover_filename>`, gde `XXX` = prva tri slova skraćenice algoritma, velika slova (npr. `LSB`, `LSB2`, `PVD`, `DCT`, `DWT`).
* Sender treba da poštuje ovu konvenciju kada kreira izlaznu stego sliku. Primatelj će:

  1. prvo pokušati `meta['algorithm']`,
  2. ako nema meta, uzeti prvih 3 znaka imena primljenog fajla i uporediti s listom poznatih algoritama,
  3. ako je validan prefix → pokušati ekstrakciju sa tim algoritmom.

---

## Zahtevi i instalacija

Preporučeno: **Python 3.10+**

### Preporučeni `requirements.txt` (primer)

```
Pillow>=9.0.0
cryptography>=41.0.0
websockets>=11.0.0
pynacl>=1.5.0
numpy>=1.24.0
sounddevice>=0.4.6
fastapi>=0.95.0
uvicorn>=0.22.0
scipy>=1.10.0
pywt>=1.4.1  # Za DWT
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
pip install pillow cryptography websockets pynacl numpy sounddevice fastapi uvicorn scipy pywt
```

---

## Pokretanje

### Server

Server je WebSocket forwarder / room manager (najčešće FastAPI + websockets).

```bash
python main.py server --port 8765
```

U logu treba biti:

```
[SERVER] Starting uvicorn on 0.0.0.0:8765
Uvicorn running on http://0.0.0.0:8765
```

### GUI klijent (preko `main.py`)

```bash
python main.py gui --username milan
```

ili:

```bash
python main.py gui --username ana
```

**Napomena:** GUI klijent automatski kreira folder `users/<username>/received/` i `users/<username>/` za privremene fajlove i izlazne stego slike.

---

## Konfiguracije (bitne varijable)

* `SERVER_WS_TEMPLATE = "ws://{host}:{port}/ws"` — promeni host/port po potrebi.
* `CHUNK_SIZE = 128 * 1024` — veličina chunk-a; možeš povećati smanjiti zavisno od mreže.
* `ALGORITHMS` — lista podržanih algoritama u `stego.py`: `{"LSB":..., "LSB2":..., "PVD":..., "DCT":..., "DWT":...}`

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

## Testiranje

Pripremi fajlove u `./Test/` folderu: `cover.png` (velika slika, npr. sa Unsplash-a) i `secret.txt` (mali tekst fajl).

### CLI testovi (embed + extract)

```bash
# LSB
python main.py embed --image ./Test/cover.png --infile ./Test/secret.txt --out ./Test/stego_LSB.png --algorithm LSB
python main.py extract --image ./Test/stego_LSB.png --out extracted/ --algorithm LSB

# DCT
python main.py embed --image ./Test/cover.png --infile ./Test/secret.txt --out ./Test/stego_DCT.png --algorithm DCT
python main.py extract --image ./Test/stego_DCT.png --out extracted/ --algorithm DCT

# PVD
python main.py embed --image ./Test/cover.png --infile ./Test/secret.txt --out ./Test/stego_PVD.png --algorithm PVD
python main.py extract --image ./Test/stego_PVD.png --out extracted/ --algorithm PVD

# LSB2
python main.py embed --image ./Test/cover.png --infile ./Test/secret.txt --out ./Test/stego_LSB2.png --algorithm LSB2
python main.py extract --image ./Test/stego_LSB2.png --out extracted/ --algorithm LSB2

# DWT
python main.py embed --image ./Test/cover.png --infile ./Test/secret.txt --out ./Test/stego_DWT.png --algorithm DWT
python main.py extract --image ./Test/stego_DWT.png --out extracted/ --algorithm DWT
```

### Sa lozinkom

```bash
python main.py embed --image ./Test/cover.png --infile ./Test/secret.txt --out ./Test/stego_enc.png --algorithm DCT --password tajna123
python main.py extract --image ./Test/stego_enc.png --out extracted/ --algorithm DCT --password tajna123
```

### Autodetect

```bash
python main.py extract --image ./Test/stego_DCT.png --out extracted/
```

### Debug tool

```bash
python stego_debug.py ./Test/stego_DCT.png
```

### Server + klijenti

```bash
# Server
python main.py server --port 8765

# Klijent 1 (u novom terminalu)
python main.py gui --username milan

# Klijent 2 (u još jednom terminalu)
python main.py gui --username ana
```

Pošalji poruke/fajlove iz GUI-a i provjeri received folder.

---

## Troubleshooting — često viđeni problemi

### 1) `Extraction failed: Ne postoji magic header (nije STG)`

* **Uzrok:** MAGIC bajtovi (`STG0`) nisu nađeni u ekstrahovanom stream-u — embed nije uspešan ili podatci korumpirani.
* **Rešenje:** Koristi `stego_debug.py` da provjeriš MAGIC offsets. Ako nema, povećaj `scale` u DCT embed-u (u `stego.py`) na manju vrijednost (npr. 50) da bitovi budu jače embedovani.

### 2) `DWT embedding failed: could not broadcast input array`

* **Uzrok:** Dimenzije slike nisu parne (za Haar wavelet).
* **Rešenje:** Dodan padding u `stego.py` — provjeri ažurirani kod.

### 3) `PVD/DCT clamping warning u logu`

* **Uzrok:** Pikseli prelaze 0-255 nakon embeda.
* **Rešenje:** Dodan fallback u PVD; za DCT smanji scale.

### 4) File chunkovi se ne sastave / nedostaju chunkovi

* Proveri server log (treba da vidiš `Forwarded file chunk` za svaki chunk).
* Proveri `chunk_total` i `chunk_index` koje šalješ.
* Proveri `max_size` parametar prilikom `websockets.connect()` u klijentu/serveru.

### 5) Želim da logovi ne idu u chat (samo u konzolu / poseban panel)

* Po defaultu klijent koji ti je poslan stavlja debug/log poruke u **log panel** (desno) i u konzolu (`print()`). Chat polje sadrži isključivo dekriptovane poruke i sistemske kratke notifikacije.
* Ako želiš da potpuno ukloniš log panel, izbriši UI element koji prikazuje log ili zameni `_log()` sa običnim `print()` i obriši upis u chat widget.

---

## Provera kompatibilnosti DCT <-> PNG/JPEG

* Ako implementacija DCT u `stego.py` radi sa block DCT / JPEG-like transformacijama, onda:

  * **Koristi JPEG kao cover** prilikom embedovanja DCT stega.
  * Ako želiš rad sa PNG, trebа refaktorisati DCT embed/extract da radi nad raster podacima pravilno.
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

## Licence

MIT Licence
---
```