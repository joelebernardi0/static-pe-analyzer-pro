# 🛡️ Static PE Analyzer PRO  
Analizzatore statico di file PE (EXE/DLL) con integrazione VirusTotal  
_By Joele_
---

![image alt](https://github.com/joelebernardi0/static-pe-analyzer-pro/blob/2e105e37404bcc578bc9caac641d261bc52323f1/Screenshot%202026-05-19%20142736.png)

---

## 📌 Descrizione del progetto

**Static PE Analyzer PRO** è uno strumento avanzato per l’analisi statica di file PE (Portable Executable) su Windows.  
È progettato per essere:

- 🔍 **Utile per analisti SOC / Malware Analyst**
- 🎨 **Elegante e leggibile grazie alla grafica Rich**
- ⚡ **Veloce e leggero**
- 🌐 **Integrato con VirusTotal**
- 🧠 **Dotato di un sistema di scoring intelligente**
---

![image alt](https://github.com/joelebernardi0/static-pe-analyzer-pro/blob/2e105e37404bcc578bc9caac641d261bc52323f1/Screenshot%202026-05-19%20142803.png)

---

Il tool analizza:

- Hash (MD5, SHA1, SHA256)
- Header PE
- Sezioni + entropia
- Import / Export
- Stringhe ASCII/Unicode
- Firma digitale (Authenticode)
- Version Info
- Indicatori sospetti (API, URL, registry, networking, crypto, injection)
- Whitelist Microsoft (riduzione falsi positivi)
- VirusTotal (malicious / suspicious / harmless)
---

![image alt](https://github.com/joelebernardi0/static-pe-analyzer-pro/blob/2e105e37404bcc578bc9caac641d261bc52323f1/Screenshot%202026-05-19%20142748.png)

---

## 🧩 Funzionalità principali

### ✔️ Analisi PE completa
```cmd
- Entry Point
- Image Base
- Numero sezioni
- Timestamp
- Dimensione immagine
```

✔️ Analisi sezioni

```cmd
- Nome sezione
- Virtual Size
- Raw Size
- Entropia (rilevamento packer)
- Characteristics
```

✔️ Import / Export

```cmd
- DLL importate
- Funzioni importate
- Funzioni esportate
```

✔️ Stringhe

```cmd
- ASCII
- Unicode
- URL
- Comandi PowerShell / CMD
- Indicatori di rete
- Indicatori registry
- Indicatori crypto
```
✔️ Firma digitale

```cmd
- Signed: Yes/No
- Riduzione punteggio se firmato
```

✔️ Version Info

```cmd
- CompanyName
- ProductName
- FileDescription
```

✔️ VirusTotal Integration

```cmd
- Malicious
- Suspicious
- Harmless
- Undetected
- Link al report
```

✔️ Sistema di scoring intelligente
Basato su:

API sospette

Stringhe sospette

Entropia alta

Firma digitale

Version info

DLL di sistema

Sezioni standard

VirusTotal

🧠 Sistema di classificazione
Punteggio	Classificazione
0–24	🟢 LIKELY CLEAN
25–59	🟡 SUSPICIOUS
60–100	🔴 HIGHLY SUSPICIOUS

📦 Installazione

1️⃣ Clona il progetto

```cmd
git clone https://github.com/tuo-username/StaticPEAnalyzer
cd StaticPEAnalyzer
```

2️⃣ Crea un ambiente virtuale

```cmd
python -m venv venv
venv\Scripts\activate
```

3️⃣ Installa le dipendenze

```cmd
pip install -r requirements.txt
```

4️⃣ Inserisci la tua API key VirusTotal

Modifica config.py:

```python
VT_API_KEY = "LA_TUA_API_KEY"
```
🚀 Utilizzo
▶️ Modalità interattiva

```cmd
python main.py
```

▶️ Modalità CLI

```cmd
python main.py --scan C:\Windows\System32\notepad.exe
```

▶️ Disabilitare VirusTotal

```cmd
python main.py --scan file.exe --no-vt
```

📁 Struttura del progetto
```cmd
StaticPEAnalyzer/
│
├── analyzer.py        # Logica di analisi PE
├── main.py            # Menu + CLI
├── utils.py           # Grafica + report
├── vt.py              # Integrazione VirusTotal
├── config.py          # API key (NON caricare su GitHub)
├── requirements.txt   # Dipendenze
└── reports/           # Report TXT + JSON generati
```

## 🏁 Conclusione

Static PE Analyzer PRO rappresenta un progetto completo e professionale pensato per attività di **analisi statica**, **threat hunting** e **malware triage**.  
L’obiettivo è fornire uno strumento leggero ma potente, capace di estrarre rapidamente informazioni critiche da file PE e di supportare l’analista nelle prime fasi di valutazione di un potenziale artefatto malevolo.

Grazie a:

- integrazione con **VirusTotal**
- sistema di **scoring intelligente**
- analisi approfondita di **header, sezioni, import/export e stringhe**
- rilevamento di **indicatori sospetti**
- riduzione dei falsi positivi tramite **whitelist Microsoft**
- generazione automatica di **report TXT e JSON**
- interfaccia **CLI** e **interattiva** con grafica Rich

il progetto si propone come un valido strumento per ambienti SOC, laboratori di malware analysis e percorsi formativi in cybersecurity.

Questo repository è stato realizzato per consolidare competenze tecniche, dimostrare capacità di sviluppo di strumenti di analisi e offrire un esempio concreto di lavoro orientato alla sicurezza informatica.  
Il progetto è in continua evoluzione: ogni suggerimento, miglioramento o contributo è benvenuto.

> 🔒 **Nota:** l’integrazione VirusTotal richiede una API key personale, che non deve essere condivisa o caricata pubblicamente.

Se questo strumento ti è utile, lascia una ⭐ sul repository.  
Grazie per aver esplorato Static PE Analyzer PRO.


