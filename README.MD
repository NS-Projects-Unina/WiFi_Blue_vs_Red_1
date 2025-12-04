# 🛰️ Wi-Fi Camera Attack & Defense Simulation

### *Progetto Red Team vs Blue Team*

## 📌 Descrizione generale

Questo progetto realizza un ambiente controllato per simulare un attacco Wi-Fi contro una telecamera IP e le relative contromisure difensive.
L’obiettivo è analizzare **dinamiche di attacco e difesa** tra un Red Team (attaccante) e un Blue Team (difensore), concentrandosi sui pattern di traffico generati durante un tentativo di compromissione di rete e sulle strategie per rilevarli e mitigarli.

Lo scenario è composto da un **Access Point** e da un **host interno**, nel nostro caso una **webcam Wi-Fi**.


## 🔴 Red Team — Scenario di attacco (simulato)

Il Red Team utilizza un dispositivo con **Kali Linux** e un’antenna Wi-Fi basata su chipset **Realtek** (injection + monitor mode).
L’obiettivo è studiare i comportamenti della rete e della telecamera sotto condizioni anomale.

Le fasi simulate includono:

### 1️⃣ Analisi preliminare (Network reconnaissance)

* Osservazione del traffico Wi-Fi nell’area.
* Identificazione del MAC address della telecamera tramite prefisso OUI del produttore.
* Individuazione dell’Access Point a cui la telecamera è associata.

### 2️⃣ Simulazione di deauthentication

L’attaccante simula un disturbo forzando la disconnessione della telecamera tramite l’invio di pacchetti di deauthentication, producendo un pattern anomalo riconoscibile dal sistema difensivo.

### 3️⃣ Cattura del 4-way handshake

Durante la riconnessione della telecamera all’AP, vengono osservati i messaggi del processo di handshake.
Questa fase serve esclusivamente ad analizzare il comportamento della rete e non include tecniche di cracking.

### 4️⃣ Analisi del traffico video

Una volta ricreato l’ambiente di rete, vengono osservati i flussi **RTP** e **RTSP** per comprendere come il traffico video possa essere interpretato o protetto in contesti di sicurezza.

---

## 🔵 Blue Team — Sistema di Difesa

Il Blue Team impiega una **ESP32-CAM** con capacità Wi-Fi, progettata per:

### 🛡️ 1. Rilevamento di attività sospette (IDS)

* Analizza il traffico locale.
* Rileva pattern tipici di attacchi Wi-Fi, come un numero anomalo di pacchetti di deauthentication.
* Avvisa l’utente tramite un **indicatore luminoso** (LED).

### 🎭 2. Chaffing — Generazione di handshake fittizi

Il sistema genera **handshake artificiali** allo scopo di:

* aumentare il rumore nei dati osservabili dall’attaccante,
* rendere più complesso distinguere handshake validi da quelli fittizi.

### 🧪 3. Sperimentazione di “handshake poisoning”

Si testa una tecnica difensiva che introduce perturbazioni negli handshake osservabili dall’esterno, rendendo inutilizzabili (o meno affidabili) i dati raccolti da uno strumento d’attacco.

---

## 📡 Hardware utilizzato

### 🔴 *Red Team*

* Laptop/PC con **Kali Linux**
* Antenna Wi-Fi USB **Realtek** (monitor mode + packet injection)
  → *RTL8812AU 

### 🔵 *Blue Team*

* **ESP32-CAM**
* LED di stato
* Alimentazione USB / Modulo programmabile

### 🎥 Host interno

* **Telecamera Wi-Fi**

  * MAC prefix/OUI: **8C:85:80**
  * Collegata all’Access Point dedicato allo scenario

### 📶 Infrastruttura

* Access Point configurato per il laboratorio.

---

## 📊 Diagramma di Sequenza

Di seguito è previsto un diagramma di sequenza che illustra le interazioni principali tra Red Team, AP, telecamera e Blue Team, mostrando la cronologia completa dell’attacco simulato e delle tecniche difensive.

![sequencediagram](images/sequencediagram.png)


