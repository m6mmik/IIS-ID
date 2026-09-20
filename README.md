# IIS-ID: WCF + IIS + ID-kaart + TCP load balancing

Kodune lab, mis kopeerib töökeskkonna mustri: **ClickOnce / .NET 4.8 WCF klient**, ID-kaardi **PIN1 (mTLS)** ja **PIN2 (allkiri)**, **HAProxy-laadne TCP passthrough** mitme IIS backend’i ette.

Eesmärk ei ole tavaline veebileht, vaid vastata küsimusele: **kuidas selline klient käitub load balanceri taga** — millal ta jääb ühe IIS-i külge, millal hüppab teisele, ja mis peab olema identne igal Windows Serveril.

Windows 11 Home’il ei ole täis-IIS-i. Lab kasutab **kahte IIS Expressi protsessi** (`Backend1Pool`, `Backend2Pool`). TLS tuleb ikka **HTTP.sys / Schannel** kaudu, nagu päris IIS-is.

Ametlik serveripoolne juhend: [IIS veebiserverile ID-kaardi toe seadistamine](https://open-eid.github.io/iis/index.et.html).

> Enne kui seda mustrit töökeskkonda viid, loe [Enne toodangut: kriitiline nimekiri](#enne-toodangut-kriitiline-nimekiri). Lab on teadlikult lihtsustatud (allkirja formaat, poliitika-kontroll, tühistus, TLS-versioonid) ja mõni lihtsustus murdub tootmises.
>
> Kui annad selle repo mudelile ette, et võrrelda töö tegeliku seisuga: [Töö repoga võrdlemine](#töö-repoga-võrdlemine-ai-le-antav-ülesanne) — seal on maatriks, valmis prompt ja nimekiri tüüpilistest valedest soovitustest.

> Kui lab on roheline, aga toodangus on ikka viga: [Vead, mida see lab ise esile ei kutsu](#vead-mida-see-lab-ise-esile-ei-kutsu) — GPO, korporatiivproxy, HTTP/2, idle-timeout'id, Citrix, kaardi vahetus, vahemälud. Seal on ka sümptomite kiirtabel ja käsud, millega vead labis tahtlikult tekitada.

> Tööl on väljapääs vaikimisi kinni ja iga URL tuleb tellida? [Suletud võrgu lab](#suletud-võrgu-lab-lockdown-proxy-ja-windows-server-vm) teeb sama olukorra kodus: lockdown-stsenaariumid, logiv proxy (= tellimisnimekiri) ja Windows Server VM host-only võrgus.
>
> Labis 20.09.2026 läbi mängitud vead + küsimused, mida tööl küsida: [Tööl kontrollida (labi järeldused)](#tööl-kontrollida-labi-järeldused).

---

## Sisukord

1. [Arhitektuur](#arhitektuur)
2. [Mida lab tõestab](#mida-lab-tõestab)
3. [Projektid](#projektid)
4. [Ühekordne ettevalmistus](#ühekordne-ettevalmistus)
5. [Käivitamine](#käivitamine)
6. [Kliendi voog (PIN1, tavaline päring, PIN2)](#kliendi-voog-pin1-tavaline-päring-pin2)
7. [Kleepuvus: miks kõik päringud lähevad ühte backend’i](#kleepuvus-miks-kõik-päringud-lähevad-ühte-backendi)
8. [Failover: kui üks IIS sureb](#failover-kui-üks-iis-sureb)
9. [Stats-leht (Kinni / Käima)](#stats-leht-kinni--käima)
10. [Kaks Windows Serverit](#kaks-windows-serverit)
11. [403.16 vs 403.13](#40316-vs-40313) — sh [APP12 juhtum](#app12-40316-kui-root-ja-ca-näivad-korras) ja [teised 403.16 teed](#teised-40316-teed-sama-sümptom)
12. [Tööl kontrollida (labi järeldused)](#tööl-kontrollida-labi-järeldused)
13. [Toodangu IIS: ID-kaardi ahel ja paigaldus](#toodangu-iis-id-kaardi-ahel-ja-paigaldus)
14. [Täpsed IIS seaded](#täpsed-iis-seaded)
15. [URL-id, mida IIS peab kätte saama (AIA / OCSP / CRL)](#url-id-mida-iis-peab-kätte-saama-aia--ocsp--crl)
16. [WCF Web.config proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp)
17. [HAProxy (passthrough, kaks kihti)](#haproxy-passthrough-kaks-kihti)
18. [Diagnostika: üks koht, kust vaadata](#diagnostika-üks-koht-kust-vaadata)
19. [PIN1 järel ebaõnnestumine: skriptid ja logid](#pin1-järel-ebaõnnestumine-skriptid-ja-logid)
20. [lab.ps1 käsud](#labps1-käsud)
21. [URL-id ja pordid](#url-id-ja-pordid)
22. [Terraform ja Ansible](#terraform-ja-ansible)
23. [Enne toodangut: kriitiline nimekiri](#enne-toodangut-kriitiline-nimekiri)
24. [Vead, mida see lab ise esile ei kutsu](#vead-mida-see-lab-ise-esile-ei-kutsu)
25. [Suletud võrgu lab: lockdown, proxy ja Windows Server VM](#suletud-võrgu-lab-lockdown-proxy-ja-windows-server-vm)
26. [Töö repoga võrdlemine (AI-le antav ülesanne)](#töö-repoga-võrdlemine-ai-le-antav-ülesanne)
27. [Seos töökeskkonnaga](#seos-töökeskkonnaga)
28. [Docker HAProxy](#docker-haproxy)
29. [Tõrkeotsing](#tõrkeotsing)

---

## Arhitektuur

TLS-i **lab ei ava**. Balancer näeb ainult TCP baite. PIN1 sertifikaat liigub kätlusel otse kliendist IIS-i / HTTP.sys-i.

```
WinForms klient  (.NET 4.8, WCF wsHttpBinding, Transport + Certificate)
        |
        |  HTTPS  demo.local:9443/Demo.svc
        |  (mTLS: PIN1 sertifikaat TLS kätlusel)
        v
TCP passthrough LB
  Demo.LoadBalancer  või  HAProxy mode tcp
  stats http://127.0.0.1:8404/
        |
        |  valib ühe elus backend’i uue TCP peale
        |  (round-robin või source; health HTTP, mitte 443)
        |
        +-- Backend1  HTTPS :8443  mTLS + WCF Demo.svc
        |              health GET http://127.0.0.1:8080/health.json
        |
        +-- Backend2  HTTPS :8444  mTLS + WCF Demo.svc
                       health GET http://127.0.0.1:8081/health.json
```

Tööl on sama loogika, ainult masinad on eraldi:

```
klient  →  väline HAProxy (TCP)  →  sisemine HAProxy (TCP)  →  IIS VM1
                                                           →  IIS VM2
```

Kui IIS vastab **403.16**, jõudis kliendisertifikaat masinasse. Siis ei ole probleem SSL termination vs passthrough — probleem on **selle Windows Serveri** usaldusahelas.

---

## Mida lab tõestab

| Teema | Tulemus |
|---|---|
| PIN1 | Autentimine on TLS kätlus. ID-kaart küsib PIN1. Lab-sertifikaat PIN-i ei küsi. |
| Tavaline päring | Pärast sisselogimist `Ping` **ilma PIN1/PIN2-ta**, sama TCP/TLS kanal. |
| PIN2 | Allkiri tehakse **kliendi masinas**. Serverile läheb juba allkirjastatud bait. PIN2 ei osale load balancingus. |
| Kleepuvus | Keep-Alive: kõik kutsed ühel kanalil jäävad **samasse IIS-i**, isegi kui balancer on round-robin. |
| Failover | Kinni pandud backend: vana kanal sureb, klient avab uue TCP, LB saadab elus masinasse. Kasutaja näeb lihtsalt õnnestunud päringut. |
| Health | Eraldi HTTP-port **ilma** kliendisertifikaadita. CRL/OCSP ei tohi health’i tappa. |
| 403.16 | Sertifikaat jõudis IIS-i, ahel ei ole usaldatud. See ei ole vale nupujärjekord. |
| Diagnostika | „Anonymous“ vea taga olev päris alamstaatus tuleb kätte ühe käsuga: `.\lab.ps1 probe` või `.\lab.ps1 report`. |

WCF teenus **ei hoia serveris seanssi**. Iga `WhoAmI` / `Ping` / `SubmitSignature` loeb PIN1 sertifikaadi uuesti sellest TLS-ühendusest. Seetõttu võib failover töötada ilma uuesti “Logi sisse” nuputa: klient mäletab sisselogimist, uus kätlus saadab sama serti.

---

## Projektid

| Projekt | Roll |
|---|---|
| `src/Demo.Contracts` | WCF leping (`WhoAmI`, `Ping`, `SubmitSignature`), ESTEID OID-d, sertifikaadi parser |
| `src/Demo.Service` | IIS-hosted WCF (`Demo.svc`), `health.json` |
| `src/Demo.Client` | WinForms: PIN1, tavaline päring, PIN2; kanal + failover |
| `src/Demo.LoadBalancer` | TCP passthrough (HAProxy analoog kodus) |
| `src/Demo.Host` | WCF self-host, kui IIS Express puudub |
| `src/Demo.CertProbe` | Diagnostikakuulaja: võtab iga kliendiserdi vastu ja ütleb, miks IIS 403.16 annaks |
| `lab.ps1` | build, start, Kinni/Käima, certs, bind |
| `backends.txt` | milliste hostide/portide peale LB suunab |
| `haproxy/haproxy.cfg` | sama muster Dockeris / töö HAProxy jaoks |
| `scripts/` | HTTP.sys, lab-CA, toodangu ESTEID paigaldus, PIN1 diagnostika, IIS Express config |

Lahendus on **.NET Framework 4.8** (`IIS-ID.slnx`).

---

## Ühekordne ettevalmistus

Repo juurkaustas:

```powershell
.\lab.ps1 certs
```

Loob lab-CA, serveri sertifikaadi nimele `demo.local` ja tarkvaralised PIN1/PIN2 test-sertifikaadid (CurrentUser\My).

Seejärel **Administrator** PowerShellis:

```powershell
.\lab.ps1 bind
```

See:

- usaldab lab-CA juurika (`Root`, `CA`, `ClientAuthIssuer`)
- seob serveri serti HTTP.sys-iga portidel **8443** ja **8444**
- paneb `clientcertnegotiation=enable` (kliendisertifikaat TLS kätlusel, sh TLS 1.3)
- keelab labis tühistuskontrolli (`verifyclientcertrevocation=disable`)
- seab Schannel `ClientAuthTrustMode=2`
- lisab `urlacl` HTTP health-portidele
- lisab `127.0.0.1 demo.local` hosts-faili

Päris ID-kaardiga (valikuline, Administrator):

```powershell
.\lab.ps1 eid-ca
```

Paigaldab `certs/eid-ca/` failid: `EE-GovCA2018`, `EEGovCA2025` juurikasse; `ESTEID2018`, `ESTEID2025` Intermediate **ja** Client Authentication Issuers hoidlasse. Lisa ka [ID-tarkvara](https://www.id.ee/artikkel/paigalda-id-tarkvara/).

Labi `Web.config` on `RevocationMode=NoCheck`. Toodangus pane WCF-is soovi korral `Online` **ja** sea WinHTTP igal IIS-il (mitte ainult `Web.config` proxy URL). Täpsustus: [WCF Web.config proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp).

---

## Käivitamine

```powershell
.\lab.ps1 start
.\lab.ps1 client
```

`start` kompileerib, kirjutab IIS Express `applicationhost.config` (kaks saiti / kaks app pooli), käivitab TCP balanceri ja kaks IIS Expressi.

Kui IIS Express puudub:

```powershell
.\lab.ps1 start-selfhost
```

Peatamine: `.\lab.ps1 stop`.

---

## Kliendi voog (PIN1, tavaline päring, PIN2)

Järjekord on oluline ainult sisselogimise mõttes, mitte 403.16 mõttes.

1. **Logi sisse** — TLS kätlus PIN1 sertifikaadiga, siis WCF `WhoAmI`.
   - ID-kaart: Windows/minidriver küsib **PIN1** (kui PIN pole juba selle protsessi jaoks vahemälus).
   - Lab-sertifikaat: PIN-dialoogi ei tule. See on oodatav.
   - Vastuses on isik, poliitika-OID otsus ja **server**: `ARVUTINIMI/Backend1` (või Backend2).
2. **Tavaline päring** — `Ping` samal avatud kanalil. PIN1/PIN2 ei küsita.
3. **Allkirjasta** — PIN2 ainult kliendis (ECDSA/RSA). Serverile läheb `SubmitSignature`: andmed + allkiri + allkirjastamise sert. Server kontrollib matemaatikat ja et isikukood kattuks PIN1 omaga.

Allkirja- ja ping-nupud on kuni sisselogimiseni kinni.

Lab vs päris kaart: klient peab ESTEID-iks ainult sertifikaate, mille väljastaja on ESTEID / EE-Gov. Lab-CA (`PNOEE-` test) ei ole ID-kaart — muidu näitaks “Leitud ID-kaart”, aga PIN-i ei tuleks.

---

## Kleepuvus: miks kõik päringud lähevad ühte backend’i

Balancer on **round-robin uue TCP ühenduse kohta**, mitte WCF-operatsiooni kohta.

Pärast PIN1 kätlust hoiab klient kanalit lahti (`KeepAliveEnabled=true`). Järgmised `Ping` ja PIN2 lähevad **samasse IIS-i**, kuni:

- klient suletakse
- vajutatakse uuesti “Logi sisse” (uus kanal)
- backend sureb ja kanal fault’ib

See **ei ole** cookie ega `balance source`. See on sama TCP/TLS toru.

`balance source` (stats-lehel) kinnitaks klienti IP järgi. Kodus on kõik `127.0.0.1`, seega source paneks **kõik** ühte backend’i. Failoveri testiks jäta **roundrobin**.

Töö WCF-is on sama: connection pool hoiab sind ühe IIS-i küljes. Round-robin “ei tööta”, kuni vaatad **uusi** ühendusi, mitte ühe kasutaja pingide jada.

---

## Failover: kui üks IIS sureb

Oodatav käitumine: **tavaline päring õnnestub edasi**. Backend nimi logis / staatusereal võib muutuda; kasutaja ei pea midagi “parandama”.

### Mis juhtub

1. Stats-lehel **Kinni** (või `.\lab.ps1 down Backend1`) tapab selle IIS Expressi.
2. Olemasolev TCP balancerist surnud protsessi juurde katkeb.
3. Järgmine `Ping`: WCF saab “connection aborted” / HTTP.SYS-i meenutava vea (see ei ole vale serverisert).
4. Klient **viskab kanali minema**, tühjendab HTTP keep-alive pooli, ootab ~400 ms, avab **uue** TCP/TLS `demo.local:9443` peale.
5. Balancer ei suuna enam DOWN masinasse: enne TCP-d teeb ta `GET /health.json`. HTTP.sys võib 8443 peal veel kuulata (protsess on surnud, kernel-seos elab), aga health :8080 ei anna 200.
6. Elus backend võtab uue kätluse vastu. PIN1 sertifikaat käib kaasa. Teenus on olekuta → `Ping` töötab ilma uuesti sisse logimata.
7. Lab-sertifikaadiga PIN1 uuesti ei küsita. Päris kaardiga võib Windows PIN1 uuesti küsida, kui CSP vahemälu aegus.

Kuni kanal elab, **ei ole** vahet, et balancer on round-robin. Hüpe toimub alles **uuel** ühendusel.

### Mida failover ei ole

- Session cookie / Affinity cookie
- WCF serveri-session ühest VM-ist teise kolimine
- SSL termination balanceris (siis oleks mTLS balanceril, mitte IIS-il)

### HTTP.SYS hoiatus

WCF tekst *“server certificate is not configured properly with HTTP.SYS”* ilmub tihti siis, kui **surnud keep-alive** või **HTTP.sys kuulab pordil ilma workerita**. See ei tähenda, et `demo.local` sert oleks vale. Uus TCP + health-põhine valik on selle vastu.

---

## Stats-leht (Kinni / Käima)

Ava [http://127.0.0.1:8404/](http://127.0.0.1:8404/). Leht uueneb ~3 s tagant.

| Nupp | Mõju |
|---|---|
| **Kinni** | Tapab selle backend’i protsessi (`lab.ps1 down`). Failoveri test. |
| **Käima** | Käivitab sama backend’i uuesti (`lab.ps1 up`). |
| **drain** | Protsess jääb käima, **uusi** TCP-sid sinna ei anta. Olemasolev Keep-Alive jääb elama. |
| **ready** | Võtab drain’i maha. |
| roundrobin / source | Uue TCP valiku algoritm. |

Failoveri proov:

1. `.\lab.ps1 start` ja `.\lab.ps1 client`
2. Logi sisse, vaata milline `ARVUTINIMI/BackendX` vastas
3. Stats-lehel vajuta **Kinni** sellel real
4. Kliendis **Tavaline päring** — peaks õnnestuma; staatus võib öelda “Kanal hüppas teise serverisse”
5. **Käima** toob vana masina tagasi (uued ühendused võivad jälle sinna sattuda)

Käsurealt sama:

```powershell
.\lab.ps1 down Backend1
.\lab.ps1 up Backend1
```

---

## Kaks Windows Serverit

Balancer ei jaga mälu ega seanssi IIS-idega. Iga server on oma HTTP.sys, Schannel ja sertide hoidla.

`backends.txt` (labi vaikimisi localhost):

```text
Backend1 127.0.0.1 8443 8080
Backend2 127.0.0.1 8444 8081
```

Kaks VM-i, LB kolmandas masinas või ühel neist:

```text
Backend1 10.0.0.11 443 8080
Backend2 10.0.0.12 443 8080
```

```powershell
.\lab.ps1 start-lb 0.0.0.0
```

Mõlemal IIS-il peab olema:

- sama WCF-sait (`Demo.svc`)
- sama **avalik nimi** serveri sertifikaadis (klient kontrollib `demo.local` / töö FQDN-i; TLS lõpeb IIS-is)
- ESTEID / EE-GovCA ahel **selle masina** Root + Intermediate + **Client Authentication Issuers** hoidlas
- `Negotiate Client Certificate : Enabled` (`netsh http show sslcert`)
- HTTP health **ilma** kliendisertita, kuhu balancer ligi pääseb (labis `:8080/health.json`)

403.16 ühel VM-il ei parane teise VM-i pealt — ahel on masinapõhine.

Self-host teises masinas: `Demo.Host.exe --name IIS1 --https 443 --http 8080 --bind 0.0.0.0` (HTTP.sys urlacl peab lubama).

---

## 403.16 vs 403.13

WCF: `The HTTP request was forbidden with client authentication scheme 'Anonymous'` on peaaegu alati **IIS 403.16** ümberjutustus.

| Kood | Tähendus |
|---|---|
| **403.16** | HTTP.sys sai kliendiserti kätte, **ahel ei ole usaldatud** (puudu vahepealne CA, tühi ClientAuthIssuer, vale CTL). |
| **403.13** | Tühistus / OCSP / CRL ebaõnnestus. |

403.16 **ei ole** “klient läks anonüümsena” ega vale nupujärjestus. PIN1 jõudis kohale.

Kõige sagedasem tootmise põhjus (ka neli IIS-i HAProxy taga):

1. **Client Authentication Issuers** tühi või täidetud ainult ühel serveril.
2. `ESTEID2018` / `ESTEID2025` puuduvad *Intermediate* **ja** *Client Authentication Issuers* hoidlas **igal** IIS-il.
3. `EE-GovCA2018` / `EEGovCA2025` puuduvad *Trusted Root* hoidlas.
4. `sslctlstorename=ClientAuthIssuer`, aga CTL on tühi või vana.
5. VM-il puudub võrk / vale **WinHTTP** süsteemiproxy — see on pigem 403.13 (OCSP), mitte 403.16. WCF `Web.config` `<defaultProxy>` **ei** paranda HTTP.sys 403.13-t; vt [WCF Web.config proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp).

Diagnostika:

```powershell
.\lab.ps1 diagnose
```

Kodus pärast uut `certs` alati uuesti Administratoris `bind`. ID-kaart: `eid-ca`, siis `bind`, siis `stop` / `start`.

Toodangus igal IIS-il (identselt):

```text
certutil -addstore -f Root EE-GovCA2018.der.crt
certutil -addstore -f Root EEGovCA2025.crt
certutil -addstore -f CA esteid2018.der.crt
certutil -addstore -f CA ESTEID2025.crt
certutil -addstore -f ClientAuthIssuer esteid2018.der.crt
certutil -addstore -f ClientAuthIssuer ESTEID2025.crt
```

`netsh http show sslcert`: `Negotiate Client Certificate : Enabled`. Kui Ctl Store on `ClientAuthIssuer`, ei tohi see hoidla olla tühi.

Poliitika-OID-d (rakendus, mitte HTTP.sys): NCP+ `0.4.0.2042.1.2` ja ESTEID2018/2025 dokumendi-OID-d `EsteidPolicies` klassis. Lab lubab test-CA (`AllowLabCertificates=true`).

### Loe alamstaatuse kõrvalt ka `sc-win32-status`

Alamstaatus ütleb, **mis kihis** viga on. Kõrvalolev Win32-kood ütleb, **mis täpselt** valesti läks. IIS logib selle kümnendkujul, seega teisenda see kuueteistkümnendsüsteemi (`'0x{0:X}' -f <number>`):

| Kood | Nimi | Tähendus |
|---|---|---|
| `0x800B0109` | `CERT_E_UNTRUSTEDROOT` | ahel ehitus, aga lõppes juurikaga, mida **see kontekst** ei usalda → 403.16 |
| `0x800B010A` | `CERT_E_CHAINING` | ahel ei ehitunud lõpuni: vahepealne CA puudub |
| `0x800B0101` | `CERT_E_EXPIRED` | sert või mõni lüli aegunud, või masina kell on paigast |
| `0x800B010C` | `CERT_E_REVOKED` | sert on tühistatud (serveripoolel pole midagi parandada) |
| `0x80092013` | `CRYPT_E_REVOCATION_OFFLINE` | tühistusteenus ei vastanud → 403.13 rada |

### Kui rakendus ütleb „sert on kehtiv", aga IIS annab ikka 403.16

See on kõige petlikum variant: rakenduse logis on kliendisert olemas ja **kehtivaks** hinnatud, HTTP.sys aga keeldub. Vastuolu ei ole — **need kaks hindavad erinevate reeglitega**:

| | HTTP.sys / Schannel | Rakenduse `X509Chain` |
|---|---|---|
| Millised hoidlad loevad | sõltub `ClientAuthTrustMode`-st: võib nõuda, et ahel lõpeks **`ClientAuthIssuer`** hoidlas | `Root` + `CA` masina/kasutaja kontekstis |
| Puuduva vahelüli allalaadimine (AIA) | keelatud, kui `disableaia=Enabled` | üldjuhul lubatud |
| Tühistus | bindingu lipud (`verifyclientcertrevocation`) | rakenduse `RevocationMode` |

Sellest järeldub kolm asja, mida tasub teada, enne kui hakkad hoidlaid uuesti täitma:

1. **„`Root` ja `CA` on korras" ei tõesta midagi**, kui `ClientAuthTrustMode` on `1` või `2`. Siis nõuab HTTP.sys, et ahel lõpeks `ClientAuthIssuer` hoidlas, ja tühi `ClientAuthIssuer` annab **igale** kaardile `0x800B0109` — samal ajal kui rakenduse enda kontroll ütleb „kehtiv".
2. **`disableaia=Enabled` teeb kohaliku CA-hoidla täielikkuse kohustuslikuks.** See on mõistlik seade (väldib rippumist ja väliseid päringuid kätluse ajal), aga see tähendab, et **täpselt selle** kaardigeneratsiooni väljastaja CA peab olema kohapeal. Uue generatsiooni kaart vanal masinal = 403.16, ilma et miski muu oleks muutunud.
3. **Kui tühistus on bindingul välja lülitatud, ei saa OCSP-vead olla 403.16 põhjus.** Sündmuselogis olevad „could not retrieve OCSP response" read on sellisel masinal müra (tõenäoliselt ettevõtte sisese PKI pärand) — need kuuluvad 403.13 juurde, mitte siia.

Kolm käsku, mis selle vastuolu lahendavad:

```powershell
certutil -store ClientAuthIssuer
Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" |
    Select-Object ClientAuthTrustMode, SendTrustedIssuerList
netsh http show sslcert                      # Disable Authority Info Access + Negotiate Client Certificate
```

Ja üks asi, mis ütleb kohe ka selle, mida käsud ei näita — **millisest hoidlast iga ahela lüli päriselt tuleb** ja mis on esitatud serdi väljastaja: `Demo.CertProbe` (`.\lab.ps1 probe`), vt [Diagnostika](#diagnostika-üks-koht-kust-vaadata). Ilma esitatud serdi **väljastajat** teadmata ei saa hoidlate sisu kohta järeldusi teha.

### APP12: 403.16 kui Root ja CA näivad korras

Töö raport `RRMT-IdCardDiag-RR-MT-DEV-APP12-20260917-130221.txt` (`RR-MT-DEV-APP12`, 17.09.2026). Sama kaart, mis labis: `PNOEE-39904250267`, väljastaja ESTEID2018.

| Raport ütles | Tegelik järeldus |
|---|---|
| `Last IIS CommonService NOT 403.16` = **FAIL** | IIS: `403 16 2148204809` (`0x800B0109` `CERT_E_UNTRUSTEDROOT`) |
| `IdCardAuth WcfEntry` / `ALLOW` = FAIL | WCF-i ei jõuta. Klient näeb ainult *Anonymous* / 403 |
| `ClientCert Present=true Valid=True` + `HttpStatus=403` | Rakendus ja HTTP.sys **hindavad eri reeglitega** — see ei ole vastuolu |
| ESTEID2018 `CA`s, EE-GovCA2018 `Root`is | „Ahel korras” **selles** kontrollis. `ClientAuthIssuer` ja `ClientAuthTrustMode` jäid vaatamata |
| `Ctl Store Name: (null)`, Negotiate = Enabled, tühistus Disabled, `disableaia` Enabled | Tühistus on väljas → Schannel OCSP `ocsp.smit.sise` timeout on **müra**, mitte 403.16 põhjus |
| `sslFlags=Ssl, SslNegotiateCert` (ilma Require-ita) | Sert ikkagi saadeti. 403.7 see ei ole |

**Miks `ocsp.smit.sise` timeout ei ole see viga.** Raportis on kaks hirmutavat rida: otsene `ocsp.smit.sise` aegub ja Schannel 36928 *Could not retrieve an OCSP response*. See näeb välja nagu „tühistus katki”. Aga:

1. Bindingul on `Verify Client Certificate Revocation : Disabled`. HTTP.sys **ei tohi** kätlust OCSP pärast 403-ga tapma. Kui tühistus oleks sees ja OCSP maas, oleks IIS rida **`403 13`** ja win32 **`0x80092013`** (`CRYPT_E_REVOCATION_OFFLINE`), mitte `403 16` / `2148204809`.
2. `2148204809` = `0x800B0109` = `CERT_E_UNTRUSTEDROOT` — usaldus, mitte tühistus.
3. Schannel küsib ettevõtte sisest OCSP-d ka muude serdite jaoks (ajatempel, Windows Update, skripti enda `certutil`). `ThisUpdate/NextUpdate = 1601-01-01` tähendab: vastust ei ole kunagi saadud. See täidab System logi ka siis, kui ID-kaardi rada tühistust ei tee.

Järeldus: ocsp.smit.sise tasub **eraldi** korda teha (403.13 ootab ees, kui keegi lülitab `verifyclientcertrevocation=enable`), aga see APP12 login suri usalduse, mitte OCSP peale.

Probleem: HTTP.sys ei küsi „kas kaart on ehtne?”, vaid „kas **selle masina selle usaldusreegli** järgi tohib see sert sisse?”. Reegel võib olla CTL (`sslctlstorename=ClientAuthIssuer`), exclusive `ClientAuthTrustMode`, või Trusted Issuers nimekiri, kuhu ESTEID2018 ei kuulu. `Root`/`CA` võivad samal ajal laitmatud olla.

#### Mida lab näitas (Hyper-V IIS, 20.09.2026)

Päris kaart saadab ESTEID2018 **kätlusega kaasa**. Siis ei piisa `CA` tühjendamisest ega tühjast `ClientAuthIssuer`ist: ahel on kätluses olemas ja lõpeb `EE-GovCA2018` juurikaga `Root`is → IIS logib **200**.

Kaks kätlust andsid **sama** kliendi pildi (`403.16`, sert saadeti, WCF Anonymous) ja **sama** win32 `0x800B0109`, aga parandus on erinev:

| Katse | Seis | Tulemus | Järeldus |
|---|---|---|---|
| A. CTL `ClientAuthIssuer` = ainult lab-root; juur `Root`is olemas; ESTEID `CA`s | `Ctl Store Name: ClientAuthIssuer` | 403.16 | HTTP.sys usaldab **CTL-i**, mitte `Root`/`CA`. APP12 sümptom (raportis oli juur `Root`is olemas). |
| B. CTL maas; `EE-GovCA2018`/`EEGovCA2025` **`Root`ist ära**; ESTEID `CA` + `ClientAuthIssuer` | `Ctl Store Name: (null)` | 403.16 | Kätluse vahelüli ei päästa, kui **juur ise** pole usaldatud. APP12-t see **ei** korda — seal oli juur `Root`is. |

Kuidas neid hiljem eristada, kui IIS rida on identne (`403 16 2148204809`):

1. `certutil -store Root` — kas EE-GovCA2018 / EEGovCA2025 on kirjas?
2. `netsh http show sslcert` — kas `Ctl Store Name` on `ClientAuthIssuer` või `(null)`?
3. `certutil -store ClientAuthIssuer` — kas ESTEID2018/2025 on kirjas?

Aparatuur: juur puudu → `certutil -addstore -f Root EE-GovCA2018.der.crt`. CTL/issuer → ESTEID `ClientAuthIssuer`isse (või CTL maha). Mõlemat korraga „igaks juhuks” täita tohib, aga raportist näed, kumb tegelikult katki oli.

Kliendi diagnostika mõlemal korral: `Server küsis serti: True`, klient saatis serdi, alamstaatus **403.16**.

```powershell
# Katse A (ADMIN, ainult lab): CTL ilma ESTEID-ita
# ansible/lockdown-app12.yml  (praegune fail = viimati katse B)
# Katse B: eemalda juur Rootist, CTL maha, ESTEID jäta CA+issuer
# Taasta alati: .\lab.ps1 ansible
```

### Teised 403.16 teed (sama sümptom)

WCF tekst on alati sama. Vahe on ainult IIS `sc-substatus=16` + `sc-win32-status`.

| Olukord | HTTP.sys näeb | Win32 | Kuidas ära tunda | Labis |
|---|---|---|---|---|
| **CTL / `ClientAuthIssuer` ilma ESTEID-ita** (APP12 sümptom) | juur või vahelüli ei ole *selles* nimekirjas | `0x800B0109` | `netsh http show sslcert` → `Ctl Store Name`; `certutil -store ClientAuthIssuer` ei näita ESTEID2018/2025 | `lockdown-app12.yml` |
| Exclusive režiim + tühi või vale `ClientAuthIssuer` | sama, kui CTL või TrustMode 1/2 on päriselt aktiivne | `0x800B0109` | `ClientAuthTrustMode` + hoidla. Uuemal Serveril **tühi** hoidla *ilma* CTL-ita võib langeda `Root`/`CA` peale — 403.16 ei tule | `lockdown no-issuer` hostis; VM-is kontrolli, et CTL on päriselt küljes |
| Puudub ESTEID `CA`s **ja** klient ei saada vahelüli + `disableaia` | ahel ei ehitu | `0x800B010A` | uus kaardigeneratsioon vanal masinal; suletud võrk | `lockdown no-aia`. Päris kaart, mis saadab ESTEID2018 kätlusega, **ei** kuku siia, kui juur on `Root`is |
| Puudub EE-GovCA `Root`is | ahel lõpeb usaldamata juurikaga | `0x800B0109` | `certutil -store Root` ilma EE-GovCA2018 / EEGovCA2025 | **tõestatud 20.09.2026** (katse B): 403.16, kuigi ESTEID oli `CA` + issuer ja CTL `(null)` |
| Ühel backendil ahel olemas, teisel mitte | sõltub, kuhu RR/LB saadab | `0x800B0109` | vahelduv 403.16; `service.log` `backend=` | jäta ESTEID ainult ühele saidile |
| Uus generatsioon (ESTEID2025) vanal IIS-il | 2018 on olemas, 2025 mitte | `0x800B0109` / `0x800B010A` | ainult uued kaardid, vanad töötavad | pane hoidlasse ainult 2018 |
| Aegunud leht / vahelüli / masina kell | kätlus ehitub, kehtivus ei | `0x800B0101` | `certutil -dump`; võrdle kella | — |
| `SendTrustedIssuerList=1` + suur / vale CTL | klient ei vali ID-kaarti või saadab „vale” serdi | 403.16 või katkenud kätlus | diagnostika: „väljastajate loend”; labis on loend **väljas** | — |
| GPO kirjutab `ClientAuthIssuer` üle | eile töötas, täna 403.16 | `0x800B0109` | `gpresult`; raport enne/pärast `gpupdate` | — |
| Client Certificate Mapping / NTAuth | IIS mapib AD kontole, ID-kaart ei ole NTAuth-is | 401 / 403.16 | IIS *Client Certificate Mapping Authentication* | ära seda ID-kaardiga kasuta |

`ClientAuthTrustMode` (Schannel, kogu masin):

| Väärtus | Nimi | Tähendus |
|---|---|---|
| `0` | Machine Trust (vaikimisi) | väljastaja peab olema Trusted Issuers nimekirjas; CTL-ita võib langeda masina `Root`/`CA` peale |
| `1` | Exclusive Root | ahel peab lõppema **juurikaga** caller-specified hoidlas |
| `2` | Exclusive CA | ahel peab lõppema **vahelüli või juurikaga** caller-specified hoidlas. Labis on see tavaliselt **parandus** (IIS 8+ 403.16 ilma CTL-ita). APP12 sümptom labis: `2` **koos** `sslctlstorename=ClientAuthIssuer`, kus ESTEID puudub |

#### Sama `403 16 2148204809` — mis tasub labis läbi proovida

`2148204809` = ahel **sai valmis**, lõpp-juur ei ole selles kontekstis usaldatud. Enne uut katset: `.\lab.ps1 ansible` (puhas baas), siis **üks** muudatus, päris kaart, diagnostika, `sc-win32-status` IIS logis.

| # | Katse | Oodatav | Mida tõestab | Tasub? |
|---|---|---|---|---|
| 1 | CTL `ClientAuthIssuer` = ainult lab-root, TrustMode 2 | **juba tehtud** — 403.16 / `800B0109` | HTTP.sys usaldab CTL-i, mitte `Root`/`CA` | — |
| 2 | Eemalda `EE-GovCA2018` (+ soovi korral `EEGovCA2025`) **`Root`ist**. CTL maha, TrustMode 2, ESTEID jäta `CA`sse | **tehtud** — 403.16 / `800B0109` | masina juur puudub; kätluse vahelüli ei päästa. APP12-t ei korda (seal oli juur olemas) | — |
| 3 | CTL sees, `ClientAuthIssuer` = **ainult** `EE-GovCA2018` (juur), ESTEID *ei* ole issuer-hoidlas. TrustMode **2** | tihti **200** | Exclusive CA lubab ahelal lõppeda juurikaga CTL-is; „pane juur ClientAuthIssuerisse” võib labis töötada ja tööl ikka petta | **jah** — näitab, miks juur vale kohta panna on ohtlik järeldus |
| 4 | Sama mis 3, aga TrustMode **1** (Exclusive Root) + `ClientAuthIssuer` = ainult ESTEID2018 (vahelüli, mitte juur) | 403.16 / `800B0109` | Exclusive Root nõuab, et lõpp oleks **juur** selles hoidlas; vahelüli ei piisa | **jah** kui tahad TrustMode 0/1/2 vahet tunda |
| 5 | CTL + lab-root **ainult Backend2-l** (`8444`); Backend1 jääb puhtaks. Klient `:9443` roundrobin | vahelduv 403.16 / 200 | „üks VM katki” — APP-id erinevad, LB vahetab | **jah** kui failover/RR on teema |
| 6 | `SendTrustedIssuerList=1` + CTL ainult lab-root | kätlus katkeb või klient ei paku ID-kaarti; või 403.16 | loend on ~16 KB piiriga; tööl suur ettevõtte CTL | valikuline; sümptom on tihti teine kui 403.16 |
| 7 | Eemalda ESTEID `CA`st, `disableaia` peal, **ilma** CTL-ita | päris kaardiga sageli **200** | kaart saadab vahelüli kätlusega; `no-aia` ei korda `800B0109` | ei tasu uuesti — juba nähtud |
| 8 | Tühi `ClientAuthIssuer`, CTL *ei* ole, TrustMode 0 | **200** sellel Serveril | IIS 8+ „tühi CTL = 403.16” ei kordu siin | ei tasu uuesti |
| 9 | `ocsp.smit.sise` kinni, tühistus **Disabled** | endiselt 200 või sama 403.16 mis #1, **mitte** 13 | OCSP müra | ei — tühistus off |
| 10 | Tühistus **Enabled** + lab-proxy `deny` (WinHTTP `192.168.56.2:3128`) | **tehtud** — 403.13, TLS OK, WCF „Anonymous“ | ahel usaldatud; OCSP/CRL läks WinHTTP-st, mitte `Web.config`-ist. Päris URL-id: `http://aia.sk.ee/esteid2018/...`, `http://aia.sk.ee/ee-govca2018/...`, `http://c.sk.ee/EE-GovCA2018.crl`. `ocsp.smit.sise` ei käinud | `lockdown-ocsp.yml` + `.\lab.ps1 proxy deny` |

Katsed 1–2 = 403.16 (CTL / puuduv juur). Katse 10 = 403.13 (proxy keelas SK OCSP). APP12 ei olnud see rada: seal tühistus Disabled.

**Tööproxy vs lab.** `http://ocsp.smit.sise/ocsp` on ettevõtte sisene OCSP. ID-kaardi leht küsib serdis olevat URL-i (SK / eidpki). Mõlemad lähevad WinHTTP proxyst, kui `netsh winhttp show proxy` on seatud. Labis: host `.\lab.ps1 proxy deny` kuulab `0.0.0.0:3128`, guest WinHTTP `http://192.168.56.2:3128`, binding `verifyclientcertrevocation=enable`. `allow` + `.lab\proxy.log` näitab täpse URL-i nimekirja (tellimus). `timeout` kordab „The operation has timed out”, mitte kohest 403-t.

---

## Tööl kontrollida (labi järeldused)

Päris ID-kaart `ESTEID2018` / `PNOEE-39904250267`, Hyper-V IIS (`WIN-R2NUJEQC8CV`), 20.09.2026. Töö raport: `RRMT-IdCardDiag-RR-MT-DEV-APP12-20260917-130221.txt`. Täpsemad katsed: [403.16 vs 403.13](#40316-vs-40313), URL-id: [AIA / OCSP / CRL](#url-id-mida-iis-peab-kätte-saama-aia--ocsp--crl).

### Mis labis kindlaks tehti

| # | Seis | Tulemus | Järeldus tööl |
|---|---|---|---|
| A | CTL `ClientAuthIssuer` = ainult lab-root; juur `Root`is olemas | **403.16** / `2148204809` (`0x800B0109`) | HTTP.sys usaldab **CTL-i**, mitte „Root/CA on korras”. APP12 sümptom. |
| B | CTL maas; `EE-GovCA` **`Root`ist ära**; ESTEID `CA` + issuer | **403.16** / sama win32 | Kätluse vahelüli ei päästa puuduvat juurt. APP12-t ei korda (seal oli juur `Root`is). |
| 10 | Tühistus **Enabled** + WinHTTP lab-proxy `deny` | **403.13** (TLS OK, WCF „Anonymous”) | Proxy/OCSP **ei** ole 403.16. Päris URL-id: `aia.sk.ee/esteid2018`, `aia.sk.ee/ee-govca2018`, `c.sk.ee/EE-GovCA2018.crl`. `ocsp.smit.sise` ei käinud. |
| Puhas | Ansible taastas: tühistus off, CTL `(null)`, neli CA-d hoidlates | **PIN1 OK** (`WhoAmI`, `fc8c53fc`) → **PIN2 OK** (sama isik, `Backend1`) | Suletud VM + revocation off = login töötab **ilma SK aukudeta**. PIN2 on siin lokaalne allkiri, ajatemplit ei küsitud. |

WCF tekst oli alati `client authentication scheme 'Anonymous'`. Päris kood on IIS alamstaatus (16 vs 13). `Web.config` proxy PIN1 kätlust ei mõjuta.

### Kaks kihti — ära sega neid tööl kokku

| Kiht | Küsimus | Kui puudu | Võrk? |
|---|---|---|---|
| **A. Ahel** | Kas neli CA faili on **igal** IIS-il õigetes hoidlates ja CTL ei filtreeri ESTEID-i välja? | **403.16** | Ei, kui failid tulevad Ansible `win_copy` / `certs/eid-ca` |
| **B. Tühistus** | Kas `verifyclientcertrevocation` on sees **ja** WinHTTP näeb SK-d? | **403.13** | Jah: otse või korporatiivproxy |

APP12 login suri kihil A (tühistus oli Disabled; `ocsp.smit.sise` timeout oli müra).

### Küsimused, mida tööl küsida / mõõta

Iga rida: **jah / ei / väärtus**. Käivita **igal** IIS VM-il (ühe masina roheline ei tõesta teist). APP12-l jäi `ClientAuthIssuer` ja `ClientAuthTrustMode` vaatamata.

**1. Hoidlad (kiht A)**

- [ ] `certutil -store Root` näitab `EE-GovCA2018` **ja** `EEGovCA2025`?
- [ ] `certutil -store CA` näitab `ESTEID2018` **ja** `ESTEID2025`?
- [ ] `certutil -store ClientAuthIssuer` näitab samu ESTEID vahelülisid (mitte ainult juuri)?
- [ ] Sert on **LocalMachine**, mitte ainult CurrentUser / sinu desktop?
- [ ] CA serdi omadustes on *Client Authentication* linnuke peal?

**2. HTTP.sys / Schannel (kiht A, APP12)**

```text
netsh http show sslcert
Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL |
    Select-Object ClientAuthTrustMode, SendTrustedIssuerList
```

- [ ] Õige seos (kontrolli **nii** `0.0.0.0:443` kui masina IP:443 — need on erinevad)?
- [ ] `Negotiate Client Certificate : Enabled`?
- [ ] `Ctl Store Name` — `(null)` **või** `ClientAuthIssuer` kus ESTEID **on** kirjas? Tühi/vale CTL = katse A.
- [ ] `ClientAuthTrustMode` väärtus? `1` = Exclusive Root (vahelüli issueris ei piisa). `2` + CTL ilma ESTEID-ita = sama 403.16.
- [ ] `SendTrustedIssuerList` — kui `1`, kas CTL on väike ja sisaldab ESTEID-i?
- [ ] `Disable Authority Info Access` Enabled → kohalik `CA` hoidla peab olema täielik.
- [ ] IIS *Client Certificate Mapping* / *IIS Client Certificate Mapping* **väljas**?

**3. Tühistus vs võrk (kiht B)**

- [ ] Binding: `Verify Client Certificate Revocation` Enabled või Disabled? APP12-l oli **Disabled** — siis SK/smit auke login **ei** vaja.
- [ ] Kui Enabled: kas väljuv on **otse** või **ainult proxy**? (Töö VM-il vaikimisi ei ole väljapääsu.)
- [ ] `netsh winhttp show proxy` — kas **sama** proxy, mida masin tegelikult kasutab? `Direct access` + suletud NSG + revocation on = 403.13.
- [ ] Kas `Web.config` `<defaultProxy>` / WCF SK URL on **ainus** koht, kuhu proxy pandi? Sellest ei piisa — HTTP.sys loeb WinHTTP-d.
- [ ] Kas proxy laseb masinakonto / Local System **ilma 407-ta**?
- [ ] Kas NSG/tellimus on ainult `:443`? OCSP/CRL on **:80**.

Kui tühistus on sees, WinHTTP (otse või proxy allowlist) peab nägema:

```text
aia.sk.ee          :80     ESTEID2018 / GovCA2018 OCSP
c.sk.ee            :80,:443  CRL + 2018 failid
ocsp.eidpki.ee     :80     ESTEID2025 OCSP
crl.eidpki.ee      :80     EEGovCA2025.crl
crt.eidpki.ee      :80,:443  2025 failid
ocsp.sk.ee         :80     varu
```

- [ ] Kas keegi tellib `ocsp.smit.sise` *ID-kaardi* jaoks? Seda PIN1 ei küsi. Tasub ettevõtte PKI jaoks, mitte APP12 403.16 paranduseks.
- [ ] Õige test: `certutil -verify -urlfetch` IIS-il, mitte PowerShell `Invoke-WebRequest` / IE sinu kasutajaga.

**4. Ansible / IaC (et roll ei tapaks loginit)**

Mall: `ansible/inventories/work.example.yml`. Ära kopeeri labi `group_vars` proxyt (`192.168.56.2:3128`).

- [ ] `eid_download_certs: false` ja neli faili on **kontrolleril** `certs/eid-ca`? (Suletud VM ei lae SK-st.)
- [ ] `eid_revocation: false` **kuni** kiht B on tellitud ja WinHTTP paigas? `true` liiga vara = 403.13.
- [ ] `eid_allow_lab_certificates: false` toodangus?
- [ ] `eid_sslctl_store` tühi (vaikimisi) — CTL-i ei panda, kuni issuer on igal masinal täis?
- [ ] `eid_winhttp_proxy` / `eid_wcf_default_proxy` = **töö** proxy või tühi, mitte labi aadress?
- [ ] Roll jooksis **kõigil** `iis` hostidel (uus Nutanixi VM ilma rollita = vahelduv 403.16)?
- [ ] GPO / CIS ei kirjuta pärast Ansible’it `ClientAuthIssuer`, `ClientAuthTrustMode` ega WinHTTP üle (`gpresult`)?
- [ ] HAProxy `mode tcp` (TLS lõpeb IIS-is)? `mode http` + SSL = 403.7, mitte 16.
- [ ] Health `:8080` `/health.json` **ilma** kliendiserdita?

**5. Pärast esimest PIN1-t**

- [ ] IIS W3C: `sc-status` / `sc-substatus` / `sc-win32-status` — 200, või 403 **16** `2148204809` (`0x800B0109`), või 403 **13** `2148081683` (`0x80092013`)?
- [ ] Kui 16: küsi punktid 1–2 (CTL vs juur). Kui 13: punkt 3.
- [ ] Kas viga on **ühel** APP-il (nagu APP12) või kõigil? Üks masin = selle VM-i hoidla/CTL/WinHTTP, mitte HAProxy.
- [ ] PIN2: see demo ei küsi SK ajatemplit. Töö juriidiline allkiri võib vajada eraldi URL-i — see ei ole PIN1.

Taasta / võrdle labiga: `ansible-playbook -i work.yml iis.yml` (samad rollid mis `.\lab.ps1 ansible`).

### Kust VM-ist vaadata, kui login ei õnnestu

Kihid räägivad **järjest**. 403.7 / 13 / 16 sünnivad **enne** w3wp-d — siis on rakenduse logi tühi ja see on oodatav, mitte „logimine katki”. WCF ütleb alati `Anonymous`; päris kood on IIS `sc-substatus`. Labis koondab sama asja `.\lab.ps1 report` / `Get-EidReport.ps1` — all on **käsitsi teed täis-IIS VM-il**.

| # | Kiht | Räägib millal | Kus sellel IIS VM-il | Mida otsid |
|---|---|---|---|---|
| 0 | Klient (mitte VM) | alati | `%LOCALAPPDATA%\IIS-ID\client.log` + nupp Diagnostika | PIN1 küsiti? päris `403.16` / `.13` / `.7` kehast; `correlation=` |
| 1 | HAProxy / LB | päring ei jõua IIS-i | HAProxy `show stat`, rsyslog | backend UP/DOWN; `mode tcp`? |
| 2 | HTTP.sys | kätlus katkeb enne saiti | `C:\Windows\System32\LogFiles\HTTPERR\httperr*.log` + `netsh http show sslcert` | `Timer_ConnectionIdle`, SSL; Negotiate / CTL / revocation |
| 3 | IIS W3C | päring **jõudis saidini** | `%SystemDrive%\inetpub\logs\LogFiles\W3SVC*\*.log` | `sc-status` `sc-substatus` `sc-win32-status`. Puhverdab ~60 s. **UTC**. |
| 4 | Failed Request Tracing | kui FREB 403 peale sees | `%SystemDrive%\inetpub\logs\FailedReqLogFiles\W3SVC*\` | 403.x XML (Ansible: `iis_enable_freb`) |
| 5 | CAPI2 | ahel / OCSP (kui logi sees) | Event Viewer → *Apps and Services* → *Microsoft* → *Windows* → *CAPI2* → *Operational* | `800B0109` = 16, revocation offline = 13. Luba: `wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true` |
| 6 | Schannel | TLS / OCSP müra | Event Viewer → *System*, allikas **Schannel** | alert 48 unknown_ca; 36928 OCSP (`ocsp.smit.sise` võib olla müra, kui tühistus off) |
| 7 | App pool / WAS | pool ei käivitu, recycle, 503 | *System* allikad **WAS**, **IIS-W3SVC**, **IIS-W3SVC-WP**; `Get-IISAppPool` | identity, crash; health 200 eraldi poolis petab HAProxy’t |
| 8 | ASP.NET / w3wp | CLR / `web.config` | *Application*: **ASP.NET**, **.NET Runtime** | moodul ei laadi; **ei** selgita 403.16 |
| 9 | Rakendus (WCF) | ainult kui IIS andis **200** | `Web.config` `serviceLogPath` (lab: `App_Data\service.log`; toodang: nt `D:\logs\demo\service.log`) | `WhoAmI` / `correlation=` / `backend=` / `pool=`. Tühi + kliendil 403 → loe rida 3, mitte siit. |
| 10 | WinHTTP | tühistus / 403.13 | `netsh winhttp show proxy` | `Direct access` suletud VM-il |

**Otsustus:** `service.log` tühi + klient 403 → rida 3 (IIS). `service.log`-is `WhoAmI` / poliitika → HTTP.sys lubas, viga on rakenduses. `HTTPERR` rida, IIS-is tühjus → kätlus suri HTTP.sys-is. Ühel APP-il 16, teisel 200 → selle VM-i hoidla/CTL (rida 3 + `certutil -store`), mitte HAProxy.

```powershell
# Igal katkisel IIS-il (Administrator), pärast üht ebaõnnestunud PIN1-t:
netsh http show sslcert
netsh winhttp show proxy
Get-ChildItem $env:SystemDrive\inetpub\logs\LogFiles\W3SVC*\*.log |
    Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
    ForEach-Object { Select-String -Path $_.FullName -Pattern ' 403 ' | Select-Object -Last 5 }
Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 20 -ErrorAction SilentlyContinue
Get-Content (Get-ChildItem C:\Windows\System32\LogFiles\HTTPERR\httperr*.log | Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName -Tail 20
```

IIS saidi logikaust: IIS Manager → sait → *Logging* → *Directory* (mitte alati vaikimisi `W3SVC1`). `sc-substatus` / `sc-win32-status` peavad olema W3C väljades — muidu näed ainult `403`. Täpsem labi voog: [Diagnostika](#diagnostika-üks-koht-kust-vaadata).

---

## Toodangu IIS: ID-kaardi ahel ja paigaldus

Ametlik allikas: [IIS veebiserverile ID-kaardi toe seadistamine](https://open-eid.github.io/iis/index.et.html). Juhend toetab **EE-GovCA2018** ja **EEGovCA2025** ahelaid; ESTEID-SK 2011/2015 on eemaldatud.

Tee **iga IIS VM** peal samad sammud. Ühe masina Root ei aita teist masinat.

### Ahel (kolm tasandit)

```
ID-kaardi PIN1 leht
    väljastaja ESTEID2018  või  ESTEID2025     <- LocalMachine\CA  +  ClientAuthIssuer
        väljastaja EE-GovCA2018  või  EEGovCA2025  <- LocalMachine\Root
```

| Fail | Lae | Hoidla |
|---|---|---|
| `EE-GovCA2018` | https://c.sk.ee/EE-GovCA2018.der.crt | **Root** |
| `EEGovCA2025` | https://crt.eidpki.ee/EEGovCA2025.crt | **Root** |
| `ESTEID2018` | https://c.sk.ee/esteid2018.der.crt | **CA** (Intermediate) **ja** **Client Authentication Issuers** |
| `ESTEID2025` | https://crt.eidpki.ee/ESTEID2025.crt | **CA** **ja** **Client Authentication Issuers** |

Juuri **ära** pane ainsaks ClientAuthIssuer sisuks — IIS 8+ vaatab sealt **kesktaseme** väljastajaid. Tühi ClientAuthIssuer = kõik kaardid **403.16**.

### Paigaldus (Administrator, iga IIS)

Selles repos:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Install-EsteidIisProduction.ps1
```

Käsitsi:

```text
certutil -addstore -f Root EE-GovCA2018.der.crt
certutil -addstore -f Root EEGovCA2025.crt
certutil -addstore -f CA esteid2018.der.crt
certutil -addstore -f CA ESTEID2025.crt
certutil -addstore -f ClientAuthIssuer esteid2018.der.crt
certutil -addstore -f ClientAuthIssuer ESTEID2025.crt
```

Kontroll:

```text
certutil -store Root    | findstr /i "EE-Gov EEGov"
certutil -store CA      | findstr /i "ESTEID"
certutil -store ClientAuthIssuer | findstr /i "ESTEID"
```

Lab-masinas (`ClientAuthTrustMode=2`, kõik failid kõigis hoidlates) on lõdvem; toodangus kasuta ülaltoodud paigutust.

Serveri **HTTPS sertifikaat** (sait `wcf.example.com` vms) peab olema LocalMachine\My ja **sama avalik nimi kõigil IIS-idel**, sest klient kontrollib nime TLS-is, mis lõpeb IIS-is (passthrough).

---

## Täpsed IIS seaded

Platvorm: Windows Server 2016–2025, IIS 10, sait .NET 4.8, app pool **Integrated / v4.0**.

### 1. Sait ja app pool

- App pool: `No Managed Code` ei sobi WCF `.svc` jaoks — kasuta **.NET CLR v4.0**, Integrated.
- Identity: `ApplicationPoolIdentity` (või gMSA). See konto **ei** kasuta kasutaja IE-proxyt.
- Sait: HTTPS 443, host header = avalik FQDN (või tühi, kui IP-põhine).
- Eraldi sait või binding **HTTP :8080** (või 80) **ainult** `/health.json` jaoks, **ilma** kliendisertita. HAProxy teeb `GET /health.json` sellele pordile.

### 2. Autentimine (IIS Manager → Authentication)

WCF + mTLS näide (nagu lab):

| Meetod | Toodang / lab |
|---|---|
| Anonymous | **Enabled** (identiteet tuleb TLS serdist, mitte IIS-i kasutajast) |
| Windows / Basic / Forms | Disabled, kui ainult ID-kaart |

`web.config`: `<authentication mode="None" />`.

### 3. SSL Settings (sait või `/Demo.svc`)

| Väli | Väärtus |
|---|---|
| Require SSL | Yes |
| Client certificates | **Require** (WCF mTLS). `Accept` lubab ka serdita kutseid. |

`applicationHost.config` / location (IIS Express labis `sslFlags` saidi peal):

```xml
<access sslFlags="Ssl, SslNegotiateCert, SslRequireCert" />
```

- `Ssl` — HTTPS
- `SslNegotiateCert` — küsi kliendiserti
- `SslRequireCert` — ilma serdita 403.7

### 4. Negotiate Client Certificate (HTTP.sys, kohustuslik TLS 1.3)

TLS 1.3 ei tee renegotiation’it. Sert tuleb küsida **esimesel kätlusel**.

Windows Server 2025 IIS Manager → Site Bindings → HTTPS → Edit → märgi **Negotiate Client Certificate**. Ära märgi “Disable TLS 1.3 over TCP”.

Server 2022-l ruutu pole. `netsh` (asenda räsi, appid, ipport):

```text
netsh http show sslcert 0.0.0.0:443

netsh http delete sslcert ipport=0.0.0.0:443

netsh http add sslcert ipport=0.0.0.0:443 ^
    certhash=<THUMBPRINT_WITHOUT_SPACES> ^
    appid={<APPLICATION_ID>} ^
    certstorename=MY ^
    clientcertnegotiation=enable ^
    verifyclientcertrevocation=enable ^
    verifyrevocationwithcachedclientcertonly=disable ^
    usagecheck=enable
```

Kontroll `netsh http show sslcert`:

| Väli | Oodatav |
|---|---|
| Negotiate Client Certificate | **Enabled** |
| Verify Client Certificate Revocation | **Enabled** (toodang). Labis `disable`. |
| Verify Revocation with Cached Client Certificate Only | **Disabled** (ära jää ainult vahemällu) |
| Usage Check | Enabled |
| Ctl Store Name | `(null)` või `ClientAuthIssuer` (kui CTL kasutusel, hoidla ei tohi olla tühi) |
| Disable Authority Info Access | Kui **Enabled**, peab kohalik `CA` hoidla sisaldama iga kasutusel oleva kaardigeneratsiooni väljastajat — HTTP.sys ei lae puuduvat lüli enam alla |

Kliendisertifikaatide **filtreerimine** (valikuline, juhendi “lisakonfiguratsioon”): lisa `sslctlstorename=ClientAuthIssuer` ja `SendTrustedIssuerList=1`. Siis saadab server kliendile lubatud CA loendi. Vale/tühi CTL = 403.16.

Automatiseerimise nüansid (Ansible):

- Seos on **IP:port põhine**. `0.0.0.0:443` muutmine ei mõjuta konkreetse IP seost (`10.0.0.11:443`) ja vastupidi. Kontrolli, mis real `netsh http show sslcert` väljundis päriselt on.
- Olemasoleva seose muutmiseks kasuta `netsh http update sslcert ...` — `delete` + `add` jätab vahepeale akna, kus sait on ilma serdita.
- `appid` on suvaline GUID, aga IIS-i loodud seostel on see IIS-i oma: `{4dc3e181-e14b-4a21-b022-59fc669b0914}`. Hoia sama, muidu IIS Manager ja `netsh` näitavad erinevat juttu.
- **Serdi uuendamine muudab `certhash`-i.** Ansible peab uuendamise järel seose üle kirjutama, muidu mTLS jääb vana serdi peale või katkeb.
- IIS *Client Certificate Mapping Authentication* ja *IIS Client Certificate Mapping* peavad olema **väljas**, kui identiteet tuleb rakenduse koodist. Sisse lülitatud mapping ilma reeglita annab 403 ka siis, kui ahel on korras.

### 5. WCF

`wsHttpBinding` `security mode="Transport"`, `clientCredentialType="Certificate"`. IIS/HTTP.sys teeb mTLS; teenus loeb serti `HttpContext.Request.ClientCertificate` / `ServiceSecurityContext`.

Toodangus `certificateValidationMode="ChainTrust"`, `revocationMode="Online"` (lab: `PeerOrChainTrust` + `NoCheck`).

Rakendus peab pärast usaldust kontrollima NCP+ `0.4.0.2042.1.2` **ja** ESTEID2018 **või** ESTEID2025 dokumendipoliitika OID-d (väljastajaga seotud). `anyPolicy` (`2.5.29.32.0`) ei ole ID-kaart. Ära usalda `X-Client-Cert` HTTP päist, kui TLS ei lõpe selles protsessis.

### 6. TLS protokollid

Keela TLS 1.0/1.1 Schannelis.

**Hoiatus .NET Framework 4.8 kliendile:** juhendi soovitus “uutes lahendustes ainult TLS 1.3” käib pigem brauseripõhiste lahenduste kohta. .NET Framework 4.8 WCF klient räägib praktikas **TLS 1.2**-t. Kui keelad Schannelis TLS 1.2 enne, kui oled oma ClickOnce kliendiga TLS 1.3 üle testinud, kaob ühendus üldse (mitte 403, vaid handshake ei õnnestu).

mTLS **töötab TLS 1.2-ga täiesti korralikult**: `clientcertnegotiation=enable` küsib serti kätluse ajal ka TLS 1.2 all. Seega jäta TLS 1.2 lubatuks, kuni klient on TLS 1.3 peal tõestatud.

### 7. Logimine

- IIS logging: W3C, väljad `sc-status`, `sc-substatus`, `sc-win32-status`.
- Failed Request Tracing: staatus 403, saidi `/Demo.svc`.
- CAPI2 Operational log (allpool).

---

## URL-id, mida IIS peab kätte saama (AIA / OCSP / CRL)

HTTP.sys ehitab ahela **CAPI2 / Schannel** kaudu. Võrk käib **WinHTTP** kui **Local System**, **mitte** IE ega `Web.config` `<defaultProxy>`.

Töö VM-il **ei ole vaikimisi väljuvat ligipääsu**. Tellimus on kas **otse** nendele hostidele või **ainult korporatiivproxyle** (siis WinHTTP peab proxyle minema, proxy lubab allolevad URL-id, **ilma 407-ta** masinakontole).

### Kaks kihti — ära telli kõike “igaks juhuks” ühe hunnikuna

| Kiht | Vaja PIN1-ks? | Võrk | Kui puudu |
|---|---|---|---|
| **A. Ahel (usaldus)** | **Jah, alati** | **Ei**, kui neli CA faili on juba hoidlates (Ansible `win_copy` kontrollerilt) | **403.16** / `800B0109` |
| **B. Tühistus (OCSP/CRL)** | Ainult kui `verifyclientcertrevocation=enable` | Jah — allolevad :80 (ja varu :443) | **403.13** / `80092013` |
| WCF `Web.config` proxy | Ei (PIN1 kätlus) | Ainult kui rakendus ise teeb `revocationMode=Online` või PIN2 ajatempli | rakenduse viga, mitte IIS 403.16 |
| `ocsp.smit.sise` | **Ei** | Ettevõtte PKI müra | Schannel 36928; APP12-l tühistus off → ei tapa loginit |

Suletud VM + Ansible vaikimisi (`eid_revocation: false`, `eid_download_certs: false`): **PIN1 töötab ilma ühegi SK auguta**, kui `certs/eid-ca` on kontrolleril ja roll jookseb **igal** IIS-il. Tühistus lülita sisse alles pärast kihi B tellimust + `netsh winhttp show proxy`.

### Kiht A — failid (kord, paigalduseks)

RIA juhend: [IIS veebiserverile ID-kaardi toe seadistamine](https://open-eid.github.io/iis/index.et.html). Allalaadimine on vaja **ainult kontrolleril** või kui `eid_download_certs: true`.

| Fail | URL (juhend) | Port | Hoidla |
|---|---|---|---|
| `EE-GovCA2018` | `https://c.sk.ee/EE-GovCA2018.der.crt` | 443 | **Root** |
| `EEGovCA2025` | `https://crt.eidpki.ee/EEGovCA2025.crt` | 443 | **Root** |
| `ESTEID2018` | `http://c.sk.ee/esteid2018.der.crt` (HTTPS ka) | 80 / 443 | **CA** + **ClientAuthIssuer** |
| `ESTEID2025` | `https://crt.eidpki.ee/ESTEID2025.crt` | 443 | **CA** + **ClientAuthIssuer** |

Organisatsiooni kaardid (ainult kui neid kasutate): `EID-SK 2016` → `https://www.sk.ee/upload/files/EID-SK_2016.der.crt` ka **CA** + **ClientAuthIssuer**.

Ansible **ei** pane vaikimisi `sslctlstorename`. CTL + puudulik issuer = APP12 403.16.

### Kiht B — mida HTTP.sys kätluse ajal päriselt küsib

RIA: ESTEID2018 OCSP `http://aia.sk.ee/esteid2018`, ESTEID2025 OCSP `http://ocsp.eidpki.ee`. Lab (päris kaart, 20.09.2026, WinHTTP → lab-proxy):

| URL | Port | Milleks |
|---|---|---|
| **`http://aia.sk.ee/esteid2018/...`** | **80** | ESTEID2018 lehe OCSP (kirjas kaardi AIA-s) |
| **`http://aia.sk.ee/ee-govca2018/...`** | **80** | juurika OCSP (HTTP.sys küsis koos kaardiga) |
| **`http://c.sk.ee/EE-GovCA2018.crl`** | **80** | CRL, kui OCSP keelatakse / ei vasta |
| `http://aia.sk.ee/EE-GovCA2018` | 80 | sama juur, teine tee (juhend / certutil) |
| **`http://ocsp.eidpki.ee`** | **80** | ESTEID2025 lehe OCSP (RIA; 2018 kaart seda ei küsinud) |
| **`http://crl.eidpki.ee/EEGovCA2025.crl`** | **80** | 2025 juurika CRL (`ESTEID2025.crt` CDP) |
| `http://crt.eidpki.ee/EEGovCA2025.crt` | 80 | 2025 juur AIA-st (HTTP, mitte ainult 443) |
| `http://ocsp.sk.ee` | 80 | vanem SK OCSP / varu |
| `http://c.sk.ee/crls/esteid/esteid2018.crl` | 80 | ESTEID2018 CRL varu |
| `http://www.sk.ee/crls/esteid/esteid2018.crl` | 80 | CRL varu |

Tellimuse lühike nimekiri (otse **või** proxy allowlist, HTTP.sys = WinHTTP, **mitte** kasutaja IE):

```text
Hostid:  aia.sk.ee  ocsp.eidpki.ee  ocsp.sk.ee  c.sk.ee  crt.eidpki.ee  crl.eidpki.ee
Pordid:  TCP 80  ja  TCP 443
Auth:    masinakonto / Local System — proxy 407 = 403.13
```

`crt.eidpki.ee:443` on 2025 failide jaoks (kiht A). OCSP/CRL on **:80** — NSG ainult 443 = tühistus ikka 403.13. `crl.eidpki.ee` oli varem nimekirjast puudu.

PIN2 selles demos on **lokaalne** allkiri (ajatemplit SK-st ei küsita). Toodangu allkirjastamine võib vajada eraldi ajatempli URL-i — see ei ole PIN1.

Kui kesktaseme CA-d on **juba** LocalMachine\CA-s, AIA allalaadimist ahela *ehituseks* ei ole vaja — 403.16 kaob. **OCSP** on eraldi: `verifyclientcertrevocation=enable` => 403.13, kui kiht B on kinni.

WinHTTP süsteemiproxy (Administrator, **iga** IIS):

```text
netsh winhttp show proxy
netsh winhttp set proxy proxy-server="http://proxy.corp.local:8080" bypass-list="*.corp.local;<local>"
netsh winhttp reset proxy
```

App pool “load user profile” ei asenda WinHTTP masina proxyt CAPI2 jaoks.

Test (IIS masinas, SYSTEM kontekstile lähim on tavaline admin-sessioon + `certutil -verify -urlfetch`):

```text
powershell -File .\scripts\Test-EidAfterPin1.ps1
```

OCSP GET ilma päringukehata võib anda 400 — see on OK, kui **TCP :80 avaneb**. Tegelik OCSP on POST; seda näitab `certutil -verify -urlfetch`.

---

## WCF Web.config proxy vs WinHTTP

Tööl võib WCF teenuse `Web.config` / `app.config` olla rida proxy URL-iga, näiteks:

```xml
<system.net>
  <defaultProxy enabled="true" useDefaultCredentials="true">
    <proxy proxyaddress="http://proxy.corp.local:8080"
           bypassonlocal="true"
           usesystemdefault="false" />
  </defaultProxy>
</system.net>
```

**PIN1 kätluse ja IIS 403.16 / 403.13 jaoks seda faili ei loeta.** Sertifikaadi ahel ja OCSP teeb HTTP.sys / CAPI2 **enne**, kui päring WCF-i jõuab. WCF `Web.config` `<defaultProxy>` mõjutab ainult .NET-i enda väljuvat HTTP-d (`HttpWebRequest`, `HttpClient`, `X509Chain.Build` teenuse koodis).

| Kiht | Millal | Proxy |
|---|---|---|
| TLS + PIN1, IIS 403.7/13/16 | Enne WCF-i | **WinHTTP** masinal (`netsh winhttp`), Local System / HTTP.sys |
| WCF `serviceCredentials` `revocationMode="Online"` | Pärast edukat mTLS-i, rakenduse kood | `<system.net><defaultProxy>` / `ServicePointManager` |
| IE / Edge “augud”, kasutaja proxy | Sinu desktop | **Ei** kehti IIS app poolile ega HTTP.sys-ile |

Järjestus:

1. Klient saadab PIN1 serti TLS-is.
2. HTTP.sys / Schannel ehitab ahela ja (kui lubatud) küsib OCSP-d **WinHTTP** kaudu → ebaõnnestumisel **403.16** (usalda) või **403.13** (tühistus). WCF ei käivitu.
3. Alles 200 TLS-i järel jõuab SOAP WCF-i. Kui seal on `revocationMode="Online"`, võib .NET teha *teise* OCSP-päringu — **siis** loeb `Web.config` proxy.

Sellepärast võib töö `Web.config`-is proxy olla “õige” ja kaart ikkagi ebaõnnestuda: IIS VM-il puudub sama URL **WinHTTP**-s, või Local System ei pääse `aia.sk.ee` / `ocsp.eidpki.ee` peale.

Kontroll igal IIS-il (Administrator):

```text
netsh winhttp show proxy
```

Kui tühi (`Direct access`), aga `Web.config`-is on proxy — HTTP.sys OCSP **ei** kasuta seda XML-i. Pane sama proxy WinHTTP-sse:

```text
netsh winhttp set proxy proxy-server="http://proxy.corp.local:8080" bypass-list="*.corp.local;<local>"
```

`usesystemdefault="true"` `Web.config`-is tähendab WinINET (IE) vaikimisi proxyt **selle protsessi kasutajale**, mitte automaatselt `netsh winhttp` sätet. App pool `ApplicationPoolIdentity` ei impordi sinu desktopi IE-proxyt.

Labis on `RevocationMode=NoCheck` ja HTTP.sys `verifyclientcertrevocation=disable`, seega kodus SK-proxyt ei ole vaja. Toodangus: WinHTTP **igal** IIS VM-il + soovi korral sama URL ka `Web.config`-is, kui WCF ise teeb `Online` tühistust.

See lab **ei pea** `Web.config`-i proxy rida sisaldama, et ID-kaardi kätlus töötaks. Kui kopeerid töö confist `<defaultProxy>`, jäta see WCF-i teise kihi jaoks ja sea WinHTTP eraldi.

---

## HAProxy (passthrough, kaks kihti)

Eesmärk: PIN1 sertifikaat jõuab **IIS-i**. Seega `mode tcp`, backend’i real **ei ole** `ssl`.

Täisnäide: `haproxy/haproxy-production.cfg`. Kodune Docker: `haproxy/haproxy.cfg` + `.\lab.ps1 haproxy`.

### Üks HAProxy, kaks IIS-i

```text
frontend https_front
    mode tcp
    bind *:443
    default_backend iis_backends

backend iis_backends
    mode tcp
    balance roundrobin
    option httpchk GET /health.json
    http-check expect status 200
    server iis1 10.0.0.11:443 check port 8080
    server iis2 10.0.0.12:443 check port 8080
```

- `check port 8080` — health **mitte** 443 peal (muidu mTLS / 403 rikub check’i).
- Timeoutid pikad (`timeout tunnel 1h`): WCF Keep-Alive.
- `balance source`: uus TCP sama kliendi IP-st samasse IIS-i. Keep-Alive kleepub niikuinii ühe TCP eluajaks.

**Vale:** `server iis1 10.0.0.11:443 ssl verify none` — TLS lõpeb HAProxy-s, IIS ei näe kaarti (403.7 või tühi cert).

### Väline HAProxy → sisemine HAProxy → IIS

Kui väline teeb `balance source` ilma PROXY protocolita, näeb sisemine kõigil ühendustel **välise HAProxy IP-d** → kõik kliendid ühte IIS-i.

- Väline: `server int1 10.0.0.2:443 send-proxy-v2 check`
- Sisemine: `bind *:443 accept-proxy` ja soovi korral `balance source`

403.16 IIS-is tähendab: TCP/TLS (ja tavaliselt ka kliendisert) **jõudis VM-i** → passthrough töötab; paranda selle VM-i ahelat, mitte HAProxy SSL-i.

### Health IIS-is

Eraldi HTTP sait/binding, näiteks `http://10.0.0.11:8080/health.json`, vastus 200, **Anonymous**, **ilma** SSL Require. Ära pane health’i `Demo.svc` taha (mTLS + OCSP tapaks check’i).

**Aga:** health peab olema **samas app poolis** kui WCF rakendus. Kui teed health’i eraldi saidiks eraldi app pooliga, siis app pooli krahh, hang või `.NET`-i laadimise viga jätab health’i **200** peale — HAProxy hoiab masinat UP ja kasutaja saab 503 / timeout. Labis on `health.json` ja `Demo.svc` samal saidil ja samas poolis, seetõttu **Kinni** test töötab.

Praktiline kompromiss: health on samas rakenduses ja teeb ühe odava kontrolli (nt kas WCF host käivitus), aga **ilma** kliendisertifikaadi ja tühistuskontrollita.

---

## Diagnostika: üks koht, kust vaadata

Tüüpiline häda: klient näitab ainult `The HTTP request was forbidden with client authentication scheme 'Anonymous'`, aga päris põhjus on kolmes eri kohas — Windowsi sündmuselogi, IIS-i logi ja rakenduse logi. Selles labis on see kokku toodud.

Miks WCF ei saa ise põhjust öelda: 403.7 / 403.13 / 403.16 tekivad **enne** rakendust (HTTP.sys ja IIS), alamstaatus on ainult IIS-i logis, ja WCF ümbersõnastab kõik 403-d „Anonymous“ jutuks. Seepärast on vaja kolme asja: kaardi test masina vastu, serveri koondraport ja kliendipoolne päris staatus.

### 1. CertProbe — kõige otsem vastus (kaart selle masina vastu)

```powershell
.\lab.ps1 probe          # kuulab https://demo.local:9444/
.\lab.ps1 probe-stop
```

Ava see aadress **ID-kaardiga** (brauser või klient). `Demo.CertProbe` teeb sama mTLS kätluse nagu IIS, aga **usaldab iga kliendisertifikaati**. Seetõttu jõuab päring alati raportini ka siis, kui IIS oleks vastanud 403.16-ga ilma selgituseta.

Raport ütleb ühel lehel:

| Osa | Mida näed |
|---|---|
| TLS kätlus | protokoll (Tls12/Tls13), kas server küsis serti, Schannel-i hinnang |
| Kliendi sertifikaat | subject, väljastaja, kehtivus, isikukood, EKU, poliitika-OID-d |
| Ahel ja hoidlad | iga lüli ja **millisest hoidlast** see tuli (`LocalMachine\CA`, `ClientAuthIssuer`, `Root`) |
| Tühistus | kaardi OCSP/CRL URL-id ja kas need vastasid (koos kestusega) |
| Masina seaded | `ClientAuthIssuer` sisu, `ClientAuthTrustMode`, `SendTrustedIssuerList` |
| Rakenduse poliitika | mida `DemoService` OID-kontroll otsustaks |

Verdikt on esimese asjana lehe alguses: `[403.7]`, `[403.16]`, `[403.13]`, `[TUHISTATUD]` või `[OK]`, ja kohe alla parandamise käsud (õige `certutil -addstore` täpselt selle väljastaja jaoks). Logi: `.lab\certprobe.log`.

Lisaks salvestab probe iga kätluse järel nähtud kliendisertifikaadi faili `.lab\lastclient.cer`. Järgmine `.\lab.ps1 report` võtab selle ise ette ja laseb sellel `certutil -verify -urlfetch` — nii saad ühe käiguga teada, kas **see** kaart **selles** võrgus ka ahela ja OCSP kätte saab.

See fail sisaldab kasutaja avalikku sertifikaati, seega nime ja isikukoodi. `.lab/` on `.gitignore`-s, aga toodangu masinas kustuta see pärast tõrkeotsingut ära (`Remove-Item .lab\lastclient.cer`) — sama reegel nagu logidega.

Toodangus: kopeeri `Demo.CertProbe.exe` + `Demo.Contracts.dll` IIS VM-i, käivita `Demo.CertProbe.exe --cert <serveri serdi thumbprint> --port 9444` ja ava kaardiga. **Eemalda pärast** — see tööriist ei kontrolli usaldust, seega ei tohi see jääda kuulama.

### 2. Get-EidReport.ps1 — üks fail serveri poolelt

```powershell
.\lab.ps1 report 15      # viimased 15 min, avab faili
.\lab.ps1 diagnose       # sama raport, ei ava
```

Kirjutab `.lab\eid-report-<aeg>.txt`, kus verdikt on **faili alguses** ja allpool üheksa sektsiooni:

1. Hoidlad (Root / CA / ClientAuthIssuer + Schannel registrivõtmed)
2. HTTP.sys seosed — ainult mTLS-i puudutavad (arendusmasina VS-seoseid ei näidata)
3. WinHTTP proxy
4. Väljuvad OCSP/CRL hostid (TCP test) ja **`certutil -verify -urlfetch`** kliendiserdi peal: iga AIA/OCSP/CRL URL eraldi, koos kestusega — see leiab proxy 407, MITM ja aeglase CRL-i, mida TCP test läbi laseb
5. IIS / IIS Express W3C read koos **`sc-substatus`**-ega — siin on see number, mis WCF ära peidab
6. HTTPERR
7. CAPI2 (`800B0109` → 403.16, revocation offline → 403.13, `800B010C` → tühistatud)
8. Schannel süsteemilogist (TLS alert 48 = unknown_ca jne)
9. Rakenduse logid: CertProbe, teenus, klient, load balancer

Kui CAPI2 on välja lülitatud, ütleb raport seda ja `-EnableLogs` lülitab sisse (siis korda PIN1 ja käivita uuesti).

Sertifikaadikontroll (3c sektsioon) käivitub kolmel viisil:

```powershell
.\lab.ps1 probe                                   # kaardiga -> .lab\lastclient.cer
.\lab.ps1 report                                  # kontrollib selle serdi automaatselt
.\scripts\Get-EidReport.ps1 -CertFile kaart.cer   # oma failiga (nt kasutaja eksporditud sert)
```

Tulemus näeb välja nii (siin terve masin, kus kõik URL-id vastasid):

```text
FILE ...\lastclient.cer
  Verified   0s  Certificate (0)  http://c.sk.ee/EE-GovCA2018.der.crt
  Verified   0s  Base CRL (25)    http://c.sk.ee/EE-GovCA2018.crl
  Verified   0s  OCSP             http://aia.sk.ee/ee-govca2018
  VERDICT certutil: chain + revocation OK on this machine
```

Kui mõni rida on `Failed`, ütleb verdikt ka põhjuse: `12016` / „requires user authentication" = **proxy nõuab 407 autentimist**, `12002` = aegumine (suur CRL või aeglane proxy), `0x80092013` = tühistusteenus kättesaamatu (403.13 rada), `0x800B0109` = ahel ei ole usaldatud (403.16 rada).

Kolm asja, mis muidu eksitavad:

- **Proxy taga on 3b sektsioon eksitav.** 3b teeb **otse** TCP-ühendusi SK/eidpki hostidele. Kui masin käib väljapoole ainult süsteemiproxy kaudu, näitab see FAIL-i ka siis, kui tühistus töötab, ja vastupidi: port võib vastata, aga proxy nõuab autentimist. Proxy keskkonnas on otsustav 3c (`certutil -verify -urlfetch`, mis kasutab WinHTTP seadeid) ja käsitsi kontroll:

```powershell
netsh winhttp show proxy                         # proxy + bypass-list
Invoke-WebRequest -Uri <ocsp-url> -Proxy <proxy-url> -UseBasicParsing -TimeoutSec 15
```

- **IIS logi puhverdab kuni ~60 s.** Kui käivitad raporti kohe pärast viga, võib rida veel puududa. Raport ütleb siis „no 403/4xx/5xx in the last N min“ — oota hetk ja käivita uuesti, ära järelda, et kõik on korras.
- **Ajatemplid IIS logis on UTC**, sündmuselogis kohalik aeg. Raport arvestab sellega, aga kui võrdled käsitsi, ära jahi „kadunud“ ridu vale tunniga.

### 3. Klient: nupp „Diagnostika“

Kliendi vormil on nupp **Diagnostika: mis täpselt ebaõnnestus?**, mis **käivitub ka automaatselt**, kui teenus vastab 403-ga. See teeb sama kätluse käsitsi, ilma WCF-ita, ja näitab:

- kas server **küsis** kliendisertifikaati (kui ei → 403.7 rada: `Negotiate Client Certificate` või TLS-i lõpetav balancer)
- kas server saatis lubatud väljastajate loendi (`SendTrustedIssuerList`) ja mis selles on
- **päris HTTP staatus ja alamstaatus** vastuse kehast: `403.16` / `403.13` / `403.7`
- verdikt ühe lausena, mitte „Anonymous“

Kliendi logi: `%LOCALAPPDATA%\IIS-ID\client.log`.

### 4. Mis seadistuses muutus, et logid üldse tekiksid

| Muudatus | Miks |
|---|---|
| IIS Express W3C logimine sisse, kaust `.lab\iislogs` | vaikimisi oli **väljas** — ilma selleta ei ole alamstaatust kuskilt võtta |
| Logiväljad `sc-substatus` + `sc-win32-status` | 403 vs 403.16 vs 403.13 vahe on ainult siin |
| `httpErrors errorMode="Detailed"` (`Web.config`) | server saadab alamstaatuse ka kliendile; toodangus jäta `DetailedLocalOnly` |
| `App_Data\service.log` (`ServiceLog`) | rakenduse tasand: correlation, backend, app pool, sert, poliitika otsus |
| `appSettings` võti `serviceLogPath` | logitee on seadistatav; toodangus suuna rakendusest väljapoole |
| correlation-ID kliendi logis ja teenuse logis | sama päring kahes failis leitav |

Isikukood läheb `service.log`-i **maskitult** (`390******00`). Toodangus hoia see reegel — logid on isikuandmed.

Näide, mida `service.log` päriselt sisaldab (sama `correlation` on ka kliendi logis):

```text
2026-09-17 23:09:20  WhoAmI    correlation=test1234 backend=HOST/Backend1 pool=Backend1Pool cert=LAB USER AUTH issuer=IIS-ID Home Lab Root thumb=84FD... isik=390******00 -> OK poliitika: ...
2026-09-17 23:09:20  Ping      correlation=test1234 backend=HOST/Backend1 pool=Backend1Pool cert=LAB USER AUTH issuer=IIS-ID Home Lab Root thumb=84FD... isik=390******00 -> OK
```

**Logikataloog peab olema olemas juba enne esimest päringut.** Kui rakendus loob `App_Data` ise, võib ASP.NET selle failimuutuse peale AppDomain'i taaskäivitada ja **esimene rida kaob** — täpselt see rida, mida tõrkeotsingul vaja on. Seepärast on kataloog repos olemas ja logitee on seadistatav:

```xml
<add key="serviceLogPath" value="~/App_Data/service.log" />
```

Toodangus pane see rakendusest väljapoole (`D:\logs\demo\service.log`): logi jääb deploy'de vahel alles, kirjutamine ei puutu rakenduse kataloogi ja Ansible saab kataloogile anda app pooli identiteedile kirjutusõiguse.

### 5. Kust vaadata, kui...

| Sümptom | Esimene koht | Mida see tähendab |
|---|---|---|
| PIN1 küsiti, siis 403 | `.\lab.ps1 probe` kaardiga | verdikt ütleb kohe 403.7 / 13 / 16 |
| Klient ütleb „Anonymous“ | kliendi nupp Diagnostika | näitab päris alamstaatuse |
| Vaja tõendit, mis serveris juhtus | `.\lab.ps1 report 15` | IIS `sc-substatus` + CAPI2 + Schannel |
| `service.log` on tühi, aga klient sai vea | HTTP.sys / IIS tasand | päring ei jõudnudki WCF-ini → loe alamstaatust |
| `service.log`-is on „POLIITIKA TAGASI LUKATUD“ | rakenduse OID-kontroll | HTTP.sys lubas läbi; see ei ole 403 |
| Ükski logi ei näita midagi | LB logi `.lab\lb.out.log` | päring ei jõudnud serverini üldse |

### 6. Toodangus (Ansible peab need sisse lülitama)

- IIS saidi W3C logimine + väljad `sc-substatus`, `sc-win32-status` (muidu kordub sama pimedus)
- CAPI2 Operational: `wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true` (jäta sisse ainult tõrkeotsingu ajaks, logi kasvab kiiresti)
- logikataloog **luuakse ette** ja saab app pooli identiteedile kirjutusõiguse; `serviceLogPath` osutab rakendusest väljapoole
- `Get-EidReport.ps1` **igal** IIS-il — 403.16 on masinapõhine, ühe masina roheline vastus ei tõesta midagi teise kohta. Sama kehtib `Get-IdCardMatrix.ps1` kohta: selle mõte on just kahe hosti `FINGERPRINT` rea vahe
- `httpErrors` jäta `DetailedLocalOnly`; alamstaatus võta logist, mitte kliendi ekraanilt

---

## PIN1 järel ebaõnnestumine: skriptid ja logid

PIN1 aken = **kliendi** Windows oskab kaarti. Viga pärast seda = **selle IIS-i** HTTP.sys / CAPI2 / OCSP.

Kiire tee on [Diagnostika: üks koht, kust vaadata](#diagnostika-üks-koht-kust-vaadata) (`.\lab.ps1 probe` + `.\lab.ps1 report`). Allpool on sama asi käsitsi — kasulik siis, kui tahad täpselt teada, kust mingi number tuleb, või kui tööl ei tohi neid tööriistu kopeerida.

### Skriptid (selles repos)

Käivita **sellel Windows Serveril**, kuhu handshake läks (või labis samas PC-s).

```powershell
.\lab.ps1 diagnose
```

või eraldi:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\Get-EidReport.ps1 -Minutes 15
powershell -ExecutionPolicy Bypass -File .\scripts\Get-EidReport.ps1 -EnableLogs
powershell -ExecutionPolicy Bypass -File .\scripts\Get-IdCardMatrix.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Test-ClientCertTrust.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Test-EidAfterPin1.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Test-EidAfterPin1.ps1 -EnableCapi2Log
```

`Get-EidReport.ps1` on koondraport (üks fail, verdikt ees): *mis juhtus*. `Get-IdCardMatrix.ps1` vastab [võrdlusmaatriksi](#2-võrdlusmaatriks) ridade kaupa: *millises reas on viga*; `-Compare` diffib kaks hosti (rida 18) ja `-NoNetwork` sobib suletud VM-i. `Test-*` skriptid on vanemad üksiktestid, mis kirjutavad ainult ekraanile.

Mitme hosti peale korraga (fetchib väljundid `.lab/matrix-<host>.txt`):

```bash
ansible-playbook -i inventories/work.yml matrix.yml -e matrix_minutes=1440
```

`-EnableCapi2Log` paneb CAPI2 Operational logi käima; tee PIN1 uuesti ja käivita skript veel kord.

`Install-EsteidIisProduction.ps1` — ainult õiged hoidlad (toodangu paigutus).

### Mida skriptid kontrollivad

1. Root / CA / ClientAuthIssuer sisu  
2. `netsh http show sslcert` (Negotiate, revocation, Ctl Store)  
3. `netsh winhttp show proxy`  
4. TCP/HTTP SK ja eidpki URL-idele  
5. `certutil -verify -urlfetch` PIN1 lehele (kui see kasutaja hoidlas on)  
6. CAPI2 viimased sündmused  
7. `HTTPERR` (`C:\Windows\System32\LogFiles\HTTPERR\`)  
8. IIS / IIS Express W3C logid, read `403` / `Demo.svc`

### Logid käsitsi

| Koht | Otsid |
|---|---|
| IIS W3C `%SystemDrive%\inetpub\logs\LogFiles\W3SVC*\` | `sc-status` **403**, `sc-substatus` **16** (ahel) või **13** (OCSP) või **7** (serti pole) |
| IIS Express | `%USERPROFILE%\Documents\IISExpress\Logs\` |
| Failed Request Tracing | IIS Manager → Failed Request Tracing Rules, staatus 403 |
| HTTPERR | `C:\Windows\System32\LogFiles\HTTPERR\httperr*.log` — katkestus enne IIS-i |
| CAPI2 | Event Viewer → *Applications and Services Logs* → *Microsoft* → *Windows* → *CAPI2* → *Operational*. Luba: `wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true` |
| Schannel | System log, allikas Schannel |
| HAProxy | `log stdout` / rsyslog; `show stat` — backend UP/DOWN |

CAPI2 tüüpilised koodid:

- `800B0109` (`CERT_E_UNTRUSTEDROOT` / chaining) → **403.16**, puudu CA/Root  
- revocation offline / `CERT_E_REVOCATION_FAILURE` → **403.13**, OCSP/WinHTTP  
- `CERT_E_REVOKED` → kaart tühistatud  

Lehe eksport kliendist, kontroll **IIS masinas**:

```text
certutil -dump client.cer
certutil -verify -urlfetch client.cer
```

`Chain` peab olema 3 sertifikaati (leht + ESTEID + EE-Gov). `Leaf` + `AIA` / `OCSP` read näitavad, kas SK vastas.

### Otsustuspuu pärast PIN1

```
PIN1 küsiti?
  ei -> klient ei valinud ID-kaardi PIN1 serti (lab-CA, vale EKU, SendTrustedIssuerList)
  jah ->
    IIS log 403.7  -> sert ei jõudnud (Negotiate off, HAProxy ssl termination)
    IIS log 403.16 -> ahel / ClientAuthIssuer / CTL  -> Test-ClientCertTrust + stores
    IIS log 403.13 -> OCSP                         -> Test-EidAfterPin1 URL + WinHTTP
    200, aga WCF Fault "poliitika" -> OID (NCP+ / vale ESTEID põlvkond), mitte HTTP.sys
```

WCF `forbidden ... scheme 'Anonymous'` = loe IIS **alamstaatus** 16 või 13, ära otsi “anonüümset kasutajat”.

---

## lab.ps1 käsud

```powershell
.\lab.ps1 help
```

| Käsk | Mis |
|---|---|
| `certs` | Lab CA + `demo.local` server + PIN1/PIN2 test-sertid |
| `bind` | **ADMIN:** HTTP.sys mTLS, urlacl, hosts |
| `eid-ca` | EE-GovCA / ESTEID ahelad ID-kaardi testiks |
| `build` | Kompileeri (sulgeb avatud `Demo.Client` kui fail lukus) |
| `start` | 2 × IIS Express + TCP LB |
| `start-selfhost` | Sama pordid ilma IIS Expressita |
| `start-lb` | Ainult balancer `backends.txt` pealt; valikuline `.\lab.ps1 start-lb 0.0.0.0` |
| `client` | Ava WinForms klient |
| `down Backend1` | Tape backend (failover) |
| `up Backend1` | Toob backend’i tagasi |
| `stop` | Peata lab |
| `status` | PID-d ja kuulavad pordid |
| `diagnose` | Koondraport failina: hoidlad, HTTP.sys, WinHTTP, SK URL-id, CAPI2, Schannel, IIS/HTTPERR, rakenduse logid |
| `report` / `report 15` | Sama raport ja avab selle kohe (vaikimisi 30 min aken) |
| `probe` / `probe-stop` | `Demo.CertProbe` pordil 9444: ava ID-kaardiga, saad verdikti 403.7 / 403.13 / 403.16 / OK; salvestab serdi `.lab\lastclient.cer` |
| `proxy [mode]` / `proxy-stop` | Logiv lab-proxy pordil 3128: näitab, **mis URL-e Windows ise küsib**. `allow` / `allowlist` / `auth407` / `deny` / `timeout` |
| `lockdown [nimi]` | **ADMIN:** tee masinast suletud võrgu server. Ilma nimeta = status. `hosts-blackhole` / `system-no-net` / `proxy-only` / `dead-proxy` / `no-aia` / `no-issuer` |
| `unlock` | **ADMIN:** võtab kõik lockdown-muudatused tagasi |
| `haproxy` / `haproxy-stop` | Docker HAProxy TCP passthrough |
| `hyperv` / `vm` / `vm-start` / `vm-check` / `vm-fix` | Hyper-V suletud võrgu VM (vt [peatükk 24](#suletud-võrgu-lab-lockdown-proxy-ja-windows-server-vm)) |
| `iac` | Ansible kontrollsõlm WSL-i (ansible-core + Windows collectionid) |
| `ansible-ping` | WinRM `win_ping` guestile `192.168.56.10` (`$env:LAB_WINRM_PASSWORD`) |
| `ansible` | Sama IIS/ESTEID/WinHTTP roll mis Nutanixis; buildib ja teeb ClickOnce `/install` enne |
| `publish` | ClickOnce paigaldus `publish\clickonce` (leht: `http://demo.local:8080/install/`) |
| `tf` / `tf apply` | Terraform juur `terraform/hyperv` (switch + VM; destroy ei kustuta Windowsit) |

Diagnostika täpsem selgitus: [Diagnostika: üks koht, kust vaadata](#diagnostika-üks-koht-kust-vaadata). Suletud võrgu stsenaariumid ja VM: [Suletud võrgu lab](#suletud-võrgu-lab-lockdown-proxy-ja-windows-server-vm).

Skriptid, mida `lab.ps1` ei mähi:

| Skript | Mis |
|---|---|
| `scripts\Set-LabLockdown.ps1 <nimi> -Preview` | näitab täpselt, mida muudetakse, ilma muutmata |
| `scripts\Start-LabProxy.ps1 allow -Bind any` | proxy ka VM-idele (host = ainus tee välja) |
| `scripts\Install-LabServer.ps1` | **VM-i sees, ilma Ansible'ta:** päris IIS, app poolid, W3C alamstaatus, valikuline FREB |
| `scripts\Enable-LabWinRm.ps1` | **VM-i sees, kord:** staatiline IP + WinRM HTTP:5985, et host saaks Ansible’t joosta |
| `scripts\Install-LabIac.ps1` | Hostis: ansible-core WSL-i (`.\lab.ps1 iac`) |

---

## URL-id ja pordid

| URL | Mis |
|---|---|
| `https://demo.local:9443/Demo.svc` | Klient läbi balanceri (mTLS) |
| `http://127.0.0.1:8404/` | LB juhtimine: Kinni / Käima / drain / roundrobin |
| `http://demo.local:8080/install/` | ClickOnce paigaldusleht (ilma PIN1 / kliendiserdita) |
| `http://127.0.0.1:8080/health.json` | Backend1 health (ilma serdita) |
| `http://127.0.0.1:8081/health.json` | Backend2 health |
| `https://127.0.0.1:8443/Demo.svc` | Otse Backend1 (mööda balancerist) |
| `https://127.0.0.1:8444/Demo.svc` | Otse Backend2 |
| `https://demo.local:9444/` | `Demo.CertProbe` diagnostikaraport (ainult `.\lab.ps1 probe` ajal) |

Klient peab kasutama nime **`demo.local`**, sest WCF DNS-identiteet ja serveri sert on sellele nimele. `https://127.0.0.1:9443` võib anda nime-mittesobivuse.

---

## Terraform ja Ansible

Kood on repos:

| Kaust | Mis | Kas kodus `apply` / playbook |
|---|---|---|
| [`terraform/hyperv`](terraform/hyperv) | Internal switch + Windows Server VM (kutsub `New-LabVm.ps1`) | jah, kui Hyper-V ja ISO on olemas. Olemasolev `IIS-ID-Server` = no-op |
| [`terraform/nutanix`](terraform/nutanix) | 2 IIS-i + 1 HAProxy, subnet, image — **töö mall** | ei. Kopeeri töö IaC-sse, ära rakenda Prismile siit labist |
| [`ansible/`](ansible) | `eid_trust`, `winhttp_proxy`, `iis_eid`, `haproxy_passthrough` | jah, vastu guest’i `192.168.56.10` pärast WinRM-i |

Hüperviisori Terraform **ei kanna üle** (erinev provider). Ansible rollid **kannavad**: nad räägivad Windowsi, HTTP.sys-i ja HAProxy `mode tcp` peale, mitte Prismiga ega Hyper-V-ga. Pikem seletus: [`terraform/README.md`](terraform/README.md), [`ansible/README.md`](ansible/README.md).

```powershell
# guestis, kord (pärast Windows Setupi):
powershell -File C:\IIS-ID\scripts\Enable-LabWinRm.ps1 -StaticIp 192.168.56.10

# hostis:
.\lab.ps1 certs
.\lab.ps1 iac                          # ansible-core WSL-i
$env:LAB_WINRM_PASSWORD = '<VM Administrator>'
.\lab.ps1 ansible-ping
.\lab.ps1 ansible                      # IIS + ESTEID + WinHTTP; sama roll mis Nutanixis
# .\lab.ps1 tf plan                    # valikuline; VM on sul juba olemas
```

`Install-LabServer.ps1` jääb alles: see on sama töö **ilma** Ansible’ta, kui WinRM-i veel pole. Ära jooksuta mõlemat järjest vastuollu minevate muutujatega — vali üks.

Alljärgnev checklist on selleks, et PIN1/mTLS tükid ei jääks “käsitsi ühele VM-ile”, mis on tüüpiline 403.16 põhjus (üks IIS-il ahel olemas, teisel mitte).

### Mis kuhu kuulub

| Kiht | Tüüpiline tööriist | ID-kaardi jaoks oluline |
|---|---|---|
| VM-id, NIC, disk, NSG/SG, VIP, sise-DNS | **Terraform** | IIS-id ja HAProxy peavad olemas olema; **väljuv 80/443** SK/eidpki hostidele või korporatiivproxyle |
| HAProxy VIP :443, stats :8404 | Terraform (LB/VM) + **Ansible** (config) | `mode tcp`, **mitte** TLS termination |
| Windows: IIS, app pool, sait, `web.config` | **Ansible** | `.NET 4.8`, Anonymous, SSL Require + kliendisert `/Demo.svc` peal |
| ESTEID/EE-GovCA hoidlad | **Ansible, iga IIS host** | Root / CA / ClientAuthIssuer idempotentselt |
| `netsh http add sslcert` | **Ansible, iga IIS** | `clientcertnegotiation=enable`; toodangus revocation enable |
| WinHTTP proxy | **Ansible, iga IIS** | `netsh winhttp set proxy ...` — **mitte** ainult `Web.config` `<defaultProxy>` |
| Health HTTP :8080 `/health.json` | Ansible sait + Terraform NSG sisse HAProxy-st | Check **ilma** mTLS-ita |
| WCF `Web.config` proxy URL | Ansible template | Ainult .NET teine kiht; vt [WCF proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp) |
| Serveri HTTPS sert (sama CN/SAN kõigil IIS-idel) | Terraform ACM/Key Vault **või** Ansible `win_certificate` | Passthrough: klient kontrollib IIS-i serti |

Terraform **security group / NSG**, mida inimesed unustavad:

- Sisse: HAProxy → IIS `:443` (mTLS) ja HAProxy → IIS `:8080` (health).
- Välja **igalt IIS-ilt** (ainult kui tühistus on sees): HTTP 80 ja HTTPS 443 `aia.sk.ee`, `ocsp.eidpki.ee`, `c.sk.ee`, `crt.eidpki.ee`, `crl.eidpki.ee` **või** ainult korporatiivproxy + WinHTTP. PIN1 usaldus (403.16) SK auku ei vaja.
- “VM-il pole internetti, IE-s on augud” + Terraform default-deny egress = OCSP **403.13**, isegi kui Ansible pani `Web.config` proxy.

### Ansible: idempotentne IIS-i roll (kõik backend’id)

Mängi roll **kõigil** `iis` hostidel, mitte ühel “golden” masinal. Uus VM Terraformist ilma selle rollita = vahelduv 403.16 (round-robin tabab tühja ClientAuthIssuer’it).

Soovituslikud ülesanded (nimed on näited):

1. `win_feature`: IIS, ASP.NET 4.8, HTTP activation (WCF).
2. Sertide failid repositooriumist või `get_url` SK-st (võrgu korral); `win_certificate` / `certutil -addstore` täpselt [hoidlate tabeli](#toodangu-iis-id-kaardi-ahel-ja-paigaldus) järgi.
3. `win_shell`: `netsh winhttp show proxy` / `set proxy` samast Ansible muutujast, mida kasutad `Web.config` proxy URL-i jaoks — **kaks kohta, sama URL**.
4. `win_iis_website` + HTTPS binding; seejärel `netsh http` Negotiate Client Certificate (Server 2022-l Manageri ruutu pole).
5. Eraldi site või binding health-pordile, `SslRequireCert` **väljas**.
6. WCF rakenduse deploy (zip/win_copy) + `web.config` template (`RevocationMode`, valikuline `<defaultProxy>`).
7. CAPI2 log: `wevtutil sl Microsoft-Windows-CAPI2/Operational /e:true`.
8. Verify: `scripts/Test-EidAfterPin1.ps1` **kõigil** hostidel (`ansible iis -m script` või `win_command`). Fail ühel hostil = ära märgi rolli OK.

`serial: 1` + HAProxy drain/health DOWN enne IIS-i taaskäivitust — sama idee mis labi **Kinni** / **drain**.

### Terraform: HAProxy ja kaks kihti

- External + internal HAProxy: Terraform loob VM-id/VIP-d; Ansible kirjutab `haproxy.cfg` (`mode tcp`, `check port 8080`).
- Kui `balance source` üle kahe kihi: Ansible template `send-proxy-v2` / `accept-proxy`. Terraform üksi IP-sid ei “paranda”.
- `user_data` / cloud-init Windowsile: ära jäta ESTEID ahelat ainult esimese image’i külge; Ansible peab uue scale-out VM-i ikka üle käima.

### Muutujad (üks allikas)

Hoia nt `group_vars/iis.yml`:

```yaml
eid_winhttp_proxy: "http://proxy.corp.local:8080"
eid_winhttp_bypass: "*.corp.local;<local>"
eid_wcf_default_proxy: "{{ eid_winhttp_proxy }}"   # sama URL, teine kiht
eid_health_port: 8080
eid_https_port: 443
```

Terraform NSG egress ja Ansible WinHTTP peavad **sama** proxy või **sama** SK CIDR/hostide nimekirja kasutama. Kui TF lubab ainult 443 ja OCSP on :80, Ansible “proxy Web.config-is” ei aita HTTP.sys-i.

### Lab vs töö IaC

| Lab | Töö (Nutanix) |
|---|---|
| `terraform/hyperv` + `New-LabVm.ps1` | `terraform/nutanix` (päris `nutanix` provider, töö repos) |
| `ansible/inventories/lab.yml` (`192.168.56.10`, kaks saiti ühel VM-il) | `inventories/work.example.yml` või TF väljund `ansible_inventory` (üks sait `:443` per VM) |
| `.\lab.ps1 ansible` | `ansible-playbook -i work.yml site.yml` — **samad rollid** |
| `bind` / `eid-ca` / `Install-LabServer.ps1` | asendatud Ansible rollidega; skriptid jäävad varuvariandiks |
| Docker HAProxy hostil | Linux VM + `haproxy_passthrough` |
| Stats Kinni | Ansible drain + HAProxy server state või instance stop |

Ära pane Terraform state’i ega Ansible vaulti asemel labi `certs/*.pfx` toodangusse. Lab CA parool `lab` on ainult selle repo jaoks.

---

## Enne toodangut: kriitiline nimekiri

Lühivastus: **muster on õige**. Passthrough `mode tcp`, TLS lõpeb IIS-is, ahel iga masina peal, olekuta teenus, klient loob kanali vea korral uuesti — sellega saab ClickOnce / .NET 4.8 WCF + ID-kaardi HAProxy taha tööle.

Aga labis on viis asja lihtsustatud nii, et **tootmises need murduvad**. Need ei ole “nice to have”.

### 1. WCF sessioon tapab failoveri (kontrolli esimesena)

Labi teenus on **olekuta**: iga kutse loeb PIN1 serdi TLS-ühendusest uuesti. Sellepärast töötab teise IIS-i hüpe ilma uuesti sisse logimata.

Töö `Web.config` võib olla teine. Kui seal on:

- `[ServiceContract(SessionMode = SessionMode.Required)]`
- `<reliableSession enabled="true" />`
- `wsHttpBinding` `security mode="Message"` / `TransportWithMessageCredential`, kus `establishSecurityContext` on **true** (see on vaikimisi)

siis seob WCF seansi (WS-SecureConversation / reliable session) **ühe** IIS-i mäluga. Failover ei tööta: teine masin ei tunne seanssi ja klient saab `The message could not be processed because the action ... is invalid` või security-context vea.

Sel juhul on kaks teed: kas tee teenus olekuta (`mode="Transport"`, `establishSecurityContext="false"`, ilma reliable session’ita, nagu labis), või lisa HAProxy-sse päris kleepuvus (`balance source` + PROXY protocol) ja lepi sellega, et VM-i kukkumine lõpetab kasutaja seansi. Labi järeldus “kleepuvus tuleb Keep-Alive’ist” kehtib **ainult** olekuta variandi puhul.

### 2. TLS 1.3-only lõikab .NET 4.8 kliendi ära

Vt [TLS protokollid](#6-tls-protokollid). Ära keela Schannelis TLS 1.2, enne kui ClickOnce klient on TLS 1.3 peal päriselt testitud. Sümptom ei ole 403, vaid handshake ei õnnestu üldse — ja tundub “HAProxy viga”.

### 3. PIN2 allkiri labis ei ole juriidiline allkiri

`LocalSigner` teeb **toorallkirja** (ECDSA/RSA) UTF-8 baitide üle ja server kontrollib ainult matemaatikat + isikukoodi kattumist. Toodanguks on puudu:

| Puudu | Miks oluline |
|---|---|
| Serveri **nonce / challenge** | Praegu saab kliendi saadetud allkirja uuesti mängida (replay). Allkirjastatav sisu peab tulema serverist ja olema seotud PIN1 seansiga. |
| Allkirjastamissertifikaadi **ahel + OCSP** | Server usaldab praegu `SigningCertificateDer`-i sisu. Vaja `X509Chain` ChainTrust + tühistus, sama ESTEID ahela vastu. |
| **Ajatempel** (RFC 3161) ja konteiner (**ASiC-E / XAdES**) | Toorallkiri ei ole eIDAS-mõttes kehtiv allkiri ja seda ei saa hiljem tõendada. |

Kui tööl on vaja päris allkirja, käib see **libdigidocpp / DigiDoc SDK** kaudu, mitte `RSA.SignData` peal. Kui vaja on ainult “tõesta, et kaart on käes”, piisab serveri nonce’ist — aga siis ära nimeta seda allkirjastamiseks.

### 4. Poliitika-OID kontroll on hapras kohas

`CertificateInspector` loeb `Certificate Policies` laiendi `extension.Format(true)` **tekstist** ja korjab regexiga numbrid välja. See sõltub Windowsi keelest ja formaadist ning võib korjata numbreid ka CPS-URL-i seest.

Toodangus tee seda ahela kaudu: `X509ChainPolicy.CertificatePolicy` (lisa NCP+ `0.4.0.2042.1.2` ja seejärel eraldi valideering õige põlvkonna dokumendi-OID-ga). Nii teeb valiku CryptoAPI, mitte string-parsimine.

### 5. Usalduskontroll on labis lahti keeratud

| Koht | Labis | Toodangus |
|---|---|---|
| `DemoChannel.cs` (klient, serveri sert) | `PeerOrChainTrust` + `RevocationMode.NoCheck` | `ChainTrust` + tühistus. Muidu on VIP-i vastu MITM triviaalne. |
| `DemoChannel.cs` DNS-identiteet | kõvakodeeritud `demo.local` | VIP-i FQDN. Passthrough tähendab, et **kõik** IIS-id esitavad sama CN/SAN-i serti. |
| `DemoHostFactory.cs` / `Web.config` (teenus, kliendi sert) | `PeerOrChainTrust` (kõvakodeeritud) + `RevocationMode=NoCheck` | `ChainTrust` + `Online`. `PeerOrChainTrust` võtab vastu ka `TrustedPeople` hoidlas oleva self-signed serdi. |
| `Web.config` `AllowLabCertificates` | `true` | **`false`** — muidu läheb test-CA sert autentimisest läbi. |
| Kliendi retry (`MainForm.CallAsync`) | 2 katset + keep-alive pooli tühjendus | Sama loogika on tööl **kohustuslik**, mitte lisa. |

Viimane rida on see, mille peale inimesed kukuvad: app pooli recycle, HAProxy timeout, VM-i patch — kõik need katkestavad pooli jäänud keep-alive ühenduse ja klient saab “underlying connection was closed”. Kui töö klient ei loo kanalit uuesti (`DemoChannel.Close` + `DropPooledConnections` + uus kanal), näeb kasutaja juhuslikke vigu ka siis, kui kõik IIS-id on terved.

Tähelepanu: `DemoHostFactory` seab `PeerOrChainTrust` koodis, mitte configist. Kui seda mustrit töö teenusesse kopeerid, tee sellest configi väärtus, muidu jääb lõdvem kontroll märkamatult toodangusse.

### 6. Väiksemad, aga reaalselt hammustavad

| Teema | Mida teha |
|---|---|
| **Kellaaeg** | NTP igal IIS-il. Skew = vahelduv 403.13 (OCSP `thisUpdate`/`nextUpdate`). |
| **OCSP/CRL vahemälu** | Tulemüüri parandus ei mõju kohe. Testimisel `certutil -urlcache * delete`, siis uus kätlus. |
| **App pool recycle / idleTimeout** | Vaikimisi `idleTimeout=20min` ja öine `regularTimeInterval` katkestavad keep-alive’i. Kas 0 või kliendi retry (vt 5). |
| **HAProxy timeoutid** | `timeout client` / `server` peab olema pikem kui kliendi jõudeaeg; TCP-režiimis loeb `timeout tunnel`. Liiga lühike = “aborted connection” süüdistus IIS-i suunas. |
| **`balance source` + NAT** | Kui kliendid tulevad korporatiivsest NAT-ist, on kõigil sama IP → **kõik** ühte IIS-i. Kaks HAProxy kihti ilma PROXY protocolita annavad sama tulemuse. |
| **Isikukood logides** | `sc-status` read ja rakenduse logid sisaldavad isikuandmeid. Maskeerimine + säilitustähtaeg. |
| **`SendTrustedIssuerList=1`** | Muudab seda, mida kliendi sertifikaadivaliku aken näitab. Testi ClickOnce kliendiga, enne kui toodangusse paned. |
| **`ClientAuthTrustMode` ja `ClientAuthIssuer` käivad koos** | Kui turvabaseline seab range režiimi (ahel peab lõppema `ClientAuthIssuer` hoidlas), peab see hoidla olema **igal** masinal täidetud. Range režiim + tühi hoidla = 403.16 igale kaardile, ka siis kui `Root` ja `CA` on laitmatud — ja rakenduse enda kontroll ütleb samal ajal „kehtiv". |
| **`disableaia`** | Kui AIA-allalaadimine on keelatud, ei tohi kohalikust `CA` hoidlast puududa ühegi kasutusel oleva kaardigeneratsiooni väljastaja. Uue generatsiooni kaardi kasutuselevõtt on siis eraldi paigaldustöö, mitte „tuleb ise". |

### 7. Mida see lab ei ole tõestanud

Aus nimekiri, et sa ei loeks labi rohelist tulemust rohkemaks, kui see on:

- **Päris ID-kaart on PIN1-ga läbi käidud** (ESTEID2018). Vaikimisi labis on tühistus off → 200. Katse 10 (revocation + proxy deny) andis **403.13**.
- **Tühistus on vaikimisi väljas** (`verifyclientcertrevocation=disable` + `RevocationMode=NoCheck`). 403.13 tuleb ainult `lockdown-ocsp.yml` + `.\lab.ps1 proxy deny` peale. `.\lab.ps1 ansible` paneb tühistuse jälle kinni.
- **Kaks füüsilist masinat, kaks HAProxy kihti, PROXY protocol** — konfid on olemas (`haproxy/haproxy-production.cfg`), testitud on üks Windows 11 masin.
- **ClickOnce deploy on olemas** — `.\lab.ps1 publish` (või `start` / `ansible`) paneb lehe `http://demo.local:8080/install/`. See URL **ei tohi** nõuda kliendisertifikaati; PIN1 tuleb alles `Demo.svc` peal. Firefox laadib `.application` faili alla; ava Edge’is.
- **IIS Express ≠ täis-IIS** — app pooli recycle’i, Failed Request Tracingut ja W3C `sc-substatus` käitumist saab päriselt kontrollida ainult Windows Serveris.

### Järjekord, kuidas ma seda tööle viiksin

1. Kontrolli töö `Web.config` sessiooni-seaded (punkt 1). See otsustab, kas failover on üldse võimalik.
2. Aja Ansible’iga ahel + `Negotiate Client Certificate` + WinHTTP **kõigile** IIS-idele ja lase `scripts/Test-EidAfterPin1.ps1` igal hostil läbi. Ükski host ei tohi FAIL-i anda.
3. Jäta TLS 1.2 lubatuks, tõesta kätlus ühe IIS-i vastu **ilma** HAProxy-t (`https://iis1.fqdn/...`). Kui siin on 403.16, ei ole HAProxy süüdi — võrdle siis `ClientAuthTrustMode`, `ClientAuthIssuer` sisu ja `disableaia` seadeid **koos**, mitte ükshaaval (vt [403.16 vs 403.13](#40316-vs-40313)).
4. Alles siis pane HAProxy `mode tcp` ette ja kontrolli, et health tuleb WCF-i app poolist.
5. Failoveri test: võta üks IIS drain’i, tee klientis päring, vaata et backend nimi muutus ja kasutaja viga ei näinud.
6. Alles siis lülita sisse `verifyclientcertrevocation=enable` ja vaata, kas OCSP jõuab kohale (403.13 tuleb siin, mitte varem).

Kui punktid 1–6 on läbi ja midagi ikka logiseb, on järgmine peatükk see, mis vastuse annab: [Vead, mida see lab ise esile ei kutsu](#vead-mida-see-lab-ise-esile-ei-kutsu) — GPO, proxy 407, HTTP/2 renegotiation, idle-timeout'id, Citrix, vahemälud.

---

## Vead, mida see lab ise esile ei kutsu

Lab tõestab ahela, passthrough'i ja alamstaatuste lugemise. Toodangus on peal kihid, mida kodus **ei ole**: GPO ja ettevõtte PKI, korporatiivproxy, kaks LB kihti, pilve/riistvara idle-timeout'id, ClickOnce paigaldus, Citrix/RDP, päris kaart päris PIN-iga ja mitu kasutajat korraga. Allpool on nende kihtide tüüpvead: **sümptom → põhjus → kust vaadata → parandus**. Diagnostikatööriistad ([peatükk 17](#diagnostika-üks-koht-kust-vaadata)) näitavad neid kõiki, aga sa pead teadma, mida küsida.

### 1. PIN1 küsitakse uuesti keset tööd

Labis seda ei näe, sest lab-sertifikaadil ei ole PIN-i. Iga uus TCP-ühendus tähendab uut TLS kätlust ja päris kaardiga võib see tähendada uut PIN1 akent. Ühendus katkeb kõige nõrgemast lülist:

| Kiht | Tüüpiline vaikeväärtus | Märkus |
|---|---|---|
| HTTP.sys idle | ~120 s | HTTPERR-is `Timer_ConnectionIdle` |
| Pilve/riistvara LB | Azure LB 4 min, AWS NLB 350 s (fikseeritud), F5 sõltub profiilist | tapab vaikselt, logi ei teki |
| HAProxy | `timeout client` / `server`; passthrough'is on määrav **`timeout tunnel`** | vaikimisi liiga lühike inimese mõttepausiks |
| IIS app pool | `idleTimeout` 20 min, `regularTimeInterval` 1740 min | TCP jääb alles → PIN-i **ei** küsi, aga esimene päring on aeglane |
| Klient | kanal luuakse iga kutse jaoks uuesti | kõige sagedasem päris põhjus |

Kuidas kindlaks teha: mõõda pausi pikkust. Kui PIN tuleb tagasi täpselt ~2 min pausi järel, on see HTTP.sys; ~4 min → pilve LB; suvalisel ajal → klient avab kanali uuesti. Tõendid: HTTPERR `Timer_ConnectionIdle` read ja `service.log` ajavahed sama `correlation`-i sees.

Parandus: `timeout tunnel` ja LB idle **suuremaks** kui kasutaja paus, kanalit ära ava iga kutse jaoks uuesti, ja kui vaja, hoia ühendus elus kerge taustapäringuga (teadlik valik — see hoiab ka backendi kleepuvust).

### 2. Juhuslik 403.7 ainult mõnel kliendil: HTTP/2 ja renegotiation

Kui sertifikaati ei küsita kätluse alguses, vaid alles siis, kui päring jõuab kataloogini, teeb Schannel TLS 1.2 all **renegotiation'i**. HTTP/2 keelab renegotiation'i → HTTP/2 klient (brauser) saab 403.7, .NET 4.8 WCF klient (HTTP/1.1) töötab. Sümptom on „brauseriga ei tööta, rakendusega töötab" või vastupidi ühel backendil.

Kontroll: `netsh http show sslcert` → `Negotiate Client Certificate : Enabled` **igal** IP:port real (raporti 2. sektsioon), ja `HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\EnableHttp2Tls`. Parandus: `clientcertnegotiation=enable`; kui vajadus jääb, keela HTTP/2 ainult sellel VIP-il. Vt ka [Negotiate Client Certificate](#4-negotiate-client-certificate-httpsys-kohustuslik-tls-13).

### 3. GPO ja ettevõtte PKI kirjutavad sinu seaded üle

Kõige petlikum vea klass: **paranda ära ja mõne päeva pärast on 403.16 tagasi.**

- „Trusted Root / Third-Party Root Certification Authorities" GPO **asendab** hoidla sisu — käsitsi või Ansible'ga lisatud EE-GovCA kaob järgmise `gpupdate` järel.
- `DisableRootAutoUpdate` + suletud võrk → Microsofti CTL vananeb.
- Schannel võtmed (`ClientAuthTrustMode`, `SendTrustedIssuerList`, `Protocols`) tulevad turvabaseline'ist (CIS/STIG). Ansible seab, GPO võtab tagasi.
- Kui IIS-is on **Client Certificate Mapping Authentication** (mitte rakenduse tasandi kontroll), peab sert olema **NTAuth** hoidlas ja seotud AD kontoga. ID-kaardiga see üldjuhul ei sobi; sümptom on 401.x või „many-to-one mapping" 403.16.

Kontroll: `gpresult /h gpo.html` (otsi Public Key Policies), `certutil -store -enterprise Root`, `certutil -viewstore -enterprise NTAuth`, ja **`Get-IdCardMatrix.ps1` enne ja pärast `gpupdate /force`** (teine kord `-Compare <esimene fail>`, mis nimetab muutunud võtmed ise) — kui vahe on, on GPO ülem. Parandus: vii ahel GPO/AD poolele ja lepi turvameeskonnaga kokku, et baseline jätab TLS 1.2 ja teie Schannel võtmed alles.

### 4. „Kaardil ei ole sertifikaate" — lubatud väljastajate loend

`SendTrustedIssuerList=1` + suur `ClientAuthIssuer` = pikk loend (Schannelil on ~16 KB piir). Tagajärg: klient ei näita ühtegi sertifikaati või kätlus katkeb. See on **kliendipoolne** sümptom serveri seadest.

Kontroll: kliendi nupp Diagnostika ütleb, kas server saatis loendi ja mis selles on. Parandus: `SendTrustedIssuerList=0` ja hoia `ClientAuthIssuer` minimaalne (ESTEID2018/2025, mitte kõik ettevõtte CA-d).

### 5. Proxy pärismaailmas: 407, MITM, bypass-list

- Proxy nõuab autentimist → CAPI2/WinHTTP ei autendi → OCSP ei õnnestu → **403.13**. Proxy logis on 407, serveris ainult „revocation offline".
- Proxy, mis avab TLS-i (MITM), rikub AIA/OCSP allalaadimise — vastus tuleb võltsitud CA alt.
- Bypass-list peab katma `*.sk.ee` ja `*.eidpki.ee`, või proxy peab need lubama ilma autentimiseta.

Selle vastu on raportis eraldi kontroll: **3c sektsioon** käivitab `certutil -verify -urlfetch` kliendiserdi peal ja näitab iga AIA/OCSP/CRL URL-i eraldi, koos kestusega. 3b (TCP test) ütleb ainult „port vastab" ja laseb 407 rahulikult läbi — seepärast on vaja mõlemat. Vt [Diagnostika](#diagnostika-üks-koht-kust-vaadata) ja [WCF proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp).

### 6. HTTP.sys tühistuse ja vahemälu parameetrid

Labis on tühistus välja lülitatud, seega neid vigu siin ei teki. Toodangus on need **IP:port kaupa** — uus binding (uus IP, uus port) on vaikimisi **ilma** sinu seadeteta.

| Parameeter | Mida teeb / kuidas tagasi lööb |
|---|---|
| `verifyclientcertrevocation` | tühistuse kontroll sisse/välja; võrguprobleem = 403.13 |
| `disableaia` | kui `enable`, ei lae HTTP.sys puuduvat vahelüli AIA-st alla → kohalik `CA` hoidla peab olema **täielik**, sh uue kaardigeneratsiooni väljastaja. Muidu 403.16 (`0x800B0109`) |
| `verifyrevocationwithcachedclientcertonly` | kui `enable`, kasutab ainult vahemälu → värsket tühistust ei märka |
| `revocationfreshnesstime` | 0 = vana CRL kehtib kuni oma kehtivusaja lõpuni; sekundid sunnivad uuendama |
| `urlretrievaltimeout` | SK CRL on suur; liiga lühike = 403.13 just tippkoormusel |
| `dsmapperusage` | AD mapping; ID-kaardiga jäta `disable` |
| `sslctlstorename` / `sslctlidentifier` | CTL filter; tühi CTL = **kõik** kaardid 403.16 |

Muuda alati `netsh http update sslcert` (mitte `add`), muidu ei ole Ansible idempotentne. Kontroll: raporti 2. sektsioon näitab need read kõigi mTLS-seoste kohta.

### 7. Serveri sertifikaat ja privaatvõti

- HTTP.sys loeb võtme **masina** hoidlast. Kasutaja hoidlas olev sert või puuduv võtme-ACL → kätlus katkeb ilma IIS-i logikirjeta (Schannel 36870).
- CNG vs vana CAPI CSP: HTTP.sys tuleb mõlemaga toime, aga vana .NET API (`X509Certificate2.PrivateKey`) ei tule — sama sert „töötab IIS-is, aga mitte koodis".
- Rotatsioon: `netsh http update sslcert`, mitte `add`; muidu jääb vana thumbprint kehtima.

Kontroll: Schannel 36870/36874 sündmused (raporti 7. sektsioon), `netsh http show sslcert` thumbprint vs tegelikult paigaldatud sert.

### 8. Passthrough peidab kliendi IP

IIS logis on `c-ip` = **load balanceri** IP. Kasutaja tuvastamiseks jääb ainult sertifikaadi thumbprint / isikukood rakenduse logis, correlation-ID ja aeg — täpselt seepärast on `service.log` nii üles ehitatud. PROXY protokoll seda ei lahenda: **HTTP.sys ei mõista PROXY päist**, ja kui keegi lisab `send-proxy` IIS-i poole, saad katkise kätluse ja HTTPERR-i, mitte kliendi IP.

Mida saab teha: HAProxy `mode tcp` näeb SNI-d ja valitud serverit — logi need välja (vt `haproxy/haproxy-production.cfg`), siis saab LB rea ja IIS rea aja järgi kokku viia. Päris kliendi IP IIS-i logisse nõuaks TLS-i lõpetamist balanceris (bridging) — see tähendab, et serdi kehtivust hindab LB, mitte IIS, ja kogu see peatükk kolib HAProxy poolele.

### 9. Drain ja juba avatud ühendused

HAProxy `on-marked-down shutdown-sessions` katkestab kohe ka olemasolevad TCP-d (kasutaja näeb ühte viga ja läheb edasi). Ilma selleta teenindab vana ühendus lõpuni — hooldusaknas tähendab see, et backend „ei tühjene" tundide kaupa. `retries` ja `option redispatch` puudutavad ainult **uut** ühendust.

Labis käitub „Kinni" nagu `shutdown-sessions` (protsess sureb). Toodangus kontrolli, kumb režiim on — muidu tuleb sinu failover-test valesti positiivne. Kontroll: pane backend drain'i ja vaata `service.log`-ist, kas vanad correlation ID-d jätkuvad endise masina peal.

### 10. Klient: Citrix/RDP, kaarditarkvara, mitu sertifikaati, ClickOnce

- **Citrix/RDP:** kaardi läbisuunamine peab olema lubatud. Ilma selleta on `CurrentUser\My` tühi ja kasutaja näeb „sertifikaate ei leitud" — mitte 403.
- **CertPropSvc** (Certificate Propagation) peab jooksma, muidu kaardi serte hoidlasse ei ilmu.
- **Uuendatud kaart:** vanad serdid jäävad hoidlasse. Klient valib aegunud või tühistatud serdi → 403.16 / 403.13 **ainult ühel kasutajal**.
- **PIN1 blokeerub** kolme vale katsega — see on PIN-akna, mitte serveri viga.
- **ClickOnce:** paigalduse URL ei tohi nõuda kliendisertifikaati (install kukub vaikselt läbi); allkirjastamissert aegub → „Cannot verify application"; ClickOnce vahemälu võib olla katki; per-user proxy ≠ WinHTTP proxy.

Kontroll kliendis: `certutil -scinfo` (mis kaardil päriselt on) ja kliendi logi thumbprint — võrdle neid omavahel.

### 11. Aeg ja vahemälud: „eile töötas"

- NTP hälve → `CERT_E_EXPIRED (0x800B0101)` või kõrvale visatud OCSP vastus. Kontroll: `w32tm /query /status`.
- Enne testi tühjenda vahemälu: `certutil -urlcache crl delete` ja `certutil -urlcache ocsp delete`. Muidu „läbib" test ainult vahemälu tõttu ja päris kasutaja saab ikka 403.13.
- HTTP.sys hoiab oma tühistuse vahemälu (`revocationfreshnesstime`) — muudatus ei jõustu kohe.
- CA vahetus: ESTEID2025 / EEGovCA2025 peavad olema **ette** paigaldatud, muidu uued kaardid annavad vanadel masinatel 403.16 ja see näeb välja nagu juhuslikkus.

### 12. Vahelduv viga tähendab, et üks masin erineb

Muster: iga N-i katse ebaõnnestub. `service.log`-i `backend=` väli ütleb, millisel masinal õnnestus. Kinnita nii: pane HAProxy-s kõik peale ühe drain'i ja korda katset, siis järgmine. Lõpuks käivita `Get-EidReport.ps1` igal masinal ja võrdle `certutil -store` **thumbprint'e**, mitte CN-e.

### 13. Ülejäänud, mida labis pole

- EDR/AV TLS-inspekteerimine kliendis või serveris → resetid ilma logikirjeteta.
- Erinev `machineKey` backendide vahel, kui rakendus kasutab ASP.NET seanssi, ViewState'i või DataProtection API-t.
- FIPS-režiim (GPO) → osa algoritme keelatud, .NET viskab „not FIPS compliant".
- Kuupäevased Windows-uuendused muudavad Schanneli vaikeseadeid (eemaldavad ciphereid) — sama sümptom nagu vale baseline.

### 14. Diagnostikaskripti enda lõksud

Kui kirjutad oma koguja-skripti (või loed kellegi teise oma), on need vead kallimad kui see, mida sa otsid — vale roheline saadab tõrkeotsingu mitmeks päevaks kõrvale.

- **Skript tekitab ise neid sündmusi, mida ta loeb.** Iga ahelaehitus sinu skripti sees (ka `certutil`) kirjutab CAPI2 logisse oma read. Kui filter on lai ja ridade arv piiratud, täidab skript selle akna oma müraga ja tegeliku kätluse ahelaehitus ei mahu sisse. Filtreeri esitatud serdi thumbprindi järgi ja arvesta, et kätluse teeb **süsteemiprotsess**, mitte sinu PowerShell.
- **Sektsioon, mis ei jooksnud, ei tohi paista kontrollituna.** Skripti enda parameetriviga või ajalimiit peab jõudma verdiktini eraldi reana („SKIPPED" / „ERROR"), muidu jääb mulje, et kõige otsustavam kontroll on tehtud ja tulnud puhas.
- **PASS/FAIL nimekiri peab ütlema ka selle, mida ta ei tõestanud.** Kui raportis on ainult need kontrollid, mida on lihtne teha, saad lehe rohelist ja ikka mitte põhjust. Usaldusotsuse jaoks on vaja **esitatud serdi väljastajat** ning `ClientAuthIssuer` + `ClientAuthTrustMode` — ilma nendeta on 403.16 kohta võimatu midagi öelda.
- **Roheline TCP-test ei tõesta tühistust.** Port võib vastata ja OCSP ikka mitte töötada (407, MITM, vale marsruut). Proxy taga tuleb testida **läbi süsteemiproxy** ja arvestada bypass-listi.
- **Eralda ettevõtte sisese PKI vead ID-kaardi omadest.** Sisemise tühistusteenuse tõrked täidavad sündmuselogi ka siis, kui ID-kaardi rajaga pole neil mingit pistmist. Kui tühistus on bindingul välja lülitatud, ei saa need olla 403.16 põhjus — ütle see raportis välja.
- **Ära kopeeri raportisse rohkem isikuandmeid, kui vaja.** Sertifikaadi subjektis on nimi ja isikukood. Tõrkeotsinguks piisab thumbprindist ja väljastajast; isikukood maski taha.

### Sümptomite kiirtabel

| Sümptom | Tõenäoline põhjus | Kust vaadata |
|---|---|---|
| PIN1 küsitakse uuesti keset tööd | idle-timeout mõnes kihis | HTTPERR `Timer_ConnectionIdle`, LB timeout'id |
| Kliendis „sertifikaate ei leitud" | kaardi läbisuunamine, CertPropSvc, trusted issuer list | `certutil -scinfo`, kliendi Diagnostika |
| 403.7 ainult brauserist | HTTP/2 + renegotiation | `netsh http show sslcert`, `EnableHttp2Tls` |
| 403.16 tuleb päevade pärast tagasi | GPO kirjutas hoidla üle | `gpresult /h`, raport enne/pärast `gpupdate /force` |
| Rakendus logib „sert kehtiv", IIS annab ikka 403.16 | HTTP.sys usaldab teisi hoidlaid kui rakendus | `certutil -store ClientAuthIssuer`, `ClientAuthTrustMode`, `disableaia` — vt [403.16 vs 403.13](#40316-vs-40313) |
| 403.13 ainult tippkoormusel | `urlretrievaltimeout`, suur CRL, proxy 407 | `certutil -verify -urlfetch`, proxy logi |
| Iga teine päring ebaõnnestub | üks backend erineb | `service.log` `backend=`, raport igal masinal |
| Kätlus katkeb, IIS-i logis pole rida | serveri serdi võti või Schannel baseline | Schannel 36870/36874, HTTPERR |
| Ühendus sureb pausi järel, PIN-i ei küsita | pilve LB idle-timeout | LB seaded (logi ei teki) |

### Kuidas neid labis tahtlikult tekitada

Kõige kiirem viis diagnostikat usaldama õppida on vead ise sisse panna. Tee seda **ainult lab-masinas** ja taasta pärast.

```powershell
# 403.16 (APP12 sümptom): CTL ClientAuthIssuer ilma ESTEID-ita — vt ülal
# ansible/lockdown-app12.yml   seejärel päris kaart :8443
# Ära looda ainult: certutil -delstore ClientAuthIssuer ESTEID2018
# Päris kaart saadab vahelüli kätlusega; ilma CTL-ita võib IIS jääda 200 peale.

# 403.16 vanem / teine tee: eemalda vahepealne CA ClientAuthIssuer hoidlast
certutil -delstore ClientAuthIssuer "ESTEID2018"
.\lab.ps1 probe            # ava kaardiga -> verdikt [403.16] *kui* exclusive/CTL on aktiivne
.\lab.ps1 eid-ca           # taasta
.\lab.ps1 ansible          # VM: taasta hoidlad + binding (eemaldab labi CTL-i, kui ansible seda üle kirjutab)

# 403.7: keela sertifikaadi küsimine ühel seosel
netsh http update sslcert ipport=127.0.0.1:8443 certhash=<thumb> appid={00112233-4455-6677-8899-AABBCCDDEEFF} clientcertnegotiation=disable
.\lab.ps1 bind             # taasta

# 403.13: lõika OCSP ära (päris kaardiga)
Add-Content $env:WINDIR\System32\drivers\etc\hosts "127.0.0.2 aia.sk.ee"

# Vahelduv viga: jäta üks backend katki ja lase round-robinil vahetada
.\lab.ps1 down Backend2

# Uus kätlus pausi järel: oota 2+ min ilma päringuta ja tee siis päring
```

Iga kord kontrolli, et `.\lab.ps1 report` verdikt näitab **sama**, mida sa katki tegid. Kui ei näita, on diagnostikas auk — ja parem leida see kodus.

Need käsud on käsitsi variant. Sama asi ühe käsuga ja automaatse tagasivõtmisega (pluss suletud võrgu stsenaariumid, mida käsitsi teha ei saa) on järgmises peatükis: [Suletud võrgu lab](#suletud-võrgu-lab-lockdown-proxy-ja-windows-server-vm).

---

## Suletud võrgu lab: lockdown, proxy ja Windows Server VM

Kodune masin on „kõik lubatud", karastatud server on „kõik keelatud, iga URL tuleb eraldi tellida". Enamik selle repo peatükke kirjeldab vigu, mida **internetiga masin ise ära peidab**: puuduv vahelüli laetakse AIA-st, OCSP vastab, DNS lahendab. Siin peatükis on kolm taset, kuidas see peitmine kodus välja lülitada — kõige kergemast kõige tõetruumani.

| Tase | Tööriist | Mida annab |
|---|---|---|
| 1 | `.\lab.ps1 lockdown <stsenaarium>` | kirurgiline keelamine samas masinas, minutiga peale ja maha |
| 2 | `.\lab.ps1 proxy` | **nimekiri URL-idest, mida Windows ise küsib** — täpselt see, mida tööl tellima pead |
| 3 | Windows Server VM host-only võrgus | päris IIS, päris app poolid, ainus tee välja on host |

### 1. Lockdown: keela see, mida tööl vaikimisi ei lubata

`scripts\Set-LabLockdown.ps1` (ADMIN) lülitab sisse ühe olukorra korraga ja kirjutab muudatused faili `.lab\lockdown.json`, et need täpselt tagasi võtta. Eelvaade ilma muutmata: lisa `-Preview`.

| Stsenaarium | Mida muudab | Mida tõestab |
|---|---|---|
| `hosts-blackhole` | PKI hostinimed → marsruutimatu IP (203.0.113.x) + tulemüür kukutab vaikselt | AIA/CRL/OCSP **aegumine** (mitte „refused") — nii käitub päris tulemüür |
| `system-no-net` | blokeerib 80/443 **ainult** `lsass` / `iisexpress` / `w3wp` jaoks | sinu `Invoke-WebRequest` ja `certutil` annavad ikka PASS, aga kätluse rada on surnud. Kõige olulisem stsenaarium: näitab, miks „ma testisin, URL vastas" ei tõesta midagi |
| `proxy-only` | blackhole + masina **WinHTTP** proxy lab-proxy peale | ainult proxy kaudu töötav maailm; proxy logi näitab iga küsitud URL-i |
| `dead-proxy` | WinHTTP proxy pordile, kus keegi ei kuula | „proxy on tellimata / kirjaviga" sümptom OS-i poolelt |
| `no-aia` | `disableaia=enable` + eemaldab ESTEID vahelülid `CA` hoidlast (varundab) | suletud võrgus pole puuduvat vahelüli kuskilt võtta → 403.16 (`0x800B010A`), **kui klient vahelüli kätluses ei saada**. Päris ESTEID2018 kaart sageli saadab; siis jääb 200, kuni juur `Root`is on | 
| `no-issuer` | tühjendab `ClientAuthIssuer` hoidla (varundab) | „rakendus ütleb kehtiv, IIS 403.16” **ainult kui** exclusive/CTL on päriselt aktiivne. Uuemal Serveril tühi hoidla ilma CTL-ita ei pruugi 403.16 anda. APP12 sümptom: [lockdown-app12.yml](#app12-40316-kui-root-ja-ca-näivad-korras) |

Kõik tagasi: `.\lab.ps1 unlock`. Seis: `.\lab.ps1 lockdown` (ilma nimeta = status).

Mida see **ei** tee: internetti tervikuna kinni ei pane. Hostinimede nimekiri on kitsas, protsessireeglid katavad kolme protsessi, ja WinHTTP on masinataseme säte, mida brauserid ei loe. Ainus laiem kõrvalmõju: blokeeriva proxy-režiimi ajal kannatavad ka teised WinHTTP kasutajad (nt Windows Update) — hoia need seansid lühikesed.

### 2. Lab-proxy: tellimisnimekiri, mida sa muidu pead ära arvama

Suletud võrgus on kõige kallim teadmatus lihtne: **millised URL-id peavad üldse lubatud olema?** Dokumentatsioon ütleb üht, päris kätlus küsib teist (teine CA generatsioon, teine CRL host, ajatempel). `scripts\Start-LabProxy.ps1` on pisike edasisuunav proxy, mille ainus mõte on see nimekiri kirja panna.

```powershell
.\lab.ps1 proxy             # allow: suunab edasi ja logib iga URL-i
.\lab.ps1 proxy allowlist   # ainult -Allow hostid, ülejäänud 403 (osa tellitud)
.\lab.ps1 proxy auth407     # proxy nõuab autentimist (masinakonto ei oska)
.\lab.ps1 proxy deny        # proxy poliitika keelab
.\lab.ps1 proxy timeout     # vaikne kukutamine: 15 s seisakud, mitte veateade
.\lab.ps1 lockdown proxy-only   # ADMIN: suuna Windows sinna
```

Logi `.lab\proxy.log` näeb välja nii ja **see ongi see nimekiri**, mille saad turvameeskonnale anda:

```text
2026-09-20 00:41:02  127.0.0.1:52344  GET http://c.sk.ee/esteid2018.der.crt
  -> 200  1562 bytes  84 ms
2026-09-20 00:41:02  127.0.0.1:52346  POST http://aia.sk.ee/esteid2018 body=87B
  -> 200  1795 bytes  120 ms
```

Kaks asja, mida siit õpid ja mida ükski checklist ei ütle:

- **Küsija ei ole sinu rakendus.** Päringud tulevad süsteemi poolelt (WinHTTP), sellepärast ei aita `Web.config` `<defaultProxy>` ega brauseri sätted. Vt [WCF Web.config proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp).
- **Küsitakse ka seda, mida sa ei oodanud.** Teise generatsiooni CA, CRL suurus, ajatempliteenus. Kui allowlist katab ainult „need kaks URL-i, mis juhendis olid", tuleb viga tagasi esimese uue kaardiga.

### 3. Windows Server VM: kõige tõetruum variant

Kodumasin jääb kolmes kohas päris serverist puudu ja neid ei anna skriptiga võltsida: **IIS Express ≠ IIS** (app poolid, FREB, `0.0.0.0` seosed), **suletud võrk** (siin on internet alati käeulatuses) ja **teine masin** (passthrough, kaks backendi, LB).

#### Hüperviisor Windows 11 Home peal

Hyper-V ei kuulu Home-i koosseisu — `systeminfo` rida „A hypervisor has been detected" tähendab tavaliselt ainult seda, et VBS/WSL2 hüperviisor juba töötab, mitte et Hyper-V halduskiht oleks olemas. Kolm teed:

| Variant | Plussid | Miinused |
|---|---|---|
| **VirtualBox** (tasuta) | töötab Home peal ametlikult, `Host-only Adapter` = valmis suletud võrk | Hyper-V/VBS taustal aeglustab |
| **VMware Workstation Pro** (isiklikuks tasuta) | kiire, `Host-only` ja LAN-segmendid | eraldi paigaldus, suurem |
| **Hyper-V Home-i peale käsitsi** (paketid + `Enable-WindowsOptionalFeature`) | `Internal Switch`, checkpoint'id, PowerShell automatiseerimine | **toetamata**: Windows Update võib maha võtta, litsentsiliselt hall ala |

Selle labi jaoks ei ole Hyper-V vajalik: host-only adapter annab sama tulemuse — VM-il pole marsruuti internetti, host on ainus vestluskaaslane. Kui valid ikkagi Hyper-V, on see repos automatiseeritud (vt allpool).

#### Hyper-V Home-i peal: lubamine ja VM ühe käsuga

```powershell
.\lab.ps1 hyperv                      # eelvaade: mis pakette lisataks, mis feature'd lubataks
scripts\Enable-HyperVHome.ps1         # ADMIN: lisab paketid + lubab feature'd, siis REBOOT
Get-Command New-VM ; Get-VMSwitch     # ainus aus kontroll, et halduskiht on päriselt olemas

.\lab.ps1 vm                          # eelvaade VM-i seadetest
.\lab.ps1 vm D:\iso\WindowsServer.iso # ADMIN: switch + VM + ISO + guest services
```

Kolm asja, mida siin teada:

- **„A hypervisor has been detected" ei tähenda, et Hyper-V on olemas.** See rida tekib ka VBS/Device Guardi või WSL2 tõttu. Ainus kontroll on `Get-Command New-VM`.
- **Toetamata seadistus.** Windows Update võib Home peal Hyper-V uuesti maha võtta — siis käivita `Enable-HyperVHome.ps1` uuesti. Pärast lubamist jookseb ka Windows ise hüperviisori peal, mistõttu VirtualBox ja mõned emulaatorid muutuvad aeglasemaks.
- **Internal switchil ei ole DHCP-d.** See on tahtlik: aadressid pannakse käsitsi ja default gateway jäetakse **teadlikult** andmata, nii et ainus tee välja on hosti proxy.

`New-LabVm.ps1` teeb Internal switchi `IIS-ID-Closed`, annab hostile aadressi `192.168.56.1`, loob Gen2 VM-i (2 vCPU, kuni 4 GB, 60 GB dünaamiline ketas), ühendab ISO ja lülitab sisse **Guest Service Interface**. Viimane on suletud võrgu jaoks oluline: repo saab VM-i sisse tõsta üldse ilma võrguta.

```powershell
.\lab.ps1 build
Copy-VMFile -Name IIS-ID-Server -SourcePath C:\Users\<sina>\Desktop\IIS-ID `
    -DestinationPath C:\IIS-ID -FileSource Host -CreateFullPath -Recurse
```

VM-is kaks teed (vali **üks**):

```powershell
# A) ilma Ansible'ta — kõik kohapeal:
powershell -ExecutionPolicy Bypass -File C:\IIS-ID\scripts\Install-LabServer.ps1 `
    -StaticIp 192.168.56.10 -ProxyServer 192.168.56.1:3128

# B) WinRM uks lahti, IIS tuleb hosti Ansible'st (sama roll mis Nutanixis):
powershell -ExecutionPolicy Bypass -File C:\IIS-ID\scripts\Enable-LabWinRm.ps1 -StaticIp 192.168.56.10
# hostis:  $env:LAB_WINRM_PASSWORD = '...'; .\lab.ps1 iac; .\lab.ps1 ansible
```

Ja hostis proxy, mis kuulab ka VM-i poole:

```powershell
scripts\Start-LabProxy.ps1 allow -Bind any
New-NetFirewallRule -DisplayName "IIS-ID lab proxy" -Direction Inbound -Action Allow `
    -Protocol TCP -LocalPort 3128 -RemoteAddress 192.168.56.0/24
```

Enne iga lockdown-stsenaariumi tee checkpoint (`Checkpoint-VM -Name IIS-ID-Server -SnapshotName "clean lab"`) — siis on iga katse üks `Restore-VMCheckpoint` kaugusel ja sa ei pea skriptide `restore`-le lootma.

#### „No operating system was loaded"

Generation 2 VM-i esimene käivitus ebaõnnestub tavaliselt **klahvivajutuse pärast**, mitte seadistuse pärast: „Press any key to boot from CD/DVD" on ekraanil ~2 sekundit, teist võimalust ei anta ja UEFI kukub tühjale kettale, öeldes täpselt selle lause. Ära võistle sellega käsitsi:

```powershell
.\lab.ps1 vm-start
```

See käivitab VM-i ja vajutab TÜHIKUT Hyper-V **virtuaalsele klaviatuurile** (`Msvm_Keyboard` WMI kaudu) 12 sekundi jooksul, nii et viip tabatakse sõltumata sellest, kas konsooliaken on fookuses. Käsitsi variant on: ava `vmconnect` **enne**, klõpsa aknasse, siis `Start-VM`, siis vajuta kohe korduvalt tühikut.

Kui see ei aita, lase faktid välja öelda — `vm-check` vaatab VM-i seaded **ja** monteerib ISO hostis, et kontrollida, kas seal üldse on x64 UEFI buutfailid:

```powershell
.\lab.ps1 vm-check                       # VM: generatsioon, DVD, boot order, Secure Boot, ketas
                                         # ISO: \efi\boot\*.efi, \sources\install.*, setup.exe
```

Verdikt ütleb otse, kumb kolmest põhjusest see on, ja vastavalt sellele:

```powershell
.\lab.ps1 vm-fix C:\tee\WindowsServer.iso          # DVD esimeseks + ISO uuesti külge
scripts\New-LabVm.ps1 -FixBoot -NoSecureBoot       # ISO ei ole MS templaadiga allkirjastatud
scripts\New-LabVm.ps1 -IsoPath ... -Generation 1 -Name IIS-ID-Server-Gen1
                                                   # ISO-l pole UEFI buutfaile -> BIOS-VM
```

Kui `vm-check` ütleb „ARM64 image" või „no \efi\boot\*.efi", ei ole VM-is midagi parandada: ISO on vale arhitektuuriga või pooleli laetud. Ametlik x64 evaluation ISO on ~5–7 GB ja seal on nii `\efi\boot\bootx64.efi` kui `\sources\install.wim`.

Failinimes olev tühik (`WindowsServer .iso`) annab sama tulemuse juba varem — siis ütleb `New-LabVm.ps1`, millist teed ta otsis, ja loetleb samas kaustas olevad ISO-d.

#### Skeem

```
HOST (Windows 11, kaardilugeja, Cursor, internet)
  |   .\lab.ps1 proxy  -Bind any        (127.0.0.1 -> 0.0.0.0:3128)
  |   klient: https://demo.local:8443/Demo.svc
  |
  |  host-only / internal switch, nt 192.168.56.0/24   <- MITTE NAT
  v
VM (Windows Server, ei mingit internetti)
     IIS + Demo.Service, app poolid Backend1/Backend2
     netsh winhttp set proxy proxy-server="192.168.56.1:3128" bypass-list="<local>"
```

Kaart jääb **hosti** külge (kliendi masin), VM-is on ainult IIS. Nii ei pea USB-läbisuunamisega jändama ja skeem vastab tööle: klient ühes masinas, IIS teises.

#### Sammud

1. **VM**: Windows Server 2022/2025 Evaluation ISO (180 päeva), 2 vCPU, 4 GB RAM, 40 GB ketas, **üks** host-only adapter. Tee kohe checkpoint „clean".
2. **Hostis** `.\lab.ps1 build` ja kopeeri kogu kaust VM-i (nt `C:\IIS-ID`) — `bin\` peab kaasa tulema, sest VM-is pole SDK-d ega internetti.
3. **Kopeeri ka `certs\eid-ca`** (ID-kaardi ahel) hostist: VM-is ei saa seda alla laadida. Siis `scripts\Install-EeIdTrust.ps1` paigaldab olemasolevatest failidest.
4. **VM-is** (ADMIN): kas `Install-LabServer.ps1` (kõik kohapeal) **või** `Enable-LabWinRm.ps1` ja hostis `.\lab.ps1 ansible` — vt [Terraform ja Ansible](#terraform-ja-ansible). `Install-LabServer.ps1` paneb peale IIS + ASP.NET 4.8 + WCF aktiveerimise, teeb kaks app pooli (ilma idle-timeout'i ja recycle'ita), kaks saiti (`:8443`/`:8444` + health `:8080`/`:8081`), `sslFlags` ainult `Demo.svc` peale, W3C väljad koos `sc-substatus` ja `sc-win32-status`-ga ning avab sissetuleva tulemüüri. Lisa `-Tracing`, kui tahad 403 peale Failed Request Tracingut (seda IIS Express ei oska). Eelvaade: `-Preview`.
5. **Hostis** `hosts` fail: `<VM IP>  demo.local`, siis `.\lab.ps1 client` ja aadress `https://demo.local:8443/Demo.svc`.
6. **Hostis** `.\lab.ps1 proxy` (vajadusel `-Bind any` + sissetulev reegel pordile 3128), **VM-is** `netsh winhttp set proxy proxy-server="<host IP>:3128" bypass-list="<local>"`.
7. Iga stsenaariumi järel `scripts\Get-EidReport.ps1 -Minutes 15` VM-is ja checkpoint tagasi.

#### Mida selles VM-is katsetada (järjekorras)

| Samm | Käsk VM-is | Oodatav õppetund |
|---|---|---|
| Baasjoon | klient → `Demo.svc` töötab | ahel ja passthrough on korras, edasi läheb ainult halvemaks |
| Mida üldse küsitakse | hostis `proxy` logi | tellimisnimekiri, mitte oletus |
| Osaline luba | hostis `proxy allowlist` | üks puuduv URL = 403.13 või seisakud |
| Proxy nõuab parooli | hostis `proxy auth407` | masinakonto ei autendi; „eile töötas" |
| Tühistus sisse | `Install-LabServer.ps1 -Revocation` | siit algab 403.13 rada, mida labis vaikimisi pole |
| Ahel katki | `Set-LabLockdown.ps1 no-aia` | suletud võrgus pole vahelüli kuskilt võtta |
| Usaldus katki | `Set-LabLockdown.ps1 no-issuer` | 403.16, kuigi rakendus ütleb „kehtiv" |
| Ainult süsteem ilma võrguta | `Set-LabLockdown.ps1 system-no-net` | sinu käsitsi testid annavad vale PASS |
| App pool | `Restart-WebAppPool Backend1Pool` | kliendi keep-alive ja retry — IIS Expressis ei näe |
| Kaks backendi | teine VM + `haproxy-production.cfg` | passthrough kahe masina vahel, health õigest app poolist |

---

## Töö repoga võrdlemine (AI-le antav ülesanne)

See repo on **käitumise etalon**: siin on teada, mis töötab ja miks. Töö repo on **tegelikkus**. Selle peatüki mõte on, et saaksid mõlemad mudelile ette anda ja tulemuseks tuleks **erinevuste nimekiri + muudatuste plaan**, mitte pimesi tehtud muudatused.

Reegel number üks: mudel ei tohi soovitada turvet nõrgemaks keerata selleks, et asi “tööle saada”. Labi lühendid (`PeerOrChainTrust`, `AllowLabCertificates=true`, `verifyclientcertrevocation=disable`, `RevocationMode=NoCheck`) on **labi omad**. Kui need on juba töö configis, on see leid, mitte lahendus.

### 1. Mida mudelile ette anda

**Kõik 20 rida ei ole lähtekoodist tuvastatavad.** Kood näitab *kavatsust*, masin näitab *tegelikkust*, ja nende kahe vahe ongi tihti kogu vastus. Seepärast on see töö kaks eraldi prompti:

| Rühm | Read | Kust vastus tuleb | Miks mitte teisiti |
|---|---|---|---|
| **A — ainult kood** | 2, 8, 9, 11 | Terraform / Ansible / .NET / `haproxy.cfg` | Masinast ei paista: HAProxy ei ole IIS VM-is, OID-kontroll ja kliendi retry on koodis |
| **B — ainult masin** | 4, 13, 14, 18, 20 | `scripts/Get-IdCardMatrix.ps1` | Koodis neid ei ole: päris logirida, päris hoidla sisu, kahe hosti vahe, GPO mõju |
| **C — mõlemas** | 1, 3, 5, 6, 7, 10, 12, 15, 16, 17, 19 | kood **ja** masin | Ansible ütleb X, masin näitab Y → drift, GPO, käsitsi tehtud muudatus. **See lahknevus on leid**, mitte mõõtmisviga |

Rühm C on põhjus, miks ainult koodi lugemine eksitab: töö APP võib olla käsitsi püsti pandud, baseline võib nupu tagasi keerata, ja `netsh` seaded ei ole üldse koodis, kui keegi need kunagi käsitsi tegi.

**Prompt 1 sisend (kood).** Selle repo pealt: `README.md`, `src/`, `scripts/`, `haproxy/`.

Töö poolelt (loetav koopia, mitte tootmisligipääs):

| Allikas | Fail / käsk |
|---|---|
| WCF teenus | `Web.config` (binding, `serviceCredentials`, `appSettings`) |
| WCF klient | `app.config` / `App.config`, kanali loomise kood, ClickOnce manifest |
| IIS | `applicationHost.config` väljavõte (sait, app pool, `sslFlags`, autentimine) |
| HAProxy | `haproxy.cfg` **mõlemast kihist** (väline + sisemine) |
| Ansible | IIS roll, `group_vars`, sertide ja `netsh` ülesanded |
| Terraform | NSG / security group reeglid, LB, DNS |
| Ühe IIS-i hetkeseis | tuleb prompt 2 väljundist (`Get-IdCardMatrix.ps1`): `netsh http show sslcert` sh **Disable Authority Info Access**, `netsh winhttp show proxy`, `certutil -store Root/CA/ClientAuthIssuer`, Schannel `ClientAuthTrustMode` / `SendTrustedIssuerList` |
| Vea tõendid | IIS W3C read `sc-status`/`sc-substatus` (sama skript), CAPI2 sündmused, HAProxy `show stat` |

**Ära** pane prompti privaatvõtmeid, `.pfx` faile ega päris isikukoode. Sertifikaadi räsid ja isikukoodid maskeeri — võrdluseks piisab teadmisest, *kas* väärtus on olemas ja *millisest* hoidlast.

#### Prompt 2 sisend (masin): `scripts\Get-IdCardMatrix.ps1`

Üks ASCII fail, **ei muuda midagi** (ainult `show` / `list` / `-store` / logilugemine). Kopeeri VM-i ja käivita Administrator'ina. Väljund on kirjutatud maatriksi ridade kaupa — täpselt see, mida prompt 2 sisendiks vajab.

```powershell
# katkisel APP-il
powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1

# suletud VM (ei proovi SK poole ühendust), pikem logiaken
powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1 -NoNetwork -Minutes 240

# rida 18/20: võrdle terve hostiga (või iseendaga enne gpupdate'i)
powershell -ExecutionPolicy Bypass -File Get-IdCardMatrix.ps1 -Compare \\share\idcard-matrix-APP11.txt
```

Iga rida saab ühe seisundi:

| Seisund | Tähendus |
|---|---|
| `PASS` | see rida on **sellel** masinal korras |
| `FAIL` | blokeeriv — ainuüksi see seletab ebaõnnestunud logini |
| `WARN` | kahtlane või sõltub teisest kihist |
| `DATA` | vaja rohkem sisendit (teine host, taastekitatud login, admin-õigused) |
| `REPO` | VM-ist ei paista → läheb **prompt 1**-le (rühm A) |

Lisaks annab skript:

- **`CROSS-CHECKS`** — vastuolud, mis üksikuna ei paista. Nt „logis 403.13, aga praegu on `verifyclientcertrevocation=Disabled`” tähendab, et keegi juba keeras nuppu **või** see logirida on teisest seadistusest; siis on ainus mõistlik samm üks login taastekitada, mitte serte lisada.
- **`FINGERPRINT`** — üherealine kõigi otsustavate nuppude kokkuvõte. Käivita **igal** APP-il ja diffi read 18/20 jaoks; `-Compare` teeb selle diffi ise ja nimetab erinevad võtmed.
- **`403 EVIDENCE`** — päris `sc-substatus` + `sc-win32-status` read koos dekodeeritud tähendusega (rida 14). Kui W3C-s neid välju ei logita, ütleb skript sedagi eraldi.

Kui `Get-EidReport.ps1` vastab küsimusele „*mis juhtus*”, siis see skript vastab küsimusele „*millises maatriksi reas on viga*”. Mõlemad on read-only; suletud VM-is käivita `-NoNetwork`.

Kui tööl **ei tohi** ükski skriptifail liikuda, korja tõendid ühe kleebitava plokiga (kitsam kui skript: ei anna rea-kaupa verdikti ega fingerprint'i):

```powershell
# Katkisel IIS-il, Administrator. Ei muuda midagi. Maskeeri isikukoodid enne jagamist.
$out = "$env:TEMP\idcard-evidence-$env:COMPUTERNAME.txt"
& {
  '=== sslcert ==='      ; netsh http show sslcert
  '=== winhttp ==='      ; netsh winhttp show proxy
  '=== schannel ==='     ; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' |
                             Select-Object ClientAuthTrustMode, SendTrustedIssuerList | Format-List
  '=== Root ==='         ; certutil -store Root            | Select-String 'EE-Gov|EEGov|ESTEID'
  '=== CA ==='           ; certutil -store CA              | Select-String 'ESTEID|EID-SK'
  '=== issuer ==='       ; certutil -store ClientAuthIssuer| Select-String 'ESTEID|EE-Gov|EEGov'
  '=== iis 403 ==='      ; Get-ChildItem "$env:SystemDrive\inetpub\logs\LogFiles\W3SVC*\*.log" |
                             Sort-Object LastWriteTime -Descending | Select-Object -First 1 |
                             ForEach-Object { Select-String $_.FullName -Pattern ' 403 ' | Select-Object -Last 10 }
  '=== capi2 ==='        ; Get-WinEvent -LogName 'Microsoft-Windows-CAPI2/Operational' -MaxEvents 15 -EA SilentlyContinue |
                             Select-Object TimeCreated, Id, LevelDisplayName | Format-Table -AutoSize
  '=== schannel evt ===' ; Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Schannel'} -MaxEvents 15 -EA SilentlyContinue |
                             Select-Object TimeCreated, Id | Format-Table -AutoSize
} *>&1 | Tee-Object -FilePath $out
"kogutud: $out"
```

Käivita see **igal** APP-il, ka tervetel. Kahe masina vahe on tihti kiirem vastus kui ükskõik milline config-lugemine.

### 2. Võrdlusmaatriks

Iga rida on üks küsimus, millele vastus peab tulema **töö** poolelt. Vasak veerg näitab, kus labis vastus on.

**Kui viga on praegu olemas, ära alusta siit.** Read 1–13 on „kas arhitektuur on õige”. Elava 403 puhul alusta ridadest **14–20** (tõendid ja masinapõhised nupud) — need annavad vastuse tundidega, mitte päevadega. Järjekord: `sc-substatus` + `sc-win32-status` → kumb kiht (ahel vs tühistus) → alles siis config.

Ridadele, mis on masinas mõõdetavad (4, 13, 14, 18, 20 ja kogu rühm C), vastab `scripts\Get-IdCardMatrix.ps1` automaatselt — käivita see enne, kui hakkad configi lugema.

| # | Küsimus | Kus labis | Mida tööl vaadata | Ootus |
|---|---|---|---|---|
| 1 | Kas teenus on olekuta? | `Demo.Service/Web.config`, `Demo.Contracts/IDemoService.cs` | `security mode`, `establishSecurityContext`, `reliableSession`, `SessionMode` | Transport, ilma seansita. Vastasel juhul failover ei tööta — vt [punkt 1](#1-wcf-sessioon-tapab-failoveri-kontrolli-esimesena) |
| 2 | Kas HAProxy on päriselt passthrough? | `haproxy/haproxy-production.cfg` | `mode tcp`, `server ... ` real **puudub** `ssl` | Kui `ssl` või `mode http` → IIS ei näe kaarti (403.7) |
| 3 | Kas health räägib tõtt? | sama sait/app pool kui `Demo.svc` | health saidi app pool vs WCF app pool | Sama pool. Eraldi pool = HAProxy hoiab surnud masinat UP |
| 4 | Kas ahel on **igal** IIS-il? | `scripts/Install-EsteidIisProduction.ps1` | `certutil -store` kõigil hostidel + Ansible roll | Root / CA / ClientAuthIssuer identsed. Üks puuduv host = vahelduv 403.16 |
| 5 | Negotiate Client Certificate? | `scripts/Install-HttpSysBindings.ps1` | `netsh http show sslcert` **selle** ipport rea peal | `Enabled`. Kontrolli `0.0.0.0:443` vs konkreetne IP |
| 6 | OCSP võrk ja proxy | [WinHTTP peatükk](#wcf-webconfig-proxy-vs-winhttp) | `netsh winhttp show proxy` **vs** `Web.config` `<defaultProxy>` | Kaks kohta, sama URL. Ainult `Web.config` ei aita HTTP.sys-i |
| 7 | Usalduse ranguse tase | `DemoHostFactory.cs`, `DemoChannel.cs` | `certificateValidationMode`, `revocationMode`, `AllowLabCertificates` | `ChainTrust` + `Online`, lab-luba `false` |
| 8 | Poliitika-OID kontroll | `Demo.Contracts/CertificateInspector.cs` | kuidas töö kood OID-e loeb | `X509ChainPolicy.CertificatePolicy`, mitte teksti-parsimine |
| 9 | Kas klient loob kanali uuesti? | `Demo.Client/MainForm.cs` `CallAsync`, `DemoChannel.DropPooledConnections` | töö kliendi veakäsitlus | Retry + pooli tühjendus. Ilma selleta juhuslikud vead ka tervete IIS-idega |
| 10 | TLS versioonid | [TLS protokollid](#6-tls-protokollid) | Schannel registri võtmed + kliendi `SecurityProtocol` | TLS 1.2 lubatud, kuni 1.3 on kliendiga tõestatud |
| 11 | Mis on “allkiri”? | `LocalSigner.cs`, `DemoService.SubmitSignature` | kas nonce, ahel, ajatempel, konteiner | Kui vaja juriidilist allkirja → DigiDoc SDK, vt [punkt 3](#3-pin2-allkiri-labis-ei-ole-juriidiline-allkiri) |
| 12 | Väljuv võrk OCSP jaoks | [AIA/OCSP/CRL tabel](#url-id-mida-iis-peab-kätte-saama-aia--ocsp--crl) | Terraform egress reeglid | **HTTP 80** lubatud (OCSP ei ole 443) või proxy |
| 13 | Serveri serdi nimi | `DemoChannel.cs` DNS-identiteet | VIP FQDN vs iga IIS-i serdi CN/SAN | Passthrough: kõik IIS-id esitavad sama VIP-i serti |

Read 14–20 tulevad labi katsetest 20.09.2026 — iga üks neist andis päris kaardiga **403.16 või 403.13**, kuigi „Root ja CA on korras”. Vt [Tööl kontrollida](#tööl-kontrollida-labi-järeldused) ja [APP12 juhtum](#app12-40316-kui-root-ja-ca-näivad-korras).

| # | Küsimus | Kus labis | Mida tööl vaadata | Ootus |
|---|---|---|---|---|
| 14 | **Mis on päris alamstaatus ja win32?** | [Kust VM-ist vaadata](#kust-vm-ist-vaadata-kui-login-ei-õnnestu) | IIS W3C `sc-substatus` + `sc-win32-status` **enne** iga muudatust | `403 16 2148204809` (`0x800B0109`) = usaldus; `403 13 2148081683` (`0x80092013`) = tühistus; `403 7` = serti ei tulnud. Ilma selle numbrita on iga edasine samm oletus |
| 15 | **CTL: kas `Ctl Store Name` filtreerib?** | katse A (`ansible/lockdown-app12.yml`) | `netsh http show sslcert` → `Ctl Store Name` **ja** `certutil -store ClientAuthIssuer` | `(null)`, **või** `ClientAuthIssuer` kus ESTEID2018/2025 **on** kirjas. CTL ilma ESTEID-ita = 403.16, kuigi `Root`/`CA` laitmatud |
| 16 | `ClientAuthTrustMode` 0/1/2 | `ansible/roles/eid_trust` | Schannel võti + `ClientAuthIssuer` sisu **koos** | `2` + täidetud issuer. `1` (Exclusive Root) nõuab, et ahel lõpeks **juurikaga** selles hoidlas — vahelüli ei piisa |
| 17 | Tühistus vs väljuv võrk **koos** | katse 10 (`ansible/lockdown-ocsp.yml`) | `verifyclientcertrevocation` **ja** `netsh winhttp show proxy` **ja** NSG :80 | Kas mõlemad sees või mõlemad väljas. Revocation `enable` + suletud egress = 403.13. `Disabled` = SK/`ocsp.smit.sise` vead on **müra** |
| 18 | Kas masinad on **omavahel** identsed? | `serial: 1`, roll kõigil hostidel | sama tõendiplokk **igal** APP-il, diff kahe vahel | Vahelduv viga = ühe masina nupp. APP12 oli üks host — võrdle katkist tervega, mitte labiga |
| 19 | Client Certificate Mapping / NTAuth | `iis_eid` keelab mõlemad | IIS *Client Certificate Mapping Authentication*, *IIS Client Certificate Mapping* | **Väljas**, kui identiteet tuleb rakenduse koodist. Sisse lülitatud mapping ilma reeglita annab 403 ka korras ahelaga |
| 20 | Kas GPO / CIS keerab tagasi? | — (labis GPO-t pole) | `gpresult /h`, tõendiplokk **enne ja pärast** `gpupdate /force` | Schannel võtmed ja `ClientAuthIssuer` peavad jääma. „Eile töötas, täna 403.16” = see rida |

### 3. Otsingud, millest alustada

Töö repos annavad need kõige kiiremini vastuse ridadele 1, 7, 8, 9:

```text
establishSecurityContext|reliableSession|SessionMode
security mode=|clientCredentialType
certificateValidationMode|revocationMode|AllowLab
defaultProxy|proxyaddress|winhttp
X509Chain|CertificatePolicy|Format\(
CommunicationException|Abort\(|CreateChannel
mode http|ssl verify|crt /|httpchk|check port
clientcertnegotiation|add sslcert|ClientAuthIssuer|addstore
idleTimeout|regularTimeInterval
SecurityProtocol|Tls12|Tls13
```

Ridade 14–20 jaoks (Ansible / IaC pool, kus nupud tegelikult sünnivad):

```text
sslctlstorename|ClientAuthTrustMode|SendTrustedIssuerList
verifyclientcertrevocation|disableaia|usagecheck|verifyrevocationwithcached
eid_revocation|eid_download_certs|eid_winhttp_proxy|allow_lab
logExtFileFlags|sc-substatus|sc-win32-status|traceFailedRequests
clientCertificateMappingAuthentication|iisClientCertificateMapping
ocsp.smit|aia.sk.ee|ocsp.eidpki|crl.eidpki
```

`sslctlstorename` või `ClientAuthTrustMode: 1` leidmine töö rollist / baseline'ist on tihti **kogu vastus** — see on rida 15/16 ja labis tõestatud 403.16 põhjus.

### 4. Väljundi formaat, mida mudelilt nõuda

Iga leiu kohta:

1. **Rida** maatriksist (nr).
2. **Lab** — mis siin on ja miks (viide failile/reale).
3. **Töö** — mis seal on (viide failile/reale). Kui ei leidnud, siis **“ei tuvastatud”**, mitte oletus.
4. **Risk** — `blokeeriv` / `oluline` / `kosmeetiline`.
5. **Muudatus** — konkreetne fail + väärtus.
6. **Kiht** — Terraform / Ansible / IIS / HAProxy / teenuse kood / kliendi kood.
7. **Tõestus** — käsk, mis näitab seisu **enne ja pärast** (nt `netsh http show sslcert`, `certutil -store ClientAuthIssuer`, uus IIS logirida).
8. **Tagasikeeramine** — kuidas see üks muudatus maha võtta, kui viga ei kadunud.

Nõua **üht muudatust korraga**, mitte „täida igaks juhuks kõik hoidlad ja pane CTL ka”. Kui parandad mitu nuppu koos, ei tea sa hiljem, milline oli katki — labis andsid katsed A ja B **identse** IIS rea (`403 16 2148204809`), aga vajasid **erinevat** parandust.

Lõppu kolm eraldi nimekirja:

- **“mida ei saanud kontrollida ja mis andmeid vaja”**
- **“muudatused, mis nõuavad hooldusakent”** (`netsh` seose muutmine, app pooli restart, Schannel registri muudatus → reboot)
- **“mis tuleb tellida võrgust”** — hostid + pordid eraldi ridadena, koos märkega, kas see on vajalik **ahela** (ei ole) või **tühistuse** jaoks (on). Vt [AIA/OCSP/CRL](#url-id-mida-iis-peab-kätte-saama-aia--ocsp--crl)

### 5. Valmis prompt

Kaks eraldi prompti, **selles järjekorras**, kui viga on elus: kõigepealt masin (kumb kiht katki), siis kood (miks nupp selline on). Kui elavat viga ei ole, alusta prompt 1-st.

#### Prompt 2 — masina tõendid (rühm B + C tegelikkus)

```text
Lisatud on scripts\Get-IdCardMatrix.ps1 väljund ühest või mitmest IIS masinast
(IIS-ID README peatükk "Töö repoga võrdlemine"). Skript on read-only.

Ülesanne: ütle, MILLISES maatriksi reas on viga, ja ainult selle tõendite põhjal.

Reeglid:
- Alusta reast 14 (sc-substatus + sc-win32-status). Ütle kõigepealt üks asi:
  kas katki on USALDUS (403.16 / 0x800B0109) või TÜHISTUS (403.13 / 0x80092013)
  või ei tulnud serti üldse (403.7). Ära liigu edasi, kuni see on öeldud.
- Kui rida 14 on DATA (logis pole 403.7/13/16), ütle seda ja nõua ühe logini
  taastekitamist SELLEL hostil. Ära hakka oletama configi pealt.
- Kasuta CROSS-CHECKS plokki: vastuolu kahe rea vahel on tugevam tõend kui
  ükski üksik rida.
- Kui on mitu masinat: diffi FINGERPRINT read (rida 18) ja nimeta erinevad
  võtmed. Võrdle katkist TERVEGA, mitte labiga.
- Ära seleta 403.16 OCSP-ga ega proxyga. Kui revocation=Disabled, on OCSP
  veateated müra (rida 17).
- Ära soovita serte lisada enne, kui Ctl Store Name (15) ja
  ClientAuthTrustMode (16) on vaadatud — vale CTL tekitab 403.16 ise.
- REPO-märgistatud read jäta vahele: need lähevad koodi-prompti.
- Üks muudatus korraga. Iga soovituse juurde: tõestuskäsk (mida uuesti
  jooksutada) ja tagasikeeramine.

Väljund:
1) Üks lause: kumb kiht katki on ja millisel hostil.
2) Kuni kolm kõige tõenäolisemat rida, koos tõendiga skripti väljundist
   (tsiteeri rida).
3) Järgmine üks samm + käsk, mis tõestab, kas see aitas.
4) Nimekiri "puuduvad andmed" (nt teise hosti väljund, taastekitatud login).
```

#### Prompt 1 — kood ja IaC (rühm A + C kavatsus)

```text
Sul on kaks repot:
A) IIS-ID demo (etalon) — loe kõigepealt A/README.md peatükke
   "Enne toodangut: kriitiline nimekiri" ja "Töö repoga võrdlemine".
B) töö repo + lisatud IIS-i väljundid (tegelikkus).

Ülesanne: võrdle B-d A README peatüki "Võrdlusmaatriks" 20 rea kaupa.
Kui kaasas on ka Get-IdCardMatrix.ps1 väljund, siis iga koht, kus kood ütleb
üht ja masin teist, on eraldi leid (drift / GPO / käsitsi muudatus) — nimeta
see välja, ära vali vaikimisi koodi kasuks.

Reeglid:
- Ära paku turvet nõrgemaks keeravaid lahendusi (PeerOrChainTrust,
  AllowLabCertificates=true, verifyclientcertrevocation=disable,
  RevocationMode=NoCheck, HAProxy "ssl verify none"). Need on labi lühendid.
  Kui need on juba B-s, kirjuta need leiuna välja.
- Ära paku HAProxy-s SSL termination'it mTLS-i "parandamiseks".
- Ära paku Web.config <defaultProxy> lahendust HTTP.sys OCSP probleemile.
- Ära paku session affinity cookie'd TCP-režiimis (seda ei ole olemas).
- Ära järelda "Root ja CA on olemas, seega ahel on korras" enne, kui oled
  vaadanud Ctl Store Name + ClientAuthIssuer sisu + ClientAuthTrustMode (read 15-16).
- Ära seleta 403.16 OCSP-ga. Kui verifyclientcertrevocation on Disabled,
  on OCSP/ocsp.smit.sise veateated müra (rida 17).
- Ära soovita juurikat ClientAuthIssuer'isse ega CTL-i lisamist
  "filtreerimiseks", kui issuer-hoidla sisu ei ole kõigil hostidel tõestatud.
- Ära soovita mitut muudatust korraga; iga leiu juurde tõestuskäsk ja
  tagasikeeramine.
- Kui andmed puuduvad, kirjuta "ei tuvastatud" ja loetle, mida vaja.

Väljund: tabel iga rea kohta (Lab | Töö | Risk | Muudatus | Kiht | Tõestus |
Tagasikeeramine), seejärel "puuduvad andmed", "vajab hooldusakent" ja
"tuleb tellida võrgust" nimekirjad.

Alustamise järjekord:
- Kui B-s on LIVE viga (IIS logis 403): seda ei lahendata koodi lugemisega.
  Nõua Get-IdCardMatrix.ps1 väljundit ja alusta ridadest 14-20; ütle kõigepealt,
  KUMB kiht katki on (ahel = 403.16 vs tühistus = 403.13). Kui masinaid on mitu,
  võrdle katkist tervega (rida 18).
- Kui vea tõendeid ei ole: alusta reast 1 (WCF sessioon) — see otsustab,
  kas failover on üldse võimalik.
```

### 6. Kus mudelid kõige tõenäolisemalt eksivad

Need vead tulevad ette ka heade mudelite puhul, sest üldine veebiteadmine viib ID-kaardi puhul valele rajale:

| Vale soovitus | Miks vale |
|---|---|
| “403 → tee HAProxy-s SSL termination ja saada `X-Client-Cert` päis” | Kaart ei jõua IIS-i, mTLS kaob. 403.16 tähendab, et passthrough **juba töötab** |
| “Pane proxy `Web.config`-i, siis OCSP töötab” | HTTP.sys / CAPI2 loeb WinHTTP-d, mitte `Web.config`-i |
| “Keela tühistuskontroll, siis läheb läbi” | Toodangus turvaauk — tühistatud kaart pääseb sisse |
| “Lisa sticky session cookie” | `mode tcp` ei näe HTTP päiseid ega küpsiseid |
| “Kleepuvuseks piisab `balance source`-ist” | Kahe HAProxy kihi või NAT-i taga näeb LB ühte IP-d → kõik ühte IIS-i |
| “Kaasaegne seadistus = ainult TLS 1.3” | .NET Framework 4.8 klient jääb ukse taha |
| “Pane juurika ClientAuthIssuer’isse” | IIS 8+ ootab sealt **kesktaseme** väljastajaid |
| “Health eraldi saidiks, nii on puhtam” | Eraldi app pool → health valetab WCF-i seisu kohta |
| “Rakenduse logis on sert kehtiv, järelikult server on korras” | Rakenduse `X509Chain` ja HTTP.sys otsustavad eri hoidlate ja eri lippude põhjal. 403.16 kõrval võib rakenduse kontroll rahulikult „kehtiv” öelda |
| “Sündmuselogis on OCSP timeout — paranda OCSP, siis 403.16 kaob” | Kui `verifyclientcertrevocation` on **Disabled**, ei saa HTTP.sys tühistuse pärast 403-t anda. `2148204809` on usaldus. Labis tõestatud: sama müra, login suri CTL/juure peale |
| “Rakenduse logis pole midagi, järelikult logimine on katki” | 403.7/13/16 sünnivad **enne** w3wp-d. Tühi `service.log` ongi tõend: loe IIS `sc-substatus` |
| “Lisa kõik hoidlatesse ja pane igaks juhuks CTL ka peale” | Mitu muudatust korraga peidab päris põhjuse; vale CTL **tekitab** 403.16. Üks muudatus + tõestuskäsk |
| “Ühel serveril töötab, seega server on korras — viga on kliendis/LB-s” | 403.16 on masinapõhine. Round-robin tabab vahel katkist hosti; võrdle hostide tõendeid omavahel |
| “PowerShellist / brauserist avaneb SK URL, seega võrk on korras” | Need kasutavad sinu kasutaja WinINet-i. HTTP.sys / CAPI2 käib **WinHTTP**-st Local System kontekstis |

---

## Seos töökeskkonnaga

| Töö | See lab |
|---|---|
| ClickOnce + WCF .NET 4.8 | `Demo.Client`, `wsHttpBinding` Transport + Certificate |
| Mitu IIS-i, app poolid | 2 IIS Expressi saiti, `Backend1Pool` / `Backend2Pool` |
| HAProxy `mode tcp`, SSL passthrough | `Demo.LoadBalancer` või Docker HAProxy; TLS lõpeb HTTP.sys-is |
| `/health` ilma CRL/mTLS-ita | `health.json` HTTP-pordil, `check port 8080` |
| PIN1 mTLS, PIN2 allkiri | `WhoAmI` vs lokaalne sign + `SubmitSignature` |
| Sertifikaadipoliitika OID-d | NCP+ ja ESTEID2018/2025; lab lubab test-CA |
| Ühenduse kleepuvus | WCF Keep-Alive, mitte cookie |
| Ühe VM-i kukkumine | Health DOWN → uus TCP → teine IIS; olekuta teenus |
| Terraform VM/NSG + Ansible IIS/HAProxy | Selles repos checklist; kood jääb töö IaC-sse. Vt [Terraform ja Ansible](#terraform-ja-ansible) |

open-eid juhendi vasted labis:

- HTTPS-seos + **Negotiate Client Certificate** → `netsh http add sslcert ... clientcertnegotiation=enable`
- Anonüümne IIS-autentimine; isik tuleb sertifikaadist
- Kliendisert nõutud `Demo.svc` peal; health ilma SSL-ita
- EE-GovCA / ESTEID paigaldus: `.\lab.ps1 eid-ca`
- Rakendus kontrollib poliitika-OID-sid; ahelat ei tuletata ainult Subject/EKU järgi

---

## Docker HAProxy

Kui Docker Desktop käib:

```powershell
.\lab.ps1 haproxy
```

Peatab .NET balanceri, jätab IIS Expressi, mapib hosti **9443 → konteineri 443**. Config: `haproxy/haproxy.cfg` (`mode tcp`, `option httpchk GET /health.json`, `check port 8080`).

Töö HAProxy real **ära** pane `ssl` backend’i `server` reale, kui tahad passthrough’i (mTLS peab jõudma IIS-i). Kaks Windows Serverit:

```text
server Backend1 10.0.0.11:443 check port 8080
server Backend2 10.0.0.12:443 check port 8080
```

Kaks HAProxy kihti (väline → sisemine): `balance source` kleepuvuseks on vaja **PROXY protocol**’i, muidu näeb sisemine ainult välise HAProxy IP-d. Round-robin + WCF Keep-Alive ei vaja PROXY-t.

---

## Tõrkeotsing

**PIN1 küsiti, siis WCF 403 / Anonymous.** See on server, mitte PIN. Käivita **IIS-i masinas**:

```powershell
.\lab.ps1 probe          # ava https://demo.local:9444/ ID-kaardiga -> verdikt kohe
.\lab.ps1 report 15      # koondraport failina (IIS sc-substatus, CAPI2, Schannel)
```

Loe [Diagnostika: üks koht, kust vaadata](#diagnostika-üks-koht-kust-vaadata). 403.16 = ahel/ClientAuthIssuer; 403.13 = OCSP/WinHTTP; 403.7 = sert ei jõudnud (HAProxy `ssl` või Negotiate off). Kliendi poolel vajuta nuppu **Diagnostika** — see näitab päris alamstaatuse, mille WCF „Anonymous“ taha peidab.

**Build / fail lukus.** Sulge `Demo.Client` või kasuta `.\lab.ps1 build` (see tapab kliendi protsessi). Balanceri uuendamiseks `.\lab.ps1 start-lb` või terve `start`.

**403 / Anonymous labis.** [403.16](#40316-vs-40313). Kodus: `eid-ca` + `bind` + `start`. Tööl: ahel **igal** IIS-il + `Install-EsteidIisProduction.ps1`.

**PIN-dialooge ei ole.** Lab-sertifikaat. Pane ID-kaart lugejasse ja ava klient uuesti.

**Kõik pingid ühte backend’i.** Õige, kuni Keep-Alive elab. Uus sisselogimine või Kinni+uus päring võib anda teise.

**HTTP.SYS viga pärast Kinni.** Vana kanal / HTTP.sys kummitus. Uus klient (pärast `start`) teeb uue TCP; vajuta tavalist päringut uuesti. Ära jäta vana `Demo.Client.exe` käima üle `start` peale.

**Käima ebaõnnestub, logi lukus.** `lab.ps1` ootab protsessi lõppu ja vajadusel kirjutab ajatempliga logi. Proovi Käima uuesti.

**Port 9443 kinni.** `.\lab.ps1 stop`, kontrolli `.\lab.ps1 status`, siis `start`. Vana `Demo.LoadBalancer` võib pordi kinni jätta.

**Health DOWN, kuigi IIS elab.** Vaata `.lab\backend1.out.log` / `backend2.out.log`. Health peab olema **HTTP** 8080/8081, mitte 8443.

**Otse :8443 töötab, läbi :9443 mitte.** Balancer ei jookse või klient ei kasuta `demo.local`.

**IIS VM-il SK URL-id FAIL, IE-s avanevad.** WinHTTP ≠ IE ja ≠ WCF `Web.config` proxy. `netsh winhttp show proxy`; vt [WCF Web.config proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp).

**Sümptom, mida siin nimekirjas pole.** Vaata [Vead, mida see lab ise esile ei kutsu](#vead-mida-see-lab-ise-esile-ei-kutsu) — seal on sümptomite kiirtabel toodangu kihtide kohta (GPO, proxy 407, HTTP/2, idle-timeout, Citrix, kaardi vahetus, vahemälud).
