# IIS-ID: WCF + IIS + ID-kaart + TCP load balancing

Kodune lab, mis kopeerib töökeskkonna mustri: **ClickOnce / .NET 4.8 WCF klient**, ID-kaardi **PIN1 (mTLS)** ja **PIN2 (allkiri)**, **HAProxy-laadne TCP passthrough** mitme IIS backend’i ette.

Eesmärk ei ole tavaline veebileht, vaid vastata küsimusele: **kuidas selline klient käitub load balanceri taga** — millal ta jääb ühe IIS-i külge, millal hüppab teisele, ja mis peab olema identne igal Windows Serveril.

Windows 11 Home’il ei ole täis-IIS-i. Lab kasutab **kahte IIS Expressi protsessi** (`Backend1Pool`, `Backend2Pool`). TLS tuleb ikka **HTTP.sys / Schannel** kaudu, nagu päris IIS-is.

Ametlik serveripoolne juhend: [IIS veebiserverile ID-kaardi toe seadistamine](https://open-eid.github.io/iis/index.et.html).

> Enne kui seda mustrit töökeskkonda viid, loe [Enne toodangut: kriitiline nimekiri](#enne-toodangut-kriitiline-nimekiri). Lab on teadlikult lihtsustatud (allkirja formaat, poliitika-kontroll, tühistus, TLS-versioonid) ja mõni lihtsustus murdub tootmises.
>
> Kui annad selle repo mudelile ette, et võrrelda töö tegeliku seisuga: [Töö repoga võrdlemine](#töö-repoga-võrdlemine-ai-le-antav-ülesanne) — seal on maatriks, valmis prompt ja nimekiri tüüpilistest valedest soovitustest.

> Kui lab on roheline, aga toodangus on ikka viga: [Vead, mida see lab ise esile ei kutsu](#vead-mida-see-lab-ise-esile-ei-kutsu) — GPO, korporatiivproxy, HTTP/2, idle-timeout'id, Citrix, kaardi vahetus, vahemälud. Seal on ka sümptomite kiirtabel ja käsud, millega vead labis tahtlikult tekitada.

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
11. [403.16 vs 403.13](#40316-vs-40313)
12. [Toodangu IIS: ID-kaardi ahel ja paigaldus](#toodangu-iis-id-kaardi-ahel-ja-paigaldus)
13. [Täpsed IIS seaded](#täpsed-iis-seaded)
14. [URL-id, mida IIS peab kätte saama (AIA / OCSP / CRL)](#url-id-mida-iis-peab-kätte-saama-aia--ocsp--crl)
15. [WCF Web.config proxy vs WinHTTP](#wcf-webconfig-proxy-vs-winhttp)
16. [HAProxy (passthrough, kaks kihti)](#haproxy-passthrough-kaks-kihti)
17. [Diagnostika: üks koht, kust vaadata](#diagnostika-üks-koht-kust-vaadata)
18. [PIN1 järel ebaõnnestumine: skriptid ja logid](#pin1-järel-ebaõnnestumine-skriptid-ja-logid)
19. [lab.ps1 käsud](#labps1-käsud)
20. [URL-id ja pordid](#url-id-ja-pordid)
21. [Terraform ja Ansible](#terraform-ja-ansible)
22. [Enne toodangut: kriitiline nimekiri](#enne-toodangut-kriitiline-nimekiri)
23. [Vead, mida see lab ise esile ei kutsu](#vead-mida-see-lab-ise-esile-ei-kutsu)
24. [Töö repoga võrdlemine (AI-le antav ülesanne)](#töö-repoga-võrdlemine-ai-le-antav-ülesanne)
25. [Seos töökeskkonnaga](#seos-töökeskkonnaga)
26. [Docker HAProxy](#docker-haproxy)
27. [Tõrkeotsing](#tõrkeotsing)

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

HTTP.sys ehitab ahela **CAPI2 / Schannel** kaudu. Võrk käib **WinHTTP** kui **Local System** (või app pooli identiteet), **mitte** IE / “augud” kasutaja profiilis.

Kui kesktaseme CA-d on **juba** LocalMachine\CA-s, AIA allalaadimist ahela *ehituseks* ei ole vaja — 403.16 kaob. **OCSP** on eraldi: `verifyclientcertrevocation=enable` => 403.13, kui need hostid on kinni.

| URL | Port | Milleks |
|---|---|---|
| https://c.sk.ee/EE-GovCA2018.der.crt | 443 | Juurika fail / AIA |
| https://c.sk.ee/esteid2018.der.crt | 443 | ESTEID2018 kesktase / AIA |
| https://crt.eidpki.ee/EEGovCA2025.crt | 443 | 2025 juur |
| https://crt.eidpki.ee/ESTEID2025.crt | 443 | 2025 kesktase |
| **http://aia.sk.ee/esteid2018** | **80** | ESTEID2018 **OCSP** (kirjas kaardi AIA-s) |
| http://aia.sk.ee/EE-GovCA2018 | 80 | Juurika OCSP |
| **http://ocsp.eidpki.ee** | **80** | ESTEID2025 OCSP |
| http://ocsp.sk.ee | 80 | SK OCSP (vanem / varu) |
| http://c.sk.ee/crls/esteid/esteid2018.crl | 80 | CRL, kui OCSP ei õnnestu |
| http://www.sk.ee/crls/esteid/esteid2018.crl | 80 | CRL varu |

Tulemüür / proxy: luba IIS VM-idelt **väljuv HTTP 80** (OCSP on tavaliselt HTTP, mitte 443) ja **HTTPS 443** SK/eidpki allalaadimiseks. Sise-VM ilma vaikimisi gatewayta = OCSP sureb, isegi kui “IE-s augud” töötavad sinu kasutajaga.

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

Kaks asja, mis muidu eksitavad:

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
- `Get-EidReport.ps1` **igal** IIS-il — 403.16 on masinapõhine, ühe masina roheline vastus ei tõesta midagi teise kohta
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
powershell -ExecutionPolicy Bypass -File .\scripts\Test-ClientCertTrust.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Test-EidAfterPin1.ps1
powershell -ExecutionPolicy Bypass -File .\scripts\Test-EidAfterPin1.ps1 -EnableCapi2Log
```

`Get-EidReport.ps1` on koondraport (üks fail, verdikt ees). `Test-*` skriptid on vanemad üksiktestid, mis kirjutavad ainult ekraanile.

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
| `haproxy` / `haproxy-stop` | Docker HAProxy TCP passthrough |

Diagnostika täpsem selgitus: [Diagnostika: üks koht, kust vaadata](#diagnostika-üks-koht-kust-vaadata).

---

## URL-id ja pordid

| URL | Mis |
|---|---|
| `https://demo.local:9443/Demo.svc` | Klient läbi balanceri (mTLS) |
| `http://127.0.0.1:8404/` | LB juhtimine: Kinni / Käima / drain / roundrobin |
| `http://127.0.0.1:8080/health.json` | Backend1 health (ilma serdita) |
| `http://127.0.0.1:8081/health.json` | Backend2 health |
| `https://127.0.0.1:8443/Demo.svc` | Otse Backend1 (mööda balancerist) |
| `https://127.0.0.1:8444/Demo.svc` | Otse Backend2 |
| `https://demo.local:9444/` | `Demo.CertProbe` diagnostikaraport (ainult `.\lab.ps1 probe` ajal) |

Klient peab kasutama nime **`demo.local`**, sest WCF DNS-identiteet ja serveri sert on sellele nimele. `https://127.0.0.1:9443` võib anda nime-mittesobivuse.

---

## Terraform ja Ansible

See repo **ei ole** Terraform/Ansible kood. Töö infra on juba IaC. Alljärgnev on checklist, et PIN1/mTLS tükid ei jääks “käsitsi ühele VM-ile”, mis on tüüpiline 403.16 põhjus (üks IIS-il ahel olemas, teisel mitte).

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
- Välja **igalt IIS-ilt**: HTTP 80 ja HTTPS 443 `aia.sk.ee`, `ocsp.eidpki.ee`, `c.sk.ee`, `crt.eidpki.ee` **või** ainult korporatiivproxy (siis WinHTTP peab sellele proxyle minema).
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

| Lab (`lab.ps1`) | Töö |
|---|---|
| `bind` / `eid-ca` käsitsi admin | Ansible roll igal boot/deploy |
| `backends.txt` | Terraform private IP-d + Ansible HAProxy template |
| Stats Kinni | Ansible drain + Terraform/HAProxy server state või instance stop |
| Üks Windows 11 | `count` / ASG IIS-idest; roll **kõigile** |

Ära pane Terraform state’i ega Ansible vaulti asemel labi `certs/*.pfx` toodangusse. See repo on käitumise mustand; IaC jääb töö reposse, aga checklist peab olema sama: ahel, Negotiate, WinHTTP, health port, passthrough.

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

### 7. Mida see lab ei ole tõestanud

Aus nimekiri, et sa ei loeks labi rohelist tulemust rohkemaks, kui see on:

- **Päris ID-kaardiga pole läbi käidud** — `certs/eid-ca/` failid on olemas, aga PIN1/PIN2 dialoogi vooga pole testitud. Tee `eid-ca` → `bind` → `start` → kaart lugejasse.
- **Tühistus (OCSP online) on labis välja lülitatud** — `verifyclientcertrevocation=disable` + `RevocationMode=NoCheck`. Seega 403.13 stsenaariumi labis reprodutseeritud pole, ainult dokumenteeritud.
- **Kaks füüsilist masinat, kaks HAProxy kihti, PROXY protocol** — konfid on olemas (`haproxy/haproxy-production.cfg`), testitud on üks Windows 11 masin.
- **ClickOnce deploy** — labis on tavaline `.exe`.
- **IIS Express ≠ täis-IIS** — app pooli recycle’i, Failed Request Tracingut ja W3C `sc-substatus` käitumist saab päriselt kontrollida ainult Windows Serveris.

### Järjekord, kuidas ma seda tööle viiksin

1. Kontrolli töö `Web.config` sessiooni-seaded (punkt 1). See otsustab, kas failover on üldse võimalik.
2. Aja Ansible’iga ahel + `Negotiate Client Certificate` + WinHTTP **kõigile** IIS-idele ja lase `scripts/Test-EidAfterPin1.ps1` igal hostil läbi. Ükski host ei tohi FAIL-i anda.
3. Jäta TLS 1.2 lubatuks, tõesta kätlus ühe IIS-i vastu **ilma** HAProxy-t (`https://iis1.fqdn/...`). Kui siin on 403.16, ei ole HAProxy süüdi.
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

Kontroll: `gpresult /h gpo.html` (otsi Public Key Policies), `certutil -store -enterprise Root`, `certutil -viewstore -enterprise NTAuth`, ja **`Get-EidReport.ps1` enne ja pärast `gpupdate /force`** — kui vahe on, on GPO ülem. Parandus: vii ahel GPO/AD poolele ja lepi turvameeskonnaga kokku, et baseline jätab TLS 1.2 ja teie Schannel võtmed alles.

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

### Sümptomite kiirtabel

| Sümptom | Tõenäoline põhjus | Kust vaadata |
|---|---|---|
| PIN1 küsitakse uuesti keset tööd | idle-timeout mõnes kihis | HTTPERR `Timer_ConnectionIdle`, LB timeout'id |
| Kliendis „sertifikaate ei leitud" | kaardi läbisuunamine, CertPropSvc, trusted issuer list | `certutil -scinfo`, kliendi Diagnostika |
| 403.7 ainult brauserist | HTTP/2 + renegotiation | `netsh http show sslcert`, `EnableHttp2Tls` |
| 403.16 tuleb päevade pärast tagasi | GPO kirjutas hoidla üle | `gpresult /h`, raport enne/pärast `gpupdate /force` |
| 403.13 ainult tippkoormusel | `urlretrievaltimeout`, suur CRL, proxy 407 | `certutil -verify -urlfetch`, proxy logi |
| Iga teine päring ebaõnnestub | üks backend erineb | `service.log` `backend=`, raport igal masinal |
| Kätlus katkeb, IIS-i logis pole rida | serveri serdi võti või Schannel baseline | Schannel 36870/36874, HTTPERR |
| Ühendus sureb pausi järel, PIN-i ei küsita | pilve LB idle-timeout | LB seaded (logi ei teki) |

### Kuidas neid labis tahtlikult tekitada

Kõige kiirem viis diagnostikat usaldama õppida on vead ise sisse panna. Tee seda **ainult lab-masinas** ja taasta pärast.

```powershell
# 403.16: eemalda vahepealne CA ClientAuthIssuer hoidlast
certutil -delstore ClientAuthIssuer "ESTEID2018"
.\lab.ps1 probe            # ava kaardiga -> verdikt peab olema [403.16]
.\lab.ps1 eid-ca           # taasta

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

---

## Töö repoga võrdlemine (AI-le antav ülesanne)

See repo on **käitumise etalon**: siin on teada, mis töötab ja miks. Töö repo on **tegelikkus**. Selle peatüki mõte on, et saaksid mõlemad mudelile ette anda ja tulemuseks tuleks **erinevuste nimekiri + muudatuste plaan**, mitte pimesi tehtud muudatused.

Reegel number üks: mudel ei tohi soovitada turvet nõrgemaks keerata selleks, et asi “tööle saada”. Labi lühendid (`PeerOrChainTrust`, `AllowLabCertificates=true`, `verifyclientcertrevocation=disable`, `RevocationMode=NoCheck`) on **labi omad**. Kui need on juba töö configis, on see leid, mitte lahendus.

### 1. Mida mudelile ette anda

Selle repo pealt: `README.md`, `src/`, `scripts/`, `haproxy/`.

Töö poolelt (loetav koopia, mitte tootmisligipääs):

| Allikas | Fail / käsk |
|---|---|
| WCF teenus | `Web.config` (binding, `serviceCredentials`, `appSettings`) |
| WCF klient | `app.config` / `App.config`, kanali loomise kood, ClickOnce manifest |
| IIS | `applicationHost.config` väljavõte (sait, app pool, `sslFlags`, autentimine) |
| HAProxy | `haproxy.cfg` **mõlemast kihist** (väline + sisemine) |
| Ansible | IIS roll, `group_vars`, sertide ja `netsh` ülesanded |
| Terraform | NSG / security group reeglid, LB, DNS |
| Ühe IIS-i hetkeseis | `netsh http show sslcert`, `netsh winhttp show proxy`, `certutil -store Root/CA/ClientAuthIssuer` |
| Vea tõendid | IIS W3C read `sc-status`/`sc-substatus`, CAPI2 sündmused, HAProxy `show stat` |

**Ära** pane prompti privaatvõtmeid, `.pfx` faile ega päris isikukoode. Sertifikaadi räsid ja isikukoodid maskeeri — võrdluseks piisab teadmisest, *kas* väärtus on olemas ja *millisest* hoidlast.

### 2. Võrdlusmaatriks

Iga rida on üks küsimus, millele vastus peab tulema **töö** poolelt. Vasak veerg näitab, kus labis vastus on.

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

### 4. Väljundi formaat, mida mudelilt nõuda

Iga leiu kohta:

1. **Rida** maatriksist (nr).
2. **Lab** — mis siin on ja miks (viide failile/reale).
3. **Töö** — mis seal on (viide failile/reale). Kui ei leidnud, siis **“ei tuvastatud”**, mitte oletus.
4. **Risk** — `blokeeriv` / `oluline` / `kosmeetiline`.
5. **Muudatus** — konkreetne fail + väärtus.
6. **Kiht** — Terraform / Ansible / IIS / HAProxy / teenuse kood / kliendi kood.

Lõppu kaks eraldi nimekirja: **“mida ei saanud kontrollida ja mis andmeid vaja”** ning **“muudatused, mis nõuavad hooldusakent”** (`netsh` seose muutmine, app pooli restart, Schannel registri muudatus → reboot).

### 5. Valmis prompt

```text
Sul on kaks repot:
A) IIS-ID demo (etalon) — loe kõigepealt A/README.md peatükke
   "Enne toodangut: kriitiline nimekiri" ja "Töö repoga võrdlemine".
B) töö repo + lisatud IIS-i väljundid (tegelikkus).

Ülesanne: võrdle B-d A README peatüki "Võrdlusmaatriks" 13 rea kaupa.

Reeglid:
- Ära paku turvet nõrgemaks keeravaid lahendusi (PeerOrChainTrust,
  AllowLabCertificates=true, verifyclientcertrevocation=disable,
  RevocationMode=NoCheck, HAProxy "ssl verify none"). Need on labi lühendid.
  Kui need on juba B-s, kirjuta need leiuna välja.
- Ära paku HAProxy-s SSL termination'it mTLS-i "parandamiseks".
- Ära paku Web.config <defaultProxy> lahendust HTTP.sys OCSP probleemile.
- Ära paku session affinity cookie'd TCP-režiimis (seda ei ole olemas).
- Kui andmed puuduvad, kirjuta "ei tuvastatud" ja loetle, mida vaja.

Väljund: tabel iga rea kohta (Lab | Töö | Risk | Muudatus | Kiht),
seejärel "puuduvad andmed" ja "vajab hooldusakent" nimekirjad.
Alusta reast 1 (WCF sessioon) — see otsustab, kas failover on üldse võimalik.
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
