# Ansible: IIS + ID-kaart (sama roll Hyper-V-s ja Nutanixis)

Terraform (`../terraform`) loob VM-i. See kaust paneb VM-i **sisse** selle, mis 403.16 / 403.13 tegelikult ära hoiab. Rollid ei tea hüperviisorist midagi.

| Roll | Mida teeb | Tööriist tööl |
|---|---|---|
| `eid_trust` | EE-GovCA / ESTEID õigetesse hoidlatesse, `ClientAuthTrustMode`, CAPI2 | sama |
| `winhttp_proxy` | `netsh winhttp set proxy` (HTTP.sys / Schannel tee) | sama URL mis `Web.config` |
| `iis_eid` | feature’d, app poolid, saidid, `netsh http` Negotiate, SSL ainult `Demo.svc` peal | sama |
| `haproxy_passthrough` | `mode tcp`, health `:8080` ilma kliendiserdita | sama; labis on HAProxy tihti Docker hostil |

Mängi **kõigil** `iis` hostidel. Uus Nutanixi VM ilma selle playbookita = vahelduv 403.16.

## Kodus, vastu juba töötavat Hyper-V guest’i

1. Guestis (kord): `Enable-LabWinRm.ps1 -StaticIp 192.168.56.10`
2. Hostis: `.\lab.ps1 certs` (kui lab CA-d pole), `.\lab.ps1 build`, `.\lab.ps1 iac`
3. `$env:LAB_WINRM_PASSWORD = '<VM Administrator parool>'`
4. `.\lab.ps1 ansible-ping`  →  `pong`
5. `.\lab.ps1 ansible`       →  `iis.yml` (haproxy grupp on labis tühi)

Käsitsi, WSL-ist:

```bash
export LAB_WINRM_PASSWORD='...'
cd /mnt/c/Users/.../IIS-ID/ansible
ansible -i inventories/lab.yml iis -m ansible.windows.win_ping
ansible-playbook -i inventories/lab.yml iis.yml
```

Kui WSL ei näe `192.168.56.10`, pane `%UserProfile%\.wslconfig` sisse `networkingMode=mirrored` ja `wsl --shutdown`. Hosti PowerShellist `Test-NetConnection 192.168.56.10 -Port 5985` peab enne seda juba PASS olema.

## Tööl

`inventories/work.example.yml` → `work.yml` või Terraform Nutanixi `ansible_inventory` väljund. Üle kirjutad IP-d ja pordid (`443`/`8080`).

Suletud töö VM: jäta `eid_download_certs: false` ja `eid_revocation: false`, pane neli CA faili `certs/eid-ca` kontrollerile. PIN1 ei vaja SK auke. Tühistus (`eid_revocation: true`) alles pärast WinHTTP + `aia.sk.ee` / `ocsp.eidpki.ee` / `c.sk.ee` (TCP 80) otse või proxyst ilma 407-ta.

Ära jäta `group_vars/all.yml` labi proxyt (`192.168.56.2`) töö inventorysse — see on nüüd ainult `inventories/lab.yml` peal. Rolle ei kirjutata Hyper-V jaoks ümber.
