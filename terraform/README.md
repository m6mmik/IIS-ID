# Terraform: Hyper-V lab vs Nutanix töö

Terraform loob **masinad ja võrgu**. Ansible (kaust `ansible/`) paneb masina **sisse** IIS-i, ESTEID ahela, `netsh http` ja WinHTTP proxy. Need kaks asja ei kuulu ühte `main.tf` faili.

| | `terraform/hyperv` | `terraform/nutanix` |
|---|---|---|
| Kus jookseb | sellel Windowsi hostil, kus Hyper-V on | töö Prism Central / Prism Element vastu |
| Provider | puudub: kutsub olemasolevat `New-LabVm.ps1` | `nutanix/nutanix` |
| Mida loob | internal switch + üks Windows Server VM | 2 IIS-i + 1 HAProxy Linux, subnet, image |
| Kas `apply` kodus | jah, kui Hyper-V ja ISO on olemas | ei — see on töö mall |
| Windows Setup | ikka ISO + `.\lab.ps1 vm-start` | tavaliselt valmis image / Sysprep / NGT |

Hüperviisori kood **ei kanna üle**. Ära kopeeri `hyperv/` töö state’i ega `nutanix/` kodu-apply’sse. Ansible inventory saab mõlemast samad väljundid: IP-d, roll `iis` / `haproxy`.

## Kodus (Hyper-V)

VM on sul juba olemas (`IIS-ID-Server`). `terraform apply` on siis no-op: skript näeb masinat ja väljub. Uue masina jaoks:

```powershell
cd terraform\hyperv
copy terraform.tfvars.example terraform.tfvars
# täida iso_path
terraform init
terraform plan
terraform apply
```

või `.\lab.ps1 tf` / `.\lab.ps1 tf apply`.

Pärast Setupi: guestis `scripts\Enable-LabWinRm.ps1`, hostis `.\lab.ps1 ansible`.

Destroy **ei kustuta** VM-i (seal on juba Windows). Kustutamine on teadlik `Remove-VM`.

## Tööl (Nutanix)

`terraform/nutanix` on sama topoloogia, teise provideriga. Kopeeri see töö IaC-reposse, pane külge oma cluster/subnet/image UUID-d, ära rakenda seda siit labist Prismile.

```hcl
# töö repos, mitte siin
module "iis_id" {
  source = "./terraform/nutanix"
}
```

Väljund `ansible_inventory` kleebitakse `ansible/inventories/work.yml` külge (või genereeritakse CI-s). Ansible rollid jäävad selle repo `ansible/roles/` omad — need räägivad Windowsi ja HTTP.sys-iga, mitte Prismiga.

## Mida Terraform ei tee (mõlemas)

- ESTEID hoidlad, `ClientAuthTrustMode`, `netsh http add sslcert`
- WinHTTP proxy
- IIS saidid / app poolid
- `haproxy.cfg` sisu

Uus VM ilma Ansible rollita = vahelduv **403.16**.
