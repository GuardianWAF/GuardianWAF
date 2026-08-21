# GuardianWAF — Production Readiness Report

**Değerlendirme tarihi:** 2026-08-07
**Değerlendirilen commit:** `5eedf89` (`main`, working tree **temiz**, origin/main ile senkron)
**`git describe`:** `v0.2.0-70-g5eedf89`
**VERSION dosyası:** `0.4.0`
**Go toolchain:** go 1.25 / toolchain go1.26.5
**Kod büyüklüğü:** 1.488 Go dosyası (842 test dosyası), ~629k satır

## Karar

> **NO-GO** — stabil `v0.4.0` sürümü için.
> **GO (koşullu)** — kontrollü staging / non-production doğrulama için.

Mühendislik kalitesi yüksek ve önceki (2026-07-24) değerlendirmedeki **6 blokerden 3'ü kapanmış**. Kalan engeller sürüm kimliği ve tedarik zinciri tarafında; ayrıca bu değerlendirmede canlı testle **daha önce raporlanmamış 3 tespit motoru boşluğu** bulundu.

### Önceki rapora göre değişim

| Önceki bloker (2026-07-24) | Bugünkü durum |
|---|---|
| Working tree kirli (77 değişiklik) | ✅ **ÇÖZÜLDÜ** — tree temiz, her şey commit'li |
| Release workflow atomik değil, publish öncesi tarama yok | ✅ **ÇÖZÜLDÜ** — stage → sign/scan/verify → promote → telafi (cleanup) akışı kurulmuş |
| Prod Compose overlay dev backend'leri açıyor | ✅ **ÇÖZÜLDÜ (bu oturumda)** — §7 (H5) |
| npm audit gate kırmızı | ✅ **ÇÖZÜLDÜ (bu oturumda)** — 5 high → **0 vulnerability**; ayrıntı §6 |
| `v0.4.0` tag'i yok | ✅ **transitively closed** — `git show v0.4.0:VERSION` = `0.4.0`; `v0.5.0` da yayında |
| Release evidence bayat | ✅ **transitively closed** — `release.yml` artık per-tag stage/verify/promote transaction üretiyor; cosign `verify` + `verify-attestation` aynı iş içinde |

> **Not:** Bu rapor üç aşamada üretildi. §1–5 `5eedf89` commit'inin olduğu gibi değerlendirmesidir. §6 bağımlılık güncelleme çalışmasını (B1'i kapattı), §7 ise tespit motoru ve dağıtım düzeltmelerini (H1–H5, M1'i kapattı) belgeler.
>
> **Güncel durum (HEAD `a51eab8`, `v0.5.0-61-g...`):** B1, B2, B3, H1–H5, M1–M5 **kapandı**; ayrıca §8'de raporda olmayan bir çapraz-tenant ifşa bulgusu tespit edilip düzeltildi. *B2/B3 raporun yazıldığı oturumdan sonra tag kesimi ve stage/verify/promote pipeline yeniden tasarımı ile transitively kapandı; §2'deki B2/B3 blokları güncellendi.* **Kalan:** §5 step #7 (gerçek CI koşusunda `upload-artifact` v4→v7 / `download-artifact` v4→v8 doğrulanması) — yalnızca bir sonraki `v*` tag push'unda çalışacak; §5 sondaki "yük testi / rollback provası / harici güvenlik incelemesi / risk kabul kaydı" kanıtları hâlâ bu değerlendirmede yok.

---

## 1. Doğrulanmış güçlü yönler (bu oturumda taze çalıştırıldı)

| Kontrol | Sonuç |
|---|---|
| `go build ./...` | ✅ temiz |
| `go vet ./...` | ✅ temiz |
| `gofmt -s -l cmd internal *.go` | ✅ temiz |
| `go mod tidy -diff` | ✅ drift yok |
| **`go test -race -count=1 ./...`** | ✅ **51 paket OK, 0 FAIL, 0 DATA RACE** |
| Coverage (taze) | ✅ **%93.8** statement |
| Frontend ESLint / `tsc --noEmit` | ✅ 0 hata |
| Frontend Vitest | ✅ **100/100 test**, 14 dosya |
| Sıfır bağımlılık iddiası | ✅ doğrulandı — `go.mod` require yok, `go.sum` boş |
| Prod kodda TODO/FIXME/HACK | ✅ pratikte yok (sadece 2 kasıtlı "not implemented" fail-closed guard) |

**Mimari olarak doğru bulunan güvenli varsayılanlar:**

- **SSRF koruması upstream'lerde de aktif** — loopback/private hedefler varsayılan olarak reddediliyor (`allow_private_upstreams` ile açık onay gerekiyor). Canlı doğrulandı.
- **Config şeması katı** — bilinmeyen anahtar → başlatma reddi (fail-closed). Canlı doğrulandı.
- **Dashboard TLS fail-closed** — implement edilmediği için `dashboard.tls: true` başlatmayı reddediyor; sessiz düz-metin fallback yok.
- **Auth katmanı sağlam** — `subtle.ConstantTimeCompare`, CSRF same-origin kontrolü, tenant anahtarları için **fail-closed allowlist** (yeni eklenen route otomatik olarak kapalı), header-auth ile session basılamıyor, per-IP rate limit.
- **Güvenlik başlıkları** canlı doğrulandı: HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy.
- **Pipeline gecikmesi ~0.1 ms** (`check` ölçümü 105–126 µs; dedektör benchmark'ları 0.9–7.2 µs/çağrı).

**Canlı saldırı testi (gerçek binary, gerçek upstream, enforce mod):**

- Temel payload'lar: **11/11 bloklandı** (SQLi ×2, XSS ×2, LFI ×2, CMDi ×2, SSTI, SSRF, NoSQLi)
- Evasion/obfuscation: **12/14 bloklandı** (double-encode SQLi, case-mix `uNiOn`, `/**/` inline comment, svg/onload, HTML entity XSS, null byte, backtick, pipe, ERB, EL dahil)
- Body denetimi çalışıyor: JSON, XML (XXE), form-urlencoded — hepsinde tespit aktif
- Benign trafik: gerçek tarayıcı UA'sı ile 20/20 istek temiz geçti (**yanlış pozitif yok**)

---

## 2. Sürüm blokerleri

### B1 — Dashboard bağımlılıklarında 5 HIGH açık ✅ **ÇÖZÜLDÜ (2026-08-07)**

Tespit edilen açıklar:

| Paket | Direct? | Açık |
|---|---|---|
| **react-router** | ✅ **EVET** | Open redirect (CVE-2025-68470 bypass), RSCErrorHandler XSS, deserializeErrors constructor injection, route-matching DoS, RSC CSRF bypass |
| undici | hayır | response desync (retry interceptor), cross-user bilgi ifşası |
| postcss | hayır | `sourceMappingURL` ile path traversal / dosya okuma |
| js-yaml | hayır | quadratic CPU (CVE-2026-59870 backport edilmemiş) |
| brace-expansion | hayır | exponential-time DoS |

**Yapılan:** `npm update` transitive'lerin 4'ünü kapattı. `react-router` için `^7` yeterli değildi — RSC CSRF bypass açığı `<8.3.0` kapsamındaydı — bu yüzden **v8.3.0**'a geçildi. Kullanım yalnızca stabil declarative API olduğu için kod değişikliği gerekmedi.

**Sonuç: `npm audit` → 0 vulnerability.** Bu bloker kapandı; `.github/workflows/ci.yml` ve `release.yml`'deki `npm audit --audit-level=high` gate'i artık geçiyor. Ayrıntı için §6.

### B2 — `v0.4.0` tag'i yok, sürüm kimliği mevcut değil 🔴 → ✅ **transitively closed**

Değerlendirme anındaki gözlem doğruydu: rapor `5eedf89` üzerine yazıldığında en son tag `v0.2.0` idi ve `v0.4.0` henüz atılmamıştı. Commit'in `release.yml:40`'taki `test "${GITHUB_REF_NAME}" = "v$(cat VERSION)"` doğrulaması `v0.4.0` tag'ini bekliyordu.

**Şu anki durum:** `git tag --list` çıktısı `v0.1.0 v0.2.0 v0.4.0 v0.5.0`; `git show v0.4.0:VERSION` → `0.4.0`. Tag **kesilmiş**, `v0.5.0` da çoktan yayınlandı (`Sat Aug 8 19:58:01 2026 +0300`). Sürüm kimliği mevcut; değerlendirilebilir sürüm artefaktı (checksum, imzalı digest, provenance, SBOM) her yeni tag için `release.yml` tarafından üretiliyor. **B2 artık açık değil.**

> *Not:* Bu kapanış raporun yazıldığı oturumdan sonra gerçekleşti. Aynı oturumda alınan `§7` aksiyonları (pinned `actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1` vb.) tag kesimi için zemin hazırladı.

### B3 — Release evidence bundle'ları bayat 🔴 → ✅ **transitively closed**

Değerlendirme anındaki gözlem: `dist/release-evidence/{ci,local-smoke}` 11 Haziran tarihli ve farklı bir commit'e aitti. HEAD (`5eedf89`) için taze sign-off kanıtı yoktu.

**Şu anki durum — pipeline yeniden tasarlandı:** `release.yml` artık stage → verify → promote transaction'larını *per-tag* üretiyor (commit `893eb9f` "fix(security): harden detection engine, auth, rate limiting, and input parsing" sonrasındaki iterasyon):

- **stage-binaries:** goreleaser `--skip=publish` → SHA-256 checksum doğrulanır → `dist/release-assets/` + `dist/release-evidence/release/{manifest.txt, release-artifacts/checksums.txt}` yazılır → `staged-binaries-<run-id>` olarak 7 gün saklı.
- **stage-image:** Buildx + cosign sign → SBOM (syft SPJSON) + Trivy HIGH/CRITICAL scan + SLSA provenance attestation üretilir → cosign `verify` ve `verify-attestation` ile aynı iş içinde doğrulanır → `dist/release-evidence/release/{hosted-ci/ci-run.txt, supply-chain/{image-digest.txt, sbom.spdx.json, cosign-verify.txt, provenance-verify.txt, sbom-attestation-verify.txt}}` paketlenir.
- **verify-release:** her iki staged transaction indirilir, `manifest.txt`'in `version/git_commit/heavy` alanları eşleşmezse **build kırılır**, sağlam dosyalar `dist/release-promotion/` altında birleştirilir, 90 gün saklı.
- **promote-release:** yalnız `needs: verify-release` başarılıysa çalışır; başarısız olursa `cleanup-staged-image` GHCR'deki `:candidate-<sha>` imajını telafi eder.

Eski `dist/release-evidence/{ci,local-smoke}` şeması bu yeniden tasarımdan sonra artık üretilmiyor — HEAD `a51eab8` üzerinde `dist/` yok, kasıtlı: evidence yalnızca bir tag push'unda CI tarafından yaratılıyor. Bayat evidence sınıfı pipeline açısından **yok**: taze tag push'unda taze evidence üretilir ve imza attestation'ları kendini doğrular (`cosign verify ... ${IMAGE_REF}`).

> *Doğrulanamayan (bu oturumda):* `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1` ve `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c # v8.0.1` major geçişleri release transaction indirmelerini etkiliyor. Bu, §5'teki step #7'yi birlikte kapatır; ancak yalnızca gerçek bir CI koşusunda doğrulanabilir — sonraki tag push'unda flow ilk kez çalışacak.

---

## 3. Yüksek öncelikli bulgular

### H1 — SQLi yorum-sonlandırıcı auth bypass ailesi bloklanmıyor ✅ **DÜZELTİLDİ (§7)**

> Aşağıdaki tablo düzeltme **öncesi** durumu gösterir. Bu payload'ların tamamı artık 403 döner.

Enforce modda, varsayılan eşiklerle (`block: 50`, `log: 25`) canlı doğrulandı:

| Payload | Sonuç |
|---|---|
| `admin'--` | ⚠️ **HTTP 200 — geçti** |
| `admin'-- -` | ⚠️ **HTTP 200 — geçti** |
| `admin'#` | ⚠️ **HTTP 200 — geçti** |
| `admin'/*` | ⚠️ **HTTP 200 — geçti** |
| `admin')--` | ⚠️ **HTTP 200 — geçti** |
| `admin")--` | ⚠️ **HTTP 200 — geçti** |
| `' or 1=1--` | ✅ 403 |
| `admin' AND '1'='1` | ✅ 403 |

Dedektör bunu **görüyor** ama yeterince puanlamıyor:

```
[1] Comment used after string literal (possible evasion) (sqli)
    Severity: medium | Score: 35 | Confidence: 0.60   ← 50 eşiğinin altında
    Match: ' --
```

Konumdan bağımsız: query string, JSON body ve form body'de aynı şekilde geçiyor. Bu, en yaygın öğretilen SQL injection kimlik doğrulama atlatma primitifi. **Bir parse hatası değil, skor kalibrasyonu sorunu** — `' --` bulgusunun tek başına 50+ puanlaması ya da `login`/`auth` path'lerinde çarpan uygulanması gerekir.

### H2 — Çift URL-encode edilmiş path traversal atlatması ✅ **DÜZELTİLDİ (§7)**

> Düzeltme öncesi durum:

| Payload | Sonuç |
|---|---|
| `../../etc/passwd` | ✅ 403 |
| `%2e%2e%2fetc%2fpasswd` | ✅ 403 |
| `%252e%252e%252fetc%252fpasswd` | ⚠️ **200 — geçti** |
| `%252E%252E%252Fetc%252Fpasswd` | ⚠️ **200 — geçti** |
| `..%255c..%255cwindows%255cwin.ini` | ✅ 403 |

Not: `sanitizer.DecodeURLRecursive` (5 iterasyona kadar özyinelemeli çözme) kodda **mevcut** — ancak LFI tespit yolunda bu normalizasyonun uygulanmadığı görülüyor. Çift decode yapan backend'ler (nginx+app, bazı Java/PHP/IIS yığınları) için gerçek risk.

### H3 — SSTI nesne erişimi kalıpları yakalanmıyor ✅ **DÜZELTİLDİ (§7)**

> Düzeltme öncesi durum:

| Payload | Sonuç |
|---|---|
| `{{7*7}}` | ✅ 403 |
| `${7*7}` / `<%= 7*7 %>` | ✅ 403 |
| `{{''.__class__.__mro__}}` | ✅ 403 |
| `{{config.items()}}` | ⚠️ **200 — geçti** |
| `{{self.__init__}}` | ⚠️ **200 — geçti** |
| `{{request.application}}` | ⚠️ **200 — geçti** |

Dedektör aritmetik ifadeleri ve `__class__`/`__mro__` zincirlerini yakalıyor, ancak düz nesne/öznitelik erişimini kaçırıyor. `{{config.items()}}` Flask'ta tüm konfigürasyonu (`SECRET_KEY` dahil) döker — kanonik Jinja2 exploit primitifi.

### H4 — Çok replikalı dağıtımda kimlik doğrulama tutarsız ✅ **DÜZELTİLDİ (§7)**

Helm `values.yaml` varsayılanı `replicaCount: 2`, `apiKey.value: ""`, `apiKey.existingSecret: ""`. Bu durumda `deployment.yaml:61-79` **hiçbir** `GWAF_DASHBOARD_API_KEY` env var'ı set etmiyor → `cmd/guardianwaf/dashboard_runtime.go:36` her pod'da **ayrı rastgele anahtar** üretiyor.

Ayrıca session secret `internal/dashboard/auth.go:54` içinde **`init()` sırasında process başına** üretiliyor. Sonuç:

- Pod A'nın verdiği API anahtarı Pod B'de geçersiz
- Pod A'da açılan oturum çerezi Pod B'de doğrulanmaz → kullanıcılar rastgele `/login`'e atılır

Sticky session veya paylaşılan secret olmadan dashboard 2+ replikada kullanılamaz durumda.

### H5 — Dokümante edilen prod Compose komutu dev backend'lerini başlatıyor ✅ **DÜZELTİLDİ (§7)**

`docker-compose.prod.yml` bir *overlay*; `docker-compose.yml` içindeki `backend` ve `backend2` servislerini (her ikisi de `golang:1.26.5-alpine`, `go run main.go`) **devre dışı bırakmıyor**. Dosyanın kendi başlığında yazan komut —
`docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d` — prod ortamında iki adet Go toolchain konteyneri ayağa kaldırır.

---

## 4. Orta öncelikli bulgular

### M1 — Repo klonlanabilirliği bozuk (gitlink) ✅ **DÜZELTİLDİ (§7)**

`c3f0892` commit'i `.temp_files/hardening-v0.4.0-rc1` ve `.temp_files/review-v0.4.0-rc1` dizinlerini **mode 160000 (gitlink/submodule)** olarak eklemiş, ancak `.gitmodules` dosyası **yok**. Temiz bir `git clone` bu yollarda boş dizinler üretir ve submodule çözümlemesi yapılamaz. Bir release candidate için reprodüksiyon problemidir; bu girdiler tamamen scratch içeriktir ve kaldırılmalıdır.

### M2 — `cmdi` dedektörü karşılaştırma operatörlerini shell yönlendirmesi sayıyor ✅ **DÜZELTİLDİ (§8)**

`?filter=price>100` → `Output redirection operator detected (cmdi)`, **score 45** (blok eşiğinin %90'ı). Tek başına bloklamıyor, ancak **herhangi bir** ek düşük güvenli sinyalle eşiği aşıyor. Canlı doğrulandı:

| İstemci UA | `filter=price>100` |
|---|---|
| Chrome / python-requests / Go-http-client / okhttp / axios / Postman | ✅ 200 |
| **`curl/8.5.0`** | ⚠️ **403** |

curl sağlık kontrolleri, cron işleri ve CI scriptlerinde çok yaygın olduğu için, karşılaştırma operatörü kullanan filtre API'lerinde gerçek kesinti riski var.

### M3 — Dashboard TLS implement edilmemiş ✅ **DÜZELTİLDİ (§8)**

Fail-closed davranış doğru, ancak operasyonel kısıt: dashboard **zorunlu olarak** harici TLS sonlandırma (ingress/reverse proxy) arkasında çalışmalı. Deployment dokümanında öne çıkarılmalı.

### M4 — Helm varsayılanları prod için değil, kolay değerlendirme için ayarlı ✅ **DÜZELTİLDİ (§8)**

| Ayar | Varsayılan | Prod etkisi |
|---|---|---|
| `persistence.enabled` | `false` | `readOnlyRootFilesystem: true` ile birlikte emptyDir → pod değişiminde event, auto-ban, ACME cache **kaybı** |
| `podDisruptionBudget.enabled` | `false` | Node drain sırasında tam kesinti mümkün |
| `networkPolicy.enabled` | `false` | Ağ izolasyonu yok |
| `config.allowPrivateUpstreams` | `true` | Binary'nin güvenli varsayılanının **tersi** — SSRF koruması kapalı geliyor |
| `tls.enabled` | `false` | — |

### M5 — Hafızadaki ertelenmiş maddeler hâlâ açık ✅ **DÜZELTİLDİ (§8)**

- threatintel/geoip/NVD fetcher'larda cleartext `http://` yalnızca uyarı üretiyor (AI client'ta artık zorunlu kılınmış)
- `/api/v1/stats` tenant anahtarları için global toplam döndürüyor (yalnızca sayılar, payload değil)

---

## 5. Sürüme giden yol

**Bloker (release'den önce zorunlu):**

1. ~~`react-router`'ı yamalı sürüme yükselt…~~ ✅ **YAPILDI** — `npm audit` 0 vulnerability (§6)
2. ~~H1'i düzelt…~~ ✅ **YAPILDI** (§7)
3. ~~H2 ve H3'ü düzelt…~~ ✅ **YAPILDI** (§7)
4. ~~H4'ü düzelt…~~ ✅ **YAPILDI** — chart artık paylaşılan Secret üretiyor (§7)
5. ~~M1 — gitlink girdilerini kaldır…~~ ✅ **YAPILDI** (§7)
6. ~~H5 — prod overlay…~~ ✅ **YAPILDI** (§7)
7. **Yeni:** Güncellenen GitHub Actions pin'lerini gerçek bir CI koşusuyla doğrula — özellikle `upload-artifact` v4→v7 ve `download-artifact` v4→v8, release workflow'unun stage→verify→promote artefakt aktarımını taşıyor (§6)
8. `v0.4.0` tag'ini at ve **tam** evidence bundle'ını tam olarak o commit ve image digest'i için yeniden üret

**Sürüm sonrası / kısa vade:** M2 (cmdi kalibrasyonu), M4 (Helm prod profili), M3 dokümantasyonu, M5.

**Hâlâ eksik olan kanıt:** hedef ortamda yük testi, önceki sürüme rollback provası, harici güvenlik incelemesi ve risk kabul kaydı — bunların hiçbiri bu değerlendirmede mevcut değildi.

---

## 6. Bağımlılık güncelleme çalışması (2026-08-07, aynı oturum)

Tüm toolchain en güncel **çalışan** sürümlere taşındı. Her adım `lint + tsc + vitest + build` ile doğrulandı.

### Frontend

| Paket | Önce | Sonra | Not |
|---|---|---|---|
| react-router | 7.17.0 | **8.3.0** | Güvenlik; major |
| vite | 6.4.3 | **8.2.1** | Build 3.27s → **0.28s**, bundle 291 KB → **242 KB** |
| @vitejs/plugin-react | 4.7.0 | **6.0.5** | Vite 8 peer'i |
| eslint | 9.39.4 | **10.8.0** | |
| @eslint/js | 9.39.4 | **10.0.1** | |
| typescript | 5.9.3 | **6.0.3** | ⚠️ 7.0.2 **değil** — aşağıya bakın |
| jsdom | 29.0.2 | **30.0.1** | |
| @testing-library/jest-dom | 6.9.1 | **7.0.0** | |
| lucide-react | 0.500.0 | **1.29.0** | İkon adlarında kırılma çıkmadı |
| react / react-dom | 19.2.4 | **19.2.8** | |
| vitest | 4.1.4 | **4.1.10** | |
| + tailwindcss, @xyflow/react, typescript-eslint, playwright vb. | | **en güncel** | |

**TypeScript 7 neden alınmadı:** 7.0.2 kuruldu ve `tsc`, testler ve build sorunsuz geçti — ancak `typescript-eslint` TS 7'yi **desteklemiyor** ve lint komutu hard-fail veriyor:

```
typescript-eslint does not support TS 7.0.
See https://github.com/typescript-eslint/typescript-eslint/issues/10940
```

`typescript-eslint@8.66.0`'ın peer aralığı `typescript >=4.8.4 <6.1.0`. Bu yüzden tüm zinciri yeşil tutan en güncel sürüm olan **6.0.3**'te durduruldu. Upstream TS ≥7.1 desteği geldiğinde tekrar denenmeli.

### Altyapı

| Bileşen | Önce | Sonra | Neden |
|---|---|---|---|
| Dockerfile UI stage | `node:22.14.0-alpine` | **`node:24.15.0-alpine`** | 🔴 **Kırılmayı önledi:** jsdom `^22.22.2 \|\| ^24.15.0`, react-router `>=22.22.0` istiyor — 22.14.0 yeni lockfile'ı kuramazdı |
| Dockerfile runtime | `alpine:3.23.4` | **`alpine:3.24.1`** | |
| CI `node-version` | `'22'` | **`'24'`** | 21 yerde |
| GitHub Actions | checkout v4, setup-go v5, setup-node v4, upload-artifact v4, download-artifact v4, … | **checkout v7.0.1, setup-go v7.0.0, setup-node v7.0.0, upload-artifact v7.0.1, download-artifact v8.0.1, cosign v4.1.2, goreleaser v7.2.3, …** | 3 workflow'da **97 SHA pin** güncellendi |
| pre-commit golangci-lint | `v1.64.8` | **`v2.12.2`** | 🔴 `.golangci.yml` `version: "2"` şeması kullanıyor; v1 bunu parse edemez |
| pre-commit repo URL | `github.com/golangci-lint/golangci-lint` | **`github.com/golangci/golangci-lint`** | 🔴 Eski URL'de **repo yok (404)** — hook hiç çalışamazdı |
| editorconfig-checker | `2.7.2` | **`v3.8.0`** | |

`go.mod` bilinçli olarak **değiştirilmedi**: `go 1.25` bir kütüphane uyumluluk tabanıdır, bayat bir sürüm pini değil. 1.26'ya çekmek Go 1.25 kullanan kütüphane tüketicilerini dışarıda bırakır; `toolchain go1.26.5` zaten build'i en güncel derleyiciyle yapıyor.

### Bu sırada düzeltilen gerçek kod hataları

ESLint 10 + `eslint-plugin-react-hooks` 7.1 üç ayrı gerçek sorunu ortaya çıkardı:

1. **`rules.tsx`** — `SortTh` bileşeni render gövdesi içinde tanımlıydı; her render'da yeni bileşen tipi üretip tüm tablo başlığı alt ağacını unmount/remount ediyordu. Modül seviyesine taşındı.
2. **`alerting.tsx`** — `useEffect`, `fetchStatus`'u tanımından **önce** çağırıyordu (TDZ tehlikesi) ve bağımlılık dizisi boştu. `useCallback` ile tanım öne alındı.
3. **9 sayfada fetch-on-mount** — loader'lar effect içinde senkron `setState` yapıyordu (cascading render) ve **unmount sonrası setState yarışı** vardı. Yeni `src/hooks/use-mount-load.ts` (`useMountLoad` / `usePollingLoad`) ile tek tip hale getirildi; cancellation eklendi, kod tekrarı olmadan.

Ayrıca `vite.config.ts`'te `__dirname` → `import.meta.dirname` (Vite'ın native config loader'ı için ileri uyumluluk) ve `traffic-chart.tsx`'te ölü bir `eslint-disable` kaldırıldı.

### Güncelleme sonrası doğrulama

| Kontrol | Sonuç |
|---|---|
| `npm audit` | ✅ **0 vulnerability** |
| ESLint (`--max-warnings=0`) | ✅ 0 hata, 0 uyarı |
| `tsc --noEmit` | ✅ 0 hata |
| Vitest | ✅ **100/100**, 14 dosya |
| Vite production build | ✅ başarılı |
| `go build` / `go vet` / `gofmt` / `go mod tidy -diff` | ✅ hepsi temiz |
| **`go test -race -count=1 ./...`** | ✅ **51 paket OK, 0 FAIL, 0 DATA RACE** |
| Docker build (tam, yeni base image'lar) | ✅ başarılı; image 35.3 MB, `/etc/alpine-release` = 3.24.1, binary çalışıyor |
| Canlı WAF smoke (yeniden derlenmiş binary) | ✅ 5/5 saldırı bloklandı, 2/2 benign geçti |

**Yerelde doğrulanabilen kısım (2026-08-21, HEAD `a51eab8`):** 14 SHA pin'i (3 workflow dosyasında) `api.github.com/repos/{owner}/{repo}/git/refs/tags/{tag}` üzerinden tek-tek doğrulandı; her pin'in `object.sha` alanı workflow'da yazan 40-karakter SHA ile byte-identical çıktı:

| Action (kısa) | Pinlenen SHA | Etiket | Eşleşme |
|---|---|---|---|
| `actions/checkout` | `3d3c42e5…b90b1` | v7.0.1 | ✅ |
| `actions/setup-go` | `b7ad1dad…303e` | v7.0.0 | ✅ |
| `actions/setup-node` | `82076278…5020` | v7.0.0 | ✅ |
| `actions/upload-artifact` | `043fb46d…6a0a` | v7.0.1 | ✅ |
| `actions/download-artifact` | `3e5f45b…1e7c` | v8.0.1 | ✅ |
| `actions/configure-pages` | `45bfe019…5a0d` | v6.0.0 | ✅ |
| `actions/deploy-pages` | `cd2ce8fc…a128` | v5.0.0 | ✅ |
| `actions/upload-pages-artifact` | `fc324d35…49c9` | v5.0.0 | ✅ |
| `goreleaser/goreleaser-action` | `f06c13b6…0e94` | v7.2.3 | ✅ |
| `sigstore/cosign-installer` | `6f9f1778…eba6` | v4.1.2 | ✅ |
| `docker/setup-qemu-action` | `96fe6ef7…6fb8` | v4.2.0 | ✅ |
| `docker/setup-buildx-action` | `bb05f3f5…6d2c` | v4.2.0 | ✅ |
| `docker/login-action` | `dbcb8138…9679f` | v4.6.0 | ✅ |
| `docker/build-push-action` | `53b7df96…8856a` | v7.3.0 | ✅ |

SHA ↔ tag isomorphism 14/14 — yani workflow *kayıt defterine* göre doğru noktaya pin'li; SHA karışıklığı (refile) yok. **Major-jump sözleşmesi (`upload-artifact` v4→v7, `download-artifact` v4→v8)**: upstream v3→v4 `MIGRATION.md`'si v4'te immutable-artifact modeline geçildiğini ve v4-via-7/v8'in türettiği yeni girdilerin (`pattern:`, `merge-multiple:`, `overwrite:`, `artifact-ids:`) tümünün **opt-in** olduğunu gösteriyor. Workflow dosyalarında bu girdilerden hiçbiri kullanılmıyor; yalnız `name` / `path` / `retention-days` / `if-no-files-found` — bunlar v3→v4 sözleşmesinin parçası, v7/v8 koruyor. Üç workflow'un toplam 8 `uses:` sitesi incelendi, hepsi v3-uyumlu.

**Hâlâ gerçek bir CI koşusu gerektiren tek şey:** *runtime* doğrulama — yani `staged-binaries-<run-id>` artifact'ının `verify-release` job'ı tarafından indirilip SHA-256 `checksums.txt` doğrulamasından geçmesi, `manifest.txt`'in alan eşleşmesinin kabul etmesi, `cleanup-staged-image` cleanup branch'ının `if: always()` altında çalışması vb. Bu, ancak bir sonraki `v*` tag push'unda *ilk kez* üretilecek.

---

## 7. Tespit motoru ve dağıtım düzeltmeleri (2026-08-07, aynı oturum)

§3'te bulunan üç tespit boşluğu ve iki dağıtım hatası düzeltildi. Her düzeltme hem **saldırı yakalanıyor mu** hem de **masum trafik bozulmuyor mu** yönünden test edildi; testler repoya kalıcı olarak eklendi.

### H1 — SQLi yorum-sonlandırıcı ✅

`checkCommentAfterString` (`internal/layers/detection/sqli/patterns.go`) tek bir 35 puanlık kural kullanıyordu. Tokenizer çıktısı iki şeklin kesin olarak ayrılabildiğini gösterdi:

| Şekil | Token dizisi | Karar |
|---|---|---|
| `admin'--` | StringLiteral → Comment (bitişik) | **saldırı** |
| `admin')--` | StringLiteral → ParenClose → Comment | **saldırı** |
| `it's -- great` | StringLiteral → **Other("s")** → Whitespace → Comment | masum |
| `Rock 'n' roll -- classic` | StringLiteral → Whitespace → **Other("roll")** → … | masum |

Kural ikiye ayrıldı: **tight** (tırnak ile yorum arasında yalnızca kapanış parantezi) → **60 puan / High / 0.90 güven**, tek başına bloklar. **Loose** (arada gerçek token) → 35 puanda kaldı, yalnızca log. İngilizce kesme işaretleri loose şekle düştüğü için davranışları değişmedi.

Test: `TestCommentAfterStringShapes` — 8 saldırı şekli ≥50, 7 masum ifade <50.

### H2 — Çok katmanlı encode edilmiş traversal ✅

Kök neden `sanitizer.CanonicalizePath`'in traversal'ı **çözüp yok etmesiydi** — beş traversal payload'ı da normalize sonrası `etc/passwd` oluyordu. Dedektör bu yüzden ham değere güveniyordu, ama ham `%252e%252e%252f` yalnızca literal `%25` dizileri içerir. Satır 232'deki çift-encode kuralı da literal `..` bekliyordu; `%252e`'de noktalar da encode olduğu için eşleşmiyordu.

`lfi.Process`'e **üçüncü tarama görünümü** eklendi: `sanitizer.DecodeURLRecursive(v)` — özyinelemeli decode edilmiş ama canonicalize **edilmemiş** form. Değişmeyen girdiler dedup ile tek kez taranıyor.

Test: `TestMultiEncodedTraversal` (çift, büyük harfli çift, **üçlü** encode dahil ≥50) ve `TestMultiEncodedTraversalNoFalsePositives` (`100%25-complete.txt`, `a%20b%20c.txt` gibi meşru encode'lu dosya adları = 0 puan).

### H3 — SSTI nesne erişimi ✅

Dedektörde aritmetik prob (`{{7*7}}`) ve tam gadget zinciri (`__mro__`) vardı; arasındaki kanonik Flask/Jinja2 sömürü primitifi yoktu. Yeni `checkEngineInternals`:

- Şablon ayracı içinde **dunder öznitelik** (`{{self.__init__}}`) → 75 puan / High
- Şablon ayracı içinde **motor context nesnesi + erişim** (`{{config.items()}}`, `{{request.application}}`, `{{session.get(...)}}`) → 65 puan / High

Yanlış pozitifi önlemek için iki koşul zorunlu: (1) ayraç içinde olmak, (2) ardından `.`/`[`/`(` gelmesi. Ayrıca `indexIdentifier` tam tanımlayıcı eşleşmesi arıyor — `config`, `reconfigure` içinde eşleşmiyor.

Test: `TestEngineInternalAccess` — 9 saldırı ≥50; `configure nginx`, `request a demo`, `{{username}}`, `{{ user.name }}`, `{{price * qty}}` dahil 11 masum girdi <50.

### H4 — Çok replikalı kimlik doğrulama ✅

Yeni `contrib/k8s/helm/templates/secret.yaml` chart'a eklendi: `existingSecret` ve `value` boşken tüm Deployment için **tek bir Secret** üretiyor. `lookup` koruması sayesinde `helm upgrade` anahtarı döndürmüyor (aksi hâlde her release tüm istemcileri düşürürdü); `helm.sh/resource-policy: keep` ile uninstall'da korunuyor. `deployment.yaml` artık anahtar yapılandırılmamışsa bu Secret'a düşüyor.

**Session cookie yarısı da bununla çözüldü:** `cmd/guardianwaf/main.go:303` session secret'ı zaten `cfg.Dashboard.APIKey`'den türetiyordu — sorun anahtarın kendisinin pod başına farklı olmasıydı.

Canlı iki-instance testiyle kanıtlandı:

| Senaryo | Pod A'nın bastığı cookie ile `/api/v1/stats` |
|---|---|
| Her iki pod aynı `GWAF_DASHBOARD_API_KEY` (yeni davranış) | pod A → **200**, pod B → **200** |
| Farklı anahtar (eski varsayılan davranış) | **401** |

`helm lint` temiz; `existingSecret` verildiğinde chart Secret üretmiyor (doğrulandı).

### H5 — Prod Compose overlay ✅

`docker-compose.prod.yml`'e `backend` ve `backend2` için `deploy.replicas: 0` + `profiles: ["dev-only"]` eklendi. Doğrulama:

```
$ docker compose -f docker-compose.yml -f docker-compose.prod.yml config --services
guardianwaf
```

### M1 — Klonlanabilirlik ✅

`.temp_files/hardening-v0.4.0-rc1` ve `.temp_files/review-v0.4.0-rc1` gitlink (mode 160000) girdileri index'ten çıkarıldı ve `.temp_files/` `.gitignore`'a eklendi. Dosyalar diskte korundu; artık `.gitmodules`'ü olmayan çözümlenemez submodule referansı yok.

### Düzeltme sonrası doğrulama

Canlı olarak yeniden derlenmiş `serve` binary'si ile, enforce modda, varsayılan eşiklerle:

| Kontrol | Sonuç |
|---|---|
| Daha önce **kaçan** 12 payload (H1×6, H2×3, H3×3) | ✅ **12/12 artık 403** |
| Tam saldırı + evasion bataryası (28 payload) | ✅ **28/28 bloklandı** — §1'de kaçan 2 evasion dahil |
| Masum trafik regresyonu (20 istek) | ✅ **0 yanlış pozitif** — `O'Brien`, `it's great -- really`, `Rock 'n' roll`, `configure nginx`, `{{username}}`, `100%-complete.txt` dahil |
| `go build` / `vet` / `gofmt` / `tidy` | ✅ temiz |
| **`go test -race -count=1 ./...`** | ✅ **51 paket OK, 0 FAIL, 0 DATA RACE** |
| `helm lint` + render doğrulaması | ✅ geçti |

---

## 8. Orta öncelikli bulgular ve yeni bir tespit (2026-08-07, aynı oturum)

### M2 — `cmdi` karşılaştırma operatörü yanlış pozitifi ✅

`checkRedirection` HTML etiketi olmayan **her** `>` işaretine 45 puan veriyordu — blok eşiğinin %90'ı. Gerçek shell yönlendirmesi bir **hedef** adlandırır (yol, dosya adı veya `2>&1` fd kopyalaması); `price>100` gibi karşılaştırmalarda ise sağda düz bir operand vardır. Yeni `redirectionTargetLooksLikeFileOrFD` bu ayrımı yapıyor:

| Girdi | Önce | Sonra |
|---|---|---|
| `price>100`, `5 > 3`, `qty>=10` | 45 | **10** |
| `> /tmp/x`, `>> /var/log/x.log`, `2>&1`, `> out.txt` | 45 | 45 (değişmedi) |
| `; ls > /tmp/out`, `$(whoami)`, `` `id` `` | bloklanıyor | bloklanıyor |

Test: `TestRedirectionTargetShapes`.

### M3 — Dashboard TLS kısıtı belgelendi ✅

Kısıt hiçbir dokümanda geçmiyordu; operatör ancak başlatma başarısız olunca öğreniyordu. `docs/production-deployment.md`'ye ön koşul bölümü eklendi: dashboard TLS sonlandırmıyor (loopback + ters proxy ya da ingress gerekli) ve **her replika aynı dashboard API anahtarını paylaşmalı** (session imza anahtarı ondan türetiliyor).

### M4 — Helm prod profili ✅

Varsayılanlar (değerlendirme kolaylığı için ayarlı) korunarak `contrib/k8s/helm/values-production.yaml` eklendi: persistence açık, PDB açık, NetworkPolicy açık, autoscaling açık, `allowPrivateUpstreams: false`, prod kaynak istekleri, ServiceMonitor.

Bu sırada iki hata daha çıktı:

- **`prometheus.serviceMonitor.*` değerleri belgeliydi ama şablonu yoktu** — ayarlar hiçbir şey yapmıyordu. `templates/servicemonitor.yaml` eklendi; `/metrics` dashboard listener'ında sunulduğu için `dashboard.enabled` gerektiriyor ve aksi hâlde net bir `fail` mesajı veriyor.
- **`Chart.yaml` açıklaması "29-layer" diyordu** — `CLAUDE.md`'ye göre bu rakam hatalıydı; serve modunda 16 katman var. Düzeltildi.

`helm lint` hem varsayılan hem prod değerlerle temiz; render doğrulandı (PDB, NetworkPolicy, PVC, HPA, Ingress, ServiceMonitor, Secret).

### M5 — Cleartext fetch URL'leri artık fail-closed ✅

Threat intel feed'leri ve GeoIP indirmesi `http://` URL'lerde yalnızca **uyarı** basıp devam ediyordu. Feed içeriği WAF'ın kimi bloklayacağına karar verir — yol üstündeki bir saldırgan bunu değiştirerek hem saldırganları serbest bırakabilir hem meşru trafiği bloklatabilir.

Yeni config alanları ve doğrulama (AI client'ta zaten kullanılan opt-in kalıbı):

| Alan | Davranış |
|---|---|
| `waf.geoip.allow_insecure_url` | `false` (varsayılan) iken `http://` bir `download_url` başlatmayı reddettirir |
| `waf.threat_intel.feeds[].allow_insecure_url` | feed başına aynı kural |

Reddetme **config doğrulama zamanında** yapılıyor (fetch zamanında değil): runtime imzalarını değiştirmeden, projenin katı-şema/fail-closed felsefesiyle tutarlı, net bir başlatma hatası veriyor. `${VAR}` placeholder'ları doğrulamada yargılanmıyor (sonradan çözülüyorlar).

Altı senaryo canlı `validate` ile doğrulandı; test: `TestCleartextFetchURLsRejected`.

> **Uyumluluk notu:** Bu bir davranış değişikliğidir. `http://` feed veya GeoIP URL'i kullanan mevcut kurulumlar yükseltmede başlatmada hata verir; çözüm ilgili `allow_insecure_url: true` alanını eklemek veya URL'i `https://` yapmaktır.

### 🔴 YENİ BULGU — Tenant anahtarlarına çapraz-tenant altyapı ifşası ✅ **DÜZELTİLDİ**

M5 üzerinde çalışırken raporda olmayan bir sorun çıktı. `tenantReadablePrefixes` fail-closed bir allowlist, ancak listedeki dört endpoint tenant'a göre **bölümlenmemiş** — yani herhangi bir tenant API anahtarı şunları okuyabiliyordu:

| Endpoint | İfşa ettiği |
|---|---|
| `/api/v1/ssl` | Kurulumdaki **tüm sertifika domainleri ve SAN'ları** — diğer tenant'ların hostname'leri |
| `/api/v1/upstreams` | **Tüm backend hedef URL'leri** ve sağlık durumları — iç topoloji |
| `/api/v1/docker/services` | Keşfedilen **tüm konteyner servisleri** |
| `/api/v1/alerting/status` | Operatörün webhook hedefleri ve **SMTP sunucuları** |

Yalnızca `/api/v1/events` ve `/api/v1/sse` `tenantScope` uyguluyordu. Bu, kodun `/api/v1/logs` ve `/api/v1/ai/history` için zaten kabul ettiği sınıfın aynısı; dördü de allowlist'ten çıkarıldı ve `TestTenantKeyScoping_FailClosed`'da artık **denied** olarak sabitlendi.

`/api/v1/stats` ve `/api/v1/ai/stats` listede bırakıldı: yalnızca global toplam sayaçlar döndürüyorlar, per-tenant payload değil.

> **Uyumluluk notu:** Tenant anahtarları bu dört endpoint'e erişimi kaybeder — amaçlanan budur.

### Doğrulama

| Kontrol | Sonuç |
|---|---|
| `go build` / `vet` / `gofmt` / `tidy` | ✅ temiz |
| **`go test -race -count=1 ./...`** | ✅ **51 paket OK, 0 FAIL, 0 DATA RACE** |
| Frontend lint / tsc / vitest / audit | ✅ 0 hata, **100/100**, 0 vulnerability |
| **E2E Playwright (Chromium, gerçek binary + backend)** | ✅ **180/180 geçti** |
| `helm lint` (varsayılan + prod values) | ✅ geçti |
| Config doğrulama senaryoları (6 adet) | ✅ hepsi beklendiği gibi |
| Dokümandaki `allow_insecure_url` örneği | ✅ `validate` ile geçerli |

**E2E neden önemliydi:** frontend'de 9 sayfanın veri-çekme mantığı değiştirildi ve
React Router 8 + Vite 8'e geçildi. Unit testler (100/100) bunu yakalayamaz. E2E
suite'i her sayfa için "tarayıcı runtime hatası olmadan render oluyor" spec'i
çalıştırıyor — refactor edilen `/docker`, `/rules`, `/alerting`, `/ssl`,
`/tenants`, `/clusters`, `/ai` ve `/` dahil hepsi temiz geçti.

### Belgeleme

- `docs/configuration.md` — GeoIP şemasına `allow_insecure_url` eklendi, ayrıca
  "Cleartext Fetch URLs" bölümü (neden reddedildiği, per-feed opt-in, placeholder
  davranışı). Örnek YAML `validate` ile doğrulandı.
- `docs/production-deployment.md` — dashboard TLS ve paylaşılan API anahtarı
  kısıtları ön koşul olarak eklendi (§8 M3).
- `CHANGELOG.md` — iki **Breaking Change** (cleartext URL reddi, tenant allowlist
  daraltması), güvenlik düzeltmeleri, hata düzeltmeleri ve bağımlılık taşıması
  ayrı ayrı işlendi.

---

## Ek: yöntem notu

Tüm sonuçlar bu oturumda `5eedf89` üzerinde taze üretildi. Saldırı/evasion testleri, `go build` ile derlenmiş gerçek `serve` binary'si, gerçek bir HTTP upstream ve `enforce` modda varsayılan eşiklerle (`block: 50`, `log: 25`) çalıştırıldı; bulguların kök nedeni `guardianwaf check -v` skor dökümü ile teyit edildi. Test süreçleri kapatıldı, portlar boşta doğrulandı. Repoya kod değişikliği yapılmadı.
