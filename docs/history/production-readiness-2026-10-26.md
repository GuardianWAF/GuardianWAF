# GuardianWAF üretim hazırlığı düzeltmeleri

26 Ekim 2026 tarihli [proje incelemesinin](project-review-2026-10-26.md) ardından uygulanan düzeltmeler ve güncel yerel doğrulama kayıtları.

İncelemede bulunan üç koruma farkı giderildi. Kütüphane artık mevcut katmanlar için standalone ile aynı registry builder’larını kullanıyor; API kimlik doğrulaması gerçekten uygulanıyor, yola özel gövde sınırları aktarılıyor ve varsayılan 11 dedektör korunuyor. Ek olarak Node ön kontrolü, panelin yeniden başlatma gerektiren alanları ve SMTP testindeki yarış düzeltildi.

## Düzeltmeler

| Kayıt | Değişiklik | Kalıcı regresyon |
|---|---|---|
| F216 | Programatik kurucuda eksik SSTI, NoSQLi, smuggling, open redirect ve GraphQL dedektörleri eklendi; public config alanları genişletildi. | `library_registry_regression_test.go`: beş dedektör için gerçek istekler ve temiz kontrol. |
| F217 | YAML’da etkin API security kütüphanede bağlanıyor. Library’nin desteklemediği diğer etkin registry katmanları açık başlangıç hatası veriyor. | Eksik/yanlış/geçerli anahtar, exempt path ve desteklenmeyen katman kontrolleri. |
| F218 | Sanitizer, path override ve normalizasyon ayarlarını ortak builder üzerinden alıyor. | Boş, sınırda, sınır üstü ve globalden daha büyük endpoint body limitleri. |
| F219 | Node sürüm kontrolü lockfile’ın desteklediği 22.x, 24.x ve 26+ aralıklarıyla hizalandı. | `internal/config/node_prerequisites_regression_test.go`: dokuz sürüm sınırı. |
| F220 | Panelin restart gerektiren alanları salt okunur; canlı uygulanabilen mod/eşik/body-size ve IP/ban işlemleri korunuyor. | `config-runtime.test.tsx`: salt okunur TLS/dedektör alanları ve canlı eşik kaydetme. |
| F221 | Test SMTP sunucusu işlem sayacını QUIT yanıtından önce yayımlıyor. | `smtp_counter_order_regression_test.go`: `net.Pipe` ve açık tamamlanma kapısıyla deterministik sıralama testi. |

Library kapanışı IP ban persistence ve JWKS arka plan kaynaklarını durduruyor. Kurucu hata yolları da kurulmuş kaynakları temizliyor. `Close` eşzamanlı ve tekrar çağrılabilir; banların kapanışta kaydedilip yeni instance tarafından okunması regresyonla sınanıyor.

Public API’ye beş dedektör alanı eklenmesi F216’nın API yüzeyindeki eksikliğini giderir. Kütüphanede daha önce sessizce yok sayılan etkin registry katmanlarının artık hata vermesi kasıtlı bir uyumluluk değişikliğidir: koruma beklenen bir yapılandırmayla korumasız devam edilmez. Ayrıntılar [dağıtım modlarında](../deployment-modes.md).

README, CONTRIBUTING, Node ön koşulları, library desteği ve [runtime reload sözleşmesi](../runtime-reload.md) güncellendi. Cluster belgesindeki WAL dosya adı ve “restart log büyümesini çözer” önerisi düzeltildi. [Yanıt maskelemesinin boyut ve streaming sınırları](../production-deployment.md#response-masking-boundaries) ayrıca açıklandı.

## Kanıt ve testler

Ortam: Go 1.26.10, Node 24.15.0, npm 12.0.2, Linux. Yeni uygulama bağımlılığı eklenmedi. Çalışma ağacı başlangıçta kirliydi; sonuçlar bu yerel ağaç içindir.

Her özgün `prove_F216`–`prove_F221` programı düzeltmeden önce hatayı üretti; düzeltmeden sonra `PROBLEM NOT REPRODUCED` verdi. Doğrulayıcılar üçer kez başarılı çalıştı. SMTP sıralama kanıtı zamanlamaya dayalı sleep kullanmıyor.

| Kontrol | Sonuç |
|---|---|
| `go test -race -count=1 -timeout=10m ./...` | Geçti. Yarış uyarısı yok. Tenant paketi 442,344 saniye sürdü. |
| `go vet ./...` ve `golangci-lint run ./...` | Geçti; lint 0 issue. |
| Panel unit test, lint ve TypeScript/Vite build | 20 dosyada 116 test geçti; lint/build başarılı. |
| `govulncheck ./...` | Bulgu yok. |
| Panel, website ve Playwright npm audit | Her üçünde 0 vulnerability. |
| Güncel binary smoke | 31/31 geçti. |
| Docker Compose entegrasyonu | 19/19 geçti; yalnızca bu koşu için oluşturulan Compose projesi kaldırıldı. |
| Container build, SBOM ve Trivy | Geçti; HIGH/CRITICAL bulgu yok. |
| Helm ve Kubernetes schema | Helm 40 valid / 2 skipped; statik K8s 15 valid / 1 skipped; invalid/error yok. |
| Backup/restore smoke | Geçti; bozulmuş arşiv reddedildi, restore 1 saniye; RTO bütçesi 300 saniye. |

Container image kimliği: `sha256:88f385410b1444e427042af304b41756a73e84a7140593c32d036aaa6d893806`, yerel tag `guardianwaf:readiness-20261026`. Bu yerel image kimliği, yayımlanmış ve imzalanmış release digest’i yerine geçmez.

Çıktılar: [.temp_files/production_ready_20261026](../../.temp_files/production_ready_20261026/). Ayrıntılı komutlar ve önce/sonra kayıtları [evidence ledger](../../.temp_files/ledger_project_review_20261026.md) içindedir. Bu dizin Git tarafından dışlanır; release kanıtı olarak kullanılacaksa ayrıca arşivlenmelidir.

## Üretim kullanımının sınırları

- **Uzun süreli cluster log büyümesi çözülmedi.** Mevcut WAL compaction state-machine snapshot ve log prefix truncation yapmıyor. Kalıcı WAL ile restart tarihçeyi yeniden oynatır. Sınırsız büyüyen yazma geçmişi gerektiren cluster dağıtımı için snapshot/truncation/follower transferi ayrı bir uygulama işi olarak kalıyor.
- **Maskeleme tüm yanıt biçimlerinde zorunlu DLP garantisi vermiyor.** 1 MiB üzeri yanıt, streaming flush ve desteklenmeyen encoding passthrough yapabilir. Hassas export/stream uçlarında uygulama seviyesinde redaksiyon gerekir.
- **Algılama kalitesi uygulamaya göre doğrulanmalı.** Küçük benign corpus’un yanlış pozitif oranı gerçek trafik oranı değildir. Endpoint bağlamına göre monitor aşaması ve tuning gerekir.
- **Release dış doğrulaması tamamlanmış sayılmıyor.** Hosted CI, bağımsız güvenlik incelemesi, hedef ortam yük/geri yükleme ölçümleri ve tag-time imza/provenance kayıtları bu yerel testlerin yerine konamaz.

Bu çalışma yerel üretim hazırlığını ilerletir; tüm opsiyonel özellikler ve tüm dağıtım ölçekleri için koşulsuz üretim onayı değildir. Commit, push, tag, deploy veya release publish yapılmadı.
