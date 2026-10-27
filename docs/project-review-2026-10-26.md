# GuardianWAF mevcut durum ve teknik değerlendirme raporu

Tarih: 26 Ekim 2026. İncelenen sürüm dosyası: `0.6.0`. Git başlangıç noktası: `5ddaff6` ve çalışma ağacındaki mevcut değişiklikler.

Güncelleme: Bu incelemedeki F216–F218 kusurları sonraki uygulama turunda giderildi. Güncel değişiklikler, doğrulamalar ve kalan sınırlar [üretim hazırlığı kaydında](production-readiness-2026-10-26.md). Aşağıdaki bulgular ilk incelemenin tarihsel durumunu anlatır.

GuardianWAF, çalışan bir WAF çekirdeğinin çevresinde oldukça geniş bir ürün geliştirmiş durumda. Tespit motoru, reverse proxy, yönetim API’si, panel, sertifika yönetimi, tenant yönetimi ve kümeleme gerçekten kodda mevcut. Temel sorun özellik yokluğu değil; aynı özelliklerin farklı kurulum yollarında farklı davranması ve ürünün bazı vaatlerinin güncel uygulamayla uyuşmaması.

Bu incelemede **üç davranış kusuru çalıştırılarak doğrulandı**. Üçü de kütüphane modunda yapılandırmanın güvenlik katmanlarına eksik aktarılmasıyla ilgili. Ayrıca algılama kalitesi, panelde yapılandırma deneyimi, uzun süre çalışan kümelerin ölçeklenmesi ve test güvenilirliği açısından yapılması gereken işler var. Mevcut kanıtlarla tüm dağıtım biçimleri için koşulsuz bir üretim hazırlığı onayı vermek doğru olmaz. Kontrollü standalone kullanımı için temel daha güçlü; kütüphane modunda aşağıdaki farklar önce giderilmeli.

## İnceleme kapsamı ve kanıtların anlamı

Kapsam, kullanıcının tüm proje talebi doğrultusunda depo genelidir: kök Go API’si, `cmd/guardianwaf`, `internal`, panel ve website paketleri, testler, dağıtım dosyaları, CI ve operasyon belgeleri. Modül envanteri ve genel testler depo çapındadır; ayrıntılı kod takibi özellikle kurucular, katman kurulumu, istek/yanıt işleme, runtime reload ve yaşam döngüsü sınırlarında yapılmıştır. Her satırın bağımsız güvenlik denetiminden geçtiği iddia edilmez.

Başlangıçta 293 değiştirilmiş veya yeni dosyanın içerik özeti alındı; izlenen 172 dosyanın mevcut diff’i 4.642 ekleme ve 1.856 silme içeriyordu. Bu nedenle bulgular yalnızca son commit’in değil, diskteki güncel halin bulgularıdır. Ürün koduna düzeltme uygulanmadı. Rapor, kanıt programları ve test çıktıları oluşturuldu; frontend derlemeleri üretim çıktıları üretti.

Kanıt dizini: [çalıştırma çıktıları](../.temp_files/project_review_20261026/). Başlangıç diff’i, dosya hash’leri ve modül envanteri aynı dizinde tutuluyor. `.temp_files` Git tarafından dışlandığı için rapor paylaşılırken kanıt dizini ayrıca arşivlenmeli.

Bulgular üç sınıfta sunuluyor: çalıştırılarak doğrulanmış kusurlar; kodda açıkça görülen destek sınırları; mimari değerlendirme ve öneriler. Birbirinin yerine kullanılmıyorlar.

## Projenin büyüklüğü ve mimarisi

`internal` altında, frontend bağımlılıkları hariç, **205 Go kaynak dosyası, 778 Go test dosyası ve 77.809 kaynak satırı** bulunuyor. CLI tarafı 41 kaynak ve 56 test dosyası; kök public API tarafı 2 kaynak ve 9 test dosyası içeriyor. Test sayısı burada dosya sayısıdır; test vakası sayısı değildir. Satır sayısı yorumları ve üretilmiş kodu da içerir.

Backend modülü Go `1.26.10` kullanıyor; `go.mod` içinde dış bağımlılık yok. Panel React, TypeScript, Vite ve Vitest kullanıyor. Website ayrı bir frontend paketi; `tools/deepcopy` ayrı Go modülü. Bu ayrım önemlidir: kökten `go test ./...` çalıştırmak nested modülün testlerini çalıştırmaz; deepcopy testleri ayrıca çalıştırıldı.

İşleyişin ana yolu şu:

1. CLI yapılandırmayı yükler ve doğrular; motoru, katmanları ve runtime servislerini kurar.
2. Motor istek gövdesini sınırlar, istemci IP’sini ve tenant bağlamını çıkarır.
3. Sıralı katmanlar bulgu ve skor üretir; motor enforce/monitor/disabled davranışını uygular.
4. İzin verilen istek proxy/router üzerinden backend’e gider.
5. Yanıt dönüşümleri ve sonuç kancaları uygulanır; olaylar saklama, panel, alarm ve diğer tüketicilere iletilir.

Standalone registry’deki 16 katmanın sırası: IP ACL → Threat Intel → CORS → Custom Rules → Rate Limit → ATO → API Security → API Validation → Sanitizer → CRS → Detection → Virtual Patch → DLP → Bot Detection → Client Side → Response. Custom Rules sırası kodda **155**; bazı belgelerde hâlâ 150 yazıyor. Challenge ayrı bir servis olarak bağlanıyor. WebSocket, SIEM, cluster ve tracing de registry tablosunun dışında bağlanan runtime bileşenleri; bunların tabloda görünmemesi uygulanmadıkları anlamına gelmiyor.

Kaynak: [registry](../internal/runtime/layerregistry/registry.go), [CLI katman kurulumu](../cmd/guardianwaf/layers.go), [motor](../internal/engine/engine.go), [pipeline](../internal/engine/pipeline.go).

## Modüllerin durumu

Tablodaki kapsam oranları ilk `-race -cover` koşusundaki statement coverage değerleridir. Yüksek oran, özellikle kurulum yollarının birbirine eşit olduğunu kanıtlamaz; bu incelemenin üç kusuru da bunun örneği.

| Modül | Gerçekte yapılmış olan | Değerlendirme ve kalan iş |
|---|---|---|
| Public Go API | `New`, `NewFromFile`, middleware, `Check`, event callback, istatistik ve cleanup | Kurucu/katman eşitliği bozuk. Programatik kurucu 6 dedektörle kalıyor; YAML kurucusu bazı açık güvenlik ayarlarını uygulamıyor. İlk düzeltme alanı. |
| CLI ve runtime | Serve/sidecar, başlangıç kapıları, ayrı runtime dosyaları, kaynak kapatma ve hata toplama | Kapsam %84,5. Ürün montaj noktası olduğu için bileşen testlerine ek olarak modlar arası sözleşme testleri gerekli. |
| Config | Özel YAML parser, varsayılanlar, env, doğrulama, serileştirme, placeholder koruma, üretilmiş deep copy | Kapsam %94,8. Geniş ve kritik bir altyapı. Parser/validator/builder arasında aynı alanın birkaç yerde elle eşlenmesi bakım yükü ve kanıtlanmış hata kaynağı. |
| Engine ve pipeline | Context pool, skor birikimi, monoton aksiyon yükseltme, monitor davranışı, response hook’ları | Kapsam %94,7. Temel tasarım güçlü. Katman sırası, context sahipliği ve response hook bileşimleri korunmalı. |
| IP ACL | CIDR/radix eşleştirme, izin/engelleme listeleri, süreli ban ve persistence | Kapsam %97,8. Standalone builder daha fazla alan aktarıyor; library builder’da `MaxAutoBanEntries`, `PersistPath`, `PersistInterval` aktarımı da eşitlik kontrolüne alınmalı. Bunlar bu raporda ayrıca çalıştırılmış kusur sayılmadı. |
| Rate limit | Token bucket, kural kapsamları, auto-ban ve cluster store bağlantıları | Kapsam %99,0. Global/tenant/cluster davranışlarının ayrı kabul testleri gerekli; yüksek birim kapsamı dağıtık tutarlılığı tek başına göstermez. |
| Threat intelligence | Feed indirme, IP/domain kontrolleri, cache ve periyodik yenileme | Kapsam %98,9. Feed kesintisi, eski veri ve koruma durumu operasyon ekranlarında anlaşılır kalmalı. |
| CORS | Origin/policy kontrolleri ve preflight cache | Kapsam %91,8. Cache-policy eşitliği için regresyonlar var; panelden politika değiştirme sınırı runtime sözleşmesiyle uyumlu sunulmalı. |
| Custom rules | Koşul/aksiyon motoru, regex, GeoIP entegrasyonu, yönetim API’si | Kapsam %94,1. Kullanılabilir. Yol normalizasyonu ve aynı kuralın tenant/cluster kopyalarındaki davranışı kritik. |
| ATO | Login takibi, brute force, credential stuffing ve password spray mantığı | Kapsam %94,8. Backend sonucunu kullanan hook’lar mevcut. Gerçek login biçimleri ve başarı/başarısızlık sinyalleri uygulama bazında doğrulanmalı. |
| API security | JWT, JWKS, API key ve yol kapsamı doğrulaması | Kapsam %95,7. Standalone’da gerçek katman. Kütüphanede YAML ile etkinleştirildiğinde hiç bağlanmaması F217. |
| API validation | Schema yükleme/derleme, OpenAPI rotaları, request/response doğrulama, örnek istek testi | Kapsam %95,5. Gerçek implementasyon var. Özel parser ve validator’un desteklediği OpenAPI/JSON Schema alt kümesi açık bir uyumluluk tablosuyla yayımlanmalı. |
| Sanitizer | URL/header/body/cookie sınırları, normalizasyon, yol bazlı body limitleri | Kapsam %99,4. Standalone aktarımı doğru; library aktarımında yol limitleri eksik, F218. `normalize_encoding` eşlemesi de builder eşitliği kapsamına alınmalı. |
| Detection | SQLi, XSS, LFI, CMDi, XXE, SSRF, SSTI, NoSQLi, smuggling, open redirect, GraphQL | Detection katmanı %98,8. Çalışıyor; programatik API’de son beş dedektör yok. Kalite kapısı saldırıların engellenmesini değil pozitif skor üretmesini ölçüyor. |
| CRS | Kural parser’ı, operatörler, dönüşümler, değişkenler ve hariç tutma | Kapsam %95,3. Implementasyon mevcut. “CRS desteği” ifadesi tam ModSecurity uyumluluğu olarak sunulmamalı; destek matrisi ve upstream karşılaştırma testleri gerekli. |
| Bot detection ve challenge | UA/davranış/fingerprint sinyalleri, SHA-256 PoW, cookie doğrulama | Bot modülü %99,0; challenge %91,8. Başlangıç moduna ve TLS görünürlüğüne bağlı çalışıyor; salt test kapsamı gerçek bot ayırt etme kalitesini göstermez. |
| Virtual patch | NVD veri alma, açıklamadan aday kural üretme, manuel yamalar ve inceleme durumları | Kapsam %95,8. Otomatik üretilen kurallar `pending_review`, `Enabled=false` başlıyor; bu yerinde. CVE açıklamasından pattern çıkarmak CVE’ye özgü güvenilir exploit engelleme kanıtı değildir. |
| DLP | Request/response tarama, pattern registry, masking, multipart ve dosya kontrolleri | Kapsam %97,6. Yanıt koruması motorun capture sınırlarına bağlı. Tüm boyut ve stream türlerinde eksiksiz veri sızıntısı önleme olarak değerlendirilmemeli. |
| Client side | Yanıt dönüştürme, agent injection ve şüpheli script örüntüleri | Kapsam %98,1. Gerçek kod var; tarayıcıda tam davranış analizi veya kapsamlı client-side güvenlik platformu anlamına gelmiyor. Büyük/stream yanıt sınırlarını devralıyor. |
| Response | Güvenlik başlıkları, kart/SSN/API key maskeleme, hata sayfaları | Katman %99,3. Motor wrapper’ı 1 MiB üzeri yanıtı ve streaming’i maskesiz geçiriyor; aşağıda doğrulanan destek sınırı var. |
| WebSocket | Upgrade kontrolü, frame/message sınırları ve payload inceleme entegrasyonu | Kapsam %79,5; kritik protokol modülleri içinde geliştirme alanı. Fragmentation, control frame, kapatma ve backpressure için canlı protokol testleri değerli. Binary payload tam içerik taraması kapsamına girmiyor. |
| Proxy | Router, dört dengeleme stratejisi, health check, circuit breaker, retry/failover ve transport cleanup | Kapsam %98,9. Sağlam regresyon yatırımı var. İptal, yarı açık devre, non-idempotent retry ve body replay testleri korunmalı. |
| TLS ve ACME | Sertifika store, SNI/reload, OCSP, HTTP-01, yenileme ve sertifika yayımlama | TLS %90,3; ACME %95,2. Gerçek servisler. Bu turda canlı CA, gerçek DNS veya sertifika otoritesi entegrasyonu çalıştırılmadı. |
| Events | Bellek ve JSONL store, replay, snapshot sahipliği, bus ve drop sayaçları | Kapsam %94,9. Bounded queue ve gözlenebilir drop yaklaşımı doğru. Teslim garantileri depolama/abonelik tipine göre açık tutulmalı. |
| Dashboard backend | Auth/session, yönetim ayrımı, REST, SSE, yapılandırma persistence ve audit | Kapsam %84,2. Geniş yüzey; anında uygulanan alanlarla restart isteyen alanların API/UI sözleşmesi ayrıştırılmalı. |
| Dashboard frontend | Konfigürasyon, olaylar, routing graph, tenant, AI, cluster ve compliance ekranları | 19 test dosyasında 114 test geçti; build/lint geçti. Tam browser/API E2E bu turda çalıştırılmadı. Editlenebilir form alanlarının hepsi runtime’da uygulanabilir değil. |
| Tenant | Domain/API key çözümleme, quota, usage, billing/rule/alert yönetimi ve persistence | İlk kapsamlı koşu 180 saniyede zaman aşımına uğradı; genişletilmiş ayrı koşu sonucu doğrulama bölümünde. Tenant sınırları sadece engine katmanlarıyla değil yönetim API’leri ve depolamayla birlikte sınanmalı. |
| Cluster ve clustersync | Gossip, sabit Raft voter seti, peer bridge, HMAC doğrulama, WAL, store ve yönetim entegrasyonu | Raft %88,8, gossip %90,1, sync %86,2. Aktif implementasyon. Uzun ömürlü log büyümesi ve gerçek state-machine snapshot/truncation eksikliği üretim ölçeği açısından önemli. |
| AI | Batch analiz, provider client/catalog, bütçeler, geçmiş ve kontrollü IP ban uygulama | Kapsam %92,9. Request yolundan ayrılması doğru. Dış provider ile canlı doğrulama yapılmadı; model kararı koruma garantisi olarak sunulmamalı. |
| Alerting ve SIEM | Webhook/SMTP, eşzamanlılık sınırı, timeout’lar, CEF/JSON TLS syslog | Alerting %89,3; SIEM %89,4. Genel koşuda SMTP testinde sıralama problemi görüldü; ayrı paket koşusu geçti. |
| Docker discovery | Docker client, label parsing, watcher ve routing rebuild | Kapsam %96,2. Socket/label güven sınırı geniş yetki taşır. Bu turda gerçek daemon/container değişim senaryosu çalıştırılmadı. |
| GeoIP | CIDR/country verisi, yükleme ve yenileme | Kapsam %89,0. Veri hazır olmaması ile gerçek ülke kararı ürün seviyesinde ayırt edilmeli. |
| MCP | JSON-RPC, stdio/SSE, yönetim araçları ve audit bağlamı | Kapsam %97,3. Gerçek yönetim yüzeyi. CLI/API/MCP değişikliklerinin aynı persistence ve yetki sözleşmesine uyması gerekir. |
| Tracing | Span, sampling, parent/child ilişkisi ve exporter arayüzü | Kapsam %86,1. Dahili exporter seçenekleri `stdout` ve `noop`; hazır OTLP collector entegrasyonu yok. OpenTelemetry terimleri kullanması eksiksiz OTel protokol desteği demek değil. |
| Compliance | Kontrol eşleme, metrik değerlendirme, rapor ve hash zinciri | Kapsam %100. Teknik kontrol raporlaması var; bu çıktı kuruluşun mevzuat veya standart sertifikasyonu olarak değerlendirilmemeli. |
| Dağıtım ve CI | Docker, Compose, K8s, Helm, smoke, fuzz, lint, supply-chain ve release evidence araçları | Geniş otomasyon mevcut. Bu turda render/schema kontrolleri geçti; hosted CI, container build/scan ve cluster chaos çalıştırılmadı. |
| Website ve araçlar | Ayrı tanıtım sitesi, kurulum/güncelleme scriptleri, deepcopy generator | Website build/lint ve generator testleri ayrıca kontrol edildi. Website, README, ADR ve runtime belgelerinin tek güncel yetenek matrisi etrafında hizalanması gerekiyor. |

## Çalıştırılarak doğrulanan kusurlar

### F217 YAML ile etkinleştirilen API kimlik doğrulaması kütüphanede uygulanmıyor

**Öncelik: P1. Etki: yüksek; koşul, uygulamanın kimlik doğrulamayı WAF’a devretmiş olması.** Backend kendi kimlik doğrulamasını yapıyorsa onun ayrıca aşılmış olduğu iddia edilmiyor.

`NewFromFile`, `waf.api_security.enabled=true` ve API key doğrulaması açık bir dosyayı hatasız kabul ediyor. Ancak [addDefaultLayers](../guardianwaf.go) yalnızca altı temel katmanı kuruyor; API security katmanını kurmuyor.

Kontrol: aynı yapılandırmadan standalone registry ile oluşturulan API security katmanı, anahtarsız `/private` isteğini `block` olarak değerlendirdi. Kütüphane middleware’ine aynı anahtarsız istek gönderildiğinde backend’e ulaşıldı ve **204** döndü.

Beklenen davranış: API security uygulanmalı veya kurucu, desteklemediği açık güvenlik yapılandırmasını anlaşılır bir hatayla reddetmeli. Sessiz kabul, yapılandırmaya güvenen kullanıcıya gerçekte olmayan koruma gösteriyor.

Kanıt: [program](../.temp_files/prove_F217_library_ignored_api_auth.go), [çıktı](../.temp_files/project_review_20261026/F217.log). Komut: `go run .temp_files/prove_F217_library_ignored_api_auth.go`; sonuç `PROBLEM CONFIRMED`, exit 1.

Çözüm: kurulum yollarını ortak builder’a taşıyın veya library için açık destek matrisiyle başlangıç doğrulaması ekleyin. Aynı kontrol, YAML’da etkinleştirilip library tarafından bağlanmayan diğer güvenlik katmanlarına da uygulanmalı. Bu turda diğerlerinin her biri için ayrı bypass kanıtı üretilmedi.

### F218 Kütüphane modunda yola özel body limitleri kayboluyor

**Öncelik: P1. Etki: orta; yapılandırılmış endpoint limitinin uygulanmaması.** Global body sınırı varlığını koruyor; sınırsız okuma veya uzaktan kaynak tüketimi saldırısı kanıtlandığı söylenmiyor.

Yapılandırmada global `max_body_size: 1024`, `/admin` için `path_overrides.max_body_size: 8` kullanıldı. 64 baytlık temiz POST gönderildi.

| İstek | Standalone registry ile motor | Kütüphane `NewFromFile` |
|---|---:|---:|
| `/public`, 64 bayt | 204 | 204 |
| `/admin`, 64 bayt | **413** | **204** |

Neden: [library sanitizer kurulumu](../guardianwaf.go) `PathOverrides` alanını aktarmıyor; [standalone builder](../internal/runtime/layerregistry/registry.go) aktarıyor. İlgili katmanın kendi testleri ve %99,4 kapsamı bu montaj farkını yakalamıyor.

Kanıt: [program](../.temp_files/prove_F218_library_path_body_limit.go), [çıktı](../.temp_files/project_review_20261026/F218.log). Komut: `go run .temp_files/prove_F218_library_path_body_limit.go`; sonuç `PROBLEM CONFIRMED`, exit 1.

Çözüm: aynı sanitizer builder’ını kullanın; küçük/büyük yol limitlerini, sınırda eşit gövdeyi ve normalizasyon açık/kapalı durumlarını her kurucudan geçirerek doğrulayın.

### F216 Programatik kurucu beş dedektörü dışarıda bırakıyor

**Öncelik: P1. Etki: yüksek koruma kapsamı farkı; her örneğin her uygulamada exploit olduğu iddia edilmiyor.**

[convertConfig](../guardianwaf.go), varsayılan yapılandırmanın 11 dedektörlü map’ini altı elemanlı map ile değiştiriyor: SQLi, XSS, LFI, CMDi, XXE ve SSRF. SSTI, NoSQLi, smuggling, open redirect ve GraphQL eklenmiyor. Public `DetectionConfig` de yalnızca eski altı dedektörü modelliyor. YAML’dan oluşturulan motor ise varsayılan 11 dedektörü koruyor.

İlk kanıtta SQLi kontrolü iki kurucuda da `block/85`; `{{7*7}}` için YAML kurucusunda `ssti` bulgusu varken programatik kurucuda yok. Bu örnek programatik tarafta XSS tarafından da engellendiği için buradan “tamamen geçti” sonucu çıkarılmamalı.

Ek davranış karşılaştırması farkın sonucunu gösterdi:

| Query değeri | `New(Config{})` | YAML kurucusu |
|---|---|---|
| `__class__.__mro__` | **pass / 0** | **block / 170** |
| `$where` | **pass / 0** | **block / 90** |
| `<#assign x=7*7>` | log / 45 | block / 115 |

Kanıt: [program](../.temp_files/prove_F216_library_detector_parity.go), [çıktı](../.temp_files/project_review_20261026/F216.log), [ek karşılaştırma](../.temp_files/project_review_20261026/library-payloads.log). Ana komut `go run .temp_files/prove_F216_library_detector_parity.go`; sonuç `PROBLEM CONFIRMED`, exit 1.

Çözüm: varsayılan map’i koruyup yalnızca kullanıcının override ettiği değerleri güncelleyin. Public API’nin desteklediği dedektörleri güncelleyin. Programatik/YAML kurucularının her dedektörde aynı varsayılan yeteneğe sahip olduğunu doğrulayan testler ekleyin.

## Destek sınırları ve eksik implementasyonlar

### Büyük ve stream yanıtlar eksiksiz maskelenmiyor

[maskingResponseWriter](../internal/engine/response_writer.go), `maxMaskingBufferSize = 1 << 20` sınırı aşıldığında biriktirdiği veriyi maskesiz yazar ve passthrough’a geçer. `Flush` da streaming için maskesiz geçiş yapar. Desteklenmeyen content encoding’ler ayrıca capture dışında kalır. Bu mevcut tasarım davranışıdır; yeni keşfedilmiş belirsiz bir bypass varsayımı değildir.

Public middleware ile yapılan kontrolde 100 bayt dolgu içeren yanıttaki test kartı gizlendi; 1.048.600 bayt dolgu içeren yanıtta **aynı kart açık kaldı**, iki yanıt da 200 döndü. [Kontrol çıktısı](../.temp_files/project_review_20261026/masking-boundary.log).

Yapılması gereken: hangi boyut/encoding/stream türlerinde maskeleme uygulanmadığını belgeleyin ve ölçülebilir kılın. DLP bir dağıtımın zorunlu veri çıkış politikasıysa, limit aşımında geçir/engelle seçimini açık bir policy’ye bağlayın. Streaming masking ayrı algoritma ve protokol tasarımı gerektirir; yalnızca buffer’ı büyütmek çözüm değildir.

### Cluster snapshot yaklaşımı uzun ömürlü logu sınırlamıyor

[PersistentState.Snapshot](../internal/cluster/raft/state.go) bütün log girdilerini tek WAL kaydında yeniden yazar. Bu, tekrar eden WAL kayıtlarını toplar; uygulanmış tarihçeyi state-machine snapshot’a dönüştürüp logun eski prefix’ini atmaz. [LogStore](../internal/cluster/raft/log.go) da indeksleri bellekteki tüm entries üzerinden tutuyor. [Cluster belgesi](clustering.md) hâlâ “snapshot yok” diyor; gerçekte WAL snapshot var, fakat uzun ömürlü logu sınırlayan mekanizma eksik.

Sonuç: düğüm ömrü boyunca komut geçmişi büyümesini sınırlandıran bir tasarım bu koddan çıkmıyor. Restart önerisi de WAL persistence açıkken tarihçenin replay edilmesiyle birlikte değerlendirilmelidir. Bu turda uzun süreli kaynak tüketimi veya 32 MiB snapshot sınırında hizmet kesintisi çalıştırılarak kanıtlanmadı; bunlar takip incelemesidir.

Yapılması gereken: state-machine snapshot, last-included index/term, log prefix truncation, snapshot transferi ve geride kalan follower kurtarma sözleşmesini birlikte tasarlayın. Üç düğümlü partition/restart/disk hata testleriyle doğrulayın.

### Dashboard TLS eksik ama güvenli biçimde reddediliyor

`dashboard.tls=true`, [validator](../internal/config/validate.go) ve [runtime](../cmd/guardianwaf/dashboard_runtime.go) tarafından desteklenmediği açıklanarak reddediliyor. Bu alanın bulunması yerleşik dashboard TLS’in uygulanmış olduğu anlamına gelmiyor. Ingress/reverse proxy ile TLS sonlandırma mevcut dağıtım yoludur. Burada sessiz HTTP downgrade bulunduğu iddia edilmiyor.

### Tracing exporter kapsamı dar

[Tracing](../internal/tracing/tracing.go) API’si mevcut; hazır config seçenekleri `stdout` ve `noop`. OTLP gönderimi için hazır exporter bulunmuyor. Ürün iddiası buna göre dar tutulmalı veya gerçek collector entegrasyonu eklenmeli.

### Özel protokol ve parser implementasyonlarının uyumluluk sınırları belgelenmeli

YAML, OpenAPI/JSON Schema, CRS, ACME/OCSP ve Raft kritik format/protokolleri projenin kendi koduyla uygulanıyor. Kodun varlığı, tüm standardın desteklendiğini göstermiyor. Desteklenen anahtarlar, reddedilen özellikler ve sınır davranışları test edilebilir bir matrise dönüştürülmeli. Bu rapor her birinin standartlara tam uyumluluk denetimi değildir.

## Algılama kalitesi

Mevcut corpus testi yeniden çalıştırıldı ve geçti. Fakat bu başarı doğru yorumlanmalı: saldırı örneği, `Score > 0` ve bir finding varsa “detected” sayılıyor. Bu metrik **varsayılan eşikte engelleme oranı değildir**. Ayrıca test katmanı bütün dedektörlerle çalıştırıyor; kategori oranı, yalnızca adı verilen dedektörün başarı oranı olarak okunmamalı.

| Saldırı corpus’u | Pozitif bulgu üretilen örnek | Oran |
|---|---:|---:|
| SQLi | 96 / 105 | %91,4 |
| XSS | 71 / 72 | %98,6 |
| LFI | 52 / 55 | %94,5 |
| CMDi | 46 / 49 | %93,9 |
| SSRF | 39 / 39 | %100 |
| XXE | 27 / 27 | %100 |
| SSTI | 24 / 25 | %96,0 |
| NoSQLi | 26 / 26 | %100 |
| Open redirect | 28 / 28 | %100 |
| GraphQL | 20 / 20 | %100 |

Benign corpus’ta **8/211, %3,8** örnek varsayılan block skoruna ulaştı. Bunlar gerçek trafik oranına genellenemez; küçük, seçilmiş bir corpus’un sonucudur. Buna rağmen meşru Windows dosya yolu, localhost URL’si ve MongoDB dokümanından `$where` içeren log satırı gibi kullanım biçimlerinin yanlış pozitif üretebildiğini gösteriyor. Testin izin verdiği üst sınır %6.

Kaynak: [test](../internal/layers/detection/detection_test.go), [çıktı](../.temp_files/project_review_20261026/corpus.log). Mevcut [kalite belgesi](detection-quality.md) bazı eski sayıları taşıyor: örneğin SQLi 95/105, SSTI 22/23, birleşik benign 9/211. Güncellenmeli.

Yapılması gerekenler:

- “Herhangi bir bulgu”, “block eşiğine ulaşma”, “hedef dedektör bulgusu” ve “gerçek HTTP isteğinde backend’e geçiş” ölçümlerini ayrı tutun.
- Benign corpus’u endpoint bağlamına göre büyütün: arama, doküman, log yükleme, URL preview, dosya yolu ve JSON filtreleri aynı policy gerektirmiyor.
- Kurucuların ve dağıtım modlarının aynı corpus üzerinde ayrı sonuçlarını kaydedin.
- Yeni detector sayısı eklemekten önce yanlış pozitiflerin ürün etkisini düşürün; yalnızca global eşiği yükseltmek saldırı kaçırmayı artırabilir.

## Panel ve dokümantasyon arasındaki tutarsızlıklar

README panel bölümünde dedektör toggle’ları, multiplier, bot/rate-limit/sanitizer/response ayarlarının runtime’da uygulanıp kaydedildiği belirtiliyor. Gerçekte [validateRuntimeReloadableConfig](../internal/dashboard/config_handlers.go), katman topolojisi değişikliklerini ve çoğu katman ayarını reddediyor. [Runtime reload belgesi](runtime-reload.md) bu sınırlamayı doğru açıklıyor. Panelde ise [config formu](../internal/dashboard/ui/src/pages/config.tsx) çok sayıda bu tür alanı düzenletiyor ve ortak Save akışını kullanıyor.

Bu, güvenli bir backend reddinin üstüne kurulmuş eksik ürün deneyimi. Kullanıcı ayarı değiştirebileceğini düşünüp formu dolduruyor, sonunda genel bir restart hatası alıyor. İki tutarlı çözüm var: desteklenmeyen alanları açıkça restart gerektiriyor olarak göstermek veya “şimdi uygula” ve “diske kaydet, restart sonrası uygula” işlemlerini ayrı sözleşmelerle sunmak. İkinci seçenek ayrı pending-config tasarımı gerektirir.

Diğer somut belge sapmaları:

- `scripts/check-prereqs.sh` ve README Node `20.19.0+` kabul ediyor. Lockfile’daki `react-router@8.3.0` Node `>=22.22.0`, `jsdom@30.0.1` ise `^22.22.2 || ^24.15.0 || >=26.0.0` istiyor. Ön kontrolün kabul ettiği her Node sürümü kurulu bağımlılıkların destek aralığında değil. Docker Node 24.15.0 kullanarak doğru aralığa geçmiş.
- CONTRIBUTING hâlâ “stdlib + quic-go” ve Vite 6 / ESLint 9 diyor. Backend’de quic-go bağımlılığı yok; panel package.json Vite 8 / ESLint 10 kullanıyor.
- README circuit breaker’ı lock-free olarak tarif ediyor; güncel [CircuitBreaker](../internal/proxy/circuit.go) geçişleri mutex ile seri hale getiriyor. Bu bir performans kusuru kanıtı değildir; açıklamanın kodla uyuşmamasıdır.
- CLAUDE.md, kütüphanede daha fazla katman için internal engine’e erişilip `AddLayer` çağrılmasını öneriyor. Public `Engine` içindeki motor alanı dışarı açılmıyor; dış uygulamalar Go `internal` paketlerini doğrudan import edemez. Öneri mevcut public API ile uygulanabilir değil.
- Eski production-readiness raporu temiz çalışma ağacı ve o tarihteki başarılı kontrolleri anlatıyor. Bugünkü 293 dosyalık değişiklik setine otomatik kanıt sayılmamalı.
- ADR ve roadmap dosyalarında kaldırılmış modüller hâlâ tasarım olarak listeleniyor. Tarihçe ile aktif yetenekler ayrı başlıklarda ve açık durum etiketleriyle gösterilmeli.

## Test ve doğrulama sonuçları

Bu ortamda Go `1.26.10`, Node `24.15.0`, npm `12.0.2` gözlendi. Yeni framework veya bağımlılık kurulmadı.

| Kontrol | Komut | Sonuç |
|---|---|---|
| Genel Go testleri, race ve coverage | `go test -race -count=1 -coverprofile=.temp_files/project_review_20261026/coverage.out -covermode=atomic -timeout=180s ./...` | **Exit 1**. 59 paket geçti; alerting assertion başarısızlığı ve tenant paketinde 180 sn timeout var. |
| SMTP tek test tekrar | `go test -race -count=3 -run '^TestEmailCompliantDeliveryStillWorks$' -v ./internal/alerting` | Geçti; 3/3. |
| Alerting paket tekrar | `go test -race -count=1 -timeout=180s ./internal/alerting` | Geçti; 27,158 sn. |
| Tenant paket tekrar | `go test -race -count=1 -timeout=10m ./internal/tenant` | Geçti; 288,575 sn. |
| Go vet | `go vet ./...` | Geçti. |
| Go lint | `golangci-lint run ./...` | Geçti; 0 issue. |
| Go binary build | `go build -trimpath -o .temp_files/project_review_20261026/guardianwaf ./cmd/guardianwaf` | Geçti. Mevcut embedded dashboard asset’lerini kullandı. |
| Format | `./scripts/check-gofmt.sh` | Geçti. |
| Diff whitespace | `git diff --check` | Geçti. |
| Panel unit test | Panel dizininde `npm test` | 19 dosya, 114 test geçti. |
| Panel lint | Panel dizininde `npm run lint` | Geçti. |
| Panel TypeScript ve build | Panel dizininde `npm run build` | Geçti. |
| Website TypeScript ve build | Website dizininde `npm run build` | Geçti. |
| Website lint | Website dizininde `npm run lint` | Geçti. |
| Deepcopy ayrı modül | `tools/deepcopy` içinde `go test -count=1 ./...` | Geçti; 15,014 sn. |
| Detection corpus | `go test -count=1 -v ./internal/layers/detection -run '^TestDetectionLayer_CorpusQualityBaseline$'` | Geçti; yukarıdaki oranlar üretildi. |
| Binary smoke | `bash scripts/smoke-test.sh .temp_files/project_review_20261026/guardianwaf` | 31/31 geçti. Serve/sidecar, health, auth ve temel SQLi kontrolleri dahil. |
| Kubernetes schema | `./scripts/validate-k8s.sh` | 16 resource: 15 valid, 1 skipped, 0 invalid/error. |
| Helm lint/render/schema | `./scripts/validate-helm.sh` | Lint geçti. 42 resource: 40 valid, 2 skipped, 0 invalid/error. |

Genel test çıktısında `WARNING: DATA RACE` görülmedi. Bunun anlamı bu çalıştırmada detector’ın yarış raporlamadığıdır; özellikle timeout yaşayan tenant için tam race başarısı iddiası değildir. Başarısız/kısmi koşudan çıkan toplam coverage yüzdesi tamamlanmış proje ölçümü gibi kullanılmamalı.

SMTP başarısızlığında test sunucusu `221 Bye` yanıtını yazdıktan sonra `served.Add(1)` yapıyor. İstemci goroutine’i yanıtı alıp döndüğünde sayaç henüz artmamış olabilir. Bu, görülen assertion ile uyumlu somut bir senkronizasyon kusuru; tek test ve paket tekrarlarının geçmesi de bunu destekliyor. Üretimde mail tesliminin bozuk olduğu sonucu çıkarılmıyor. Test bir completion channel/barrier üzerinden sunucunun işlemi tamamlamasını beklemeli.

Tenant timeout’unda paket o ana kadar CPU ağırlıklı anahtar türetme testleri de çalıştırıyor; timeout dökümü tek başına deadlock kanıtı değil. Daha geniş süreli ayrı koşu 288,575 saniyede geçti. İlk koşu tümüyle başarılı sayılmıyor; alerting ve tenant tekrarları ayrı kanıtlardır.

**NOT RUN:** Tam Playwright Chromium/Firefox/WebKit suite, bounded fuzz turu, canlı Docker discovery/Compose entegrasyonu, container image build, SBOM/vulnerability scan, hosted GitHub Actions, KinD dağıtımı, canlı ACME/JWKS/AI/SIEM entegrasyonu, hedef ortam yük testi ve bağımsız penetrasyon testi. Bu tur genel durum, yerel test tabanı ve kurulum davranışları incelemesidir; bu kontrollerin önceki belgelerde geçmiş olması güncel çalışma ağacı için yeniden çalıştırıldıkları anlamına gelmez.

## Doğru yapılmış olanlar

- Katmanlı motor, puanlama ve ayrılmış runtime dosyaları sorumlulukları büyük ölçüde görünür kılıyor.
- Enforce/monitor/disabled ayrımı kodda ele alınmış; monitor için yan etki engelleme regresyonlarına yatırım yapılmış.
- Standalone başlangıç, etkin güvenlik katmanı kurulamadığında varsayılan olarak duruyor. Eksik korumayla devam etmek açık bir degraded-start tercihi gerektiriyor.
- Router değişimini hazırlama/persist/swap olarak ele alan yaklaşım ve eski transport/health-check kaynaklarını kapatma çalışması yerinde.
- Context/event/config sahipliği, stale callback, iptal ve kapanış sırası için çok sayıda anlamlı regresyon testi var.
- Kuyruk, abonelik ve dispatch sınırları ile drop sayaçları düşünülmüş. Üretimde bunların alarm eşikleriyle kullanılması gerekiyor.
- Oluşturulan virtual patch’lerin otomatik aktifleşmemesi iyi bir güvenlik tercihi.
- CI yalnızca testten ibaret değil; manifest, fuzz, benchmark, supply-chain ve release evidence yüzeylerini de kapsıyor.

## Fazla karmaşıklık ve teknik borç

En önemli fazlalık tek bir dosya veya atıl özellik değil, **aynı semantiğin birden fazla yerde elle kurulması**. Registry, library builder, public config conversion, YAML loader, validator, dashboard patch ve MCP adaptörü ayrı eşleme noktaları. Yeni alan eklendiğinde hepsinin güncellenmesi gerekiyor; F216–F218 bunun pratik sonucu.

Sıfır dış Go bağımlılığı dağıtımı kolaylaştırıyor. Ancak YAML parser, OpenAPI validator, CRS uyarlaması, ACME/OCSP, tracing ve Raft’ı aynı ekip bakımına bırakıyor. Bu kararın maliyeti bağımlılık sayısıyla değil; standart uyumluluğu, hata düzeltme süresi ve operasyon kanıtıyla ölçülmeli. Hemen toplu yeniden yazım önerilmiyor. Önce doğrulanmış sözleşmeler ve uyumluluk matrisi oluşturulmalı; sonra en pahalı bileşenler için sınırları belirli karar alınmalı.

Config tarafında 2.022 satırlık defaults, 1.866 satırlık validator ve 1.322 satırlık YAML kodu; tenant manager’da 1.399 satır; dashboard ve CLI’de geniş adaptör yüzeyi bulunuyor. Üretilmiş deepcopy kodunun uzunluğu tek başına kusur değil. Asıl sadeleştirme fırsatı, alanların ve lifecycle sahipliğinin tekrarını azaltmak.

Eski hata hikâyesini uzun uzun anlatan yorumlar bazı sıcak dosyaları büyütüyor. Korunması gereken invariant ve regresyon testi bağlantısı kodda kalmalı; uzun audit anlatımları ledger/history’ye taşınabilir. Bu bir stil önerisidir, çalıştırılarak kanıtlanmış davranış kusuru değildir.

## Ne yapılmalıydı ve şimdi ne yapılmalı

| Alan | Baştan kurulması gereken sözleşme | Şimdiki eylem |
|---|---|---|
| Dağıtım modları | Her modda hangi katman ve ayarın desteklendiği | `New`, `NewFromFile`, serve ve sidecar için otomatik yetenek matrisi; desteklenmeyen açık güvenlik ayarına başlangıç hatası. |
| Builder’lar | Her config alanının tek yerde runtime bileşenine çevrilmesi | Ortak katman kurulumunu kullanın; mod farklarını veri olarak tanımlayın. |
| Yapılandırma paneli | Live, restart ve desteklenmeyen alanların ayrımı | Alan durumlarını API’den verin; UI’da kaydetme davranışını buna bağlayın. |
| Detection kalitesi | Alarm, engelleme ve yanlış pozitifin ayrı ölçülmesi | Corpus raporunu metriklere ayırın ve gerçek uygulama bağlamlarıyla büyütün. |
| Protokol desteği | Desteklenen alt kümenin açık ilanı | CRS/OpenAPI/YAML uyumluluk matrisi ve diferansiyel testler. |
| Cluster | Kalıcılık, yeniden katılma ve log büyümesi sınırları | Gerçek state snapshot/truncation tasarımı ve üç düğümlü failure testleri. |
| Yanıt güvenliği | Büyük/stream/encoded yanıtın policy’si | Masking kapsamını görünür yapın; zorunlu DLP için açık limit-aşımı davranışı. |
| Release kanıtı | Tam olarak hangi commit ve asset’in sınandığı | Kirli ağacın kontrolünü, gömülü panel asset kimliğini ve aynı binary ile E2E sonuçlarını release kaydına bağlayın. |

### İlk öncelik doğrulanmış koruma farkları

F217 ve F218’i, ardından F216’yı giderin. Her bulgu için orijinal kanıtı değiştirmeden yeniden çalıştırın; düzeltilmiş davranışı iki yakın sınır vakasıyla doğrulayın ve permanent regression ekleyin. Bu raporda düzeltme yapılmadığı için hiçbiri “çözüldü” olarak işaretlenmiyor.

Aynı çalışma içinde library/standalone sanitizer, IP ACL, response ve detector eşlemelerini alan bazında karşılaştırın. Bir alandaki düzeltmeyi, benzer bütün alanların düzeldiğine kanıt saymayın.

### İkinci öncelik ürün sözleşmesi ve test kararlılığı

Panelin restart gerektiren alanlarını düzeltin; README ve CONTRIBUTING’i güncelleyin. Node ön kontrolünü lockfile engine aralıklarıyla hizalayın. SMTP testini completion barrier ile kararlı hale getirin. Tenant testlerinin süre bütçesini doğru belirleyin; pahalı anahtar türetme entegrasyonlarını korurken gereksiz tekrarları ayırın.

### Üçüncü öncelik üretim ölçeği ve kalite

Cluster log yaşam döngüsü, masking sınırları, detection false-positive programı ve protokol uyumluluk testleri üzerinde çalışın. Aynı release binary’siyle tam browser/API E2E, container/K8s smoke, vulnerability scan ve hedef ortam yük/restore kanıtını toplayın. Bu aşamaya kadar yeni büyük ürün yüzeyi eklemek yerine mevcut yüzeyin tutarlılığını artırmak daha yüksek değer sağlar.

## Kapanış değerlendirmesi

Proje önemli miktarda çalışan kod ve güçlü bir regresyon tabanı içeriyor. “Her şey sadece stub” veya “modüller bağlı değil” değerlendirmesi mevcut kod için yanlış olur. Bununla birlikte test kapsamı ve geniş özellik listesi, kurulum yollarının aynı korumayı sağladığını garanti etmemiş. Şu anda en yüksek getirili iş; ortak builder, açık yetenek/reload sözleşmesi ve dağıtım modları arasında uçtan uca davranış eşitliğidir.

Bu çalışmanın somut çıktısı üç açık kusur, yeniden çalıştırılmış kalite ölçümleri, modül bazlı durum tablosu ve önceliklendirilmiş uygulama listesidir. Ürün kodu değiştirilmedi; kusurlar açık olarak bırakıldı.

Son içerik karşılaştırmasında başlangıçta kaydedilen 293 dosyanın hash’leri aynı kaldı. Git durumuna yeni rapor dosyası eklendi. [İçerik koruma sonucu](../.temp_files/project_review_20261026/preservation-check.json) ve [ayrıntılı evidence ledger](../.temp_files/ledger_project_review_20261026.md) inceleme kayıtlarıyla birlikte saklanıyor.
