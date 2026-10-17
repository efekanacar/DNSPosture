# DNSPosture

Python ile yazılmış, salt okunur DNS ve e-posta güvenliği ön inceleme aracı.
Python 3.10 veya üzeri gerekir. Tek harici bağımlılık `dnspython` paketidir.

## Özellikler

- A, AAAA, MX, NS, TXT ve CAA sorguları; kayıtlar, TTL ve sorgu durumları.
- SPF varlığı, birden fazla kayıt, ilk `all` mekanizmasının niteliği ve `redirect` kontrolü.
- Doğrudan `_dmarc` TXT kaydında temel etiket kontrolü; `none`, `quarantine`, `reject` ayrımı.
- İsteğe bağlı DKIM selector sorgusu, anahtar etiketi ve boş `p` kontrolü.
- Olası riskler ve bunlara yönelik öneriler; terminal veya makine tarafından okunabilir JSON.
- Sorgu başına toplam timeout; NXDOMAIN, boş yanıt, timeout ve DNS hata ayrımı.
- Unicode domainlerin IDNA dönüşümü; yerel DNS çözümleyicisi kullanımı.

## Kurulum

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Linux/macOS ortamında aktivasyon: `source .venv/bin/activate`.

## Örnek komutlar

```powershell
python dnsposture.py example.com
python dnsposture.py example.com --selector default
python dnsposture.py example.com --selector mail.s1 --timeout 3
python dnsposture.py example.com --json
python dnsposture.py example.com --selector default --json > rapor.json
python dnsposture.py --help
```

Domain bir URL olmamalıdır: `example.com` kullanın, `https://example.com/path` kullanmayın.
`--timeout` sonlu ve pozitif saniye değeridir (varsayılan 5). Sorgular sıralıdır;
altı temel kayıt ve DMARC için en fazla yaklaşık 7 × timeout, DKIM ile 8 × timeout
beklenebilir. Yerel çözümleyici kurulum süresi buna dahil değildir.

## Çıktı ve yorumlama

JSON içinde `dns`, `spf`, `dmarc_query`, `dmarc`, `dkim`, `findings` ve
`limitations` alanları bulunur. Her bulgu bir açıklama ve öneri içerir.
`ok` yanıt alındığını, `no_answer` istenen kayıt türünün yanıtta bulunmadığını,
`nxdomain` sorgulanan adın bulunmadığını gösterir. `timeout` ve `error`
durumları kayıt yokluğu olarak yorumlanmaz; ilgili analiz `unknown` kalır.
JSON çıktısı ASCII kaçışları kullanır; standart JSON ayrıştırıcıları Türkçe metni geri yükler.

Çıkış kodları: `0` sorgular tamamlandı (bulgular olabilir), `1` en az bir
sorgu/çözümleyici hatası (kısmi rapor olabilir), `2` hatalı komut satırı,
`130` kullanıcı tarafından durdurma. NXDOMAIN ve boş yanıt sorgu hatası sayılmaz.
JSON yönlendirmesinde dosyayı kullanmadan önce çıkış kodunu kontrol edin.

`p=none` özel karantina/ret talep etmez; `p=quarantine` karantina,
`p=reject` ret talep eder. Alıcının uyguladığı işlem farklı olabilir.
Bu araç yalnızca girilen domainin doğrudan DMARC kaydını inceler;
üst domain keşfi veya etkin politika hesabı yapmaz. Dolayısıyla doğrudan
kayıt bulunamaması, domainin DMARC koruması olmadığı anlamına gelmez.

DKIM selector belirtilmezse DKIM kontrol edilmez ve eksiklik bulgusu üretilmez.
Selector verildiğinde sonuç yalnızca o selector içindir. TXT parçaları aynı kayıt
içinde birleştirilir; farklı TXT kayıtları birbirine eklenmez. Anahtar bulunması,
iletilerin DKIM ile doğru imzalandığını kanıtlamaz; boş `p` iptal edilmiş anahtar olabilir.

## Kapsam ve sınırlar

Bulgular kesin güvenlik açığı veya kapsamlı standart uyumluluk kararı değildir.
E-posta göndermeyen domainler dahil, kullanım amacı ve meşru göndericiler
incelenerek değerlendirilmelidir. SPF `include`/`redirect` hedefleri takip edilmez;
DNS lookup limiti, tüm SPF sözdizimi ve mekanizmaların erişilebilirliği doğrulanmaz.
`~all` tek başına güvenlik açığı sayılmaz. DMARC kontrolü temel etiketlerle sınırlıdır;
eski `pct` gibi etiketlerden etkin uygulama oranı çıkarılmaz.
DNSSEC, anahtar uzunluğu/kriptografik geçerlilik, DKIM imzaları, SPF/DKIM hizalaması,
DMARC rapor teslimatı ve gerçek e-posta teslimatı test edilmez.
CAA üst domain mirası incelenmez; doğrudan kayıt yokluğu açık değildir.
MX, A veya AAAA yokluğu tek başına risk olarak işaretlenmez.
Sonuçlar DNS önbelleği, bölünmüş DNS ve ağ erişimine göre değişebilir.

Temel kaynaklar: [dnspython resolver belgeleri](https://dnspython.readthedocs.io/en/stable/resolver-class.html),
[SPF RFC 7208](https://www.rfc-editor.org/rfc/rfc7208.html),
[DMARC RFC 9989](https://www.rfc-editor.org/rfc/rfc9989.html).
