# Ghost Mode for PayBox — Durum Raporu ve İnceleme Talebi

**Kime:** Claude (claude.ai) — ikinci görüş için
**Kimden:** Semih (Himess, proje sahibi) ve Claude Code (uygulamayı yapan ajan)
**Tarih:** 17 Ekim 2026, 20:35 UTC
**Hackathon bitişi:** 00:00 UTC (Cumartesi 8pm New York). Kalan süre: ~3 saat 25 dakika.

---

## 0. Senden ne istiyoruz

Bu oturumda **~70 dakikada (19:26–20:35 UTC) sıfırdan** çalışan bir ZK gizlilik havuzu kurduk ve Base mainnet'e deploy ettik. Önümüzde ~3,5 saat var: video çekip göndermeden önce projeyi **daha iyi** hale getirmek istiyoruz.

Senden istediklerimiz:

1. **Eleştirel teknik inceleme.** Tasarımda, devrede, kontratta veya güven modelinde hata, eksik kısıt ya da abartılı iddia görüyor musun?
2. **"Neyi daha iyi yapabilirdik / tasarlayabilirdik?"** Süreyi düşünmeden kalite açısından ne olmalıydı?
3. **Ardından önceliklendirme:** Bölüm 13'teki aday iş paketlerinden (ya da senin önereceklerinden) hangileri jüri kriterleri (yaratıcılık ve teknik derinlik, kullanışlılık, uyumluluk, tüketici finansı, merchant araçları) açısından en çok değer katar? Hangilerine hiç girmemeliyiz?
4. **Bölüm 14'teki somut sorular.**

Lütfen kibar olma; zayıf noktaları açıkça söyle.

---

## 1. Proje: Ghost Mode nedir?

*"Your agent knows your life. The chain shouldn't."* — *"Private by default. Provable on demand."*

**PayBox**, MoonPay'in yapay zekâ ajanları için cüzdanıdır. Ajan, kullanıcının adına ödeme, swap ve x402 (HTTP 402 ile ücretli API) ödemesi yapar. Anahtar MoonX MPC/TEE içinde kalır, ajan sadece imzalı çıktı alır. Sorun şu: ajanın yaptığı her ödeme kullanıcının adresinden çıkar ve herkes görür. Ajanlar insanlardan daha sık ve örüntülü ödeme yapar (rezervasyon, API kullanımı, abonelik), bu yüzden sızıntı katlanır.

**Ghost Mode**, PayBox kullanıcısına Base üzerinde **gizli bir USDC bakiyesi** verir:

- **Shield:** Kullanıcı USDC'yi bir ZK havuzuna yatırır. Yatırma herkese açıktır, sonrası gizlidir.
- **Gizli harcama:** Başka bir Ghost kullanıcısına gönderme (tutar ve alıcı gizli), bir adrese ödeme (gönderen gizli), unshield ve x402 API ödemesi (merchant ödemeyi relayer'dan alır).
- **Ana fikir:** Her gizli harcama, kullanıcının **PayBox cüzdanıyla atılan TEK bir EIP-712 imzasıyla** yetkilendirilir. Bu imza **ZK ispatının içinde doğrulanır.** PayBox anahtarı PayBox'tan hiç çıkmaz; yeni seed ya da harcama anahtarı yoktur.
- **Uyumluluk:** Privacy Pools tarzı Association Set (ASP), kullanıcı kontrollü ifşa (dönem raporu, tek ödeme makbuzu), arka kapı yok.
- **Ajan = gizlilik operatörü:** Bağlantı riski uyarıları verir (aynı tutarı hemen çekme, küçük anonimlik kümesi vb.) ve cüzdanın ne sızdırdığını tarar.

Ürün vizyonu ve kararlar (D1–D12), Semih'in yazdığı brief'ten geliyor. Brief'in özeti Bölüm 11'de, karşılaştırmalı olarak var.

---

## 2. Tasarımı belirleyen platform kısıtları

| Kısıt | Etkisi |
| --- | --- |
| Plugin, tek dosyalık bir MCP sunucusu (`dist/plugin.mjs`, ≤ 10 MiB) | Tüm mantık bundle'da olmalı. |
| **Her çağrı taze bir sandbox'ta**, kalıcı bellek ya da disk yok | Prepare → sign → submit akışında durum plugin'de tutulamaz. |
| **Çağrı başına 10 saniye bütçe** | ~7 sn süren ZK ispatı + relay bir çağrıya sığmaz; asenkron iş deseni gerekli. |
| Ağ erişimi yalnız portalda tanımlı tam host'lara (≤ 16) | Plugin tek bir servis host'una konuşuyor. |
| Sırlar sadece **host'a bağlı header** olarak enjekte ediliyor | API anahtarı plugin'de tutulamıyor. |
| Para hareketi yalnız **öneri** ile: tek imzasız EVM çağrısı (batch yok), x402 önerisi ya da Solana işlemi | Approve + deposit = 2 ayrı onay. Plugin imza atamaz. |
| Plugin'in para hareket ettiren araçları otonom modda bile kullanıcı onayına düşer | |
| Ajan, PayBox MCP'den `request_wallet_sign` çağırabilir (message, typedData, transaction, EIP-7702 authorization, raw digest), `get_request` ile poll eder | Spend imzası buradan geliyor. |
| Starter araç zinciri Node 24.21.0 + pnpm 11.11.0; Windows desteklenmiyor (WSL2 bekleniyor) | Geliştirme Windows'ta oldu. |

**Sonuç:** Plugin **ince istemci** oldu. Ağır işler (indexer, prover, relayer, ASP) bizim **Ghost servisimizde**. Bu, brief'teki G3 fallback'iydi.

---

## 3. Ne yaptık — zaman çizelgesi (UTC)

| Saat | Ne oldu |
| --- | --- |
| 19:26 | `skill.md`, plugin geliştirici rehberi ve PayBox MCP araç referansı okundu. Starter v1.0.2 indirildi. |
| ~19:40 | Kapsam sorusu soruldu. **Semih'in kararı: "Kolaya kaçma, tam ZK havuzunu yap, riski alıyorum."** Veri kaynağı olarak Alchemy seçildi (Semih). |
| 19:45–19:55 | Araç zinciri kuruldu: taşınabilir Node 24.21.0 ve pnpm 11.11.0. Noir için Windows'ta `nargo` yok; derleme `@noir-lang/noir_wasm` ve bellek-içi POSIX dosya sistemiyle yapıldı (Windows yol hatasına geçici çözüm). bb.js ve Foundry 1.8.5 kuruldu. Devre yazıldı ve derlendi: **N = 2^18 kapı.** |
| ~19:50 | **İlk gerçek ispat:** witness 0,41 sn, **UltraHonk ZK ispatı 6,7 sn, doğrulandı.** Brief'in G1 kapısı (≤ 10 sn) geçildi. |
| 19:50–20:05 | Paylaşılan SDK (Poseidon, notlar, Merkle, şifreleme, EIP-712, spend builder), servis ve plugin (10 araç) yazıldı. **3 alt-ajan paralel çalıştı:** kontratlar (52 test), exposure tarayıcı (11 test), dokümantasyon (README, RESEARCH, ARCHITECTURE, 12 ADR). |
| ~20:05 | Plugin MCP uyumluluk testi **geçti**. **Yerel uçtan uca test geçti:** derlenmiş bundle MCP stdio üzerinden, her çağrı ayrı süreçte (PayBox gibi), anvil'de gerçek ispat ve zincirde doğrulama ile. |
| ~20:15 | Doküman ajanı 4 güvenlik açığı buldu (Bölüm 10). **Hepsi deploy'dan önce düzeltildi**; devre yeniden derlendi, verifier yeniden üretildi, testler yeniden geçti. |
| 20:27 | Semih relayer adresini fonladı (0,00217 ETH). |
| ~20:29 | **Base mainnet deploy:** 6 kontrat, 16,86M gas, ~0,000092 ETH. |
| ~20:31 | **Gerçek bir ispat mainnet'teki doğrulayıcıda `verify() = true`.** Değiştirilmiş girdi `SumcheckFailed` ile reddedildi. |
| 20:35 | Servis ve Cloudflare tüneli canlı. Plugin yüklenmeye hazır. Bu rapor yazıldı. |

**Ölçek:** ~4.800 satır kod (devre 173, kontratlar 435 + testler 832, plugin ~1.070, servis ~1.680 + testler ~620) ve ~700 satır doküman.

---

## 4. Mimari

```
 Kullanıcı ── sohbet ──> Ajan (Claude + PayBox MCP connector)
                           │ use_plugin(ghost_*)          request_wallet_sign(typedData)
                           │                                        │
                           ▼                                        ▼
        Ghost Mode plugin (PayBox sandbox)            PayBox (MoonX MPC cüzdan,
        durumsuz, ≤ 10 sn/çağrı                        passkey / onay penceresi)
         • ghost key ile not tarama/çözme                          │ 65 baytlık imza
         • spend builder + EIP-712 typed data  <───────────────────┘ (ajan getirir)
         • gizlilik operatörü (risk uyarıları)
         • öneriler: USDC.approve, GhostPool.deposit
                           │ HTTPS (tek network host)
                           ▼
        Ghost servisi (Semih'in PC'si + Cloudflare quick tunnel)
         indexer · ASP · prover (bb.js UltraHonk, worker thread)
         relayer (sıcak EOA) · x402 ödeyici · exposure tarama
                           │ JSON-RPC (mainnet.base.org → publicnode yedek)
                           ▼
        Base mainnet: GhostPool + HonkVerifier + Poseidon kütüphaneleri, USDC
```

### Akışlar

- **Kurulum (`ghost_setup`):** Plugin bir mesaj verir → PayBox imzalar (`request_wallet_sign`, op `message`) → plugin imzadan **public key'i geri çıkarır** → rastgele 32 baytlık seed üretir → `ghk1_<seed>_<pubkey>` biçiminde **ghost key** ve paylaşılabilir **ghost adresi** döner. Kullanıcıya "ghost key'i PayBox Secret olarak sakla" denir.
- **Shield (`ghost_shield`):** Adım 1 `USDC.approve(pool)` önerisi, adım 2 `GhostPool.deposit(amount, precommitment, encryptedNote)` önerisi (2 PayBox onayı). Commitment'ı kontrat zincirde hesaplar, bu yüzden deposit için ispat gerekmez. ASP etiketi onaylayınca not harcanabilir hale gelir (şu an ~5 sn).
- **Harcama:** `ghost_prepare` → plugin notları çözer, girişleri seçer, çıkışları (alıcı + para üstü) kurar ve EIP-712 `GhostSpend` typed data'sını hazırlar; paketi servise saklatır, `prepare_id` alır → ajan `request_wallet_sign` (op `typedData`) çağırır → `ghost_submit(prepare_id, signature)` → servis imzayı ghost key'in public key'ine karşı doğrular, ispatlar, relay eder → `ghost_job` ile poll.
- **x402:** Spend, fiyat + ücreti relayer'a öder. Transact onaylanınca relayer, merchant'ın `payTo` adresine EIP-3009 yetkisi imzalar, kaynağı ödemeyle tekrar ister ve yanıtı `ghost_job`'a koyar.
- **İfşa:** `ghost_receipt` (PayBox imzalı niyet + tx; tek ödeme) ve `ghost_report` (bir tarih aralığındaki notların açılımları).
- **Exposure (`ghost_exposure`):** Kullanıcı bir challenge'ı imzalar (yalnız **kendi** cüzdanı taranabilir; plugin ve servis ikisi de doğrular), servis Alchemy ile Base geçmişini analiz eder ve 0–100 arası gizlilik skoru döner.

---

## 5. Kriptografi ve devre

### Veri modeli (P = circomlib uyumlu Poseidon, BN254)

```
note          = { asset, amount (u64), ownerTag, blinding, label }
precommitment = P2(ownerTag, blinding)
commitment    = P4(asset, amount, label, precommitment)      # kontrat deposit'te bunu hesaplıyor
pkHash        = P4(x_hi, x_lo, y_hi, y_lo)                   # PayBox secp256k1 public key, 128-bit limb'ler
ownerTag      = P2(pkHash, P1(nk))
nullifier     = P3(commitment, leafIndex, nk)
label         = keccak256(pool, depositIndex) mod p          # zincirde atanıyor; çıkışlar girişin label'ını taşıyor
```

- **Ağaçlar:** State ağacı derinlik 16 (65.536 yaprak, sıfır yaprak = 0), ASP ağacı derinlik 16 (yapraklar = onaylı label'lar).
- **Ghost key:** `nk = keccak(seed ‖ "ghost-mode:nk") mod p`, görüntüleme anahtarı = `sha256(seed ‖ "ghost-mode:ivk")` (X25519).
- **Ghost adresi:** `ghost:` + ownerTag (32 B) + viewPub (32 B) + 4 baytlık checksum.
- **Not şifreleme:** X25519 ECDH + AES-256-GCM. 133 baytlık şifreli metin (amount, blinding, label). Deposit'ler label 0 şifreler; label `Deposited` event'inden okunur. Notlar her yaprak deneme-çözülerek bulunur.
- **Uygulamalar:** Devrede noir-lang/poseidon v0.4.0, zincirde poseidon-solidity, TypeScript'te poseidon-lite. Foundry testleri test vektörleriyle uyumu doğruluyor.

### `transact` devresi (2 giriş, 2 çıkış)

**Public input'lar (14, bu sırayla):** `root, aspRoot, nullifier0, nullifier1, outCommitment0, outCommitment1, publicOut (u64), extDataHash, asset, recipient, fee (u64), deadline (u64), domainHi, domainLo`

**Kısıtlar:**

1. `ownerTag = P2(pkHash(pubkey), P1(nk))`. Giriş notları imzalayana aittir.
2. En az bir giriş sıfırdan farklı olmalı. İkisi de sıfırdan farklıysa aynı label'ı taşımalı. Çıkışlar bu label'ı alır.
3. Her giriş için nullifier doğru olmalı. `amount ≠ 0` ise state ağacında üyelik ve label'ın ASP ağacında üyeliği kanıtlanır.
4. **Çıkış 1 (para üstü) harcayana döner:** `out_owner_tags[1] == ownerTag`. İnceleme sonrası eklendi.
5. Çıkış commitment'ları doğru olmalı.
6. Değer korunumu: `Σin = Σout + publicOut` ve `publicOut ≥ fee`.
7. `intent = P5(n0, n1, c0, c1, extDataHash)`, burada `extDataHash = keccak256(abi.encode(relayer, encOut0, encOut1)) mod p`.
8. **EIP-712 devre içinde:** `GhostSpend(bytes32 intent, address token, uint256 amount, address to, uint256 fee, uint256 deadline, bytes32 recipientTag)` struct hash'i ve `0x1901 ‖ domainSeparator ‖ structHash` digest'i keccak ile hesaplanır. Okunabilir alanlar **gerçek harcamadan türetilir**: `amount = out0.amount + publicOut − fee`; `recipientTag = out0.ownerTag` (yalnız `out0.amount ≠ 0` ise). Domain (name GhostMode, version 1, chainId, verifyingContract = pool) iki 128-bit public input olarak verilir.
9. **secp256k1 ECDSA doğrulaması** (Noir black-box). İmzalar ispattan önce low-s'e normalize edilir (MPC yüksek-s döndürebilir).

Devrenin tam kaynağı Ek C'de.

### Ölçümler

| Ölçüt | Değer |
| --- | --- |
| Devre boyutu | N = 2^18 = 262.144 |
| Witness üretimi | 0,4–0,6 sn |
| İspat (bb.js WASM, 10–12 thread, 12 çekirdekli Windows PC) | 6,1–7,3 sn |
| İspat boyutu | 9.536 B |
| VK boyutu | 1.888 B |
| Solidity verifier | 18.092 B runtime + RelationsLib 7.913 B + ZKTranscriptLib 6.098 B |
| Araç zinciri | Noir 1.0.0-beta.22 + `@aztec/bb.js` 5.0.0-nightly.20260522 (Aztec'in resmi bbup eşleşmesi), `verifierTarget: "evm"` (keccak transcript, **zero-knowledge** varyant) |

---

## 6. Kontratlar (Foundry, solc 0.8.28, Base mainnet)

- **`deposit(amount, precommitment, encryptedNote)`:** Pause ve tavanları kontrol eder (deposit başına 100 USDC, toplam TVL 1.000 USDC, `amount < 2^64`). Label atar, `commitment = PoseidonT5(token, amount, label, precommitment)` hesaplar, `transferFrom` yapar, Merkle'a ekler. Event'ler: `NewCommitment`, `Deposited`.
- **`transact(proof, TransactArgs{root, aspRoot, nullifiers[2], outCommitments[2], publicOut, recipient, fee, deadline, relayer, encryptedOutput0, encryptedOutput1})`:**
  - Kontroller: root ve ASP root bilinen kökler olmalı; nullifier'lar < p, farklı ve harcanmamış; commitment'lar < p; deadline geçmemiş; u64 aralıkları; `fee ≤ publicOut`; ödeme varsa recipient ≠ 0.
  - Sonra: 14 public input'u kurar → `HonkVerifier.verify` → nullifier'ları işaretler → 2 çıkışı ekler → `publicOut − fee` alıcıya, `fee` relayer'a. Herkes çağırabilir (relayer'lar).
- **Yönetim:** `setAspRoot` (yalnız ASP operatörü, 16'lık geçmiş), 64'lük root geçmişi, `pause`, tavan ayarları, owner.
- **Testler:** **52/52.** Poseidon vektörleri poseidon-lite ile, sıfır zinciri, Node'da hesaplanan Merkle kökleri, tüm deposit/transact revert yolları ve verifier'a giden tam calldata (mock ile).
- **Gas:**
  - deposit ≈ 780k
  - `verify` ≈ 4,08M (Base'de gerçek ispatla `eth_estimateGas`)
  - transact toplamı tahminen ≈ 5,3M
  - Base gas fiyatı şu an 0,006 gwei, yani transact başına ≈ 0,00003 ETH.

### Base mainnet adresleri (deploy bloğu 52.739.791)

| Kontrat | Adres |
| --- | --- |
| GhostPool | `0x1882d5b6910c418c79ee6997179d473bc884693d` |
| HonkVerifier | `0x519a6d1022586ca29071e6d8c7a92180d5397d4f` |
| RelationsLib / ZKTranscriptLib | `0x8f20b5662868e011d86db01657399e20c4890e91` / `0xb3d028c39a88bbfbb56973fbb44638345749e96b` |
| PoseidonT3 / PoseidonT5 | `0xa6e3d33abef457db3a2f1504c91eee1a77375891` / `0x95d619151c18632fd0e6271d8376a44da2a2290e` |
| Relayer, ASP operatörü ve owner | `0x06cb7dDa8a2E453097085629A6bBfAf33EB9d78b` (bakiye 0,00208 ETH) |

---

## 7. Ghost servisi (Node 24 + TypeScript)

| Uç nokta | Görev |
| --- | --- |
| `GET /v1/info` | chainId, pool, token, relayer, ücret, x402 tavanı |
| `GET /v1/state` | Yapraklar + şifreli notlar, deposit'ler, harcanmış nullifier'lar, yayınlanmış ASP label listesi |
| `POST /v1/x402/quote` | Merchant'a ödemesiz istek atar, 402'yi ayrıştırır (v1 JSON `accepts` / v2 `PAYMENT-REQUIRED` header) |
| `POST /v1/prepare` | Spend paketini saklar ve `prepare_id` döner. x402 için fiyat + ücretin relayer'a ödendiğini doğrular. |
| `POST /v1/submit` | İmza, ghost key'in PayBox public key'ine karşı doğrulanır → iş kuyruğu (prove → relay → x402 öde) |
| `GET /v1/jobs/:id` | Durum, tx hash, süreler, x402 yanıtı, makbuz verisi |
| `POST /v1/exposure` | İmzalı ve 15 dakikalık challenge'ı yeniden doğrular, Alchemy ile tarar |

- **Prover:** bb.js worker thread'de, thread sayısı (çekirdek − 2). Ana thread bloke olmasın diye böyle; aksi halde plugin'in 10 sn bütçesi aşılıyordu.
- **Relayer:** Sıcak EOA. Tüm işlemleri tek bir kilitle sıralanır (nonce yarışı olmasın diye). Ücret sabit 0,01 USDC.
- **ASP:** Deposit sırasıyla deterministik otomatik onay, depositor denylist'i (şu an boş) ve gecikme (0 sn). Kökü zincire yayınlar.
- **Indexer:** Event'lerden yeniden kurar. Log aralığı sağlayıcıya göre uyarlanır (50k → 10k → …). RPC yedekli.
- **Güvenlik ekleri:** x402 URL'leri yalnız herkese açık HTTPS host'lar olabilir (localhost, özel IP ve `.local` reddedilir). Exposure sahipliği sunucu tarafında da doğrulanır.
- **Barındırma:** Semih'in Windows PC'si + Cloudflare quick tunnel: `https://achieving-window-commissioner-welding.trycloudflare.com`. Tünel yeniden başlarsa hostname değişir; portal ayarı deadline'dan sonra da güncellenebilir.
- **Durum:** İşler (jobs) ve hazırlanmış harcamalar **bellekte**; servis yeniden başlarsa kaybolur.

---

## 8. PayBox plugin'i (10 araç)

| Araç | Ne yapar | Para hareketi |
| --- | --- | --- |
| `ghost_setup` | 2 adım: mesaj → imza → ghost key + ghost adresi | Hayır |
| `ghost_address` | Ghost adresini gösterir | Hayır |
| `ghost_shield` | `approve`, sonra `deposit` önerisi (her biri bir PayBox onayı) | Öneri |
| `ghost_balance` | Notları yerelde çözer: harcanabilir / ASP bekleyen / harcanmış, havuz istatistikleri | Hayır |
| `ghost_prepare` | `send_ghost`, `pay_address`, `unshield` ya da `pay_x402` için spend + typed data + risk uyarıları | Hayır (imza ister) |
| `ghost_submit` | İmzayı prover ve relayer'a verir | Evet (imzalı niyetle) |
| `ghost_job` | Durum ve sonuç (tx, x402 yanıtı) | Hayır |
| `ghost_exposure` | Challenge → imza → gizlilik raporu | Hayır |
| `ghost_receipt` | Tek ödeme makbuzu: imzalı niyet + tx + doğrulama adımları | Hayır |
| `ghost_report` | Bir tarih aralığı için not açılımları (muhasebeci paketi) | Hayır |

- **Uyumluluk testi geçti.** Bundle 575.308 B, sha256 `e63e6552…b234`, örnek çağrı `ghost_setup {}`.
- **Gizlilik operatörünün kuralları:**
  - anonimlik kümesi < 5
  - herkese açık çıkış tutarı son 24 saatteki bir deposit'e %1 yakınsa
  - kendi deposit'inden sonraki 30 dakika içinde çıkış
  - alıcı daha önce havuza yatırma yapmışsa
  - yuvarlak olmayan tutarlar
  - deposit'te 5'in katlarına yuvarlama önerisi

---

## 9. Test ve doğrulama matrisi

| Ne | Durum | Kanıt / not |
| --- | --- | --- |
| Devre (iki harcama türü: adrese ödeme ve ghost transferi) | ✅ | Gerçek imza + ispat + doğrulama |
| Kontrat birim testleri | ✅ 52/52 | Foundry |
| Yerel uçtan uca test (bundle MCP üzerinden, anvil, gerçek ispatlar) | ✅ | Kurulum ×2, 50 USDC shield, ASP, Ayşe'ye 20 gizli, adrese 10 (+10 USDC ulaştı), makbuz (imzalayan doğru), Ayşe'nin unshield'ı. Son bakiyeler 19,98 / 14,99, tam beklenen. Tüm plugin çağrıları 10 sn bütçesinin altında; ispat worker thread’e taşındıktan sonra job sorguları < 1 sn. |
| Mainnet deploy | ✅ | Bölüm 6 |
| Mainnet doğrulayıcı, gerçek ispat | ✅ | `verify() = true`; değiştirilmiş girdi → `SumcheckFailed` |
| x402 teklif ayrıştırma (canlı, ödemesiz) | ✅ | Blockscout PRO API, x402 v2: 0,002 USDC, Base USDC, payTo `0xd441…b4b4` |
| x402 gerçek ödeme (EIP-3009 + `PAYMENT-SIGNATURE`) | ❓ | Kod var, canlı ödeme yapılmadı (G4) |
| PayBox hosted kontroller | ⏳ | Paket henüz yüklenmedi |
| **PayBox onay ekranında `GhostSpend` nasıl görünüyor (G2)** | ❓ | Gerçek PayBox cüzdanıyla görülmedi |
| PayBox imza biçimi ve low-s davranışı (R2) | ❓ | Kod iki durumu da karşılıyor; gerçek imza görülmedi |
| Gerçek PayBox cüzdanıyla mainnet shield ve harcama | ❓ | Semih'in ajan testini bekliyor |
| Exposure canlı tarama | ❓ | **Alchemy anahtarı henüz yok**; birim testleri 11/11 |
| Starter'ın resmi `pnpm test`'i Linux'ta | ❓ | Windows'ta platform kapısı kaldırılmış bir kopyayla çalıştırıldı |

---

## 10. Güvenlik

### Bulunup deploy'dan önce düzeltilenler

1. **Para üstü bağlı değildi.** Kötü niyetli bir hazırlayıcı (plugin ya da servis), onay ekranında görünmeyen para üstünü kendine yönlendirebilirdi. Devreye `out_owner_tags[1] == ownerTag` eklendi.
2. **x402'de relayer boşaltılabilirdi.** Fiyat + ücreti relayer'a ödemeyen sahte bir paket, relayer'ın merchant'a kendi cebinden ödemesine yol açabilirdi. `/v1/prepare` artık bunu kontrol ediyor.
3. **SSRF:** Servis, istemcinin verdiği herhangi bir HTTPS URL'ye Semih'in makinesinden istek atıyordu. Artık yalnız herkese açık host'lar kabul ediliyor (DNS rebinding hâlâ açık).
4. **Exposure sahipliği yalnız plugin'de kontrol ediliyordu.** Artık servis de imzalı challenge'ı doğruluyor.

### Açık riskler / zayıflıklar

- **Prover gizlilik güveni:** Servis tam witness'ı görüyor (nk, notlar, blinding'ler). Hedef TEE ya da istemci tarafı ispat.
- **Ghost key LLM bağlamından geçiyor:** PayBox Secret olarak saklanması öneriliyor. Sızarsa gizlilik kaybı olur, para gitmez; kaybolursa notlara erişim kaybolur.
- **Tek relayer, tek ASP, tek indexer, tek prover**, hepsi bir PC'de; quick tunnel'a bağımlı.
- Relayer sıcak anahtarı yerel diskte.
- Kontratlar **denetlenmemiş.** Tavanlar ve pause mevcut.
- `SERVICE_TOKEN` açık değil, servis uç noktaları kimlik doğrulamasız. Geçerli imza olmadan zarar verilemiyor; ama spam ve RPC tüketimi mümkün.
- **Relayer ücreti (0,01 USDC) gas maliyetinin (≈ 0,00003 ETH) altında**, yani her işlem zararına. Relayer ~60 transact'a yetecek ETH'ye sahip.
- **Anonimlik kümesi şu an 0.** İlk demo'da gerçek gizlilik zayıf; dürüst anlatım gerekiyor.

---

## 11. Brief'e göre ne yaptık, neyi ertelendik

| Brief | Durum |
| --- | --- |
| D1 ZK shielded UTXO havuzu, önce USDC | ✅ |
| D2 Noir + UltraHonk | ✅ (ZK varyantı, EVM verifier) |
| D3 Harcama yetkisi = PayBox ECDSA imzası, devre içinde | ✅ (EIP-712 + secp256k1 devre içinde) |
| D4 Gizlilik anahtarları harcama yetkisinden ayrı | ✅ (nk ve ivk ghost key'de) |
| D5 Base mainnet, USDC | ✅ (havuz tek token; not yapısı çok varlıklı ama kontrat değil) |
| D6 ASP + ragequit | ⚠️ ASP var (otomatik onay); **ragequit yok** |
| D7 İfşa paketi + **public doğrulama sayfası**, viewing key | ⚠️ Rapor ve makbuz var; **doğrulama sayfası yok**; ovk kopyası yok |
| D8 x402'de relayer = payer of record | ✅ kod; ❓ canlı ödeme yok |
| D9 Hazırla → `request_wallet_sign` → gönder → poll | ✅ |
| D10 Ajan = gizlilik operatörü | ✅ (kural tabanlı) |
| D11 MEV / private orderflow | ⚠️ Ayrıca bir şey yapılmadı (Base sequencer); iddia yok |
| D12 Swap ve vault adapter'ları (stretch) | ❌ Çok varlıklı havuz gerektirir |
| Ghost session modu (G1 fallback) | Gerek kalmadı (ispat 7 sn) |
| Exposure taraması (R11) | ✅ kod + test; ❓ Alchemy anahtarı bekleniyor |
| `docs/RESEARCH.md`, `ARCHITECTURE.md`, `adr/` (12), G1–G5 tablosu | ✅ Semih'in kararları "Decided by", ajan önerileri "onay bekliyor" olarak işaretli |

**Kapı durumu:**

| Kapı | Durum |
| --- | --- |
| G1 | ✅ (ispat ≤ 10 sn, verifier deploy edildi, gas ölçüldü) |
| G2 | ✅ devre içinde, ❓ PayBox ekranı |
| G3 | ✅ |
| G4 | ⚠️ (kod hazır, canlı test yok) |
| G5 | ⚠️ (Secret önerisi, PayBox'ta test edilmedi) |

---

## 12. Öz-eleştiri: neyi daha iyi yapabilirdik / tasarlayabilirdik?

Bu bizim kendi listemiz. Lütfen değerlendir, ekle ya da çıkar.

1. **Shield UX zayıf:** 2 PayBox onayı (approve + deposit) var ve kullanıcının cüzdanında gas için ETH olması gerekiyor. Daha iyisi şu: kullanıcı **tek bir EIP-3009 `ReceiveWithAuthorization`** typed data'sı imzalar (PayBox ekranında okunabilir: from, to, value). Relayer `depositWithAuthorization` çağırır. Sonuç: tek onay, kullanıcıda ETH gerekmez. Bunun için kontrat değişikliği ve yeniden deploy gerekir (havuz boş olduğu için ucuz).
2. **Onay ekranı tam okunabilir değil:** `amount` atomik birimde (20000000), `deadline` unix zamanı, `intent` ve `recipientTag` opak bytes32. Devre içinde doğrulanan insan-okunur bir alan (ör. "20.00 USDC → 0xabc…") mümkün; ancak devre değişir, yeniden deploy gerekir ve dikkatli test ister.
3. **Relayer ekonomisi gerçekçi değil:** Ücret sabit ve gas'tan düşük. Dinamik ücret teklifi (gas × fiyat + marj) gerekirdi.
4. **Geçmiş ve makbuzlar servis belleğine bağlı.** Daha iyisi: para üstü notunun şifreli metnine ödeme detayını (alıcı, tutar) **kendine şifreli bir memo (ovk)** olarak eklemek. Böylece kullanıcı tüm geçmişini yalnız ghost key + zincirden yeniden kurabilir; kontrat değişikliği gerekmez. Ayrıca işleri diske yazmak.
5. **Ghost key yönetimi:** Rastgele seed hem kaybolabilir hem LLM bağlamından geçer. Alternatifler: (a) PayBox imzası deterministikse seed'i imzadan türetmek (R2 test edilmedi); (b) ghost key'i PayBox'ın şifreli Secret kasasında tutup ajanın her seferinde `request_secret` ile passkey onayıyla alması; (c) bir key servisi ve TEE.
6. **Merkezî servis ve laptop barındırma:** Jüri değerlendirmesi sırasında makine kapalıysa plugin çalışmaz. Kalıcı barındırma (VPS ya da Fly.io) ve named tunnel daha iyi olurdu.
7. **Label soyu kısıtı:** İki farklı deposit'in notları aynı harcamada birleştirilemiyor (Privacy Pools ile aynı). Bakiye parçalanıyor.
8. **ASP sembolik:** Gerçek bir yaptırım listesi (OFAC SDN kripto adresleri) yüklenebilirdi. Ragequit yok, bu yüzden onaylanmayan deposit kilitli kalır.
9. **Zamanlama gizliliği:** Relayer hemen gönderiyor. İsteğe bağlı rastgele gecikme (ör. 1–15 dk) zaman korelasyonunu kırar.
10. **Exposure verisi tek sağlayıcıya bağlı (Alchemy).** Alternatif: Blockscout PRO'nun x402 uç noktasını **relayer'ın x402 ile ödemesi**. Kendi ürünümüzü kullanmış oluruz (dogfooding); ama relayer'da USDC olması gerekir.
11. **Doğrulama sayfası yok:** "Provable on demand" vaadi için muhasebecinin paketi tarayıcıda doğrulayacağı statik bir sayfa (poseidon-lite ile commitment'ları yeniden hesaplar, zincirdeki event'leri kontrol eder) çok güçlü bir demo parçası olurdu.
12. **Test boşlukları:** PayBox tarafı (G2, R2, G4, G5) gerçek cüzdanla görülmedi. En büyük bilinmeyen bu.
13. **Mimari:** Spend paketi servise gidiyor; plugin istemci tarafında ispatlayamadığı için witness gizliliği servise emanet. Tasarım dürüst ama "trustless privacy" iddia edemeyiz.

---

## 13. Kalan süre için aday iş paketleri

Not: Havuz şu an **boş**. Devre ya da kontrat değişikliği gerekirse yeniden deploy ucuz (~0,0001 ETH). Ancak her devre değişikliği şu zinciri gerektirir: yeniden derle → verifier'ı yeniden üret → Foundry testleri → deploy → servis `.env` → plugin'i yeniden yükle (pool pin) → uçtan uca test. Bu ~20–30 dakikalık sabit bir maliyet. **Kod yüklemesi yalnız 00:00 UTC'den önce yapılabiliyor;** network host ve env ayarları sonra da değişebiliyor.

| # | İş paketi | Değer (jüri) | Tahmini efor | Risk | Redeploy? |
| --- | --- | --- | --- | --- | --- |
| A | **Gerçek PayBox cüzdanıyla mainnet testi** + çıkan hataları düzeltmek (G2/R2 görülür) | Zorunlu | 30–60 dk | PayBox'a bağlı | Hayır |
| B | Alchemy anahtarı → exposure canlı (demo açılışı) | Yüksek | 5 dk | Düşük | Hayır |
| C | **Tek imzalı shield** (EIP-3009, relayer gönderir, kullanıcıda ETH gerekmez) | Yüksek (tüketici UX'i) | 45–60 dk | Orta | **Evet** (kontrat) |
| D | Kendine şifreli ödeme memo'su (ovk) + işleri diske yazma: geçmiş ve makbuzlar zincirden yeniden kurulabilir | Orta–yüksek (ifşa, sağlamlık) | 30–40 dk | Düşük | Hayır |
| E | **İfşa doğrulama sayfası** (statik HTML: commitment yeniden hesaplama + event kontrolü + makbuzda imza doğrulama) | Yüksek ("Provable on demand") | 45 dk | Düşük | Hayır |
| F | Dinamik relayer ücreti | Orta (gerçekçilik) | 15 dk | Düşük | Hayır |
| G | Rastgele relay gecikmesi seçeneği | Orta (gizlilik) | 20 dk | Düşük | Hayır |
| H | ASP'ye OFAC denylist'i | Orta (uyumluluk) | 15 dk | Düşük | Hayır |
| I | Onay ekranında devre içinde doğrulanan insan-okunur alanlar | Orta | 60–90 dk | Orta–yüksek | **Evet** (devre) |
| J | Servisi bulut barındırmaya taşımak | Güvenilirlik | 30–60 dk | Hesap gerekir | Hayır |
| K | Ragequit (onaylanmayan deposit'i geri alma) | Uyumluluk bütünlüğü | 60+ dk | Yüksek | **Evet** |
| L | Demo videosu + X gönderisi + Submit | Zorunlu | 45–60 dk (Semih) | — | — |

Bizim ilk eğilimimiz: **A + B + L zorunlu; ardından E, D, C**; vakit kalırsa F, G, H. I, J ve K riskli ya da pahalı. Sen ne dersin?

---

## 14. Somut sorular

1. **Devre sağlamlığı:** Bölüm 5 ve Ek C'deki kısıtlarda eksik gördüğün bir şey var mı? Örnekler: dummy giriş, label kuralı, `publicOut`/`fee`/`recipient` bağlama, nullifier'a leafIndex katmak, domain'i public input olarak almak, `recipientTag` gösterimi, low-s normalizasyonu.
2. **Onay ekranında yalan söylenemezlik:** `GhostSpend` alanları gerçekten yeterli mi? Kötü niyetli bir hazırlayıcı kullanıcıyı başka nasıl kandırabilir? (Örneğin public payout'ta `out0`'ı başkasına sıfırdan farklı tutarla yazmak, `recipientTag` ve `amount` üzerinden görünür olur. Bu yeterli mi?)
3. **Ghost key:** PayBox kısıtları içinde (durumsuz plugin, ajan bağlamı, PayBox Secret kasası, `request_wallet_sign`) daha iyi bir anahtar yönetimi önerir misin?
4. **Tek imzalı shield (C):** EIP-3009 `receiveWithAuthorization` mı, EIP-2612 permit mi? Relayer'ın gönderdiği deposit'te front-running ya da griefing riski var mı?
5. **Gizlilik iddiaları:** README ve demo için hangi iddialar dürüst, hangileri abartılı? Anonimlik kümesi sıfırken demoyu nasıl dürüst anlatmalıyız?
6. **Jüri değeri:** Kalan sürede hangi 2–3 iyileştirme projeyi "iyi"den "kazanan"a taşır?
7. **Mimari alternatif:** Prover güvenini azaltmanın hackathon ölçeğinde gerçekçi bir yolu var mı (ör. sandbox'ta ispat, TEE, ispatı bölmek)?
8. **x402 akışı:** Relayer = payer of record modelinde merchant tarafında ya da facilitator'la uyumda gözden kaçan bir şey var mı (v2 `PAYMENT-SIGNATURE` biçimi, `resource` alanı, nonce yönetimi)?
9. **Demo senaryosu** (`docs/DEMO.md`, 2,5 dk): Sırayı ve vurguyu nasıl değiştirirdin?

---

## Ek A — Depo yapısı

```
ghost-mode/
  circuits/transact/      Noir devresi (src/main.nr), target/ (ACIR, vk)
  circuits/lib/           vendored noir-lang/poseidon v0.4.0, noir-lang/keccak256 v0.1.3
  contracts/              Foundry: GhostPool, MerkleTreeWithHistory, HonkVerifier (üretilmiş), Poseidon, testler, Deploy.s.sol
  plugin/                 PayBox plugin (starter 1.0.2): src/plugin.ts, src/core/*, src/ghost/*  →  dist/plugin.mjs
  service/                indexer, ASP, prover (worker), relayer, x402, exposure; test/ (prove, e2e, exposure)
  docs/                   RESEARCH.md, ARCHITECTURE.md, DEMO.md, adr/0001–0012, bu rapor
  deploy-mainnet.sh, start-mainnet.sh, SUBMISSION.md, README.md
```

## Ek B — Örnek `GhostSpend` typed data (`ghost_prepare` çıktısı, kısaltılmış)

```json
{
  "domain": { "name": "GhostMode", "version": "1", "chainId": 8453, "verifyingContract": "0x1882d5b6910c418c79ee6997179d473bc884693d" },
  "types": {
    "EIP712Domain": [ {"name":"name","type":"string"}, {"name":"version","type":"string"}, {"name":"chainId","type":"uint256"}, {"name":"verifyingContract","type":"address"} ],
    "GhostSpend": [ {"name":"intent","type":"bytes32"}, {"name":"token","type":"address"}, {"name":"amount","type":"uint256"}, {"name":"to","type":"address"}, {"name":"fee","type":"uint256"}, {"name":"deadline","type":"uint256"}, {"name":"recipientTag","type":"bytes32"} ]
  },
  "primaryType": "GhostSpend",
  "message": {
    "intent": "0x1c3f…(Poseidon intent)",
    "token": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "amount": "10000000",
    "to": "0x000000000000000000000000000000000000bEEF",
    "fee": "10000",
    "deadline": "1792270000",
    "recipientTag": "0x0000000000000000000000000000000000000000000000000000000000000000"
  }
}
```

## Ek C — Devrenin tam kaynağı (`circuits/transact/src/main.nr`)

```rust
// Ghost Mode `transact` circuit: 2 inputs, 2 outputs, one asset per transaction.
//
// Spend authority is the user's PayBox wallet. The circuit verifies a secp256k1
// ECDSA signature over an EIP-712 `GhostSpend` digest that commits to this exact
// spend (nullifiers, output commitments, external data), so the PayBox key never
// leaves PayBox and a leaked privacy key (`nk`) cannot move funds on its own.
//
// Note:        { asset, amount, ownerTag, blinding, label }
// precommit:   H2(ownerTag, blinding)
// commitment:  H4(asset, amount, label, precommit)   (the pool recomputes this on deposit)
// ownerTag:    H2(pkHash, H1(nk)),  pkHash = H4(x_hi, x_lo, y_hi, y_lo)
// nullifier:   H3(commitment, leafIndex, nk)
// H* = circomlib-compatible Poseidon over BN254 (matches poseidon-solidity and poseidon-lite).

use poseidon::poseidon::bn254::{hash_1, hash_2, hash_3, hash_4, hash_5};

global DEPTH: u32 = 16;
global ASP_DEPTH: u32 = 16;

// keccak256("GhostSpend(bytes32 intent,address token,uint256 amount,address to,uint256 fee,uint256 deadline,bytes32 recipientTag)")
global SPEND_TYPEHASH: [u8; 32] = [
    129, 163, 97, 207, 28, 142, 60, 165, 26, 122, 233, 207, 249, 46, 81, 60, 173, 89, 63, 60, 50,
    206, 126, 208, 178, 20, 252, 205, 110, 44, 128, 240,
];

fn merkle_root<let D: u32>(leaf: Field, index: Field, path: [Field; D]) -> Field {
    let bits: [bool; D] = index.to_le_bits();
    let mut node = leaf;
    for i in 0..D {
        let sibling = path[i];
        let (left, right) = if bits[i] { (sibling, node) } else { (node, sibling) };
        node = hash_2([left, right]);
    }
    node
}

fn note_commitment(asset: Field, amount: Field, label: Field, owner_tag: Field, blinding: Field) -> Field {
    hash_4([asset, amount, label, hash_2([owner_tag, blinding])])
}

fn be_bytes_to_field<let N: u32>(bytes: [u8; N], start: u32, len: u32) -> Field {
    let mut acc: Field = 0;
    for i in 0..N {
        if (i >= start) & (i < start + len) {
            acc = acc * 256 + bytes[i] as Field;
        }
    }
    acc
}

fn write32(buf: &mut [u8; 256], offset: u32, word: [u8; 32]) {
    for k in 0..32 {
        buf[offset + k] = word[k];
    }
}

fn main(
    // ---- public inputs (order is the verifier's publicInputs layout) ----
    root: pub Field,
    asp_root: pub Field,
    nullifiers: pub [Field; 2],
    out_commitments: pub [Field; 2],
    public_out: pub u64,
    ext_data_hash: pub Field,
    asset: pub Field,
    recipient: pub Field,
    fee: pub u64,
    deadline: pub u64,
    domain_hi: pub Field,
    domain_lo: pub Field,
    // ---- private inputs ----
    in_amounts: [u64; 2],
    in_blindings: [Field; 2],
    in_labels: [Field; 2],
    in_indices: [Field; 2],
    in_paths: [[Field; DEPTH]; 2],
    asp_indices: [Field; 2],
    asp_paths: [[Field; ASP_DEPTH]; 2],
    nk: Field,
    pub_x: [u8; 32],
    pub_y: [u8; 32],
    signature: [u8; 64],
    out_amounts: [u64; 2],
    out_owner_tags: [Field; 2],
    out_blindings: [Field; 2],
) {
    // 1. Owner binding: input notes belong to (PayBox public key, nk).
    let pk_hash = hash_4([
        be_bytes_to_field(pub_x, 0, 16),
        be_bytes_to_field(pub_x, 16, 16),
        be_bytes_to_field(pub_y, 0, 16),
        be_bytes_to_field(pub_y, 16, 16),
    ]);
    let owner_tag = hash_2([pk_hash, hash_1([nk])]);

    let live0 = in_amounts[0] != 0;
    let live1 = in_amounts[1] != 0;
    assert(live0 | live1, "at least one input must carry value");
    if live0 & live1 {
        assert(in_labels[0] == in_labels[1], "inputs must share one ASP label");
    }
    let label = if live0 { in_labels[0] } else { in_labels[1] };

    // 2. Inputs: commitment, nullifier, state-tree and ASP-tree membership.
    for i in 0..2 {
        let commitment =
            note_commitment(asset, in_amounts[i] as Field, in_labels[i], owner_tag, in_blindings[i]);
        assert(hash_3([commitment, in_indices[i], nk]) == nullifiers[i], "bad nullifier");
        if in_amounts[i] != 0 {
            assert(merkle_root(commitment, in_indices[i], in_paths[i]) == root, "note not in tree");
            assert(
                merkle_root(in_labels[i], asp_indices[i], asp_paths[i]) == asp_root,
                "label not in association set",
            );
        }
    }

    // 3. Outputs inherit the input label. Output 1 is always the change and must return
    //    to the spender: the approval screen shows output 0 and the public payout, so a
    //    malicious preparer must not be able to redirect change to another owner.
    assert(out_owner_tags[1] == owner_tag, "change must return to the spender");
    for j in 0..2 {
        assert(
            note_commitment(asset, out_amounts[j] as Field, label, out_owner_tags[j], out_blindings[j])
                == out_commitments[j],
            "bad output commitment",
        );
    }

    // 4. Value conservation (u64 amounts, so the Field sums cannot wrap).
    let sum_in = in_amounts[0] as Field + in_amounts[1] as Field;
    let sum_out = out_amounts[0] as Field + out_amounts[1] as Field + public_out as Field;
    assert(sum_in == sum_out, "value not conserved");
    assert(public_out >= fee, "fee exceeds public output");

    // 5. Intent: binds nullifiers, outputs and external data (relayer + encrypted notes).
    let intent = hash_5([nullifiers[0], nullifiers[1], out_commitments[0], out_commitments[1], ext_data_hash]);

    // 6. EIP-712 GhostSpend struct hash. Readable fields are recomputed from the
    //    real spend so the PayBox approval screen cannot be lied to.
    let shown_amount = out_amounts[0] as Field + (public_out - fee) as Field;
    let shown_tag = if out_amounts[0] != 0 { out_owner_tags[0] } else { 0 };
    let mut enc: [u8; 256] = [0; 256];
    write32(&mut enc, 0, SPEND_TYPEHASH);
    write32(&mut enc, 32, intent.to_be_bytes());
    write32(&mut enc, 64, asset.to_be_bytes());
    write32(&mut enc, 96, shown_amount.to_be_bytes());
    write32(&mut enc, 128, recipient.to_be_bytes());
    write32(&mut enc, 160, (fee as Field).to_be_bytes());
    write32(&mut enc, 192, (deadline as Field).to_be_bytes());
    write32(&mut enc, 224, shown_tag.to_be_bytes());
    let struct_hash = keccak256::keccak256(enc, 256);

    let dom_hi: [u8; 16] = domain_hi.to_be_bytes();
    let dom_lo: [u8; 16] = domain_lo.to_be_bytes();
    let mut digest_input: [u8; 66] = [0; 66];
    digest_input[0] = 0x19;
    digest_input[1] = 0x01;
    for k in 0..16 {
        digest_input[2 + k] = dom_hi[k];
        digest_input[18 + k] = dom_lo[k];
    }
    for k in 0..32 {
        digest_input[34 + k] = struct_hash[k];
    }
    let digest = keccak256::keccak256(digest_input, 66);

    // 7. PayBox wallet signature (secp256k1), verified inside the proof.
    assert(
        std::ecdsa_secp256k1::verify_signature(pub_x, pub_y, signature, digest),
        "PayBox signature invalid",
    );
}
```

## Ek D — `GhostPool.transact` ve public input kurulumu (`contracts/src/GhostPool.sol`)

```solidity
    function transact(bytes calldata proof, TransactArgs calldata a) external whenNotPaused nonReentrant {
        if (!isKnownRoot(a.root)) revert UnknownRoot();
        if (!isKnownAspRoot(a.aspRoot)) revert UnknownAspRoot();

        uint256 n0 = a.nullifiers[0];
        uint256 n1 = a.nullifiers[1];
        // Defense in depth against nullifier malleability (the HonkVerifier also rejects inputs >= field).
        if (n0 >= FIELD_SIZE || n1 >= FIELD_SIZE) revert InvalidNullifier();
        if (n0 == n1) revert DuplicateNullifier();
        if (nullifierSpent[n0] || nullifierSpent[n1]) revert NullifierAlreadySpent();
        if (a.outCommitments[0] >= FIELD_SIZE || a.outCommitments[1] >= FIELD_SIZE) revert InvalidCommitment();
        if (block.timestamp > a.deadline) revert DeadlineExpired();
        if (a.publicOut >= U64_LIMIT || a.fee >= U64_LIMIT || a.deadline >= U64_LIMIT) revert ValueOutOfRange();
        if (a.fee > a.publicOut) revert FeeExceedsPublicOut();
        uint256 toRecipient = a.publicOut - a.fee;
        if (toRecipient != 0 && a.recipient == address(0)) revert ZeroRecipient();
        if (a.fee != 0 && a.relayer == address(0)) revert ZeroRelayer();

        if (!verifier.verify(proof, buildPublicInputs(a))) revert InvalidProof();

        nullifierSpent[n0] = true;
        emit NewNullifier(n0);
        nullifierSpent[n1] = true;
        emit NewNullifier(n1);

        uint32 index0 = _insert(a.outCommitments[0]);
        emit NewCommitment(a.outCommitments[0], index0, a.encryptedOutput0);
        uint32 index1 = _insert(a.outCommitments[1]);
        emit NewCommitment(a.outCommitments[1], index1, a.encryptedOutput1);

        if (toRecipient != 0) _transferOut(a.recipient, toRecipient);
        if (a.fee != 0) _transferOut(a.relayer, a.fee);

        emit Transacted(a.relayer, a.recipient, a.publicOut, a.fee);
    }

    function buildPublicInputs(TransactArgs calldata a) public view returns (bytes32[] memory inputs) {
        uint256 domain = uint256(DOMAIN_SEPARATOR);
        inputs = new bytes32[](NUM_PUBLIC_INPUTS);
        inputs[0] = bytes32(a.root);
        inputs[1] = bytes32(a.aspRoot);
        inputs[2] = bytes32(a.nullifiers[0]);
        inputs[3] = bytes32(a.nullifiers[1]);
        inputs[4] = bytes32(a.outCommitments[0]);
        inputs[5] = bytes32(a.outCommitments[1]);
        inputs[6] = bytes32(a.publicOut);
        inputs[7] = bytes32(extDataHash(a.relayer, a.encryptedOutput0, a.encryptedOutput1));
        inputs[8] = bytes32(uint256(uint160(address(token))));
        inputs[9] = bytes32(uint256(uint160(a.recipient)));
        inputs[10] = bytes32(a.fee);
        inputs[11] = bytes32(a.deadline);
        inputs[12] = bytes32(domain >> 128);
        inputs[13] = bytes32(domain & LOW_128_MASK);
    }
```

---

*Bu rapor Claude Code tarafından hazırlandı. Ürün vizyonu, kapsam kararı ("tam ZK havuzu, riski alıyorum") ve veri sağlayıcı seçimi Semih’e aittir; uygulama ayrıntılarındaki öneriler ADR’lerde "onay bekliyor" olarak işaretlidir.*
