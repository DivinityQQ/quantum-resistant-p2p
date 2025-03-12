# Kontrolní studie: P2P aplikace s postkvantovou kryptografií

## 1. Úvod a popis projektu

Tento projekt se zabývá návrhem a implementací peer-to-peer aplikace umožňující zabezpečenou komunikaci pomocí technik postkvantové kryptografie. S nástupem kvantových počítačů budou tradiční kryptografické algoritmy, jako jsou RSA a ECC, považovány za nedostatečně bezpečné, jelikož kvantové algoritmy (zejména Shorův algoritmus) mohou efektivně řešit problémy faktorizace celých čísel a diskrétního logaritmu, na kterých jsou tyto algoritmy založeny.

Aplikace umožní uživatelům navazovat přímá spojení s jinými uživateli v síti, bez nutnosti centrálního serveru, a provádět tři základní kryptografické operace:

1. **Výměna tajného klíče** prostřednictvím postkvantových algoritmů založených na veřejném klíči
2. **Důvěrný přenos dat** šifrovaný pomocí symetrických algoritmů 
3. **Podepisování dat** s využitím postkvantových podpisových algoritmů

Aplikace bude nabízet více algoritmů pro každou z těchto operací, takže uživatelé si budou moci vybrat konkrétní algoritmus podle svých potřeb. Operace budou logovány a logy i klíče budou bezpečně uloženy.

## 2. Cíle projektu

Hlavní cíle projektu jsou:

1. **Vytvořit funkční P2P komunikační síť**, která umožní přímou komunikaci mezi uživateli bez centrálního serveru
2. **Implementovat postkvantové algoritmy** pro výměnu klíčů a digitální podpisy
3. **Umožnit důvěrnou komunikaci** prostřednictvím symetrických šifrovacích algoritmů
4. **Poskytnout uživatelsky přívětivé rozhraní** pro výběr kryptografických algoritmů a správu komunikace
5. **Implementovat bezpečné logování** kryptografických operací s důrazem na ochranu citlivých informací
6. **Zajistit bezpečné ukládání klíčů a logů** na lokálním zařízení

Měřitelné cíle projektu:
- Úspěšná implementace minimálně dvou algoritmů pro každou z kryptografických operací
- Dosažení přenosové rychlosti dostatečné pro běžnou komunikaci a přenos souborů
- Vytvoření intuitivního uživatelského rozhraní s možností volby algoritmů a parametrů zabezpečení
- Implementace robustního systému logování s vhodnou granularitou informací

## 3. Teoretická část

### 3.1 Postkvantová kryptografie

Postkvantová kryptografie (PQC) označuje kryptografické systémy, které jsou považovány za odolné vůči útokům pomocí kvantových počítačů. Tradiční kryptografické algoritmy, jako jsou RSA, DSA a ECC, jsou založeny na matematických problémech, které lze efektivně řešit pomocí kvantových algoritmů, zejména Shorova algoritmu. Aby byly kryptografické systémy bezpečné i v éře kvantových počítačů, je nutné je postavit na jiných matematických problémech, které jsou považovány za obtížné i pro kvantové počítače.

Hlavní směry postkvantové kryptografie zahrnují:

#### 3.1.1 Kryptografie založená na mřížkách (Lattice-based Cryptography)

Kryptografické systémy založené na mřížkách využívají obtížnost problémů spojených s mřížkami v n-dimenzionálním prostoru. Mezi tyto problémy patří problém nejkratšího vektoru (SVP), problém nejbližšího vektoru (CVP) a Learning With Errors (LWE). Výhodou těchto systémů je jejich relativní efektivita a silná matematická základna. Algoritmy jako CRYSTALS-KYBER a NTRU patří do této kategorie.

**CRYSTALS-KYBER** je algoritmus pro ustanovení klíče založený na problému Module Learning With Errors (MLWE). Tento problém je variantou problému LWE, která využívá modulární strukturu pro zlepšení efektivity. KYBER nabízí dobrou rovnováhu mezi velikostí klíčů, rychlostí a bezpečností.

**NTRU** (N-th degree TRUncated polynomial ring) je jeden z nejstarších postkvantových kryptosystémů. Byl vyvinut v roce 1996 a je založen na problému hledání krátkých vektorů v mřížkách. NTRU je rychlý a má relativně malé veřejné klíče ve srovnání s jinými postkvantovými algoritmy.

**FrodoKEM** je konzervativnější přístup, který nepřidává další algebraickou strukturu k problému LWE. Tím se vyhýbá potenciálním slabinám strukturovaných variant, ale za cenu větších klíčů a nižší efektivity.

#### 3.1.2 Kryptografie založená na kódech (Code-based Cryptography)

Tyto systémy jsou založeny na obtížnosti dekódování náhodných lineárních kódů. Nejznámějším příkladem je McElieceův kryptosystém, který byl navržen již v roce 1978. Systémy založené na kódech mají obvykle velké veřejné klíče, ale nabízejí rychlé šifrování a dešifrování.

**Classic McEliece** je moderní implementace McElieceova kryptosystému, která používá Goppaovy kódy. Jedná se o jeden z nejdéle studovaných postkvantových algoritmů s velmi silnými bezpečnostními zárukami.

#### 3.1.3 Kryptografie založená na hashovacích funkcích (Hash-based Cryptography)

Podpisové systémy založené na hashovacích funkcích, jako jsou Lamportův jednorazový podpis, Merkleovy stromy a jejich modernější varianty (XMSS, SPHINCS+), nabízejí silné bezpečnostní záruky. Jejich bezpečnost je založena pouze na vlastnostech hashovacích funkcí, což je činí velmi důvěryhodnými.

**SPHINCS+** je bezstavový hashovací podpisový systém, který kombinuje několik různých technik k vytvoření praktického podpisového schématu. Jeho bezpečnost závisí pouze na vlastnostech použitých hashovacích funkcí.

#### 3.1.4 Kryptografie založená na multivariantních polynomech (Multivariate Cryptography)

Tyto systémy jsou založeny na obtížnosti řešení systémů multivariantních polynomiálních rovnic nad konečnými tělesy. Jsou obecně efektivní pro ověřování podpisů, ale mají velké veřejné klíče.

**Rainbow** je multivariantní podpisové schéma, které nabízí velmi rychlé ověřování podpisů a krátké podpisy. Je založeno na struktuře olejovo-octových polynomů (Oil and Vinegar).

#### 3.1.5 Kryptografie založená na izogeniích (Isogeny-based Cryptography)

Systémy založené na izogeniích mezi supersingulárními eliptickými křivkami představují novější směr v postkvantové kryptografii. Nabízejí nejmenší velikosti klíčů ze všech postkvantových kandidátů, ale jsou výpočetně náročnější.

**SIKE** (Supersingular Isogeny Key Encapsulation) je algoritmus pro ustanovení klíče založený na problému hledání izogenií mezi supersingulárními eliptickými křivkami. Vyniká velmi malými veřejnými klíči, ale je výpočetně náročnější než jiné metody.

### 3.2 Symetrická kryptografie v post-kvantovém prostředí

I když je symetrická kryptografie považována za relativně odolnou vůči kvantovým útokům, Groverův algoritmus může poskytnout kvadratické zrychlení při hledání klíčů hrubou silou. Proto je doporučeno zdvojnásobit délku klíčů pro symetrické algoritmy v postkvantovém prostředí.

**AES-256** (Advanced Encryption Standard) je široce používaný blokový šifrovací algoritmus s délkou klíče 256 bitů, který by měl poskytovat dostatečnou bezpečnost i proti kvantovým útokům.

**ChaCha20-Poly1305** je kombinace proudové šifry ChaCha20 a autentizačního kódu Poly1305. Je to moderní, rychlá a bezpečná alternativa k AES, která je obzvláště vhodná pro softwarové implementace.

### 3.3 Standardizace postkvantové kryptografie

Národní institut standardů a technologie USA (NIST) zahájil proces standardizace postkvantových kryptografických algoritmů v roce 2016. Tento proces je podobný předchozím soutěžím pro standardizaci AES a SHA-3. V červenci 2022 NIST oznámil první algoritmy vybrané pro standardizaci:

- CRYSTALS-KYBER pro ustanovení klíče
- CRYSTALS-DILITHIUM, FALCON a SPHINCS+ pro digitální podpisy

Proces standardizace pokračuje pro další kandidáty, včetně algoritmů založených na kódech a dalších přístupech.

### 3.4 Peer-to-Peer sítě

Peer-to-peer (P2P) sítě jsou distribuované systémy, kde každý uzel může fungovat jako klient i jako server. Hlavní charakteristiky P2P sítí zahrnují:

- **Decentralizace**: Neexistuje centrální server, který by řídil komunikaci
- **Škálovatelnost**: Síť se může efektivně rozrůstat s počtem uzlů
- **Robustnost**: Selhání jednoho uzlu neovlivní celou síť
- **Autonomie**: Uzly mohou nezávisle rozhodovat o svých zdrojích

Výzvy při implementaci P2P sítí zahrnují:
- Vyhledávání uzlů (peer discovery)
- NAT traversal (překonávání překladů síťových adres)
- Bezpečnost a důvěryhodnost
- Efektivní směrování zpráv

## 4. Aktuální stav řešení

### 4.1 Dosažené výsledky

Projekt je v počáteční fázi analýzy a návrhu. Byly identifikovány klíčové komponenty a požadavky na systém:

1. Byly vybrány vhodné kryptografické algoritmy pro implementaci:
   - Pro ustanovení klíče: CRYSTALS-KYBER, NTRU
   - Pro symetrické šifrování: AES-256, ChaCha20-Poly1305
   - Pro digitální podpisy: CRYSTALS-DILITHIUM, SPHINCS+

2. Byla navržena základní architektura aplikace:
   - Síťová vrstva pro P2P komunikaci
   - Kryptografická vrstva pro implementaci kryptografických algoritmů
   - Aplikační vrstva pro logiku aplikace
   - Prezentační vrstva pro uživatelské rozhraní

3. Byly identifikovány vhodné knihovny pro implementaci v Pythonu:
   - `liboqs` (Open Quantum Safe) pro postkvantové algoritmy
   - `pyca/cryptography` pro symetrické algoritmy
   - `socket` a `asyncio` pro síťovou komunikaci
   - `PyQt5` pro uživatelské rozhraní

### 4.2 Plán dalšího postupu

Další postup vývoje projektu zahrnuje následující kroky:

1. **Fáze I: Implementace základních komponent (2-3 týdny)**
   - Implementace síťové vrstvy pro P2P komunikaci
   - Integrace vybraných kryptografických knihoven
   - Návrh a implementace API pro kryptografickou vrstvu
   - Vytvoření základního rozhraní pro testování

2. **Fáze II: Implementace kryptografických funkcí (3-4 týdny)**
   - Implementace mechanismů pro výměnu klíčů
   - Implementace šifrovaného přenosu dat
   - Implementace digitálních podpisů
   - Implementace bezpečného ukládání klíčů a logů

3. **Fáze III: Vývoj uživatelského rozhraní (2-3 týdny)**
   - Návrh a implementace grafického uživatelského rozhraní
   - Implementace interaktivních prvků pro výběr algoritmů
   - Vizualizace informací o bezpečnosti a provedených operacích

4. **Fáze IV: Testování a optimalizace (2-3 týdny)**
   - Testování funkčnosti a bezpečnosti
   - Optimalizace výkonu a spotřeby zdrojů
   - Identifikace a oprava chyb
   - Zátěžové testování v simulovaném prostředí

5. **Fáze V: Finalizace a dokumentace (1-2 týdny)**
   - Dokončení implementace
   - Vytvoření uživatelské dokumentace
   - Vytvoření vývojářské dokumentace
   - Příprava na předání a zhodnocení projektu

## 5. Autoři a jejich přínos

**[Jméno autora]** - Hlavní vývojář projektu
- Návrh celkové architektury aplikace
- Výběr a implementace kryptografických algoritmů
- Vývoj síťové vrstvy pro P2P komunikaci
- Implementace bezpečného logování a ukládání klíčů
- Koordinace vývoje a dokumentace projektu

---

## Reference

1. Bernstein, D. J., & Lange, T. (2017). Post-quantum cryptography. Nature, 549(7671), 188-194.
2. NIST (2019). Status Report on the First Round of the NIST Post-Quantum Cryptography Standardization Process. NISTIR 8240.
3. Alagic, G., et al. (2022). Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process. NISTIR 8413.
4. Chen, L., et al. (2016). Report on Post-Quantum Cryptography. NISTIR 8105.
5. Grassl, M., et al. (2016). Applying Grover's algorithm to AES: quantum resource estimates. In Post-Quantum Cryptography (pp. 29-43).
6. Hoffstein, J., Pipher, J., & Silverman, J. H. (1998). NTRU: A ring-based public key cryptosystem. In Algorithmic number theory (pp. 267-288).
7. Paquin, C., Stebila, D., & Tamvada, G. (2020). Benchmarking post-quantum cryptography in TLS. In Post-Quantum Cryptography (pp. 72-91).
