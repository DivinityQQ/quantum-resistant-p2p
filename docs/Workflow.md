# Quantum Resistant P2P - Uživatelský manuál

## Obsah

1. [Úvod](#úvod)  
2. [Prvotní spuštění](#prvotní-spuštění)  
3. [Hlavní okno programu](#hlavní-okno-programu)  
4. [Záložka File](#záložka-file)  
   - [Connect to Peer](#connect-to-peer)  
   - [Send File](#send-file)  
   - [Change Password](#change-password)  
5. [Záložka Settings](#záložka-settings)  
   - [Cryptography Settings](#cryptography-settings)  
   - [Security Metrics](#security-metrics)  
     - [Algorithms](#algorithms)  
     - [Usage Metrics](#usage-metrics)  
     - [Event Summary](#event-summary)  
   - [Key Exchange History](#key-exchange-history)  
   - [View Logs](#view-logs)  
6. [Příklady scénářů použití](#příklady-scénářů-použití)  
   - [Scénář 1](#scénář-1)  
   - [Scénář 2](#scénář-2)  
   - [Scénář 3](#scénář-3)  
7. [Řešení problémů](#řešení-problémů)  
   - [Nelze nalézt stanici](#nelze-nalézt-stanici)  
   - [Odlišné kryptografické nastavení](#odlišné-kryptografické-nastavení)  
   - [Zapomenuté heslo](#zapomenuté-heslo)  

---

## Úvod

Tento dokument slouží k seznámení uživatele s programem **Quantum Resistant P2P**. Popisuje jeho funkce, nastavení a řešení možných problémů.

## Prvotní spuštění

Při prvním spuštění je uživatel vyzván k zadání hesla pro šifrování záznamů. Stejné heslo bude použito při každém dalším spuštění k dešifrování těchto záznamů.

![Prvotní Spuštění](WorkflowScreens/Unlock.png)
## Hlavní okno programu
- Levá část: seznam zařízení (peerů).
- Pravá část: zobrazuje šifrování lokálního i vzdáleného zařízení.
- Tlačítka:
  - **Use Peer Settings** – nastaví stejné šifrování jako peer.
  - **Establish Shared Key** – provede výměnu klíčů.
- Pod tlačítky: výpis akcí a zpráv.
- Spodní část: textové pole pro zprávy.

## Záložka File

![Záložka File](WorkflowScreens/File.png)
Obsahuje tyto funkce:
- **Connect to Peer** – ruční zadání IP adresy.
- **Send File** – odeslání souboru.
- **Change Password** – změna hesla pro šifrování logů.

### Connect to Peer

Zadání IP adresy zařízení, se kterým se uživatel chce spojit.
![Connect to Peer](WorkflowScreens/CtP.png)

### Send File

Umožňuje odeslat soubor přes šifrované spojení pomocí Průzkumníka Windows.
![Send File](WorkflowScreens/Send%20File.png)
### Change Password

Změna hesla bez ztráty logů nebo konfigurace stanic.

![Change Password](WorkflowScreens/Change%20Password.png)
## Záložka Settings

Obsahuje:
- **Cryptography Settings**
- **Security Metrics**
- **View Logs**
- **Key Exchange History**
![Záložka Settings](WorkflowScreens/Settings.png)
### Cryptography Settings

Nastavení algoritmů:
- Výměna klíče (např. NTRU – pouze mock).
- Symetrické šifrování.
- Digitální podpis.

![Cryptography Settings](WorkflowScreens/Cryptography%20Settings.png)

![Cryptography Settings](WorkflowScreens/Key%20Exhange.png)

![Cryptography Settings](WorkflowScreens/Symmetric%20Encryption.png)

![Cryptography Settings](WorkflowScreens/Digital%20Signature.png)
### Security Metrics


#### Algorithms

![Algorithms](WorkflowScreens/Security%20Metrics%Algorithms.png)

Zobrazuje aktuální algoritmy, počet peerů a jejich popisy.

#### Usage Metrics

Eviduje:
- Počet událostí, klíčů, zpráv a přenosů.
- Velikost dat.
- Časy první/poslední aktivity.
- Použití algoritmů.

![Usage Metrics](WorkflowScreens/Security%20Metrics%Usage%20Metrics.png)

#### Event Summary

Zkrácený přehled o:
- Inicializaci
- Připojeních
- Výměnách klíčů
- Odeslaných/přijatých zprávách
- Změnách nastavení

![Event Summary](WorkflowScreens/Security%20Metrics%Event%20Summary.png)

### Key Exchange History

Historie použitých klíčů. Možnost dešifrovat a zobrazit klíče ve formátech Hex, Base64 nebo decimálně.
![Key Exchange History](WorkflowScreens/Key%20Echange%History.png)

![Key Exchange History](WorkflowScreens/Key%20Echange%History%20Confirmation.png)

![Key Exchange History](WorkflowScreens/Key%20Echange%History%20Show%20Key.png)
### View Logs

Záznamy o typech zpráv, časech, odesílatelích a filtrech.  
Možnost vymazání všech logů.

![View Logs](WorkflowScreens/View%20Logs.png)

![View Logs](WorkflowScreens/Clear%20All%20Logs.png)
## Příklady scénářů použití

### Scénář 1

![Scénář 1](WorkflowScreens/Scenario%201.png)
Automatická výměna klíčů při připojení k zařízení ve stejné síti.  
Následná bezpečná komunikace.

### Scénář 2

Změna algoritmů před zahájením komunikace.  
Pomocí tlačítka **Crypto Settings** lze nastavení synchronizovat s peerem.

![Scénář 2](WorkflowScreens/Scenario%202.png)
### Scénář 3

Po změně zabezpečení druhé strany se komunikace přeruší.  
Obnoví se pomocí **Use Peer Settings** a **Establish Shared Key**.

![Scénář 3](WorkflowScreens/Scenario%203.png)
## Řešení problémů

### Nelze nalézt stanici

- Zkontrolujte síť a napájení zařízení.
- Vyčkejte ~30 s, nebo použijte **Connect to Peer**.

![Nelze nalézt stanici](WorkflowScreens/Issue%201.png)
### Odlišné kryptografické nastavení

- Komunikace se přeruší.
- Použijte **Use Peer Settings** a následně **Establish Shared Key**.

![Odlišné kryptografické nastavení](WorkflowScreens/Issue%202%20-%201.png)

![Odlišné kryptografické nastavení](WorkflowScreens/Issue%202%20-%202.png)

![Odlišné kryptografické nastavení](WorkflowScreens/Issue%202%20-%203.png)

![Odlišné kryptografické nastavení](WorkflowScreens/Issue%202%20-%204.png)

![Odlišné kryptografické nastavení](WorkflowScreens/Issue%202%20-%205.png)
### Zapomenuté heslo

- Lze zkusit zadat znovu nebo resetovat.
- Při resetu dojde k **nevratnému vymazání logů a konfigurace**.

![Zapomenuté heslo](WorkflowScreens/Issue%201%20-%201.png)

![Zapomenuté heslo](WorkflowScreens/Issue%201%20-%202.png)
