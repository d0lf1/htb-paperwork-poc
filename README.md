# HTB · PaperWork — PoC

Proof-of-concept per la macchina **PaperWork** (Hack The Box, Season 11).
Writeup completo: https://blog.ldsec.it/paperwork/

**Catena:** OS command injection su un LPD custom (RFC 1179, porta 1515) →
RCE come `lp` → PJL path traversal (porta 9100) → `archivist` →
fd-leak via `SCM_RIGHTS` da un daemon root → root.

| File | Ruolo |
|------|-------|
| `exploit.py` | Command injection sul daemon LPD → RCE / reverse shell (foothold `lp`) |
| `server.py` | Sorgente originale leakato dal web server (bacato di proposito) |
| `server_fixed.py` | Build ricostruita e funzionante per i test locali |
| `pjl_pwn.py` | Helper PJL per il pivot `lp → archivist` (FSUPLOAD/FSDOWNLOAD + traversal) |
| `sock_pwn.py` | Exploit SCM_RIGHTS fd-leak per il pivot `archivist → root` |
| `open_ports.txt` | Output della scansione porte |

> ⚠️ Solo a scopo educativo e per testing autorizzato.

## Licenza e uso autorizzato

Distribuito sotto licenza [MIT](LICENSE).

Codice proof-of-concept pubblicato a scopo educativo e di ricerca, come
companion dei writeup su <https://blog.ldsec.it>. Sviluppato ed eseguito
esclusivamente contro una macchina di laboratorio volutamente vulnerabile, in
un contesto isolato e autorizzato. Usalo solo su sistemi di cui sei proprietario
o per i quali hai un'autorizzazione esplicita a eseguire test di sicurezza.
