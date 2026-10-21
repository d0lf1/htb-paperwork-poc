#!/usr/bin/env python3
"""
Archive_Printer - LPD (Line Printer Daemon, RFC 1179) server.

Versione corretta e FUNZIONANTE del server.py leakato dallo zip
`paperwork-archive-v1.02.zip` sulla macchina HTB "PaperWork".

Rispetto all'originale sono stati corretti SOLO i bug che ne impedivano
l'avvio (import mancante, import duplicato, blocco `if` con indentazione
rotta). La logica applicativa - inclusa la vulnerabilita' di command
injection - e' stata mantenuta identica, in modo che l'exploit sviluppato
contro il target reale sia riproducibile 1:1 in locale.

Avvio:
    LPD_QUEUE="Archive_Printer" python3 server_fixed.py
"""

import os
import socket
import threading
import subprocess

# Coda valida. Sul target reale viene passata via variabile d'ambiente;
# qui usiamo un default cosi' il server e' eseguibile standalone.
VALID_QUEUE = os.environ.get("LPD_QUEUE", "Archive_Printer")


class LpdHandler(threading.Thread):
    """Gestisce una singola connessione LPD in un thread dedicato."""

    def __init__(self, sock, addr):
        super().__init__()
        self.sock = sock
        self.addr = addr
        self.id = f"[lpd-{addr[1]}]"

    def run(self):
        try:
            data = self.sock.recv(1024)
            if not data:
                return

            # Primo byte = comando LPD (RFC 1179, sez. "Daemon commands").
            command = data[0]

            if command == 2:                      # 0x02 = Receive a printer job
                self.handle_print_job(data)
            elif command in (3, 4):               # 0x03/0x04 = Send queue state
                self.sock.send(b"Archive_Printer is ready and printing.\n")

        except Exception as e:
            print(f"{self.id} Error: {e}")
        finally:
            self.sock.close()

    def handle_print_job(self, data):
        # Dopo il byte di comando segue il nome della coda + LF.
        queue = data[1:].decode().strip()

        # NB: `not in` su una stringa fa un match di sottostringa, non un
        # confronto esatto. Basta che `queue` sia sottostringa di VALID_QUEUE.
        if queue not in VALID_QUEUE:
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01')               # ACK negativo
            return

        print(f"{self.id} Accepted job for queue: {queue}")

        while True:
            chunk = self.sock.recv(1024)
            if not chunk:
                break

            subcommand = chunk[0]
            self.sock.send(b'\x00')               # ACK positivo del sub-comando

            # 0x02 = "Receive control file" (RFC 1179, sez. "Receive a printer job").
            # Il control file contiene i metadati del job (host, utente, nome job...).
            if subcommand == 2:
                parts = chunk[1:].decode(errors='ignore').split()
                if not parts:
                    continue

                # parts[0] = numero di byte del control file da leggere.
                size = int(parts[0])
                content = b""
                while len(content) < size:
                    content += self.sock.recv(size - len(content) + 1)

                decoded_content = content.decode(errors='ignore')

                # La riga che inizia con 'J' e' il "Job name for banner page".
                job_name = "Unknown"
                for line in decoded_content.split('\n'):
                    line = line.strip()
                    if line.startswith('J'):
                        job_name = line[1:]
                        break

                print(f"{self.id} Executing archive for: {job_name}")

                # >>> VULNERABILITA' <<<
                # job_name e' controllato dall'attaccante e finisce, senza
                # sanitizzazione, in un comando shell con shell=True.
                # -> command injection (rompendo il singolo apice).
                subprocess.Popen(
                    f"echo 'Archive: {job_name}' >> /tmp/archive.log",
                    shell=True
                )

                self.sock.send(b'\x00')
                self.sock.send(b'\x00')
                while self.sock.recv(4096):
                    pass
                break


class LpdServer:

    def __init__(self, ip='0.0.0.0', port=1515):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((ip, port))
        self.server.listen(100)
        print(f"[*] LPD Server listening on {port}")

    def run(self):
        while True:
            sock, addr = self.server.accept()
            LpdHandler(sock, addr).start()


if __name__ == "__main__":
    LpdServer(port=1515).run()
