import sys
from impacket import smbserver

def configure_shares(server):
    shares = ["IPC$", "ADMIN$", "C$", "PRINT$", "FAX$", "NETLOGON", "SYSVOL"]
    for share in shares:
        server.removeShare(share)

log_filename = "log.txt"
if len(sys.argv) >= 2:
    log_filename = sys.argv[1]
port = 445
if len(sys.argv) >= 3:
    port = int(sys.argv[2])

server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
server.setSMB2Support(True)
configure_shares(server)
server.setSMBChallenge('')
server.setLogFile(log_filename)
server.start()
