import sys
from impacket import smbserver

log_filename = "log.txt"
if len(sys.argv) >= 2:
    log_filename = sys.argv[1]
port = 445
if len(sys.argv) >= 3:
    port = int(sys.argv[2])

server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
server.setSMB2Support(True)
server.addShare("interactsh", "/interactsh")
server.setSMBChallenge('')
server.setLogFile(log_filename)
server.start()
