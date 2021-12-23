import sys
from impacket import smbserver

port = 445
if len(sys.argv) == 3:
    port = int(sys.argv[2])

server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=port)
server.setSMB2Support(True)
server.addShare("interactsh", "/interactsh")
server.setSMBChallenge('')
server.setLogFile(sys.argv[1])
server.start()
