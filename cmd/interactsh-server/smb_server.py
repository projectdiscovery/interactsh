import sys
from impacket import smbserver

server = smbserver.SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)
server.setSMB2Support(True)
server.addShare("interactsh", "/interactsh")
server.setSMBChallenge('')
server.setLogFile(sys.argv[1])
server.start()