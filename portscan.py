import nmap
import optparse

def nmapScan(tgtHost, tgtPort):
    nmScan = nmap.PortScanner()
    nmScan.scan(tgtHost, tgtPort)
    state=nmScan[tgtHost]['tcp'][int(tgtPort)]['state']
    print("[*] " + tgtHost + " tcp/" + tgtPort + " " + state)

def getHostPort():
    parser = optparse.OptionParser("Usage : -H <target_host> -p <target_port>")
    parser.add_option("-H", dest="tgtHost", type="string", help="Please Specify Target Host !")
    parser.add_option("-p", dest="tgtPort", help="Please Specify Target Port !")
    (options, args) = parser.parse_args()
    if not options.tgtHost:
        parser.error("Please specify a target host !")
    elif not options.tgtPort:
        parser.error("Please specify a target port !")
    return options


retVal = getHostPort()
tgtHost = retVal.tgtHost
tgtPort = retVal.tgtPort

nmapScan(tgtHost, tgtPort)
