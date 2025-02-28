import nmap

class Nmapping:
    def host_discovery(target):
        nm = nmap.PortScanner()
        nm.scan(hosts=target, arguments='-sn')
        return nm.all_hosts()

    def port_scan(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sS')
        return nm[target]['tcp'] if target in nm.all_hosts() else {}

    def service_version_scan(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sV')
        return nm[target]['tcp'] if target in nm.all_hosts() else {}

    def os_detection(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-O')
        return nm[target]['osmatch'] if target in nm.all_hosts() else []

    def network_mapping(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='--traceroute')
        return nm[target]['trace'] if target in nm.all_hosts() else {}

    def script_scan(target, script):
        nm = nmap.PortScanner()
        nm.scan(target, arguments=f'--script {script}')
        return nm[target] if target in nm.all_hosts() else {}

    def firewall_evasion(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-f')
        return nm.all_hosts()

    def aggressive_scan(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-A')
        return nm[target] if target in nm.all_hosts() else {}

    def stealth_scan(target):
        nm = nmap.PortScanner()
        nm.scan(target, arguments='-sN')
        return nm[target] if target in nm.all_hosts() else {}
