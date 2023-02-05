# Router PPPoE password recovery tool
# Aleksei Polukhin ai.polukhin@yandex.ru
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.ppp.html

from scapy.all import *

class PPPoEServer(object):
    def __init__(self):
        #scapy.interfaces.show_interfaces()
        self.print_interfaces()
        if_index = int(input("\nFind your network adapter index and type here: "))
        self.iface = scapy.interfaces.dev_from_index(if_index)
        print("\nYou have selected:", self.iface.description, "with MAC:", self.iface.mac)
        print("\nWaiting PADI packet from router...")
        self.ac_name = "FAKE-PPPOE-SERVER-0000"
        self.sess_id = 0x0003
        self.creds_catched = False

    # Start sniffing
    def start(self):
        # lfilter: Python function applied to each packet to determine if further action may be done
        sniff(lfilter=self.filter_data, iface=self.iface)
        
    def print_interfaces(self):
        print("index  interace")
        for iface in IFACES.data:
            i = IFACES.data[iface]
            print(str(i.index).ljust(6), i.description)
        
    # Filter for PPPoE Data
    def filter_data(self, raw):
        if hasattr(raw, "type"):
            if raw.type == 0x8863: # PPPoED Discovery
                if raw.code == 0x09:
                    print("PADI catched, PADO sending...")
                    self.send_pado_packet(raw)
                elif raw.code == 0x19:
                    print("PADR catched, PADS sending...")
                    self.send_pads_packet(raw)
            elif raw.type == 0x8864: # Seance step
                if (raw.proto == 0xc021 and raw.dst == self.iface.mac):
                    if (raw.haslayer(scapy.layers.ppp.PPP_LCP_Configure)):
                        if raw.getlayer("PPP_LCP_Configure").code == 1:
                            print("PPPoE Discovery is successful, LCP negotiation...")
                            self.lcp_negotiaion(raw)
                elif raw.proto == 0xc023 and not self.creds_catched:
                    print("\nRouter credentials:")
                    self.parse_credentials(raw)
                    
    def get_host_uniq(self, raw):
        if raw.haslayer("PPPoED_Tags"):
            for tag in raw.getlayer("PPPoED_Tags").tag_list:
                if tag.tag_type == 259: # Host-Uniq tag
                    return tag.tag_value
        return
        
    
    def send_pado_packet(self, raw):
        self._host_uniq = self.get_host_uniq(raw)
        self._router_mac = raw.src
        _pado = Ether(src=self.iface.mac, dst=self._router_mac)/ \
        PPPoED(version=1, type=1, code=7, sessionid=0, len=38)/ \
        PPPoED_Tags(tag_list = [PPPoETag(tag_type='Host-Uniq', tag_value=self._host_uniq),
                                PPPoETag(tag_type='AC-Name', tag_value=self.ac_name),
                                PPPoETag(tag_type='Service-Name')])
        sendp(_pado, verbose=0, iface=self.iface)

    
    def send_pads_packet(self, raw):
        _pads = Ether(src=self.iface.mac, dst=self._router_mac)/ \
        PPPoED(version=1, type=1, code=0x65, sessionid=self.sess_id, len=38)/ \
        PPPoED_Tags(tag_list = [PPPoETag(tag_type='Service-Name'),
                                PPPoETag(tag_type='Host-Uniq', tag_value=self._host_uniq),
                                PPPoETag(tag_type='AC-Name', tag_value=self.ac_name)])
        sendp(_pads, verbose=0, iface=self.iface)
        
    def send_lcp_req(self, raw):
        _lcp_req = Ether(src=raw.dst, dst=raw.src)/ \
            PPPoE(version=1, type=1, code="Session", sessionid=self.sess_id, len=20)/ \
            PPP(proto="Link Control Protocol")/ \
            PPP_LCP_Configure(code="Configure-Request", id=0x1, len=18, options=[
            PPP_LCP_MRU_Option(type="Maximum-Receive-Unit", len=4, max_recv_unit=1492),
            PPP_LCP_Auth_Protocol_Option(type="Authentication-protocol", len=4, auth_protocol="Password authentication protocol", data=''), 
            PPP_LCP_Magic_Number_Option(type="Magic-number", len=6, magic_number=3933994892)])/ \
            Padding(load=b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
        sendp(_lcp_req, verbose=0, iface=self.iface)
    
    def send_lcp_ans(self, raw):
        raw.getlayer("PPP_LCP_Configure").code = 2
        raw.dst, raw.src = raw.src, raw.dst
        sendp(raw, verbose=0, iface=self.iface)
    
    def lcp_negotiaion(self, raw):
        # First we need to send request to router
        self.send_lcp_req(raw)
        # Then we need to answer an initial request
        self.send_lcp_ans(raw)
        
    def parse_credentials(self, raw):
        user = raw.getlayer("PPP_PAP_Request").username.decode('ascii')
        passwd = raw.getlayer("PPP_PAP_Request").password.decode('ascii')
        print("Username:", user)
        print("Password:", passwd)
        self.creds_catched = True
        print("\nPress Enter to exit...")
        if not input():
            quit()
            
if __name__ == "__main__":
    print("* Please make sure that you have set up the same VLAN number")
    print("at network adapter options that your router has at target PPPoE profile\n")
    print("** Please connect your network adapter to router WAN interface and power on router\n")
    n = PPPoEServer()
    n.start()