package examples;

import java.io.Closeable;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;

import javax.xml.bind.DatatypeConverter;

import pcap.Convert;
import pcap.Pcap;
import pcap.Threads;

public class GetMacAddresses {

	public static final String MYINTERFACE = "\\Device\\NPF_{51306AE4-88CB-41EA-9B10-AA87F5C4076D}";
	public static final String DESTINATIONIP = "192.168.1.64";
	private static String sourceMac;
	private static ArrayList<String> addresses = new ArrayList<String>();
	
	public static void main(String[] args) {
		sourceMac = Convert.bytes2hex(Pcap.get(MYINTERFACE).getLinkLayerAddresses().get(0).getAddress());			
			try{
				System.out.println("Processing...");
				runAddressListener();
			}
			catch(IOException exep){
				 System.out.println(exep.getMessage());
			}			
			printResults();
	}
	
	private static void printResults(){
		for (String address : addresses) {
			 System.out.println(address);
		}
	}
	
	private static void sendArpToAll(){
		for(int i = 1; i < 256; i++){	
			sendArpRequest("192.168.1."+Integer.toString(i));					
		}
	}
	
	private static void sendArpRequest(String targetIpDec){			     
	       String targetMac = "ff:ff:ff ff:ff:ff";
	       String sourceIp  = Convert.dec2hex(DESTINATIONIP);
	       String targetIp  = Convert.dec2hex(targetIpDec);
		
		   byte[] packet = Convert.hex2bytes( // ----- Ethernet
	                targetMac,                 // Destination: ff:ff:ff:ff:ff:ff
	                sourceMac,                 // Source: __:__:__:__:__:__
	                "08 06",                   // Type: ARP (0x0806)
	                                           // ----- ARP
	                "00 01",                   // Hardware type: Ethernet (1)
	                "08 00",                   // Protocol type: IPv4 (0x0800)
	                "06",                      // Hardware size: 6
	                "04",                      // Protocol size: 4
	                "00 01",                   // Opcode: request (1)
	                sourceMac,                 // Sender MAC address: 6 bytes
	                sourceIp,                  // Sender IP address:  4 bytes
	                targetMac,                 // Target MAC address: 6 bytes
	                targetIp                   // Target IP address:  4 bytes
	        );
	
	        Pcap.send(MYINTERFACE, packet);
	}
	
	private static void runAddressListener() throws IOException{
		 Closeable c  = Pcap.listen(MYINTERFACE, new Pcap.Listener() {
	            public void onPacket(byte[] bytes) {
	                if(responseIsArp(Convert.bytes2hex(bytes))){
	                	addResponseAddress(Convert.bytes2hex(bytes));	               
	                }
	            }
	        });
		 sendArpToAll();
		 Threads.sleep(100);
		 c.close();
	}
	
	private static void addResponseAddress(String packetHex){		
			try {
				String ip = packetHex.substring(84, 95).replaceAll("\\s+","");
				ip  = InetAddress.getByAddress(DatatypeConverter.parseHexBinary(ip)).getHostAddress();
				addresses.add("IP: " + ip + ", MAC: " + packetHex.substring(18, 35).replace(" ", ":"));
			} catch (UnknownHostException e) {			
				e.printStackTrace();
			}					
	}
	
	private static boolean responseIsArp(String packetHex){
		if(packetHex != null && packetHex.length() == 125){					
			String recivedMac = packetHex.substring(0, 17);
			if(recivedMac.equals(sourceMac)){
				return true;
			}
		}
		return false;
	}
}
