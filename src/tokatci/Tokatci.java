/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package tokatci;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.jsoup.Connection.Response.*;
import java.util.*;
import java.net.*;

/**
 *
 * @author Ahmeth4n
 * coded by ahmeth4n

 */
public class Tokatci {
    
      
    
  static List<String> path = new ArrayList<String>();
  public static String url = "BURAYASITEGELECEK";


    public static void main(String[] args) throws IOException, InterruptedException{

        class xssTara{
                        Thread t10 = new Thread(){
                public void run(){                  

                    try {

                        Document doc = Jsoup.connect(url).get();
                        Elements links = doc.select("a[href]");
                        for (Element link : links) {
                            String href = link.attr("href");
                            if(href.contains("=")){
                                String[] parca = href.split("=");
                                String payload = "='><script>alert(1)</script>";
                                String xssGit = url + parca[0] + payload ;
                                 Document xss = Jsoup.connect(xssGit).get();
                                 String kaynak = (String)xss.toString();
                                 if(kaynak.contains(payload)){
                                     
                                     System.out.println("XSS VAR =>" + href);
                                      PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("xss.txt", true)));
                                        String test = "XSS Var ! =>" + xssGit;
                                         out.println(test);
                                        out.close();
                                     
                                 }
                                 else{
                                 System.out.println("XSS YOK => " + href);
                                 }
                                 
                            }
                            else{
                               System.out.println("XSS denenecek url bulunamadi..");
                                     }
                            System.out.println();
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(Tokatci.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }};
        }
         class portTara{

            Thread t4 = new Thread(){
                public void run(){                  
                    for (int port = 1; port <= 65535; port++) {
         try {
             for(int q = 0;q<=10;q++){
            Socket socket = new Socket();
            String parca = url.replace("http:","");
                        String parca2 = parca.replace("/","");
                        String parca3 = parca2.replace("/","");
            socket.connect(new InetSocketAddress(parca3, port), 1000);
            socket.close();
            }
          System.out.println("Port " + port + " aktif!");
           switch(port)
        {
            case 1: System.out.println("TCP Port Service Multiplexer (TCPMUX)");
                break;
            case 2: System.out.println("CompressNET Management Utility");
                break;
            case 3: System.out.println("CompressNET Compression Process");
                break;
            case 5: System.out.println("Remote job entry");
                break;
            case 7: System.out.println("Echo Protocol");
                break;
            case 9: System.out.println("Discard Protocol");
                break;
            case 11: System.out.println("Active Users (systat service)");
                break;
            case 13: System.out.println("Daytime Protocol (RFC 867)");
                break;
            case 17: System.out.println("Quote Of The Day");
                break;
            case 19: System.out.println("Character Generator Protocol");
                break;
            case 20: System.out.println("FTP data transfer");
                break;
            case 21: System.out.println("FTP control (command)");
                break;
            case 22: System.out.println("Secure Shell (SSH), secure logins, file transfers (SCP, SFTP)");
                break;
            case 23: System.out.println("Telnet protocol - unencrypted text communications");
                break;
            case 24: System.out.println("Priv-mail, any private mail system");
                break;
            case 25: System.out.println("Simple Mail Transfer Protocol (SMTP)");
                break;
            case 27: System.out.println("NSW User System FE");
                break;
            case 29: System.out.println("MSG ICP");
                break;
            case 33: System.out.println("Display Support Protocol");
                break;
            case 35: System.out.println("Any private printer server protocol");
                break;
            case 37: System.out.println("Time Protocol");
                break;
            case 39: System.out.println("Resource Location Protocol (RLP)");
                break;
            case 42: System.out.println("ARPA Host Name Server Protocol");
                break;
            case 43: System.out.println("WHOIS protocol");
                break;
            case 47: System.out.println("NI FTP");
                break;
            case 49: System.out.println("TACACS+ Login Host protocol");
                break;
            case 50: System.out.println("Remote Mail Checking Protocol");
                break;
            case 51: System.out.println("IMP Logical Address Maintenance");
                break;
            case 52: System.out.println("XNS (Xerox Network Systems) Time Protocol");
                break;
            case 53: System.out.println("Domain Name System (DNS)");
                break;
            case 54: System.out.println("Xerox Network Systems (XNS) clearinghouse");
                break;
            case 55: System.out.println("ISI Graphics Language (ISI-GL)");
                break;
            case 56: System.out.println("Xerox Network Systems (XNS) authentication");
                break;
            case 57: System.out.println("Any private terminal access");
                break;
            case 58: System.out.println("Xerox Network Systems (XNS) Mail");
                break;
            case 64: System.out.println("CI (Travelport) (formerly Covia) Comms Integrator");
                break;
            case 67: System.out.println("Bootstrap Protocol (BOOTP) server or Dynamic Host Configuration Protocol (DHCP)");
                break;
            case 68: System.out.println("Bootstrap Protocol (BOOTP) client or Dynamic Host Configuration Protocol (DHCP)");
                break;
            case 69: System.out.println("Trivial File Transfer Protocol (TFTP)");
                break;
            case 70: System.out.println("Gopher protocol");
                break;
            case 71: System.out.println("NETRJS protocol");
                break;
            case 72: System.out.println("NETRJS protocol");
                break;
            case 73: System.out.println("NETRJS protocol");
                break;
            case 74: System.out.println("NETRJS protocol");
                break;
            case 77: System.out.println("Any private Remote job entry");
                break;
            case 79: System.out.println("Finger protocol");
                break;
            case 80: System.out.println("Hypertext Transfer Protocol (HTTP)");
                break;
            case 88: System.out.println("Kerberos authentication system");
                break;
            case 90: System.out.println("DNSIX Security Attribute Token Map");
                break;
            case 101: System.out.println("NIC host name");
                break;
            case 102: System.out.println("ISO Transport Service Access Point (TSAP)");
                break;
            case 104: System.out.println("ACR/NEMA Digital Imaging and Communications in Medicine (DICOM)");
                break;
            case 105: System.out.println("CCSO Nameserver Protocol (Qi/Ph)");
                break;
            case 107: System.out.println("Remote Telnet Service protocol");
                break;
            case 108: System.out.println("SNA Gateway Access Server");
                break;
            case 109: System.out.println("Post Office Protocol v2 (POP2)");
                break;
            case 110: System.out.println("Post Office Protocol v3 (POP3)");
                break;
            case 111: System.out.println("ONC RPC (Sun RPC)");
                break;
            case 113: System.out.println("Ident, authentication service/identification protocol");
                break;
            case 115: System.out.println("Simple File Transfer Protocol");
                break;
            case 118: System.out.println("Structured Query Language (SQL) Services");
                break;
            case 119: System.out.println("Network News Transfer Protocol (NNTP)");
                break;
            case 123: System.out.println("Network Time Protocol (NTP)");
                break;
            case 126: System.out.println("Formerly Unisys Unitary Login, renamed by Unisys to NXEdit");
                break;
            case 135: System.out.println("DCE endpoint resolution");
                break;
            case 137: System.out.println("NetBIOS Name Service");
                break;
            case 138: System.out.println("NetBIOS Datagram Service");
                break;
            case 139: System.out.println("NetBIOS Session Service");
                break;
            case 143: System.out.println("Internet Message Access Protocol (IMAP)");
                break;
            case 152: System.out.println("Background File Transfer Program (BFTP)");
                break;
            case 153: System.out.println("Simple Gateway Monitoring Protocol (SGMP)");
                break;
            case 156: System.out.println("SQL Service");
                break;
            case 162: System.out.println("Simple Network Management Protocol Trap (SNMPTRAP)");
                break;
            case 170: System.out.println("Print-srv, Network PostScript");
                break;
            case 175: System.out.println("VMNET (IBM z/VM, z/OS & z/VSE—Network Job Entry (NJE))");
                break;
            case 177: System.out.println("X Display Manager Control Protocol (XDMCP)");
                break;
            case 179: System.out.println("Border Gateway Protocol (BGP)");
                break;
            case 194: System.out.println("Internet Relay Chat (IRC)");
                break;
            case 199: System.out.println("SMUX, SNMP Unix Multiplexer");
                break;
            case 201: System.out.println("AppleTalk Routing Maintenance");
                break;
            case 209: System.out.println("Quick Mail Transfer Protocol");
                break;
            case 210: System.out.println("ANSI Z39.50");
                break;
            case 213: System.out.println("Internetwork Packet Exchange (IPX)");
                break;
            case 218: System.out.println("Message posting protocol (MPP)");
                break;
            case 220: System.out.println("Internet Message Access Protocol (IMAP), version 3");
                break;
            case 259: System.out.println("Efficient Short Remote Operations (ESRO)");
                break;
            case 262: System.out.println("Arcisdms");
                break;
            case 264: System.out.println("Border Gateway Multicast Protocol (BGMP)");
                break;
            case 280: System.out.println("http-mgmt");
                break;
            case 308: System.out.println("Novastor Online Backup");
                break;
            case 311: System.out.println("Mac OS X Server Admin");
                break;
            case 318: System.out.println("PKIX Time Stamp Protocol (TSP)");
                break;
            case 350: System.out.println("Mapping of Airline Traffic over Internet Protocol (MATIP) type A");
                break;
            case 351: System.out.println("Mapping of Airline Traffic over Internet Protocol (MATIP) type B");
                break;
            case 356: System.out.println("cloanto-net-1 (used by Cloanto Amiga Explorer and VMs)");
                break;
            case 366: System.out.println("On-Demand Mail Relay (ODMR)");
                break;
            case 369: System.out.println("Rpc2portmap");
                break;
            case 370: System.out.println("codaauth2, Coda authentication server");
                break;
            case 371: System.out.println("ClearCase albd");
                break;
            case 383: System.out.println("HP data alarm manager");
                break;
            case 384: System.out.println("A Remote Network Server System");
                break;
            case 387: System.out.println("AURP (AppleTalk Update-based Routing Protocol)[22]");
                break;
            case 389: System.out.println("Lightweight Directory Access Protocol (LDAP)");
                break;
            case 399: System.out.println("Digital Equipment Corporation DECnet (Phase V+) over TCP/IP");
                break;
            case 401: System.out.println("Uninterruptible power supply (UPS)");
                break;
            case 427: System.out.println("Service Location Protocol (SLP)");
                break;
            case 433: System.out.println("NNSP, part of Network News Transfer Protocol");
                break;
            case 434: System.out.println("Mobile IP Agent (RFC 5944)");
                break;
            case 443: System.out.println("Hypertext Transfer Protocol over TLS/SSL (HTTPS)");
                break;
            case 444: System.out.println("Simple Network Paging Protocol (SNPP), RFC 1568");
                break;
            case 445: System.out.println("Microsoft-DS Active Directory, Windows shares");
                break;
            case 464: System.out.println("Kerberos Change/Set password");
                break;
            case 465: System.out.println("URL Rendezvous Directory for SSM (Cisco protocol)");
                break;
            case 475: System.out.println("tcpnethaspsrv, Aladdin Knowledge Systems Hasp services");
                break;
            case 497: System.out.println("Dantz Retrospect");
                break;
            case 500: System.out.println("Internet Security Association and Key Management Protocol (ISAKMP) / Internet Key Exchange (IKE)");
                break;
            case 502: System.out.println("Modbus Protocol");
                break;
            case 504: System.out.println("Citadel, multiservice protocol for dedicated clients for the Citadel groupware system");
                break;
            case 510: System.out.println("FirstClass Protocol (FCP)");
                break;
            case 512: System.out.println("Rexec, Remote Process Execution");
                break;
            case 513: System.out.println("rlogin");
                break;
            case 514: System.out.println("Remote Shell, used to execute non-interactive commands on a remote system (Remote Shell, rsh, remsh)");
                break;
            case 515: System.out.println("Line Printer Daemon (LPD), print service");
                break;
            case 520: System.out.println("efs, extended file name server");
                break;
            case 524: System.out.println("NetWare Core Protocol (NCP)");
                break;
            case 530: System.out.println("Remote procedure call (RPC)");
                break;
            case 532: System.out.println("netnews");
                break;
            case 540: System.out.println("Unix-to-Unix Copy Protocol (UUCP)");
                break;
            case 542: System.out.println("commerce (Commerce Applications)");
                break;
            case 543: System.out.println("klogin, Kerberos login");
                break;
            case 544: System.out.println("kshell, Kerberos Remote shell");
                break;
            case 546: System.out.println("DHCPv6 client");
                break;
            case 547: System.out.println("DHCPv6 server");
                break;
            case 548: System.out.println("Apple Filing Protocol (AFP) over TCP");
                break;
            case 550: System.out.println("new-rwho, new-who");
                break;
            case 554: System.out.println("Real Time Streaming Protocol (RTSP)");
                break;
            case 556: System.out.println("Remotefs, RFS, rfs_server");
                break;
            case 563: System.out.println("NNTP over TLS/SSL (NNTPS)");
                break;
            case 587: System.out.println("e-mail message submission (SMTP)");
                break;
            case 591: System.out.println("FileMaker 6.0 (and later) Web Sharing (HTTP Alternate)");
                break;
            case 593: System.out.println("HTTP RPC Ep Map");
                break;
            case 601: System.out.println("Reliable Syslog Service");
                break;
            case 604: System.out.println("TUNNEL profile");
                break;
            case 631: System.out.println("Internet Printing Protocol (IPP)");
                break;
            case 635: System.out.println("RLZ DBase");
                break;
            case 636: System.out.println("Lightweight Directory Access Protocol over TLS/SSL (LDAPS)");
                break;
            case 639: System.out.println("MSDP, Multicast Source Discovery Protocol");
                break;
            case 641: System.out.println("SupportSoft Nexus Remote Command (control/listening)");
                break;
            case 643: System.out.println("SANity");
                break;
            case 646: System.out.println("Label Distribution Protocol (LDP)");
                break;
            case 647: System.out.println("DHCP Failover protocol");
                break;
            case 648: System.out.println("Registry Registrar Protocol (RRP)");
                break;
            case 651: System.out.println("IEEE-MMS");
                break;
            case 653: System.out.println("SupportSoft Nexus Remote Command");
                break;
            case 654: System.out.println("Media Management System (MMS) Media Management Protocol (MMP)");
                break;
            case 657: System.out.println("IBM RMC (Remote monitoring and Control) protocol");
                break;
            case 660: System.out.println("Mac OS X Server administration");
                break;
            case 674: System.out.println("Application Configuration Access Protocol (ACAP)");
                break;
            case 688: System.out.println("REALM-RUSD (ApplianceWare Server Appliance Management Protocol)");
                break;
            case 690: System.out.println("Velneo Application Transfer Protocol (VATP)");
                break;
            case 691: System.out.println("MS Exchange Routing");
                break;
            case 694: System.out.println("Linux-HA high-availability heartbeat");
                break;
            case 695: System.out.println("IEEE Media Management System over SSL (IEEE-MMS-SSL)");
                break;
            case 700: System.out.println("Extensible Provisioning Protocol (EPP)");
                break;
            case 701: System.out.println("Link Management Protocol (LMP)");
                break;
            case 702: System.out.println("IRIS (Internet Registry Information Service) over BEEP");
                break;
            case 706: System.out.println("Secure Internet Live Conferencing (SILC)");
                break;
            case 711: System.out.println("Cisco Tag Distribution Protocol");
                break;
            case 712: System.out.println("Topology Broadcast based on Reverse-Path Forwarding routing protocol (TBRPF)");
                break;
            case 749: System.out.println("Kerberos (protocol) administration");
                break;
            case 753: System.out.println("Reverse Routing Header (RRH)");
                break;
            case 754: System.out.println("tell send");
                break;
            case 800: System.out.println("mdbs-daemon");
                break;
            case 830: System.out.println("NETCONF over SSH");
                break;
            case 831: System.out.println("NETCONF over BEEP");
                break;
            case 832: System.out.println("NETCONF for SOAP over HTTPS");
                break;
            case 833: System.out.println("NETCONF for SOAP over BEEP");
                break;
            case 847: System.out.println("DHCP Failover protocol");
                break;
            case 848: System.out.println("Group Domain Of Interpretation (GDOI) protocol");
                break;
            case 860: System.out.println("iSCSI (RFC 3720)");
                break;
            case 861: System.out.println("OWAMP control (RFC 4656)");
                break;
            case 862: System.out.println("TWAMP control (RFC 5357)");
                break;
            case 873: System.out.println("rsync file synchronization protocol");
                break;
            case 902: System.out.println("ideafarm-door (IdeaFarm (tm) Operations)");
                break;
            case 903: System.out.println("ideafarm-panic (IdeaFarm (tm) Operations)");
                break;
            case 989: System.out.println("FTPS Protocol (data), FTP over TLS/SSL");
                break;
            case 990: System.out.println("FTPS Protocol (control), FTP over TLS/SSL");
                break;
            case 991: System.out.println("Netnews Administration System (NAS)");
                break;
            case 992: System.out.println("Telnet protocol over TLS/SSL");
                break;
            case 993: System.out.println("Internet Message Access Protocol over TLS/SSL (IMAPS)");
                break;
            case 994: System.out.println("Internet Relay Chat over TLS/SSL (IRCS)");
                break;
            case 995: System.out.println("Post Office Protocol 3 over TLS/SSL (POP3S)");
                break;
            case 1025: System.out.println("Microsoft RPC");
                break;
            case 1080: System.out.println("SOCKS Proxy");
                break;
            case 1194: System.out.println("OpenVPN");
                break;
            case 1241: System.out.println("Nessus");
                break;
            case 1311: System.out.println("Dell OpenManage");
                break;
            case 1433: System.out.println("Microsoft SQL");
                break;
            case 1434: System.out.println("Microsoft SQL");
                break;
            case 1512: System.out.println("WINS");
                break;
            case 1589: System.out.println("Cisco VQP");
                break;
            case 1701: System.out.println("L2TP");
                break;
            case 1723: System.out.println("MS PPTP");
                break;
            case 1741: System.out.println("CiscoWorks 2000");
                break;
            case 1812: System.out.println("RADIUS");
                break;
            case 1813: System.out.println("RADIUS");
                break;
            case 1985: System.out.println("Cisco HSRP");
                break;
            case 2000: System.out.println("Cisco SCCP");
                break;
            case 2002: System.out.println("Cisco ACS");
                break;
            case 2049: System.out.println("NFS");
                break;
            case 2082: System.out.println("cPanel");
                break;
            case 2083: System.out.println("cPanel");
                break;
            case 2100: System.out.println("Oracle XDB");
                break;
            case 2222: System.out.println("DirectAdmin");
                break;
            case 2483: System.out.println("Oracle DB");
                break;
            case 2484: System.out.println("Oracle DB");
                break;
            case 3050: System.out.println("Interbase DB");
                break;
            case 3124: System.out.println("HTTP Proxy");
                break;
            case 3128: System.out.println("HTTP Proxy");
                break;
            case 3222: System.out.println("GLBP");
                break;
            case 3260: System.out.println("iSCSI Target");
                break;
            case 3306: System.out.println("MySQL");
                break;
            case 3389: System.out.println("Terminal Server");
                break;
            case 3689: System.out.println("iTunes");
                break;
            case 3690: System.out.println("Subversion");
                break;
            case 4333: System.out.println("mSQL");
                break;
            case 4664: System.out.println("Google Desktop");
                break;
            case 4899: System.out.println("Radmin");
                break;
            case 5000: System.out.println("UPnP");
                break;
            case 5001: System.out.println("iperf");
                break;
            case 5004: System.out.println("RTP");
                break;
            case 5005: System.out.println("RTP");
                break;
            case 5432: System.out.println("PostgreSQL");
                break;
            case 5500: System.out.println("VNC Server");
                break;
            case 5631: System.out.println("pcAnywhere");
                break;
            case 5632: System.out.println("pcAnywhere");
                break;
            case 5800: System.out.println("VNC over HTTP");
                break;
            case 6000: System.out.println("X11");
                break;
            case 6001: System.out.println("X11");
                break;
            case 6129: System.out.println("DameWare");
                break;
            case 6566: System.out.println("SANE");
                break;
            case 6588: System.out.println("AnalogX");
                break;
            case 8080: System.out.println("HTTP Proxy");
                break;
            case 8200: System.out.println("VMware Server");
                break;
            case 8500: System.out.println("Adobe ColdFusion");
                break;
            case 9100: System.out.println("HP JetDirect");
                break;
            case 9101: System.out.println("Bacula");
                break;
            case 9102: System.out.println("Bacula");
                break;
            case 9103: System.out.println("Bacula");
                break;
            case 9800: System.out.println("WebDAV");
                break;
            case 10000: System.out.println("Webmin");
                break;
            case 11371: System.out.println("OpenPGP");
                break;
            case 13720: System.out.println("NetBackup");
                break;
            case 13721: System.out.println("NetBackup");
                break;
            case 19226: System.out.println("AdminSecure");
                break;
            case 19638: System.out.println("Ensim");
                break;
            case 20000: System.out.println("Usermin");
                break;
            case 24800: System.out.println("Synergy");
                break;
            default: System.out.println("No description");
                break;
}
           PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("ports.txt", true)));
                String test = url+"--> aktif port : " + port;
                 out.println(test);
                 out.close();
        } catch (Exception ex) {
        }
      }
    }}; 
         }

class pathYakala{
            
             Thread cms = new Thread(){
                public void run(){
   
                            try {
                                Document doc = Jsoup.connect(url).get();
                                String kaynak = (String)doc.toString();
                                if(kaynak.contains("/wp-content/")){
                                System.out.println("CMS : Wordpress!");
                                System.out.println("robots.txt -> " + url + "robots.txt");
                                Document wp = Jsoup.connect(url+"wp-content").get();
                                String wpSonuc = (String)wp.toString();
                                if(wpSonuc.contains("Index of")){
                                    System.out.println("wp-content dizini acik! -> " + url + "/wp-content");
                                }
                                Document wp2 = Jsoup.connect(url+"wp-includes").get();
                                String wpSonuc2 = (String)wp.toString();
                                if(wpSonuc2.contains("Index of")){
                                    System.out.println("wp-includes dizini acik! -> " + url + "wp-includes");
                                }
                                System.out.println("Wordpress vuln db ! -> https://wpvulndb.com/");
                                }
                                else if(kaynak.contains("/index.php?route=")){
                                System.out.println("CMS : Opencart!");
                                System.out.println("Opencart vuln db -> https://packetstormsecurity.com/search/?q=opencart");
                                }
                                else{
                                Document docJoom = Jsoup.connect(url+"administrator").get();
                                String kaynakJoom = (String)docJoom.toString();
                                
                                if(kaynakJoom.contains("joomla.org")){
                                System.out.println("CMS : Joomla!");
                                System.out.println("Joomla vuln db ! = https://www.cvedetails.com/vulnerability-list/vendor_id-3496/product_id-16499/Joomla-Joomla-.html");
                                }
                                else{
                                System.out.println("Ozgun CMS , hafizaya atiliyor!");
                                   
                                }
                                }
                          /*  Response response = Jsoup.connect(url+path.get(i)).followRedirects(false).execute();
                             System.out.println("Status Code : "+response.statusCode() + " - " + response.url()); 
                            
                             if(response.statusCode() == 403){
                             System.out.println("Giris iznimiz yok. Status code : " + response.statusCode());
                             }
                                */ 
                            }
                            catch (IOException ex) {
                                try {                                            
                                              Document doc = Jsoup.connect(url).get();
                                            Elements links = doc.select("a[href]");
                                            for (Element link : links) {
                                       // System.out.println("Linkler : " + link.attr("href"));
                                            }   
                                    
                                    System.out.println("Ozgun CMS!");
                                } catch (IOException ex1) {
                                    Logger.getLogger(Tokatci.class.getName()).log(Level.SEVERE, null, ex1);
                                }
                            }
                        
                }};
             
        }

class loginBul{
     Thread t9 = new Thread(){
                public void run(){         
                    try {
                        Document doc = Jsoup.connect(url).get();
                        Elements links = doc.select("a[href]");
                       
                        for (Element link : links) {
                            String test2 = link.attr("href");
                             List<String> loginPath = new ArrayList<String>();
                        loginPath.add("admin.php");
                        loginPath.add("panel.php");
                        loginPath.add("user.php");
                        loginPath.add("staff.php");
                        loginPath.add("login.php");
                        loginPath.add("members.php");
                        for(int p = 0 ; p < loginPath.size();p++){
                            if(test2.contains(loginPath.get(p))){
                            System.out.println("Login sayfasi bulundu. =>" + test2);
                            
                            PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("loginPage.txt", true)));
                            String test = "Login Sayfasi => " + test2;
                            out.println(test);
                            out.close();

                            }
                            else{
                            System.out.println("Login sayfasi bulunamadi!");
                            }
                        }
                            }
           }
           catch (IOException ex) {
                        Logger.getLogger(loginBul.class.getName()).log(Level.SEVERE, null, ex);
                    }
                }};
}
 class sqliScan{

            Thread t6 = new Thread(){
                public void run(){         
                    try {
                        Document doc = Jsoup.connect(url).get();
                        Elements links = doc.select("a[href]");
                         String payload = "'";
                        for (Element link : links) {   
                        String href = links.attr("href");
                            if(href.contains("login.php")){
                            System.out.println("Login sayfasi bulundu. =>" + href);
                            }
                         if(href.contains("?id=")||href.contains("php?id=") || href.contains("aspx?id=") || href.contains("jsp?id=")){
                Document sqlGit = Jsoup.connect(url+href+payload).get();
                if(!doc.equals(sqlGit)){
                System.out.println("-----------------------------");
                System.out.println("Potansiyel SQL Injection!");
                System.out.println("SQL Payload : " + payload);
                System.out.println("URL : " +url+href+payload);
                System.out.println("-----------------------------");
                PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("sqli.txt", true)));
                String test = url+href+payload;
                 out.println(test);
                 out.close();
                }
                else{
                System.out.println("SQL Bulunamadi , farkli payloadlar deneniyor.");
                //burada payload degistirilecek
                }
                                }
                  else{
                  System.out.println("php?id= bulunamadi.");
                  }
                        }
                    } catch (IOException ex) {
                        Logger.getLogger(Tokatci.class.getName()).log(Level.SEVERE, null, ex);
                    }

                }};
 
 
 }
 class sunucu{

            Thread t3 = new Thread(){
                public void run(){                  
                    try {
                        String parca = url.replace("http:","");
                        String parca2 = parca.replace("/","");
                        String parca3 = parca2.replace("/","");
      InetAddress ipaddress = InetAddress.getByName(parca3);
      System.out.println("IP address: " + ipaddress.getHostAddress());
      
      String ip = ipaddress.getHostAddress();
      
                        Document doc3 = Jsoup.connect("https://api.viewdns.info/reverseip/?host="+parca3+"&apikey=YOURAPIKEY&output=xml").get();
                         Elements links = doc3.select("name");
                         String linkler = (String)links.toString();
                         String tamLink = linkler.replace("<name>","Site :  ");
                         String simdiOldu = tamLink.replace("</name>","");
                         System.out.println(simdiOldu);
                          int k=0;
                        for(int i=0;i<simdiOldu.length();i++){
                        if(simdiOldu.charAt(i)=='.')
                            k++;
                             }
                        System.out.println("Domain sayisi : "+(k+1));

                    } catch (IOException ex) {
                        Logger.getLogger(Tokatci.class.getName()).log(Level.SEVERE, null, ex);
                    }

    }}; 
         }
          

         class linkGrabber{

            Thread t2 = new Thread(){
                public void run(){
                    try {
                        Document doc = Jsoup.connect(url).get();
                        Elements links = doc.select("a[href]");
                       
                        for (Element link : links) {
                 PrintWriter out = new PrintWriter(new BufferedWriter(new FileWriter("links.txt", true)));
                String test = link.attr("href");
                 out.println(url+test);
                 out.close();
                            System.out.println("Linkler : " + link.attr("href"));
                                    
                        }       } catch (IOException ex) {
                        Logger.getLogger(Tokatci.class.getName()).log(Level.SEVERE, null, ex);
                    }
    }}; 
         }
 
         System.out.println("Taranan URL " +  url);
         System.out.println("Tokatvi v1 ~ coded by @inject0r16");
         System.out.println("CMS tespit ediliyor...");
         
          pathYakala pathBul = new pathYakala();
            pathBul.cms.start();
            pathBul.cms.join();
            
            System.out.println("--------------------------------------------");
            System.out.println();
                      System.out.println("Linkler cekiliyor!");
            System.out.println("--------------------------------------------");
             linkGrabber linkGrabber2 = new linkGrabber();
             linkGrabber2.t2.start();
             linkGrabber2.t2.join();

           System.out.println("--------------------------------------------");
          System.out.println("Nasi cektim ama linkleri!");
          System.out.println("Linkler cekilip bulunan dizine kaydedildi.");
                     System.out.println("--------------------------------------------");
            System.out.println("Sunucudaki siteler cekiliyor...");
           System.out.println();
           
          sunucu sunucuBak = new sunucu();
          sunucuBak.t3.start();
          sunucuBak.t3.join();
                                System.out.println("--------------------------------------------");
                                System.out.println("Sqli test yapiliyor..");
                                System.out.println();
                                sqliScan sqlBak = new sqliScan();
                                sqlBak.t6.start();
                                sqlBak.t6.join();
                           System.out.println("--------------------------------------------");
                           System.out.println("Login sayfasi araniyor...");
                                   loginBul login = new loginBul();
         login.t9.start();
         login.t9.join();
      System.out.println("--------------------------------------------");
         System.out.println("XSS Deneniyor...");
         xssTara xss = new xssTara();
         xss.t10.start();
         xss.t10.join();
               System.out.println("--------------------------------------------");
         System.out.println();
            System.out.println("Portlar kontrol ediliyor...");
            System.out.println();
            
          portTara portBak = new portTara();
          portBak.t4.start();
          portBak.t4.join();
           
            }
       
    
    }
    
