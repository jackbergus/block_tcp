/*
 * Copyright (c) 2013 Giacomo Bergami,  <giacomo90@libero.it>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation;
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Using some code from:
 *     Copyright (c) 2013 Joe Kopena, Drexel University <tjkopena@cs.drexel.edu>
 */

/* g++ -std=c++11 rete.cpp -lnetfilter_queue  -D_GNU_SOURCE -lnetfilter_queue -lnfnetlink -lpthread 
   sudo iptables -A OUTPUT -p tcp -j NFQUEUE --queue-num 123
   sudo iptables -A INPUT -p tcp -j NFQUEUE --queue-num 321 */

#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>
#include <iterator>
#include <unordered_map>
#include <list>
#include <iomanip>
#include <mutex>
#include <thread>
#include <fstream>


extern "C" {
        #include <libnetfilter_queue/libnetfilter_queue.h>
        #include <time.h>
        #include <stdio.h>
        #include <string.h>
        #include <errno.h>
        #include <unistd.h>
        #include <stdlib.h>
        #include <signal.h>
        #include <sys/types.h>
        #include <sys/socket.h>
        #include <arpa/inet.h>
        #include <linux/netfilter.h>
        #include <linux/netfilter_ipv4.h>
        #include <netpacket/packet.h>
        #include <net/ethernet.h>
        #include <sys/ioctl.h>
        #include <netinet/in.h>
        #include <sys/stat.h>
        #include <netdb.h>

        #if defined(__GLIBC__) && __GLIBC__ == 2
        #include <netinet/udp.h>
        #include <netinet/tcp.h>
        #include <netinet/ip_icmp.h>
        #include <net/ethernet.h>
        #else
        #include <linux/tcp.h>
        #include <linux/udp.h>
        #include <linux/icmp.h>
        #include <linux/if_ether.h>
        #endif
}

using namespace std;

mutex           banned_list_mutex;
mutex           shbuf_threads_in;
mutex           shbuf_threads_ou;
list <string>   banned_addr;    /**< This maps the */
list<string>    banned_ip;      /**< This maps the ip with the host */
time_t          rawtime;        /**< This marks the start time */
int             minutes_wait;   /**< This indicates the minutes to wait before blocking */
bool            TRUTH = true;
bool            FALSITY = false;

#define OUTPUT_QUEUE                    123
#define INPUT_QUEUE                     321
#define MSGBUFFER_SIZE                  65536
#define DEFAULT_TIME                    1

/* Check if you've been waiting for more than minutes_wait minutes */
bool elapsed() {
        time_t nowt;
        nowt = time(NULL); // Setting the current time
        
        return ((difftime(nowt,rawtime)/60)>=minutes_wait);
}

#if 0
// DEAD CODE
unordered_map<string,string> parse_commands_http(string sentence) {

    unordered_map<string,string> test;
    istringstream iss(sentence);
    char buffer_test[300];
    memset(buffer_test,0,300);
    
    while (iss.getline(buffer_test,300,'\n')) {
    	char buffer_test2[300];
    	memset(buffer_test2,0,300);
    	
    	string command{buffer_test};
    	istringstream iss(command);
    	if (iss.getline(buffer_test2,300,':')) {
    		string command{buffer_test2};
    		if (!iss.getline(buffer_test2,300,':'))
    		continue;
    		else {
    			string attribute{buffer_test2};
    			test[command] = attribute;
    		}
    	}
    	
    	memset(buffer_test,0,300);
    }
    
    return test;

}
#endif

/*! Checks if the current IP has to be banned */
bool ban_ip(string ip, string http_msg) {
        
        unique_lock<mutex> lock{banned_list_mutex};
        
        bool toret = false;
        
        for (const auto &y: banned_ip) {
		if (ip==y) { 
#ifdef DEBUG
		        cout << "HAS banning " << ip << "\n";
#endif
		        toret = true; // Automatic unlock
		} 
	}

#ifdef DEBUG	
	cout << "\t\t\tfinding " << ip << (toret ? " BANNED " : " Ok " ) << "in current message\n";
#endif	

	return toret; // Automatic unlock
}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
#define OFFSETPROTOC  9
#define OFFSETSOURCE 12
#define OFFSETDESTIN 16
#define OFFSETSTRING 41

/*! Checks if we are using TCP Data */
int isTCP(  char *payload, int data_len)
{
	if( 	(data_len>=OFFSETPROTOC)   &&
		(*((payload) + OFFSETPROTOC) == 6)   
	)
		return(1);
	else 	return(0);
}

/*! Checks if the current TCP packet has to be banned */
bool AnalyzeTCP_forBan( char *payload, int data_len, bool ban_sender_not_dest) {
	struct iphdr *piphdr;
	struct tcphdr *ptcphdr;
	struct in_addr s, d;
	
	if(data_len < sizeof(struct iphdr)) 
	{
		fprintf(stderr, "ExistTCPoption: data_len too small a\n");
		return false;
	}
	piphdr = (struct iphdr *)payload;	/* hearder IP */
	if ( piphdr->protocol == IPPROTO_TCP )
 	{		/* TCP: 0x06 ; UDP: 0x11 ; ICMP: 0x01 **/
		if(data_len < (4*(piphdr->ihl)) )
		{
			fprintf(stdout,"ExistTCPoption: data_len too small b\n");
			return false;
		}
		ptcphdr = ((struct tcphdr *) (payload + 4*(piphdr->ihl))); /* header TCP */
		if(data_len < (4*(piphdr->ihl)+sizeof(struct tcphdr)) )
		{
			fprintf(stdout,"ExistTCPoption: data_len too small c\n");
			return false;
		}
		
	
		bool toban = false;
		s.s_addr=piphdr->saddr;
		string  strIPs{inet_ntoa(s)};
		d.s_addr=piphdr->daddr;
		string  strIPd{inet_ntoa(d)};
                string data{&payload[(4*(piphdr->ihl)+sizeof(struct tcphdr))+12]}; //HTTP message?? :D
                
                /* if ban_sender_not_dest is set to true, the we're reading from
                   the OUTPUT queue, and so we must ban the destination, otherwise
                   we're reading from the INPUT queue and we must ban the source */
                if (ban_sender_not_dest) {
                        toban =  ban_ip(strIPs,data);
                } else {
                        toban =  ban_ip(strIPd,data);
                }
                bool elapse = elapsed();
                toban = toban && elapse;
                if (toban) cout << "BANNED\n";
                
                return toban;
                
	}
	else
	{
		fprintf(stdout,"pkt Non TCP\n");
	}
	return false;
}


//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

static int Callback(nfq_q_handle *myQueue, struct nfgenmsg *msg,
                    nfq_data *pkt, void *cbData) {
  uint32_t id = 0;
  nfqnl_msg_packet_hdr *header;
  bool todrop = false;

  bool ban_sender = *((bool*)cbData);
  
  if ((header = nfq_get_msg_packet_hdr(pkt))) {
    id = ntohl(header->packet_id);
  }

  // Print the payload; in copy meta mode, only headers will be included;
  // in copy packet mode, whole packet will be returned.
  char *pktData;
  int len = nfq_get_payload(pkt, &pktData);
  if (len) {
    if (isTCP(pktData,len)) { 
        unique_lock<mutex> lock{shbuf_threads_ou};
        todrop = AnalyzeTCP_forBan(pktData,len,ban_sender); 
    }
  }

  if (todrop) cout << "OUT dropping...\n";

  if (todrop)
        return nfq_set_verdict(myQueue, id, NF_DROP, 0, NULL);
  else
        return nfq_set_verdict(myQueue, id, NF_ACCEPT, 0, NULL);

}

//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------
//------------------------------------------------------------------------------

struct nfq_handle* AllnfqHandle[2];
struct nfq_q_handle* AllmyQueue[2];
struct nfnl_handle* AllnetlinkHandle[2];
int fd[2];

void read_queue_ban(bool queue_in_true) {

  int bolint = 0;
  if (queue_in_true) bolint = 1;
  
  //struct nfq_handle *nfqHandle = AllnfqHandle[bolint];
  //struct nfq_q_handle *myQueue = AllmyQueue[bolint];



  // Get a queue connection handle from the module
  if (!(AllnfqHandle[bolint] = nfq_open())) {
    cerr << "Error in nfq_open()" << endl;
    exit(-1);
  }

  // Unbind the handler from processing any IP packets
  // Not totally sure why this is done, or if it's necessary...
  if (nfq_unbind_pf(AllnfqHandle[bolint], AF_INET) < 0) {
    cerr << "Error in nfq_unbind_pf()" << endl;
    exit(1);
  }

  // Bind this handler to process IP packets...
  if (nfq_bind_pf(AllnfqHandle[bolint], AF_INET) < 0) {
    cerr << "Error in nfq_bind_pf()" << endl;
    exit(1);
  }

  // Install a callback on queue queue_num
  if (queue_in_true)  {
       if (!(AllmyQueue[bolint] = nfq_create_queue(AllnfqHandle[bolint], INPUT_QUEUE, &Callback, (void*)&TRUTH))) {
            cerr << "Error in nfq_create_queue()" << endl;
            exit(1);
       }
  } else {
        if (!(AllmyQueue[bolint] = nfq_create_queue(AllnfqHandle[bolint], OUTPUT_QUEUE, &Callback, (void*)&FALSITY))) {
            cerr << "Error in nfq_create_queue()" << endl;
            exit(1);
       }
  }

  // Turn on packet copy mode
  if (nfq_set_mode(AllmyQueue[bolint], NFQNL_COPY_PACKET, 0xffff) < 0) {
    cerr << "Could not set packet copy mode" << endl;
    exit(1);
  }

  AllnetlinkHandle[bolint] = nfq_nfnlh(AllnfqHandle[bolint]);
  fd[bolint] = nfnl_fd(AllnetlinkHandle[bolint]);

  
}

void thread_proc(bool queue_in_true) {
        int bolint = 0;
        if (queue_in_true) bolint = 1;
        
        int res;
        char buf[MSGBUFFER_SIZE];
        memset(buf,0,MSGBUFFER_SIZE);
        
        //cout << "reading " << fd[bolint] << "\n";

        while ((res = recv(fd[bolint], buf, sizeof(buf), 0)) && res >= 0) {
            nfq_handle_packet(AllnfqHandle[bolint], buf, res);
            memset(buf,0,MSGBUFFER_SIZE);
        }

        nfq_destroy_queue(AllmyQueue[bolint]);
        nfq_close(AllnfqHandle[bolint]);
}

/*! It resolves the given url in order to add the ip to ban */
int add_banning(const char* url) {
    int i;
    struct hostent *he;
    struct in_addr **addr_list;
    
    if ((he = gethostbyname(url)) == NULL) {  // get the host info
        herror("gethostbyname");
        return 2;
    }

    addr_list = (struct in_addr **)he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++) {
        string ipaddr{inet_ntoa(*addr_list[i])};
        banned_ip.push_back(ipaddr);
        cout << "Added also: " << ipaddr << "\n";
    }
    return 0;
}

int main(int argc, char **argv) {

  rawtime = time(NULL); // Initing start time
  minutes_wait = DEFAULT_TIME;
  
  
  if (argc>=2) try {
        minutes_wait = stoi(argv[1]);
  } catch (...) {
        minutes_wait = DEFAULT_TIME;
  }
  
  cout << "Waiting for " << minutes_wait << " minutes\n";
  
  ifstream ip_file("blockedip.txt");
  ifstream urlfile("blockedurl.txt");
  
  if ((!ip_file.is_open())&&(!urlfile.is_open())) {
        cout << "Error: no input file for ip or url to ban\n";
        return 1;
  }
  
  string ip_or_url;
  int count = 0;
  
  while (getline(ip_file, ip_or_url)) {
        banned_ip.push_back(ip_or_url);
        count++;
  } 
  
  while (getline(urlfile, ip_or_url)) {
        add_banning(ip_or_url.c_str());
        count++;
  }
  
  if (!count) cerr << "NO INSERTED\n";
  else cerr << count < " counted\n";
  
  ip_file.close();
  urlfile.close();
  
  read_queue_ban(true);
  read_queue_ban(false);
  thread t1{thread_proc,true};
  thread t2{thread_proc,false};
  cout << "doing\n";
  t1.join();
  t2.join();
  
  
  
  return 0;

}
