#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <iostream>
#include <string>
#include <malloc.h>
#include <map>
#include <stdlib.h>
#include <pthread.h>
#include <algorithm>
#include <vector>
#include <queue>
#include <mutex>
//#include <tchar.h>
#include <ctime>
#include <cstdlib>
#include <vector>
#include <pthread.h>
#include <unistd.h> 






#include <string.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
using namespace std;
#define  N_rand  99
#define  p  0.3
#define  N  64
#define ETHERNET_HEADER_LEN     14
#define ETHERNET_TYPE_IP        0x0800
#define ETHERNET_TYPE_VLAN 0x8100



bool strcmp_uchar(const u_char a[],const u_char b[]){
    bool arraysEqual1 = true; // 标志变量
    
    int t = 0; //循环控制变量
    while (arraysEqual1 && t < 4)
   {
    if (a[t] != b[t]){
        arraysEqual1 = false;
        break;
    }
        t++;
    
    }
    return arraysEqual1;

} 

struct  fivetuple    //唯一标识流的结构体, 用做mapping的key，五元组
{
    int srcport;
    int destport;
    char srcip[20];
    char destip[20];
    int proto;
    bool operator < (const fivetuple &A)const{                //重载 < 运算符

    if (destport <A.destport) {
        return true;
    }
    else if(destport == A.destport){
        if (srcport <A.srcport) {
            return true;
        }
        else if(srcport == A.srcport){
            if (proto <A.proto){
                return true;
            }
            else if(proto == A.proto){
                if(strcmp(srcip,A.srcip)!= 0)
                {
                    return true;
                }
                else if(strcmp(srcip,A.srcip)==0){
                    if(strcmp(destip,A.destip)!=0)
                    {
                        return true;
                    }
                }
            }
        }
    }
    return false;
}

    bool operator == (const fivetuple &rhs);         //重载==运算符, 用于判断两个结构体是否相等
};

bool fivetuple::operator == (const fivetuple &rhs)
{   
    bool arraysEqual1 = true; // 标志变量
    bool arraysEqual2 = true; // 标志变量
    
    if (strcmp(srcip,rhs.srcip)!= 0){
           arraysEqual1 = false;
           
    }
    
    if (strcmp(destip,rhs.destip)!= 0){
           arraysEqual2 = false;
           
    }
    return ((srcport == rhs.srcport) && (destport == rhs.destport) && arraysEqual1 && arraysEqual2 && (proto == rhs.proto));
}


struct node       //mapping对应的value, 包括流的计数，上一个周期的计数, 源地址，目的地址，若下发它则给它分配的表项号, 生存周期tag.
{
    int count;       //该流统计的包的个数
    int precount;    //上一个周期该流统计的包的个数
    int index;       // 如果下发它的话，就插入到交换机的第index个表项
    char sip[20];    //源地址
    char dip[20];    //目的地址
    u_short sport;       //源端口
    u_short dport;       //目的端口
    int life;        // 一个tag, 当检测到结束了就置1, 可用来决定是否删除它，
    u_int size;        // 该流统计的字节数
    u_int presize;     //上一个周期该流统计的字节数
};

typedef struct _EtherHdr
{
  unsigned char  ether_dst[6];
    unsigned char  ether_src[6];
    unsigned short ether_type;
} EtherHdr;

typedef struct _Vlan
{
  unsigned short vlan_priority_DEI_ID;
  unsigned short type;
} VlanHdr;

typedef struct _IPHdr
{
#if defined(WORDS_BIGENDIAN)
    u_char    ip_ver:4,         /* IP version             */
      ip_hlen:4;        /* IP header length       */
#else
    u_char    ip_hlen:4,       
      ip_ver:4;
#endif
    u_char    ip_tos;           /* type of service        */
    u_short   ip_len;           /* datagram length        */
    u_short   ip_id;            /* identification         */
    u_short   ip_off;
    u_char    ip_ttl;           /* time to live field     */
    u_char    ip_proto;         /* datagram protocol      */
    u_short   ip_csum;          /* checksum               */
    u_char    ip_src[4];
    u_char    ip_dst[4];
} IPHdr;

typedef struct _TCPHdr
{       
  u_short th_sport;           /* source port            */
  u_short th_dport;           /* destination port       */
  u_long th_seq;              /* sequence number        */
  u_long th_ack;              /* acknowledgement number */
#ifdef WORDS_BIGENDIAN
  u_char  th_off:4,           /* data offset            */
                 th_x2:4;           /* (unused)               */
#else
  u_char  th_x2:4,            /* (unused)               */
                th_off:4;           /* data offset            */
#endif
  u_char  th_flags;
  u_short th_win;             /* window                 */
  u_short th_sum;             /* checksum               */
  u_short th_urp;             /* urgent pointer         */
} TCPHdr;

typedef struct _UDPHdr
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_chk;
} UDPHdr;


void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data);


long long count_Eth     = 0;
long long count_NON_Eth = 0;
long long count_IP      = 0;
long long count_NON_IP  = 0;
long long count_TCP     = 0;
long long count_UDP     = 0;
long long count_Other = 0;

map<fivetuple, node> mapping;
map<fivetuple, node>::iterator it;

int switch_slot = 65536;
int globalidx = 1;
int high_threshold = 16;
int low_threshold = 1;
int tables_constraint = 9;
int period = 3;

map <fivetuple, int> pre_offload_flow;
map <fivetuple, int> offload_flow;
queue <fivetuple> sender_buffer;
queue <fivetuple> delete_buffer;


typedef pair<fivetuple, int> pii;
vector<pii> vc;
vector<pii>::iterator vit;
bool cmp(pii a, pii b) {
    return a.second > b.second;
}

vector<fivetuple> cache;
vector <int> cache_count(N,-1);
vector<fivetuple>::iterator cache_it;
vector<int>::iterator cache_count_it;
vector<int> candidate_flow;
vector <fivetuple> candidate_flow_key; 
map <fivetuple, int>::iterator itt;



mutex mapping_lock;
mutex pre_offload_flow_lock;
mutex sender_buffer_lock;
mutex delete_buffer_lock;
mutex offload_flow_lock;

void delay_msec(int msec)
{ 
    clock_t now = clock();
    while(clock()-now < msec);
}


void sender1(char sip[], int sport, char dip[], int dport, int index){
    printf("offload a flow : %s  %d -> %s  %d  %d\n", sip, sport, dip, dport, index);
}

void sender2(int a){
    cout<<"delete a flow:"<<a<<endl;
}
void sender3(){
 printf("offload a flow\n"); 
}

void receive(vector<int> vec){
     if(vec.empty()==0){
        cout<<"geting counters from switch"<<endl;
     }
     else{
        cout<<"no messages from switch"<<endl;
     }
}

void* offload(void*){
    fivetuple temp;
    int idx;
    char sip[20];
    char dip[20];
    u_short sport;
    u_short dport;
     while(1){
        sender_buffer_lock.lock();
        if(sender_buffer.empty()==0){
          temp = sender_buffer.front();
          sender_buffer.pop();
          sender_buffer_lock.unlock();

          mapping_lock.lock();
          if (1==mapping.count(temp)){       
                 memcpy(sip,mapping[temp].sip,sizeof(mapping[temp].sip));
                 memcpy(dip,mapping[temp].dip,sizeof(mapping[temp].dip));
                 sport = mapping[temp].sport;
                 dport = mapping[temp].dport;
                 idx = mapping[temp].index;
                 mapping_lock.unlock();
                 //sender1(sip,sport,dip,dport,idx);
                 sender3();
                 offload_flow_lock.lock();
                 offload_flow[temp] = idx;
                 offload_flow_lock.unlock();
          }
          else{
            mapping_lock.unlock();
          }

        }
        else{
            sender_buffer_lock.unlock();
        }
        
     }
}





void* update(void*){
   fivetuple keytemp;
   node temp;
   while(1){
   for (it=mapping.begin();it!=mapping.end();it++){
       keytemp = it->first;
       temp = mapping[keytemp];
      if(temp.count - temp.precount == 0){
        if(temp.life > period){
            mapping_lock.lock();
            mapping.erase(keytemp);
            mapping_lock.unlock();
            
            delete_buffer_lock.lock();
            delete_buffer.push(keytemp);
            delete_buffer_lock.unlock();
            continue;
        }
        else{
            mapping[keytemp].life += 1;
            continue;
        }
      }
      else{
         mapping[keytemp].life = 0;
         
         vc.push_back(pii(keytemp, temp.count - temp.precount));
         
         mapping_lock.lock();
         mapping[keytemp].precount = mapping[keytemp].count;
         mapping[keytemp].presize = mapping[keytemp].size;
         mapping_lock.unlock();
      }
   }
    sort(vc.begin(), vc.end(), cmp);       //排序, 为了找top k
    
    int i = 0;
    for(vit=vc.begin(); vit!=vc.end() && i<tables_constraint; vit++) {
        pre_offload_flow_lock.lock();
        if(0==pre_offload_flow.count(vit->first)){
            i++;
            pre_offload_flow[vit->first] = mapping[vit->first].index;
            pre_offload_flow_lock.unlock();
            sender_buffer_lock.lock();
            sender_buffer.push(vit->first);
            sender_buffer_lock.unlock();
        }
        else{
            pre_offload_flow_lock.unlock();
        }
        

    }
    vector<pii>().swap(vc);
    sleep(1);
}
}



void* retreive(void*){
    while(1){
    offload_flow_lock.lock();
    for(itt = offload_flow.begin(); itt != offload_flow.end(); itt++) {
        candidate_flow.push_back(offload_flow[itt->first]);
        candidate_flow_key.push_back(itt->first);
    }
    offload_flow_lock.unlock();
    receive(candidate_flow);
    for(int i=0;i<candidate_flow_key.size();i++){
      mapping_lock.lock();
      if(1==mapping.count(candidate_flow_key[i])){
        mapping[candidate_flow_key[i]].count += 0;
        mapping_lock.unlock();
      }
      else{
         mapping_lock.unlock();
      }
    }
    vector <int>().swap(candidate_flow);
    vector <fivetuple>().swap(candidate_flow_key);
    sleep(1);
}
}


void* deleter(void*){
    fivetuple temp;
    int idx;
     while(1){
        if(delete_buffer.empty()==0){
           temp = delete_buffer.front();
           delete_buffer.pop();
           pre_offload_flow_lock.lock();
           if(1==pre_offload_flow.count(temp)){
                pre_offload_flow.erase(temp);
                pre_offload_flow_lock.unlock();
                offload_flow_lock.lock();
                if(1==offload_flow.count(temp)){
                   idx = offload_flow[temp];
                   offload_flow_lock.unlock();
                   sender2(idx);
                   offload_flow_lock.lock();
                   offload_flow.erase(temp);
                   offload_flow_lock.unlock();
                }
                else{
                   offload_flow_lock.unlock();
                }
            }
            else{
               pre_offload_flow_lock.unlock();
            }
           

        }
     }
}



void algorithm2(fivetuple keytemp){
            float r = rand() % (N_rand + 1) / (float)(N_rand + 1);
            if (r<p){
                for(int i = 0; i<N;i++){
                   if(cache[i]==keytemp){
                      cache_count[i] += 1;
                      if(cache_count[i]>high_threshold){
                         pre_offload_flow_lock.lock();
                         pre_offload_flow[keytemp] = 1;
                         pre_offload_flow_lock.unlock();
                         sender_buffer_lock.lock();
                         sender_buffer.push(keytemp);
                         sender_buffer_lock.unlock();
                      }
                      return;
                   }

                }
                for(int i = 0; i<N;i++){
                    if(cache_count[i]==-1){
                        cache[i] = keytemp;
                        cache_count[i] = 0;
                        return;
                    }
                }
                int insert_index = N;
                for(int i = 0; i<N;i++){
                    if(cache_count[i]>=low_threshold){
                        cache_count[i] = cache_count[i] / 2;
                    }
                    else{
                        insert_index = i;
                        break;
                    }
                }
                if(insert_index < N){
                    cache[insert_index] = keytemp;
                    cache_count[insert_index] = 0;
                }
                
            }
}




int main()
{
	pcap_t *enth; /* Session enth */
	char *dev = "eth1"; /* The device to sniff on */
	char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
	struct bpf_program fp; /* The compiled filter */
  // 只接收IP包
	char filter_exp[] = "ip"; /* The filter expression */
	bpf_u_int32 mask; /* Our netmask */
	bpf_u_int32 net; /* Our IP */
	struct pcap_pkthdr header; /* The header that pcap gives us */
	const u_char *packet; /* The actual packet */


	/* Define the device */
	//查看设备，返回句柄
	if (dev == NULL) {             //如果返回空则报错
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
	/* Find the properties for the device */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {   //获取设备详细信息，如IP、掩码等等
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	/* Open the session in promiscuous mode */
	enth = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);   //开始混杂模式监听
	if (enth == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	/* Compile and apply the filter */
	if (pcap_compile(enth, &fp, filter_exp, 0, net) == -1) {    //编译规则
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(enth));
		return(2);
	}
      	if (pcap_setfilter(enth, &fp) == -1) {                   //设置过滤器
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(enth));
		return(2);
	}
    /*
     fivetuple bb;
    bb.srcport = 0;
    bb.destport = 0;
    char temp_bb[20] = "0";
    memcpy(bb.srcip,temp_bb,sizeof(temp_bb));
    char temp_bb1[20] = "0";
    memcpy(bb.destip,temp_bb1,sizeof(temp_bb1));
    bb.proto = 0;
    for(int i =0;i<N;i++){
      cache.push_back(bb);
     }
     */
    pthread_t tids[4];
    
    int ret = pthread_create(&tids[0], NULL, offload, NULL);
    if (ret != 0)
    {
        cout << "pthread_create 1  error: error_code=" << ret << endl;
    }
    
   int  ret2 = pthread_create(&tids[1], NULL, deleter, NULL);
    if (ret2 != 0)
    {
        cout << "pthread_create 2  error: error_code=" << ret2 << endl;
    }

    int ret3 = pthread_create(&tids[2], NULL, retreive, NULL);
    if (ret3 != 0)
    {
        cout << "pthread_create 3  error: error_code=" << ret3 << endl;
    }

    int ret4 = pthread_create(&tids[3], NULL, update, NULL);
    if (ret4 != 0)
    {
        cout << "pthread_create 4  error: error_code=" << ret4 << endl;
    }

    
	/* Grab a packet */
	pcap_loop(enth, -1, callback, NULL);                    //开始循环补包

	/* And close the session */
	pcap_close(enth);
	return 0;
}

void callback(u_char* user,const struct pcap_pkthdr* header,const u_char* pkt_data)
{
   int len = 0;
  unsigned short pkt_type;                 /* type of pkt (ARP, IP, etc) */
  EtherHdr *eh = (EtherHdr *) pkt_data;      /* lay the ethernet structure over the packet data */
  VlanHdr *vlan;
  IPHdr *iph;                              /* ip header ptr */
  TCPHdr *tcph;                            /* TCP packet header ptr */
  UDPHdr *udph;                            /* UDP header struct ptr */
  u_int hlen;                              /* ip header length */
  pkt_type = ntohs(eh->ether_type);        /* grab out the network type */

  char* pktidx;
  pktidx = (char*) pkt_data;
  pktidx += ETHERNET_HEADER_LEN;

  count_Eth++;
    if (pkt_type == 0x8100)
    {
      vlan = (VlanHdr*) pktidx;
      pkt_type = ntohs(vlan->type);
      pktidx += 4;
    }
  if (pkt_type == ETHERNET_TYPE_IP)
  {
    count_IP++;
    iph = (IPHdr *) pktidx;
    hlen = iph->ip_hlen * 4;
    pktidx = pktidx + hlen;               /* move the packet index to point to the transport layer */
     fivetuple key;
    switch(iph->ip_proto)
    {
      case IPPROTO_TCP:
        count_TCP++;
        tcph = (TCPHdr *) pktidx;


            key.proto = 6;
            key.srcport = ntohs(tcph->th_sport);
            key.destport = ntohs(tcph->th_dport);
            sprintf(key.srcip, "%u.%u.%u.%u", iph->ip_src[0],iph->ip_src[1],iph->ip_src[2],iph->ip_src[3]);
            sprintf(key.destip, "%u.%u.%u.%u", iph->ip_dst[0],iph->ip_dst[1],iph->ip_dst[2],iph->ip_dst[3]);
            mapping_lock.lock();
            if (1==mapping.count(key)){
                 
                 mapping[key].count = mapping[key].count + 1;
                 mapping[key].size = mapping[key].size + iph->ip_hlen * 4;
                 mapping_lock.unlock();
            }
            else{
                mapping_lock.unlock();
                node temp;
                temp.count = 1;
                temp.precount = 0;
                temp.index = globalidx % switch_slot;
                globalidx += 1; 
                sprintf(temp.sip, "%u.%u.%u.%u", iph->ip_src[0],iph->ip_src[1],iph->ip_src[2],iph->ip_src[3]);
                sprintf(temp.dip, "%u.%u.%u.%u", iph->ip_dst[0],iph->ip_dst[1],iph->ip_dst[2],iph->ip_dst[3]);
                //strcpy(temp.dip,"10.19.0.81");
                temp.sport = ntohs(tcph->th_sport);
                temp.dport = ntohs(tcph->th_dport);
                temp.size = iph->ip_hlen * 4;
                temp.presize = 0;
                temp.life = 0;
                mapping_lock.lock();
                mapping[key] = temp;
                mapping_lock.unlock();
                printf("insert a TCP flow that is %s %d -> %s %d, and the index is %d\n",temp.sip,temp.sport,temp.dip,temp.dport,temp.index);

            }


        break;
      case IPPROTO_UDP:
        count_UDP++;
        udph = (UDPHdr *) pktidx;
        
        key.srcport = ntohs(udph->uh_sport);
        key.destport = ntohs(udph->uh_dport);
            key.proto = 17;
            key.srcport = ntohs(udph->uh_sport);
            key.destport = ntohs(udph->uh_dport);
            sprintf(key.srcip, "%u.%u.%u.%u", iph->ip_src[0],iph->ip_src[1],iph->ip_src[2],iph->ip_src[3]);
            sprintf(key.destip, "%u.%u.%u.%u", iph->ip_dst[0],iph->ip_dst[1],iph->ip_dst[2],iph->ip_dst[3]);
            mapping_lock.lock();
            if (1==mapping.count(key)){
                 
                 mapping[key].count = mapping[key].count + 1;
                 mapping[key].size = mapping[key].size + iph->ip_hlen * 4;
                 mapping_lock.unlock();
            }
            else{
                mapping_lock.unlock();
                node temp;
                temp.count = 1;
                temp.precount = 0;
                temp.index = globalidx % switch_slot;
                globalidx += 1; 
                sprintf(temp.sip, "%u.%u.%u.%u", iph->ip_src[0],iph->ip_src[1],iph->ip_src[2],iph->ip_src[3]);
                sprintf(temp.dip, "%u.%u.%u.%u", iph->ip_dst[0],iph->ip_dst[1],iph->ip_dst[2],iph->ip_dst[3]);
                //strcpy(temp.dip,"10.19.0.81");
                temp.sport = ntohs(udph->uh_sport);
                temp.dport = ntohs(udph->uh_dport);
                temp.size = iph->ip_hlen * 4;
                temp.presize = 0;
                temp.life = 0;
                mapping_lock.lock();
                mapping[key] = temp;
                mapping_lock.unlock();
                printf("insert a UDP flow that is %s %d -> %s %d, and the index is %d\n",temp.sip,temp.sport,temp.dip,temp.dport,temp.index);

            }


        break;

      default:
        count_Other++;
        return;
       }
  }
  else
  {
    count_NON_IP++;
    return;
   }


}