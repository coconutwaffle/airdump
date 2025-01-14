#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/wireless.h>
#include <errno.h>
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include "airdump.h"

int stop = 0;
int sock_ctl;
int sockfd;
int num_frequency;
struct iwreq req;
static int chan =0;
pthread_t monitor_thread;
struct node* map[MAP_MAX];

int main(int argc, char *argv[]) {
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int ret;

    if(argc!=2)
    {
        fprintf(stderr, "Use: airodump <interface>\n");
        return 2;
    }

    // Create socket: PF_PACKET / SOCK_RAW / ETH_P_ALL
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return 2;
    }

    // Retrieve the interface index.
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl - SIOCGIFINDEX");
        close(sockfd);
        return 2;
    }

    // Set the socket address structure.
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    // Set the socket address structure.
    ret = bind(sockfd, (struct sockaddr *)&sll, sizeof(sll));
    if (ret < 0) {
        perror("bind");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // Check the range of the channel.
    struct iw_range range;
    strncpy(req.ifr_name, argv[1], IFNAMSIZ - 1);

    req.u.data.pointer = (caddr_t) &range;
    req.u.data.length = sizeof(range);

    if (ioctl(sockfd, SIOCGIWRANGE, &req) == -1) {
        perror("get range fail");
        close(sockfd);
        return -1;
    }
    num_frequency = range.num_frequency;

    //Setup CLI interface
    setup_monitor();

    // Receive packets in a loop.
    info res;
    while (1) {
        if(stop) goto process_stop;

        /*
         * Extract info from packet.
         * Recommend to check the actual packets using Wireshark.
         * Filter: wlan.fc.type_subtype == 0x0008
         * 
         * Offset: exp
         *      0: Radiotap header
         *      8: Radiotap body??
         *    8+N: beacon frame
         *   40+N: beacon frame body
        */
        unsigned char buf[65536];
        struct beacon_frame *beacon;
        struct ieee80211_radiotap_header *radiotap = (struct ieee80211_radiotap_header *)buf;
        ssize_t num_bytes = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);

        res.channal = chan;
        if (num_bytes < 0) {
            perror("recvfrom");
            break;
        }

        beacon = (struct beacon_frame *)(buf + radiotap->it_len);
        if(beacon->magic == 0x0080)
        {
#ifdef DEBUG            
            printf("----------\n");
            printf("Captured %zd bytes\n", num_bytes);
            print_addr("BSS ID: ",beacon->bss_id);
#endif
            memcpy(&(res.bssid),beacon->bss_id,6);
            parse_radiotap_body(radiotap->it_present, buf+sizeof(struct ieee80211_radiotap_header), beacon, &res);
            parse_becon_body((void *)beacon + sizeof(struct beacon_frame), buf+num_bytes, &res);
            
            submit_info(&res);
        }

    }

    process_stop:
#ifndef DEBUG
        pthread_join(monitor_thread, NULL);
#endif
        close(sockfd);
        close(sock_ctl);
        return 0;
}

void parse_becon_body(void *start, void *end, info *res)
{
#ifdef DEBUG 
    uint64_t *timestamp;
    uint16_t *interver;
    uint16_t *cap;
    timestamp = start;
    interver = start + 8;
    cap = start + 10;
    printf("Timestamp: 0x%lx\n", *timestamp);
    printf("Interval: 0x%x\n", *interver);
    printf("Capa: 0x%x\n", *cap);
#endif
    for(void *pos=start+12;pos<end;)
    {
        uint8_t tag_num = *(u_int8_t *)pos;
        uint8_t len = *(u_int8_t *)(pos+1);
        pos+=2;
        switch (tag_num)
        {
            case TAG_SSID_NAME:
                res->essid = (char *)pos;
                res->length = len;
#ifdef DEBUG 
                printf("SSID(%d): %.*s\n", (int)len, (int)len, (char *)pos);
#else
                return;
#endif
                break;
            case TAG_RSN:
            default:
                break;
        }
        pos += len;
    }
}

void parse_radiotap_body(uint32_t flags, void *start, void *end, info *res)
{
    void *pos=start;
    
    if (flags & RADIOTAP_EXT)
    {
        pos +=4;
    }

    
    if (flags & RADIOTAP_TSFT)
    { 
        //printf("TST: 0x%lx\n", *(uint64_t *)pos);
        pos += 8;
    }
    if (flags & RADIOTAP_FLAGS)
    { 
        //printf("flags: 0x%x\n", *(char *)pos);
        pos += 1;
    } 
    if (flags & RADIOTAP_RATE)                 { pos += 1; }  // Rate
    if (flags & RADIOTAP_CHANNEL)              { pos += 4; }  // Channel
    if (flags & RADIOTAP_FHSS)                 { pos += 2; }  // FHSS
    if (flags & RADIOTAP_ANTENNA_SIGNAL)
    {
        res->pwr=*(char *)pos;
#ifdef DEBUG
        printf("dBm: %d\n", *(char *)pos);
#else
        return;
#endif
        pos += 1;
    }  // Antenna signal
    if (flags & RADIOTAP_ANTENNA_NOISE)        { pos += 1; }  // Antenna noise
    if (flags & RADIOTAP_LOCK_QUALITY)         { pos += 2; }  // Lock quality
    if (flags & RADIOTAP_TX_ATTENUATION)       { pos += 2; }  // TX attenuation
    if (flags & RADIOTAP_DB_TX_ATTENUATION)    { pos += 2; }  // dB TX attenuation
    if (flags & RADIOTAP_DBM_TX_POWER)         { pos += 1; }  // dBm TX power
    if (flags & RADIOTAP_ANTENNA)              { pos += 1; }  // Antenna
    if (flags & RADIOTAP_DB_ANTENNA_SIGNAL)    { pos += 1; }  // dB antenna signal
    if (flags & RADIOTAP_DB_ANTENNA_NOISE)     { pos += 1; }  // dB antenna noise
    if (flags & RADIOTAP_RX_FLAGS)             { pos += 2; }  // RX flags
    if (flags & RADIOTAP_TX_FLAGS)             { pos += 2; }  // TX flags
    if (flags & RADIOTAP_MCS)                  { pos += 3; }  // MCS
    if (flags & RADIOTAP_AMPDU_STATUS)         { pos += 8; }  // A-MPDU status
    if (flags & RADIOTAP_VHT)                  { pos += 12; }  // VHT
    if (flags & RADIOTAP_TIMESTAMP)            { pos += 12; }  // Timestamp
    if (flags & RADIOTAP_HE)                   { pos += 12; }  // HE
    if (flags & RADIOTAP_HE_MU)                { pos += 12; }  // HE-MU
    if (flags & RADIOTAP_HE_MU_OTHER_USER)     { pos += 6; }  // HE-MU-other-user
    if (flags & RADIOTAP_ZERO_LENGTH_PSDU)     { pos += 1; }  // 0-length-PSDU
    if (flags & RADIOTAP_L_SIG)                { pos += 4; }  // L-SIG
    if (flags & RADIOTAP_TLV_FIELDS)
    { 

	int length = 4 + *(uint16_t *)(pos + 2);
	int padding = (4 - (length & 3)) & 3;
        pos += length + padding;

    }  // TLV fields
    if (flags & RADIOTAP_RADIOTAP_NAMESPACE)   { BUILD_ERR();}  // Radiotap Namespace
    if (flags & RADIOTAP_VENDOR_NAMESPACE)
    { 
        pos += 6 + *(uint16_t *)(pos+4);
    }  // Vendor Namespace
    if (flags & RADIOTAP_EXT)
    {
        flags = *(uint32_t *)start;
        if (flags & RADIOTAP_S1G)                  { pos += 6; }  // S1G
        if (flags & RADIOTAP_U_SIG)                { pos += 8; }  // U-SIG
        if (flags & RADIOTAP_EHT)
        {
            //TODO Need to replace 0 to acutal user_num	
            BUILD_ERR();
            pos += 40 + 4*(0);
        }  // EHT
     }


    if(pos != end)
    {
        fprintf(stderr, "radiotap: %p, %p, %p\n", start, pos, end);
	    fprintf(stderr, "radiotap header: parsing fail\n");
        BUILD_ERR();
    }
}

/**
 * @brief Set a stop sign for all threads.
 * 
 */
void handle_sigint(int sig) {
    printf("\b\b  \b\b");
    stop=1;
}

void change_channal()
{
    chan++;
    if(chan > num_frequency ) chan = 1;
    req.u.freq.m = chan;
    req.u.freq.e = 0; // MHz
    if (ioctl(sockfd, SIOCSIWFREQ, &req) == -1){
        perror("set channal fail");
        _exit(1);
    }
}

/**
 * @brief The screen is refreshed at regular intervals
 *  Data is checked by iterating through the hash map.
 * 
 */
void *print_monitor(void *nouse)
{
    int line_cnt=0;
    Node *cur;
    while(1)
    {
        if(stop) 
        {
            printf("exit....\n");
            return NULL;
        }
        for(int i=0;i<line_cnt;i++) printf("\033[A");
        printf("CHN: (%02d)        BSSID PWR(dBm) BEACONS ESSID\n", chan);
        line_cnt=1;
        for(int i=0;i<MAP_MAX;i++)
        {
            for(cur=map[i];cur!=NULL && cur->next!=NULL ;cur = cur->next);
            if(cur)
            {
                info *d = &(cur->data);
                unsigned char *adr = d->bssid;
                printf("\033[2K\r%3d: %02x:%02x:%02x:%02x:%02x:%02x %8d %7d %.*s\n",
                d->channal, 
                adr[0], adr[1], adr[2], adr[3], adr[4], adr[5],
                d->pwr, d->beacon_cnt,
                d->length, d->essid
                );
                line_cnt++;
            }
        }
        change_channal();
        usleep(100000);
    }
}

/**
 * @brief Set up Monitor thread to print CLI interface
 * 
 */
void setup_monitor()
{
    memset(map, 0, sizeof(map));
    
#ifndef DEBUG
    if(pthread_create(&monitor_thread, NULL, print_monitor, NULL))
    {
        fprintf(stderr, "thread create: setup fail\n");
        _exit(1);
    }
#endif
    signal(SIGINT, handle_sigint);
    return;
}

/**
 * @brief Since a complex hash function is not needed, 
 * implement it simply.
 * 
 * @param key The MAC address must be 6 bytes.
 * @return int hash result
 */
int hash(addr key)
{
    unsigned int hash = 0;
    for (int i = 0; i < 6; i++) {
        hash = (hash * 31) + key[i];
    }
    return hash % MAP_MAX;
}

Node *make_node(info *res)
{
    Node *tmp = malloc(sizeof(Node));
    if(!tmp)
    {
        fprintf(stderr, "Out of Memory\n");
        return NULL;
    }
    memcpy(&(tmp->data), res, sizeof(info));
    char *str= malloc(res->length+1);
    if(!str)
    {
        free(tmp);
        fprintf(stderr, "Out of Memory\n");
        return NULL;
    }
    tmp->data.essid=str;
    memcpy(str, res->essid, res->length);
    tmp->data.beacon_cnt = 1;
    return tmp;


}



/**
 * @brief Store the data in the hash map. 
 * If the MAC address already exists, update it.
 * 
 * @param res The input data is a pointer to the info structure.
 */
void submit_info(info* res)
{
    //Search for the initial key based on the hash table.
    int index = hash(res->bssid);
    Node *cur = map[index];
    if(!cur)
    {
        cur = make_node(res);
        map[index] = cur;
        return;
    }
    
    while(cur)
    {
        int len = res->length;
        if(len != cur->data.length) goto next;
        unsigned char *c1=cur->data.bssid; 
        unsigned char *c2=res->bssid;

        //Compares the keys of nodes.
        for(int i=0; i< 6; i++) 
        {
            if(*c1!=*c2)
                goto next;
            c1++;
            c2++;
        }

        //Found smae key
        same:
            cur->data.beacon_cnt++;
            cur->data.pwr = res->pwr;
            cur->data.channal = res->channal;
            return;
        
        // If the keys are different, compare the next node
        // in the list or execute "make node" 
        // if it is the last node.
        next:
            if(!cur->next)
            {
                cur->next = make_node(res);
                return;
            }
            cur = cur->next;
    }

    // Reaching this point might indicate a potential concurrency issue.
    BUILD_ERR();
}