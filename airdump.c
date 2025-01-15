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
static int timeout = 0;
struct node* map[MAP_MAX];
spinlock_t lock[MAP_MAX];

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
    set_timeout(sockfd, 3);
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

        res.channel = chan;
        if (num_bytes < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                timeout = 1;
                continue;
            }
            if(errno != EINTR) perror("recvfrom");
            break;
        } else timeout = 0;

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
            
            res.last = time(NULL);
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
    stop=1;
}

void change_channel()
{
    chan++;
    if(chan > num_frequency ) chan = 1;

    retry:
    req.u.freq.m = chan;
    req.u.freq.e = 0; // MHz
    if (ioctl(sockfd, SIOCSIWFREQ, &req) == -1){
        if(chan!=1)
        {
            chan=1;
            goto retry;
        }
    }
}

int expire_node(int index, Node *prev, Node *cur, Node **next)
{
    time_t diff = difftime(time(NULL),cur->data.last);
    if( diff > 5)
    {
        if(diff>10)
        {
            spinlock_lock(&lock[index]);
            if(!prev)
            {
                map[index] = NULL;
            }
            else
            {
                prev->next = cur->next;
            }
            *next = cur->next;
            spinlock_unlock(&lock[index]);
            del_node(cur);
            return 2;
        }
        return 1;

    }

    return 0;
}
void get_terminer_size(struct winsize *w)
{
    // Get terminel size
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, w) == 0) {
        // printf("Terminal Rows: %d\n", w.ws_row);
        // printf("Terminal Columns: %d\n", w.ws_col);
    } else {
        perror("ioctl error");
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
    Node *prev;
    struct winsize w;
    int warn;



    while(1)
    {
        if(stop) 
        {
            printf("\033[2K\rexit....\n");
            return NULL;
        }
        get_terminer_size(&w);
        printf("\033[?25l");
        for(int i=0;i<line_cnt;i++) printf("\033[A");
        printf("\033[K\rCHN: (%02d)        BSSID PWR(dBm) BEACONS ESSID", chan);
        if(timeout)
            printf("\033[K\r---Time out occured---");
        putchar('\n');
        line_cnt=1;

        for(int i=0;i<MAP_MAX;i++)
        {
            if(line_cnt + 2 > w.ws_row)
            {
                printf("\033[K\r---truncate-----");
                line_cnt++;
                break;
            }
            
            cur=map[i];
            prev = NULL;
            while(cur!=NULL)
            {
                warn = expire_node(i, prev, cur, &cur);
                if(warn == 2)
                {
                    continue;
                }
                info *data = &(cur->data);
                unsigned char *adr = data->bssid;
                printf("\033[K\r%3d: %02x:%02x:%02x:%02x:%02x:%02x %8d %7d ", 
                    data->channel, 
                    adr[0], adr[1], adr[2], adr[3], adr[4], adr[5],
                    data->pwr, data->beacon_cnt
                );

                if(strlen(data->essid))
                    printf("%.*s", data->length, data->essid);
                else
                    printf("\033[1;35mNo SSID\033[0m");
                if(warn) printf("\033[31m--Time out--\033[0m");
                putchar('\n');
                line_cnt++;
                prev = cur;
                cur = cur->next;
            }
        }

        for(;line_cnt+1<w.ws_row;line_cnt++, putchar('\n'))
            printf("\033[K");
        

        change_channel();
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
    init_spinlocks();
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

__attribute__((noinline)) void del_node(Node *res)
{
    void *tmp = res->data.essid;
    res->data.essid = NULL;
    free(tmp);
    free(res);
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
    tmp->next = NULL;
    return tmp;


}

void change_name(Node *node, info *inf)
{
    if(node->data.length != inf->length) goto diff;

    char *c1= node->data.essid;
    char *c2= inf->essid;
    for(int i=0;i<inf->length;i++)
        if(c1++ != c2++) goto diff;
    return;

    diff:
    if(node->data.length > inf->length)
    {
        node->data.length = inf->length;
        memcpy(node->data.essid, inf->essid, inf->length);
        return;
    }

    char *tmp = malloc(inf->length+1);
    if(!tmp)
    {
        fprintf(stderr, "Out of Memory\n");
        return;
    } else
    {
        free(node->data.essid);
        node->data.essid = tmp;
        memcpy(tmp, inf->essid, inf->length);
    }
    
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
    if(!cur) goto not_found;
    

    int len = res->length;
    if(len != cur->data.length) goto not_found;
    unsigned char *c1=cur->data.bssid; 
    unsigned char *c2=res->bssid;

    //Compares the keys of nodes.
    for(int i=0; i< 6; i++) 
    {
        if(*c1++!=*c2++)
            goto not_found;
    }

    //Found smae key
    found:
        cur->data.beacon_cnt++;
        cur->data.pwr = res->pwr;
        cur->data.channel = res->channel;
        cur->data.last = time(NULL);
        change_name(cur, res);
        return;
    
    // No key founds, insert key
    not_found:
        Node *tmp = make_node(res);
        tmp->next = map[index];
        
        spinlock_lock(&lock[index]);
        map[index] = tmp;
        spinlock_unlock(&lock[index]);
        return;

}


int set_timeout(int sockfd, int seconds) {
    struct timeval timeout;
    timeout.tv_sec = seconds;
    timeout.tv_usec = 0;


    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_RCVTIMEO) failed");
        return -1;
    }


    if (setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("setsockopt(SO_SNDTIMEO) failed");
        return -1;
    }
    return 0;
}

void init_spinlocks() {
    for (int i = 0; i < MAP_MAX; i++) {
        atomic_flag_clear(&(lock[i].lock_flag));
    }
}

void spinlock_lock(spinlock_t *lock) {
    while (atomic_flag_test_and_set(&lock->lock_flag)) {
        // busy-wait
    }
}

void spinlock_unlock(spinlock_t *lock) {
    atomic_flag_clear(&lock->lock_flag);
}