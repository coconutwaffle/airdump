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
#include <errno.h>
#include <ctype.h>

#include "airdump.h"

void print_addr(char *str, addr adr)
{
    unsigned char *ptr=adr;
    if(str) printf("%s", str);
    for(int i=0;i<6;i++)
    {
        printf("%02x:",ptr[i]);
    }
    printf("\b \n");
}

// HEX 덤프 함수
void hexDump(const void *buffer, size_t size) {
    const unsigned char *data = (const unsigned char *)buffer;
    size_t i, j;

    printf("Address         Hexadecimal Values                    ASCII\n");
    printf("---------------------------------------------------------------\n");

    for (i = 0; i < size; i += 16) {
        // 주소 출력
        printf("%08zx  ", i);

        // HEX 출력
        for (j = 0; j < 16; ++j) {
            if (i + j < size)
                printf("%02x ", data[i + j]);
            else
                printf("   ");  // 남은 공간 채우기
        }

        printf(" ");

        // ASCII 출력
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = data[i + j];
                printf("%c", isprint(c) ? c : '.');  // 출력 가능한 문자 아니면 '.' 출력
            }
        }

        printf("\n");
    }
}

int main(int argc, char *argv[]) {
    int sockfd;
    struct ifreq ifr;
    struct sockaddr_ll sll;
    int ret;

    if(argc!=2)
    {
        fprintf(stderr, "Use: airodump <interface>\n");
        return 2;
    }

    // 1. 소켓 생성: PF_PACKET / SOCK_RAW / ETH_P_ALL(모든 이더타입 캡처)
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("socket");
        return 2;
    }

    // 2. 인터페이스 인덱스 가져오기
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ - 1);

    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) == -1) {
        perror("ioctl - SIOCGIFINDEX");
        close(sockfd);
        return 2;
    }

    // 3. 소켓 주소 구조체 설정
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_ifindex  = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);

    // 4. 바인드
    ret = bind(sockfd, (struct sockaddr *)&sll, sizeof(sll));
    if (ret < 0) {
        perror("bind");
        close(sockfd);
        return EXIT_FAILURE;
    }


#ifndef DEBUG
    setup_monitor();
#endif

    // 5. 패킷 수신 루프
    while (1) {
        unsigned char buf[65536];
        struct beacon_frame *beacon;
        struct ieee80211_radiotap_header *radiotap = (struct ieee80211_radiotap_header *)buf;
        info res;
        ssize_t num_bytes = recvfrom(sockfd, buf, sizeof(buf), 0, NULL, NULL);
        if (num_bytes < 0) {
            perror("recvfrom");
            break;
        }
        //hexDump(buf, num_bytes);
        beacon = (struct beacon_frame *)(buf + radiotap->it_len);
        if(beacon->magic == 0x0080)
        {
#ifdef DEBUG            
            printf("----------\n");
            printf("Captured %zd bytes\n", num_bytes);
            print_addr("BSS ID: ",beacon->bss_id);
#endif
            parse_radiotap_body(radiotap->it_present, buf+sizeof(struct ieee80211_radiotap_header), beacon, &res);
            parse_becon_body((void *)beacon + sizeof(struct beacon_frame), buf+num_bytes, &res);
        }

    }

    close(sockfd);
    return 0;
}

void parse_becon_body(void *start, void *end, info *res)
{
    uint64_t *timestamp;
    uint16_t *interver;
    uint16_t *cap;
    timestamp = start;
    interver = start + 8;
    cap = start + 10;
#ifdef DEBUG 
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

#define NOT_YET() {asm volatile("int $3");}
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
#ifdef DEBUG
        printf("dBm: %d\n", *(char *)pos);
#else
        res->pwr=*(char *)pos;
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
    if (flags & RADIOTAP_RADIOTAP_NAMESPACE)   { NOT_YET();}  // Radiotap Namespace
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
            NOT_YET();
            pos += 40 + 4*(0);
        }  // EHT
     }


    if(pos != end)
    {
        fprintf(stderr, "radiotap: %p, %p, %p\n", start, pos, end);
	    fprintf(stderr, "radiotap header: parsing fail\n");
        NOT_YET();
    }
}


void setup_monitor()
{
    return;
}