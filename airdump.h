#ifndef AIRDUMP_25_1_10
#define AIRDUMP_25_1_10
#include <ctype.h>
#include <stdint.h>
#include <stdatomic.h>
#include <time.h>

#define TAG_SSID_NAME 0
#define TAG_RSN 48
#define MAP_MAX 0x200



//https://www.radiotap.org/fields/defined
#define RADIOTAP_TSFT                 (1 << 0)   // TSFT
#define RADIOTAP_FLAGS                (1 << 1)   // Flags
#define RADIOTAP_RATE                 (1 << 2)   // Rate
#define RADIOTAP_CHANNEL              (1 << 3)   // Channel
#define RADIOTAP_FHSS                 (1 << 4)   // FHSS
#define RADIOTAP_ANTENNA_SIGNAL       (1 << 5)   // Antenna signal
#define RADIOTAP_ANTENNA_NOISE        (1 << 6)   // Antenna noise
#define RADIOTAP_LOCK_QUALITY         (1 << 7)   // Lock quality
#define RADIOTAP_TX_ATTENUATION       (1 << 8)   // TX attenuation
#define RADIOTAP_DB_TX_ATTENUATION    (1 << 9)   // dB TX attenuation
#define RADIOTAP_DBM_TX_POWER         (1 << 10)  // dBm TX power
#define RADIOTAP_ANTENNA              (1 << 11)  // Antenna
#define RADIOTAP_DB_ANTENNA_SIGNAL    (1 << 12)  // dB antenna signal
#define RADIOTAP_DB_ANTENNA_NOISE     (1 << 13)  // dB antenna noise
#define RADIOTAP_RX_FLAGS             (1 << 14)  // RX flags
#define RADIOTAP_TX_FLAGS             (1 << 15)  // TX flags
#define RADIOTAP_MCS                  (1 << 19)  // MCS
#define RADIOTAP_AMPDU_STATUS         (1 << 20)  // A-MPDU status
#define RADIOTAP_VHT                  (1 << 21)  // VHT
#define RADIOTAP_TIMESTAMP            (1 << 22)  // Timestamp
#define RADIOTAP_HE                   (1 << 23)  // HE
#define RADIOTAP_HE_MU                (1 << 24)  // HE-MU
#define RADIOTAP_HE_MU_OTHER_USER     (1 << 25)  // HE-MU-other-user
#define RADIOTAP_ZERO_LENGTH_PSDU     (1 << 26)  // 0-length-PSDU
#define RADIOTAP_L_SIG                (1 << 27)  // L-SIG
#define RADIOTAP_TLV_FIELDS           (1 << 28)  // TLV fields in radiotap
#define RADIOTAP_RADIOTAP_NAMESPACE   (1 << 29)  // Radiotap Namespace
#define RADIOTAP_VENDOR_NAMESPACE     (1 << 30)  // Vendor Namespace
#define RADIOTAP_EXT                  (1 << 31)
#define RADIOTAP_S1G                  (1 << 0)  // S1G
#define RADIOTAP_U_SIG                (1 << 1)  // U-SIG
#define RADIOTAP_EHT                  (1 << 2)  // EHT

#define BUILD_ERR() {asm volatile("int $3");}

struct ieee80211_radiotap_header {
        uint8_t        it_version;
        uint8_t        it_pad;
        uint16_t       it_len;
        uint32_t       it_present;
} __attribute__((__packed__));

typedef unsigned char addr[6];
struct beacon_frame {
    uint16_t magic;
    uint16_t dur;
    addr dst_addr;
    addr src_addr;
    addr bss_id;
    uint16_t extra;
} __attribute__((__packed__));

struct info {
    char pwr;
    char padding;
    addr bssid;
    char *essid;
    int length;
    int beacon_cnt;
    int channel;
    time_t last;
};
struct node {
    struct info data;
    struct node *next;
};
typedef struct {
    atomic_flag lock_flag;
} spinlock_t;

typedef struct info info;
typedef struct node Node;

void parse_radiotap(void *start, void *end, info *res, void *align_base);
void *parse_radiotap_body(uint32_t flags, void *start, void *end, info * res, void *align_base);
void parse_becon_body(void *start, void *end, info *res);
void setup_monitor();
void submit_info(info* res);
int hash(addr key);
void change_channel();
void print_info(info* res);
void print_addr(char *str, addr adr);
int set_timeout(int sockfd, int seconds);


void init_spinlocks();
void spinlock_lock(spinlock_t *lock);
void spinlock_unlock(spinlock_t *lock);
void del_node(Node *res);
void print_bits(unsigned int num);
#endif
