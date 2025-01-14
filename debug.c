#include <stdio.h>
#include "airdump.h"

void print_info(info* res)
{
    printf("pwr: %d\n", res->pwr);
    print_addr("addr: ", res->bssid);
    printf("ssid: %.*s\n",res->length, res->essid);
    printf("cnt: %d\n",res->beacon_cnt);
}


void print_addr(char *str, addr adr)
{
    unsigned char *ptr=adr;
    if(str) printf("%s", str);
    for(int i=0;i<6;i++)
    {
        printf("%02x:",ptr[i]);
    }
    if(str) printf("\b \n");
    else printf("\b ");
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