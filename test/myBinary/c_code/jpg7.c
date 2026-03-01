#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* * JPG7: 模拟 DQT 越界写 和 SOS 堆溢出漏洞
 * * 目标 1 (DQT): 修改 DQT 表 ID (0-3) 为大数 (如 50)，触发全局数组越界写。
 * * 目标 2 (SOS): 修改 SOS 后的压缩数据，使其解压后的数据量超过图像尺寸，触发堆溢出。
 */

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;


#define M_SOI   0xD8
#define M_EOI   0xD9
#define M_SOF0  0xC0
#define M_DQT   0xDB
#define M_DHT   0xC4
#define M_SOS   0xDA


struct {
    const uint8_t* pos;     
    int size;               
    int width;              
    int height;             
    uint8_t* frame_buffer;  
} nj;



uint8_t QuantizationTables[4][64]; 

void njThrow(const char* msg) {
    
    exit(0);
}

uint8_t njReadByte(void) {
    if (nj.size < 1) njThrow("Unexpected EOF");
    nj.size--;
    return *nj.pos++;
}

uint16_t njReadWord(void) {
    uint16_t z = njReadByte() << 8;
    return z | njReadByte();
}


void njDecodeDQT(void) {
    uint16_t len = njReadWord();
    len -= 2;

    while (len > 0) {
        uint8_t info = njReadByte();
        len--;
        
        uint8_t id = info & 0x0F; 

        
        printf("[*] Parsing DQT table ID: %d\n", id);

        for (int i = 0; i < 64; ++i) {
            if (len < 1) njThrow("Bad DQT length");
            QuantizationTables[id][i] = njReadByte(); 
            len--;
        }
    }
}

void njDecodeSOF0(void) {
    uint16_t len = njReadWord();
    njReadByte(); 
    nj.height = njReadWord();
    nj.width = njReadWord();
    
    int skip = len - 2 - 1 - 2 - 2;
    while (skip-- > 0) njReadByte();

    printf("[*] Size: %dx%d\n", nj.width, nj.height);

    if (nj.width > 5000 || nj.height > 5000) njThrow("Image too big");
    
    nj.frame_buffer = (uint8_t*)malloc(nj.width * nj.height * 3); 
    if (!nj.frame_buffer) njThrow("OOM");
}

void njDecodeSOS(void) {
    uint16_t len = njReadWord();
    int skip = len - 2;
    while (skip-- > 0) njReadByte();

    printf("[*] Start decoding entropy data (SOS)...\n");
    
    if (!nj.frame_buffer) return;

    int max_size = nj.width * nj.height * 3;
    int cursor = 0;
    
    while (nj.size > 0) {
        uint8_t b = njReadByte();
        
        if (b == 0xFF) {
            uint8_t b2 = njReadByte();
            if (b2 == 0xD9) break; 
            if (b2 == 0x00) b = 0xFF; 
            else continue; 
        }

        int repeat = 1;
        if (b >= 128) repeat = 10; 

        for (int k = 0; k < repeat; k++) {
            
            nj.frame_buffer[cursor++] = 0xCC; 
            
            if (cursor > max_size + 4096) {
                 
                 volatile uint8_t* crash_ptr = (uint8_t*)0x1;
                 *crash_ptr = 0;
            }
        }
    }
    
    free(nj.frame_buffer);
    nj.frame_buffer = NULL;
    printf("[*] Decoding finished.\n");
}

void njDecode(const uint8_t* data, int size) {
    nj.pos = data;
    nj.size = size;
    nj.frame_buffer = NULL;

    if (njReadWord() != 0xFFD8) njThrow("Not a JPEG");

    while (nj.size > 0) {
        if (njReadByte() != 0xFF) continue;
        uint8_t marker = njReadByte();
        
        switch (marker) {
            case M_DQT: njDecodeDQT(); break;
            case M_SOF0: njDecodeSOF0(); break;
            case M_SOS: njDecodeSOS(); return; 
            case M_EOI: return;
            default: {
                
                uint16_t len = njReadWord();
                int payload = len - 2;
                while (payload-- > 0) njReadByte();
            }
        }
    }
}

int main(int argc, char* argv[]) {
    
    FILE* f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) return 1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    if (fsize <= 0) { 
        uint8_t* buf = malloc(1024 * 1024 * 5); 
        int n = 0;
        while(!feof(f) && n < 1024 * 1024 * 5) {
            n += fread(buf + n, 1, 4096, f);
        }
        njDecode(buf, n);
        free(buf);
    } else {
        fseek(f, 0, SEEK_SET);
        uint8_t* buf = malloc(fsize);
        fread(buf, 1, fsize, f);
        njDecode(buf, fsize);
        free(buf);
    }

    if (f != stdin) fclose(f);
    return 0;
}