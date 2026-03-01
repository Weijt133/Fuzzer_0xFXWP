#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


typedef unsigned char  nj_uint8_t;
typedef unsigned int   nj_uint32_t;
typedef unsigned short nj_uint16_t;

typedef struct _nj_context_t {
    nj_uint8_t* pos;          
    int size;                 
    int length;               
    nj_uint8_t* file;         
    int width;                
    int height;               
    int ncomp;                
    nj_uint8_t* image;        
} nj_context_t;

static nj_context_t nj;

void njThrow(const char* e) {
    exit(0);
}


unsigned char njReadByte(void) {
    if (nj.size <= 0) njThrow("Unexpected EOF");
    nj.size--;
    return *nj.pos++;
}

unsigned short njReadWord(void) {
    unsigned short z = njReadByte() << 8;
    return z | njReadByte();
}

void njDecode(void) {
    
    if (njReadWord() != 0xFFD8) njThrow("Not a JPEG");

    while (1) {
        if (nj.size <= 0) break;
        if (njReadByte() != 0xFF) continue;
        unsigned char marker = njReadByte();
        if (marker == 0xD9) break; 
        if (marker == 0x00) continue; 
        if ((marker >= 0xD0 && marker <= 0xD7) || marker == 0x01) continue;
        unsigned short len = njReadWord();
        int payload_len = len - 2;
        if (payload_len < 0) njThrow("Bad length");

        if (marker == 0xC0) {
            njReadByte(); 
            nj.height = njReadWord();
            nj.width = njReadWord();
            nj.ncomp = njReadByte();
            
            
            nj.pos += (payload_len - 6);
            nj.size -= (payload_len - 6);

            printf("[+] Found SOF0: %d x %d (Components: %d)\n", nj.width, nj.height, nj.ncomp);

 
            uint64_t real_size = (uint64_t)nj.width * (uint64_t)nj.height * (uint64_t)nj.ncomp;

            uint16_t alloc_size = (uint16_t)real_size;

            printf("[DEBUG] Real Size: %lu, Alloc Size (Truncated): %d\n", real_size, alloc_size);

            nj.image = (nj_uint8_t*)malloc(alloc_size);
            if (!nj.image && alloc_size > 0) njThrow("Out of memory");

            if (nj.image) {
                printf("[+] Start 'decoding' (writing to heap)...\n");
                uint64_t limit = real_size;
                volatile uint8_t* ptr = nj.image;
                for (uint64_t i = 0; i < limit; ++i) {
                    ptr[i] = 0xCC; 
                    if ((i % 4096 == 0) && (i > alloc_size + 65536)) {
                        
                        ptr[real_size - 1] = 0x41;
                        break;
                    }
                }
                free(nj.image);
            }
            
            break; 
        } 
        else {
            
            if (nj.size < payload_len) njThrow("Incomplete file");
            nj.pos += payload_len;
            nj.size -= payload_len;
        }
    }
}

int main(int argc, char* argv[]) {
    FILE* f = stdin;
    if (argc > 1) {
        f = fopen(argv[1], "rb");
        if (!f) {
            printf("Error opening file.\n");
            return 1;
        }
    }

    
    fseek(f, 0, SEEK_END);
    int size = (int)ftell(f);
    if (size <= 0) {
        
        if (f == stdin) {
            nj.file = malloc(1024 * 1024 * 10); 
            int read = 0;
            while (!feof(stdin)) {
                read += fread(nj.file + read, 1, 4096, stdin);
                if (read > 1024 * 1024 * 9) break;
            }
            nj.size = read;
            nj.length = read;
            nj.pos = nj.file;
        } else {
             return 0;
        }
    } else {
        fseek(f, 0, SEEK_SET);
        nj.length = size;
        nj.size = size;
        nj.file = (unsigned char*)malloc(size);
        fread(nj.file, 1, size, f);
    }

    if (f != stdin) fclose(f);
    nj.pos = nj.file;
    njDecode();
    if (nj.file) free(nj.file);
    return 0;
}