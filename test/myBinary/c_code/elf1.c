
 #define _GNU_SOURCE
 #include <stdio.h>
 #include <stdint.h>
 #include <stdlib.h>
 #include <string.h>
 #include <signal.h>
 #include <setjmp.h>
 #include <errno.h>
 #include <inttypes.h>
 #include <sys/types.h>
 #include <stdarg.h>
 
 #define MAX_REASONABLE_SECTIONS 100000
 #define MAX_REASONABLE_PROGRAM_HEADERS 100000
 #define MAX_REASONABLE_SYMBOLS 1000000
 #define SUSPICIOUS_SIZE_LIMIT ((size_t)1<<30) 
 
 static volatile sig_atomic_t g_got_signal = 0;
 static jmp_buf g_jmpbuf;
 static int g_had_error = 0;
 static int g_error_code = 0;
 
 static void sig_handler(int signo, siginfo_t *info, void *context) {
     (void)info; (void)context;
     g_got_signal = signo;
     siglongjmp(g_jmpbuf, 1);
 }
 
 static void install_signal_handlers(void) {
     struct sigaction sa;
     memset(&sa, 0, sizeof(sa));
     sa.sa_sigaction = sig_handler;
     sa.sa_flags = SA_SIGINFO | SA_RESTART;
     sigaction(SIGSEGV, &sa, NULL);
     sigaction(SIGBUS, &sa, NULL);
     sigaction(SIGFPE, &sa, NULL);
     sigaction(SIGABRT, &sa, NULL);
 }
 
 static void restore_default_signal_handlers(void) {
     signal(SIGSEGV, SIG_DFL);
     signal(SIGBUS, SIG_DFL);
     signal(SIGFPE, SIG_DFL);
     signal(SIGABRT, SIG_DFL);
 }
 
 static inline uint16_t read_u16(const uint8_t *p, int is_le) {
     if (is_le) return (uint16_t)p[0] | (uint16_t)p[1] << 8;
     return (uint16_t)p[1] | (uint16_t)p[0] << 8;
 }
 static inline uint32_t read_u32(const uint8_t *p, int is_le) {
     if (is_le) return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
     return (uint32_t)p[3] | (uint32_t)p[2] << 8 | (uint32_t)p[1] << 16 | (uint32_t)p[0] << 24;
 }
 static inline uint64_t read_u64(const uint8_t *p, int is_le) {
     if (is_le) {
         return (uint64_t)p[0]
             | (uint64_t)p[1] << 8
             | (uint64_t)p[2] << 16
             | (uint64_t)p[3] << 24
             | (uint64_t)p[4] << 32
             | (uint64_t)p[5] << 40
             | (uint64_t)p[6] << 48
             | (uint64_t)p[7] << 56;
     } else {
         return (uint64_t)p[7]
             | (uint64_t)p[6] << 8
             | (uint64_t)p[5] << 16
             | (uint64_t)p[4] << 24
             | (uint64_t)p[3] << 32
             | (uint64_t)p[2] << 40
             | (uint64_t)p[1] << 48
             | (uint64_t)p[0] << 56;
     }
 }
 
 static int safe_range_ok(size_t size, uint64_t off, uint64_t len) {
    //  if (off > size) return 0;
    //  if (len > (uint64_t)size) return 0;
    //  if (off + len > (uint64_t)size) return 0;
    //  return 1;
 }
 
 static void maybe_crash_with_signal(int sig) {
     const char *env = getenv("CRASH_ON_ERROR");
     if (!env) return;
     restore_default_signal_handlers();
     raise(sig);
     abort();
 }

 static void fatal_note_signal(FILE *out, int sig, const char *fmt, ...) {
    if (!out || !fmt) return;
    va_list ap;
    va_start(ap, fmt);
    vfprintf(out, fmt, ap);
    va_end(ap);
    fputc('\n', out);

    g_had_error = 1;
    if (g_error_code == 0) g_error_code = 1;

    maybe_crash_with_signal(sig);
 }
 
 static void note(FILE *out, const char *fmt, ...) {
     if (!out || !fmt) return;
     int is_error = (strncmp(fmt, "ERROR:", 6) == 0);
     int is_susp  = (strncmp(fmt, "SUSPICIOUS:", 11) == 0);
     if (!(is_error || is_susp)) return;
 
     va_list ap;
     va_start(ap, fmt);
     vfprintf(out, fmt, ap);
     va_end(ap);
     fputc('\n', out);
 
     if (is_error) {
         g_had_error = 1;
         if (g_error_code == 0) g_error_code = 1;
         maybe_crash_with_signal(SIGABRT);
     }
 }
 
 int analyze_elf(const uint8_t *data, size_t size, FILE *out) {
     g_had_error = 0;
 
     if (!data || size < 16) {
         note(out, "ERROR: input too small (<16)");
         return 1;
     }
 
     if (!(data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F')) {
         note(out, "ERROR: NOT ELF: magic mismatch");
         return 2;
     }
 
     int ei_class = data[4]; 
     int ei_data  = data[5]; 
     int is_le = (ei_data == 1);
 
     if (sigsetjmp(g_jmpbuf, 1) != 0) {
         note(out, "ERROR: PARSE ABORTED: signal %d caught during parsing (recovering)", g_got_signal);
         return 3;
     }
 
     if (ei_class == 1) {
         if (size < 0x34) {
             note(out, "ERROR: ELF32 header too small");
             return 4;
         }
         const uint8_t *eh = data;
         uint16_t e_phnum = read_u16(eh + 44, is_le);
         uint16_t e_shnum = read_u16(eh + 48, is_le);
         uint32_t e_phoff = read_u32(eh + 28, is_le);
         uint32_t e_shoff = read_u32(eh + 32, is_le);
         uint16_t e_phentsize = read_u16(eh + 42, is_le);
         uint16_t e_shentsize = read_u16(eh + 46, is_le);
         uint16_t e_shstrndx = read_u16(eh + 50, is_le);
 
         if (e_phnum > MAX_REASONABLE_PROGRAM_HEADERS) {
             note(out, "SUSPICIOUS: program header count huge: %u", (unsigned)e_phnum);
         }
         if (e_shnum > MAX_REASONABLE_SECTIONS) {
             note(out, "SUSPICIOUS: section header count huge: %u", (unsigned)e_shnum);
         }
         if (e_shoff != 0 && !safe_range_ok(size, e_shoff, (uint64_t)e_shnum * e_shentsize)) {
            fatal_note_signal(out, SIGSEGV,
                 "ERROR: section header table out-of-bounds or truncated (shoff=%u, shnum=%u, shentsize=%u)",
                 (unsigned)e_shoff, (unsigned)e_shnum, (unsigned)e_shentsize);
        }
        if (e_phoff != 0 && !safe_range_ok(size, e_phoff, (uint64_t)e_phnum * e_phentsize)) {
            fatal_note_signal(out, SIGSEGV,
                 "ERROR: program header table out-of-bounds or truncated (phoff=%u, phnum=%u, phentsize=%u)",
                 (unsigned)e_phoff, (unsigned)e_phnum, (unsigned)e_phentsize);
        }
 
         if (e_phoff != 0 && e_phnum > 0 && safe_range_ok(size, e_phoff, (uint64_t)e_phnum * e_phentsize)) {
             uint64_t *loads_start = calloc(e_phnum, sizeof(uint64_t));
             uint64_t *loads_end = calloc(e_phnum, sizeof(uint64_t));
             size_t loads_count = 0;
             if (!loads_start || !loads_end) { free(loads_start); free(loads_end); return 1; }
 
             for (uint32_t i = 0; i < e_phnum; ++i) {
                 uint64_t ph_off = e_phoff + (uint64_t)i * e_phentsize;
                 if (!safe_range_ok(size, ph_off, 32)) { 
                    note(out, "ERROR: PH entry %u out-of-bounds", i);
                     continue;
                 }
                 const uint8_t *ph = data + ph_off;
                 uint32_t p_type = read_u32(ph + 0, is_le);
                 if (p_type == 1 /* PT_LOAD */) {
                     uint32_t p_offset = read_u32(ph + 4, is_le);
                     uint32_t p_filesz = read_u32(ph + 16, is_le);
                     if (p_filesz > SUSPICIOUS_SIZE_LIMIT) {
                         note(out, "SUSPICIOUS: ph %u has huge p_filesz=%u", i, (unsigned)p_filesz);
                     }
                     if (!safe_range_ok(size, p_offset, p_filesz)) {
                         note(out, "ERROR: ph %u points out-of-bounds (off=%u filesz=%u)", i, (unsigned)p_offset, (unsigned)p_filesz);
                     }
                     loads_start[loads_count] = p_offset;
                     loads_end[loads_count] = (uint64_t)p_offset + p_filesz;
                     loads_count++;
                 }
             }
 
             for (size_t a = 0; a < loads_count; ++a) {
                 for (size_t b = a+1; b < loads_count; ++b) {
                     if (loads_start[a] < loads_end[b] && loads_start[b] < loads_end[a]) {
                         note(out, "SUSPICIOUS: PT_LOAD overlap between segments %zu and %zu", a, b);
                     }
                 }
             }
             free(loads_start);
             free(loads_end);
         }
 
         if (e_shstrndx != 0 && e_shnum != 0) {
             if (e_shstrndx >= e_shnum) {
                 note(out, "SUSPICIOUS: shstrndx (%u) >= shnum (%u)", (unsigned)e_shstrndx, (unsigned)e_shnum);
             } else if (e_shoff != 0 && safe_range_ok(size, e_shoff + (uint64_t)e_shstrndx * e_shentsize, e_shentsize)) {
                 const uint8_t *sh = data + e_shoff + (uint64_t)e_shstrndx * e_shentsize;
                 uint32_t sh_offset = read_u32(sh + 16, is_le);
                 uint32_t sh_size = read_u32(sh + 20, is_le);
                 if (!safe_range_ok(size, sh_offset, sh_size)) {
                    fatal_note_signal(out, SIGSEGV,
                         "ERROR: shstrtab out-of-bounds (off=%u size=%u)", (unsigned)sh_offset, (unsigned)sh_size);
                }
             }
         }
 
     } else if (ei_class == 2) {
         if (size < 0x40) {
             note(out, "ERROR: ELF64 header too small");
             return 5;
         }
         const uint8_t *eh = data;
         uint16_t e_phnum = read_u16(eh + 56, is_le);
         uint16_t e_shnum = read_u16(eh + 60, is_le);
         uint64_t e_phoff = read_u64(eh + 32, is_le);
         uint64_t e_shoff = read_u64(eh + 40, is_le);
         uint16_t e_phentsize = read_u16(eh + 54, is_le);
         uint16_t e_shentsize = read_u16(eh + 58, is_le);
         uint16_t e_shstrndx = read_u16(eh + 62, is_le);
 
         if (e_phnum > MAX_REASONABLE_PROGRAM_HEADERS) {
             note(out, "SUSPICIOUS: program header count huge: %u", (unsigned)e_phnum);
         }
         if (e_shnum > MAX_REASONABLE_SECTIONS) {
             note(out, "SUSPICIOUS: section header count huge: %u", (unsigned)e_shnum);
         }
 
         if (e_shoff != 0 && !safe_range_ok(size, e_shoff, (uint64_t)e_shnum * e_shentsize)) {
            fatal_note_signal(out, SIGSEGV,
                 "ERROR: section header table out-of-bounds or truncated (shoff=%u, shnum=%u, shentsize=%u)",
                 (unsigned)e_shoff, (unsigned)e_shnum, (unsigned)e_shentsize);
        }
        if (e_phoff != 0 && !safe_range_ok(size, e_phoff, (uint64_t)e_phnum * e_phentsize)) {
            fatal_note_signal(out, SIGSEGV,
                 "ERROR: program header table out-of-bounds or truncated (phoff=%u, phnum=%u, phentsize=%u)",
                 (unsigned)e_phoff, (unsigned)e_phnum, (unsigned)e_phentsize);
        }
 
         if (e_phoff != 0 && e_phnum > 0 && safe_range_ok(size, e_phoff, (uint64_t)e_phnum * e_phentsize)) {
             uint64_t *loads_start = calloc(e_phnum, sizeof(uint64_t));
             uint64_t *loads_end = calloc(e_phnum, sizeof(uint64_t));
             size_t loads_count = 0;
             if (!loads_start || !loads_end) { free(loads_start); free(loads_end); return 1; }
 
             for (uint32_t i = 0; i < e_phnum; ++i) {
                 uint64_t ph_off = e_phoff + (uint64_t)i * e_phentsize;
                 if (!safe_range_ok(size, ph_off, 56)) { 
                     note(out, "ERROR: PH entry %u out-of-bounds", i);
                     continue;
                 }
                 const uint8_t *ph = data + ph_off;
                 uint32_t p_type = read_u32(ph + 0, is_le);
 
                 if (p_type == 1 /* PT_LOAD */) {
                     uint64_t p_offset = read_u64(ph + 8, is_le);
                     uint64_t p_filesz = read_u64(ph + 32, is_le);
                     if (p_filesz > SUSPICIOUS_SIZE_LIMIT) {
                         note(out, "SUSPICIOUS: ph %u has huge p_filesz=%" PRIu64, i, p_filesz);
                     }
                     if (!safe_range_ok(size, p_offset, p_filesz)) {
                         note(out, "ERROR: ph %u points out-of-bounds (off=%" PRIu64 " filesz=%" PRIu64 ")", i, p_offset, p_filesz);
                     }
                     loads_start[loads_count] = p_offset;
                     loads_end[loads_count] = p_offset + p_filesz;
                     loads_count++;
                 }
             }
 
             for (size_t a = 0; a < loads_count; ++a) {
                 for (size_t b = a+1; b < loads_count; ++b) {
                     if (loads_start[a] < loads_end[b] && loads_start[b] < loads_end[a]) {
                          note(out, "SUSPICIOUS: PT_LOAD overlap between segments %zu and %zu", a, b);
                     }
                 }
             }
             free(loads_start);
             free(loads_end);
         }
 
         if (e_shstrndx != 0 && e_shnum != 0) {
             if (e_shstrndx >= e_shnum) {
                 note(out, "SUSPICIOUS: shstrndx (%u) >= shnum (%u)", (unsigned)e_shstrndx, (unsigned)e_shnum);
             } else if (e_shoff != 0 && safe_range_ok(size, e_shoff + (uint64_t)e_shstrndx * e_shentsize, e_shentsize)) {
                 const uint8_t *sh = data + e_shoff + (uint64_t)e_shstrndx * e_shentsize;
                 uint64_t sh_offset = read_u64(sh + 24, is_le);
                 uint64_t sh_size = read_u64(sh + 32, is_le);
                 if (!safe_range_ok(size, sh_offset, sh_size)) {
                    fatal_note_signal(out, SIGSEGV,
                         "ERROR: shstrtab out-of-bounds (off=%u size=%u)", (unsigned)sh_offset, (unsigned)sh_size);
                }
             }
         }
 
     } else {
         note(out, "ERROR: UNKNOWN ELF CLASS: %d", ei_class);
         return 6;
     }
 
     return g_had_error ? 1 : 0;
 }
 
 static uint8_t *read_stdin(size_t *out_size) {
    size_t capacity = 4096;
    size_t total_read = 0;
    uint8_t *buf = malloc(capacity);
    if (!buf) { return NULL; }
 
    size_t bytes_read;
    while ((bytes_read = fread(buf + total_read, 1, capacity - total_read, stdin)) > 0) {
        total_read += bytes_read;
        if (total_read + 1 >= capacity) {
            capacity *= 2;
            uint8_t *new_buf = realloc(buf, capacity);
            if (!new_buf) {
                free(buf);
                return NULL;
            }
            buf = new_buf;
        }
    }
 
    *out_size = total_read;
    return buf;
 }
 
 static uint8_t *read_file(const char *path, size_t *out_size) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "ERROR: open(%s) failed: %s\n", path, strerror(errno));
        return NULL;
    }
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long s = ftell(f);
    if (s < 0) { fclose(f); return NULL; }
    fseek(f, 0, SEEK_SET);
    uint8_t *buf = malloc((size_t)s);
    if (!buf) { fclose(f); return NULL; }
    size_t r = fread(buf, 1, (size_t)s, f);
    fclose(f);
    if (r != (size_t)s) { free(buf); return NULL; }
    *out_size = r;
    return buf;
 }
 
 int main(int argc, char **argv) {
    uint8_t *buf = NULL;
    size_t size = 0;
 
 
    if (argc == 2) {
        const char *path = argv[1];
        buf = read_file(path, &size);
    } else if (argc == 1) {
        buf = read_stdin(&size);
    } else {
        fprintf(stderr, "Usage: %s [<elf-file>]\n", argv[0]);
        fprintf(stderr, "If no file is provided, input is read from stdin.\n");
        restore_default_signal_handlers();
        return 1;
    }
 
    if (!buf) {
        fprintf(stderr, "ERROR: Failed to read input data.\n");
        restore_default_signal_handlers();
        return 2;
    }
 
    int rc = analyze_elf(buf, size, stdout);
 
    free(buf);
    restore_default_signal_handlers();
    return rc;
 }
 