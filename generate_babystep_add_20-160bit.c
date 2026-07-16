/*
gcc -O2 generate_babystep_add_20-160bit.c -lsecp256k1 -o generate_babystep_add_20-160bit

Examples:
  # Fresh start
  ./generate_babystep_add_20-160bit \
    --steps 101 --interval 1 --step-bits 20 \
    --output DB1_add_20bit.csv \
    --start-iter 0 \
    --start-key 03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852

  # Resume from mid-point
  ./generate_babystep_add_20-160bit \
    --steps 101 --interval 1 --step-bits 20 \
    --output DB_add_from1000.csv \
    --start-iter 1000 \
    --start-key 0379b59c51b74c17d11ed3a3daf55ae889ba77161719f983b16fe9846e8ce022b1 \
    --initial-gadd 0x9b9b4f3135e3e0aa3230fb9b6d08d1e17
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include <secp256k1.h>

/* ============================================================
   GLOBALS
   ============================================================ */
static int STEP_BITS = 120;
static secp256k1_context *ctx = NULL;

/* ============================================================
   scalar256_t
   ============================================================ */
typedef struct { unsigned char b[32]; } scalar256_t;

static scalar256_t parse_scalar256(const char *s) {
    scalar256_t r; memset(r.b, 0, 32);
    if (s[0]=='0' && (s[1]=='x'||s[1]=='X')) s += 2;
    size_t len = strlen(s);
    if (len > 64) len = 64;

    for (int i = 0; i < (int)len; i++) {
        char c = s[len - 1 - i];
        unsigned char v = (c>='0'&&c<='9') ? (unsigned char)(c-'0') :
                          (c>='a'&&c<='f') ? (unsigned char)(c-'a'+10) :
                          (c>='A'&&c<='F') ? (unsigned char)(c-'A'+10) : 0;
        int byte_idx = 31 - i/2;
        if (i % 2 == 0)
            r.b[byte_idx]  = v;
        else
            r.b[byte_idx] |= (unsigned char)(v << 4);
    }
    return r;
}

/* ============================================================
   SECP256K1 HELPERS
   ============================================================ */
static inline int init_secp256k1(void) {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return ctx != NULL;
}

static inline void cleanup_secp256k1(void) {
    if (ctx) secp256k1_context_destroy(ctx);
}

static inline int hex_to_bytes(const char *hex, unsigned char *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (sscanf(hex + i*2, "%2hhx", &bytes[i]) != 1) return 0;
    }
    return 1;
}

static inline int setup_pubkey(const char *hex, secp256k1_pubkey *pubkey) {
    unsigned char bytes[33];
    return hex_to_bytes(hex, bytes, 33) &&
           secp256k1_ec_pubkey_parse(ctx, pubkey, bytes, 33);
}

static inline int pubkey_to_hex_fast(const secp256k1_pubkey *pubkey, char *hex) {
    unsigned char bytes[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bytes, &len, pubkey,
                                       SECP256K1_EC_COMPRESSED)) return 0;
    for (int i = 0; i < 33; i++)
        sprintf(hex + i*2, "%02x", bytes[i]);
    hex[66] = '\0';
    return 1;
}

static inline int get_x(const secp256k1_pubkey *pubkey, unsigned char *x) {
    unsigned char bytes[33];
    size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bytes, &len, pubkey,
                                       SECP256K1_EC_COMPRESSED)) return 0;
    memcpy(x, bytes + 1, 32);
    return 1;
}

/* ============================================================
   STEP / TWEAK / SCALAR HELPERS
   ============================================================ */
static void calc_step_scalar(const unsigned char x[32],
                              unsigned char step[32],
                              int step_bits) {
    memset(step, 0, 32);
    int bytes = step_bits / 8;
    int rem   = step_bits % 8;

    memcpy(step + (32 - bytes), x + (32 - bytes), bytes);

    if (rem) {
        unsigned char mask = (unsigned char)((1 << rem) - 1);
        step[32 - bytes - 1] = x[32 - bytes - 1] & mask;
    }

    for (int i = 31; i >= 0; i--) {
        if (++step[i] != 0) break;
    }
}

static inline int tweak_add_scalar(secp256k1_pubkey *pubkey,
                                    const unsigned char scalar[32]) {
    return secp256k1_ec_pubkey_tweak_add(ctx, pubkey, scalar);
}

static inline void add_scalar(unsigned char a[32], const unsigned char b[32]) {
    int carry = 0;
    for (int i = 31; i >= 0; i--) {
        int v = a[i] + b[i] + carry;
        a[i]  = (unsigned char)(v & 0xff);
        carry = v >> 8;
    }
}

static void print_hex_trimmed(FILE *f, const unsigned char *v, size_t len) {
    size_t i = 0;
    while (i < len && v[i] == 0) i++;
    if (i == len) { fprintf(f, "0"); return; }

    if ((v[i] >> 4) == 0)
        fprintf(f, "%x",  v[i] & 0x0F);
    else
        fprintf(f, "%02x", v[i]);

    for (i = i + 1; i < len; i++)
        fprintf(f, "%02x", v[i]);
}

/* ============================================================
   MAIN GENERATION - แก้ไขชื่อตัวแปรให้ถูกต้อง
   ============================================================ */
static void generate_baby_steps(const char *outfile,
                                 int interval,
                                 int target_steps,
                                 long long start_iter,
                                 const char *start_key,
                                 const unsigned char init_gadd[32]) {
    secp256k1_pubkey pubkey;
    unsigned char x[32];
    unsigned char step_scalar[32];
    unsigned char g_add_scalar[32];

    memcpy(g_add_scalar, init_gadd, 32);

    if (!setup_pubkey(start_key, &pubkey)) {
        printf("❌ Invalid start_key\n"); return;
    }

    FILE *f = fopen(outfile, "w");
    if (!f) { printf("❌ Cannot open output file: %s\n", outfile); return; }

    fprintf(f, "iter,pubkey,hex_G_add\n");

    int recorded = 0;
    /* ✅ เปลี่ยนเป็น long long */
    long long total_steps = (long long)interval * target_steps;
    time_t start_time = time(NULL);
    long long next_display = total_steps / 5;   /* ✅ long long */
    long long next_save = 500000;

    printf("\n🚀 GENERATION STARTED\n");
    printf("========================================\n");
    printf("Output:      %s\n", outfile);
    printf("Target:      %d steps (record every %d)\n", target_steps, interval);
    printf("Total steps: %lld\n", total_steps);  /* ✅ %lld */
    printf("Start iter:  %lld\n", start_iter);
    printf("Step bits:   %d\n", STEP_BITS);
    printf("========================================\n");

    /* บันทึก iter 0 */
    char hex0[67];
    if (pubkey_to_hex_fast(&pubkey, hex0)) {
        fprintf(f, "%lld,%s,0x", start_iter, hex0);
        print_hex_trimmed(f, g_add_scalar, 32);
        fprintf(f, "\n");
        recorded++;
    }

    /* ✅ ใช้ long long ใน loop */
    for (long long i = 1; i <= total_steps; i++) {

        if (!get_x(&pubkey, x)) {
            printf("\n❌ Failed to get X at step %lld\n", i); break;
        }

        memset(step_scalar, 0, 32);
        calc_step_scalar(x, step_scalar, STEP_BITS);

        add_scalar(g_add_scalar, step_scalar);

        if (!tweak_add_scalar(&pubkey, step_scalar)) {
            printf("\n❌ tweak failed at step %lld\n", i); break;
        }

        if (i % interval == 0) {
            char hex[67];
            if (pubkey_to_hex_fast(&pubkey, hex)) {
                fprintf(f, "%lld,%s,0x", start_iter + i, hex);
                print_hex_trimmed(f, g_add_scalar, 32);
                fprintf(f, "\n");
                recorded++;
            }
        }

        /* Progress */
        if (i >= next_display) {
            time_t now = time(NULL);
            double elapsed = difftime(now, start_time);
            double speed = elapsed > 0 ? (double)i / elapsed : 0;
            double percent = (double)i / total_steps * 100.0;
            int eta = speed > 0 ? (int)((total_steps - i) / speed) : 0;

            printf("📊 %6.1f%% | %.0f iter/s | ETA: ", percent, speed);
            if (eta < 60) printf("%d sec", eta);
            else if (eta < 3600) printf("%d:%02d min", eta/60, eta%60);
            else printf("%d:%02d:%02d h", eta/3600, (eta%3600)/60, eta%60);
            printf("\n");

            next_display = i + total_steps / 5;
        }

        if (i >= next_save) {
            printf("💾 Checkpoint at step %lld\n", i);
            next_save = i + 100000000;
        }

        if (recorded >= target_steps) {
            printf("\n✅ Target reached: %d recorded\n", target_steps); break;
        }
    }

    fclose(f);

    time_t end_time = time(NULL);
    int total_elapsed = (int)difftime(end_time, start_time);
    double avg_speed = total_elapsed > 0 ? (double)total_steps / total_elapsed : 0;

    printf("\n✅ GENERATION COMPLETE\n");
    printf("========================================\n");
    printf("Output:    %s\n", outfile);
    printf("Recorded:  %d/%d\n", recorded, target_steps);
    printf("Time:      %d:%02d:%02d\n",
           total_elapsed/3600, (total_elapsed%3600)/60, total_elapsed%60);
    printf("Avg speed: %.0f steps/s\n", avg_speed);
    printf("========================================\n");
}

/* ============================================================
   HELP
   ============================================================ */
static void show_help(const char *prog) {
    printf("Baby Steps Generator (ADD mode: pubkey += step*G)\n");
    printf("==================================================\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -s, --steps N          Baby steps to record    (default: 30)\n");
    printf("  -i, --interval N       Record every N steps    (default: 1000000)\n");
    printf("  -o, --output FILE      Output CSV file         (default: baby_steps.csv)\n");
    printf("  --start-iter N         Starting iteration      (default: 0)\n");
    printf("  --start-key KEY        Starting pubkey (66 hex chars, required)\n");
    printf("  --initial-gadd HEX     Initial g_add value     (default: 0x0)\n");
    printf("  --step-bits N          Bits for step size      (default: 120)\n");
    printf("  -h, --help             Show this help\n");
    printf("\nOutput format: iter,pubkey,hex_G_add\n\n");
    printf("Example (fresh):\n");
    printf("  %s --steps 101 --interval 1 --step-bits 20 \\\n", prog);
    printf("     --output DB_add.csv \\\n");
    printf("     --start-key 03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852\n\n");
    printf("Example (resume):\n");
    printf("  %s --steps 101 --interval 1 --step-bits 20 \\\n", prog);
    printf("     --output DB_add_from1000.csv \\\n");
    printf("     --start-iter 1000 \\\n");
    printf("     --start-key 0379b59c51b74c17d11ed3a3daf55ae889ba77161719f983b16fe9846e8ce022b1 \\\n");
    printf("     --initial-gadd 0x9b9b4f3135e3e0aa3230fb9b6d08d1e17\n");
}

/* ============================================================
   MAIN
   ============================================================ */
int main(int argc, char **argv) {
    int           steps      = 30;
    int           interval   = 1000000;
    long long     start_iter = 0;
    const char   *outfile    = "baby_steps.csv";
    const char   *start_key  = "025e466e97ed0e7910d3d90ceb0332df48ddf67d456b9e7303b50a3d89de357336";
    scalar256_t   init_gadd;
    memset(init_gadd.b, 0, 32);

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        if      (!strcmp(arg, "-h") || !strcmp(arg, "--help")) {
            show_help(argv[0]); return 0;
        }
        else if (!strcmp(arg, "-s") || !strcmp(arg, "--steps")) {
            if (i+1 < argc) steps = atoi(argv[++i]);
            else { printf("❌ Missing value for %s\n", arg); return 1; }
        }
        else if (!strcmp(arg, "-i") || !strcmp(arg, "--interval")) {
            if (i+1 < argc) interval = atoi(argv[++i]);
            else { printf("❌ Missing value for %s\n", arg); return 1; }
        }
        else if (!strcmp(arg, "-o") || !strcmp(arg, "--output")) {
            if (i+1 < argc) outfile = argv[++i];
            else { printf("❌ Missing value for %s\n", arg); return 1; }
        }
        else if (!strcmp(arg, "--start-iter")) {
            if (i+1 < argc) start_iter = atoll(argv[++i]);
            else { printf("❌ Missing value for --start-iter\n"); return 1; }
        }
        else if (!strcmp(arg, "--start-key")) {
            if (i+1 < argc) start_key = argv[++i];
            else { printf("❌ Missing value for --start-key\n"); return 1; }
        }
        else if (!strcmp(arg, "--initial-gadd")) {
            if (i+1 < argc) init_gadd = parse_scalar256(argv[++i]);
            else { printf("❌ Missing value for --initial-gadd\n"); return 1; }
        }
        else if (!strcmp(arg, "--step-bits")) {
            if (i+1 < argc) STEP_BITS = atoi(argv[++i]);
            else { printf("❌ Missing value for --step-bits\n"); return 1; }
        }
        else {
            printf("❌ Unknown option: %s\n", arg);
            show_help(argv[0]); return 1;
        }
    }

    if (steps <= 0)              { printf("❌ steps must be > 0\n"); return 1; }
    if (interval <= 0)           { printf("❌ interval must be > 0\n"); return 1; }
    if (start_iter < 0)          { printf("❌ start-iter must be >= 0\n"); return 1; }
    if (strlen(start_key) != 66) { printf("❌ start-key must be 66 hex chars\n"); return 1; }
    if (STEP_BITS <= 0 || STEP_BITS > 256) {
        printf("❌ step-bits must be 1..256\n"); return 1;
    }

    char gadd_hex[65];
    for (int i = 0; i < 32; i++) sprintf(gadd_hex + i*2, "%02x", init_gadd.b[i]);
    char *gadd_trim = gadd_hex;
    while (*gadd_trim == '0' && *(gadd_trim+1) != '\0') gadd_trim++;

    printf("========================================\n");
    printf("  BABY STEPS GENERATOR (ADD)\n");
    printf("========================================\n");
    printf("Output:       %s\n", outfile);
    printf("Steps:        %d  |  Interval: %d\n", steps, interval);
    printf("Step bits:    %d\n", STEP_BITS);
    printf("Start iter:   %lld\n", start_iter);
    printf("Initial gadd: 0x%s\n", gadd_trim);
    printf("Start key:    %.20s...\n", start_key);
    printf("Total steps:  %lld\n", (long long)interval * steps);  /* ✅ ใช้ %lld */
    printf("Final iter:   %lld\n", start_iter + (long long)interval * steps);
    
    printf("========================================\n");

    if (!init_secp256k1()) { printf("❌ secp256k1 init failed\n"); return 1; }

    generate_baby_steps(outfile, interval, steps,
                        start_iter, start_key, init_gadd.b);

    cleanup_secp256k1();
    return 0;
}
