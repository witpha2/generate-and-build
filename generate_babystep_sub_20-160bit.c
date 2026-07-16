/*
gcc -O2 generate_babystep_sub_20-160bit.c -lsecp256k1 -o generate_babystep_sub_20-160bit

Modes:

  1) Single walker fresh start
     ./generate_babystep_sub_20-160bit \
       --steps 2600000 --step-bits 20 \
       --output DB.csv \
       --start-key 03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852

  2) Multi-walker: เดินต่อ N steps → เซฟ snapshot เดียว (ไฟล์เล็ก)
     ./generate_babystep_sub_20-160bit \
       --steps 20000 --step-bits 20 \
       --start-from-file snap_4600000.csv \
       --output snap_4620000.csv \
       --final-only

  3) Multi-walker: เดินต่อ + บันทึกทุก interval (ใช้เป็น DB)
     ./generate_babystep_sub_20-160bit \
       --steps 2600000 --interval 1 --step-bits 20 \
       --start-from-file snap_4600000.csv \
       --output DB_4600000_4620000.csv

  4) Resume ต่อจาก output เดิม
     ./generate_babystep_sub_20-160bit \
       --steps 5000000 --interval 1 --step-bits 20 \
       --output DB.csv --resume
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
#define MAX_WALKERS 65536

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
        if (i % 2 == 0) r.b[byte_idx]  = v;
        else            r.b[byte_idx] |= (unsigned char)(v << 4);
    }
    return r;
}

static void scalar256_to_trimhex(const scalar256_t *v, char *out, size_t outsz) {
    char tmp[65];
    for (int i = 0; i < 32; i++) sprintf(tmp + i*2, "%02x", v->b[i]);
    tmp[64] = '\0';
    const char *p = tmp;
    while (*p == '0' && *(p+1) != '\0') p++;
    snprintf(out, outsz, "%s", p);
}

/* ============================================================
   Walker struct
   ============================================================ */
typedef struct {
    secp256k1_pubkey pk;
    scalar256_t      gsub;
    long long        iter;
} Walker;

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
    for (size_t i = 0; i < len; i++)
        if (sscanf(hex + i*2, "%2hhx", &bytes[i]) != 1) return 0;
    return 1;
}
static inline int setup_pubkey(const char *hex, secp256k1_pubkey *pubkey) {
    unsigned char bytes[33];
    return hex_to_bytes(hex, bytes, 33) &&
           secp256k1_ec_pubkey_parse(ctx, pubkey, bytes, 33);
}
static inline int pubkey_to_hex_fast(const secp256k1_pubkey *pubkey, char *hex) {
    unsigned char bytes[33]; size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bytes, &len, pubkey,
                                       SECP256K1_EC_COMPRESSED)) return 0;
    for (int i = 0; i < 33; i++) sprintf(hex + i*2, "%02x", bytes[i]);
    hex[66] = '\0';
    return 1;
}
static inline int get_x(const secp256k1_pubkey *pubkey, unsigned char *x) {
    unsigned char bytes[33]; size_t len = 33;
    if (!secp256k1_ec_pubkey_serialize(ctx, bytes, &len, pubkey,
                                       SECP256K1_EC_COMPRESSED)) return 0;
    memcpy(x, bytes + 1, 32);
    return 1;
}

/* ============================================================
   STEP / TWEAK / SCALAR HELPERS
   ============================================================ */
static void calc_step_scalar(const unsigned char x[32],
                              unsigned char step[32], int step_bits) {
    memset(step, 0, 32);
    int bytes = step_bits / 8;
    int rem   = step_bits % 8;
    memcpy(step + (32 - bytes), x + (32 - bytes), bytes);
    if (rem) {
        unsigned char mask = (unsigned char)((1 << rem) - 1);
        step[32 - bytes - 1] = x[32 - bytes - 1] & mask;
    }
    for (int i = 31; i >= 0; i--)
        if (++step[i] != 0) break;
}

static inline int tweak_sub_scalar(secp256k1_pubkey *pubkey,
                                    const unsigned char scalar[32]) {
    if (!secp256k1_ec_pubkey_negate(ctx, pubkey)) return 0;
    if (!secp256k1_ec_pubkey_tweak_add(ctx, pubkey, scalar)) return 0;
    if (!secp256k1_ec_pubkey_negate(ctx, pubkey)) return 0;
    return 1;
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
    if ((v[i] >> 4) == 0) fprintf(f, "%x",  v[i] & 0x0F);
    else                  fprintf(f, "%02x", v[i]);
    for (i = i + 1; i < len; i++) fprintf(f, "%02x", v[i]);
}

static void trim_right(char *s) {
    char *p = s + strlen(s) - 1;
    while (p >= s && (*p=='\r'||*p=='\n'||*p==' '||*p=='\t')) *p-- = '\0';
}

/* ============================================================
   LOAD WALKERS FROM CSV
   เลือกเฉพาะบรรทัดที่ iter == max_iter ในไฟล์
   ============================================================ */
static int load_walkers_from_csv(const char *filename,
                                  Walker    **out_walkers,
                                  int        *out_count,
                                  long long  *out_base_iter) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { printf("❌ Cannot open: %s\n", filename); return 0; }

    char line[512];

    /* skip header — ตรวจ return value เพื่อป้องกัน warning */
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp); printf("❌ Empty file: %s\n", filename); return 0;
    }

    /* pass 1: หา max iter */
    long long max_iter = -1;
    while (fgets(line, sizeof(line), fp)) {
        trim_right(line);
        if (strlen(line) < 5) continue;
        long long it = atoll(line);
        if (it > max_iter) max_iter = it;
    }
    if (max_iter < 0) { fclose(fp); printf("❌ No data in %s\n", filename); return 0; }

    /* pass 2: โหลดเฉพาะ iter == max_iter */
    rewind(fp);
    if (!fgets(line, sizeof(line), fp)) {   /* skip header */
        fclose(fp); return 0;
    }

    Walker *ws = (Walker*)malloc(MAX_WALKERS * sizeof(Walker));
    if (!ws) { fclose(fp); printf("❌ malloc failed\n"); return 0; }

    int cnt = 0;
    while (fgets(line, sizeof(line), fp) && cnt < MAX_WALKERS) {
        trim_right(line);
        if (strlen(line) < 5) continue;

        char tmp[512];
        strncpy(tmp, line, sizeof(tmp)-1); tmp[511] = '\0';

        char *it  = strtok(tmp, ",");
        char *pub = strtok(NULL, ",");
        char *gs  = strtok(NULL, ",");
        if (!it || !pub || !gs) continue;

        while (*it  == ' ') it++;
        while (*pub == ' ') pub++;
        while (*gs  == ' ') gs++;
        trim_right(pub); trim_right(gs);

        if (atoll(it) != max_iter) continue;
        if (strlen(pub) != 66)     continue;

        ws[cnt].iter = max_iter;
        ws[cnt].gsub = parse_scalar256(gs);
        if (!setup_pubkey(pub, &ws[cnt].pk)) {
            printf("⚠️  Skip invalid pubkey at row %d\n", cnt+1);
            continue;
        }
        cnt++;
    }
    fclose(fp);

    if (cnt == 0) {
        free(ws);
        printf("❌ No valid walkers at iter=%lld\n", max_iter);
        return 0;
    }

    *out_walkers   = ws;
    *out_count     = cnt;
    *out_base_iter = max_iter;
    printf("✅ Loaded %d walkers  (base iter=%lld)\n", cnt, max_iter);
    return 1;
}

/* ============================================================
   SAVE SNAPSHOT (เขียน header + บรรทัดทุก walker)
   ============================================================ */
static void save_snapshot(FILE *f, Walker *walkers, int nwalkers) {
    for (int w = 0; w < nwalkers; w++) {
        char hex[67];
        if (pubkey_to_hex_fast(&walkers[w].pk, hex)) {
            fprintf(f, "%lld,%s,0x", walkers[w].iter, hex);
            print_hex_trimmed(f, walkers[w].gsub.b, 32);
            fprintf(f, "\n");
        }
    }
}

/* ============================================================
   MAIN GENERATION  (multi-walker)

   final_only = 1  → เดินครบแล้วเซฟ snapshot เดียว (ไฟล์เล็ก เร็ว)
   final_only = 0  → เซฟทุก interval (ใช้เป็น DB สำหรับ walker)
   ============================================================ */
static void generate_baby_steps_multi(const char *outfile,
                                       int interval,
                                       int steps_to_run,
                                       Walker *walkers,
                                       int nwalkers,
                                       int append_mode,
                                       int final_only) {
    /* final_only: ไม่เปิดไฟล์ตอนเริ่ม เปิดแค่ตอนสุดท้าย */
    FILE *f = NULL;
    if (!final_only) {
        f = fopen(outfile, append_mode ? "a" : "w");
        if (!f) { printf("❌ Cannot open: %s\n", outfile); return; }
        if (!append_mode) {
            fprintf(f, "iter,pubkey,hex_G_sub\n");
            save_snapshot(f, walkers, nwalkers);   /* start snapshot */
        }
    }

    unsigned char x[32], step_scalar[32];
    time_t start_time = time(NULL);
    int next_display  = 100000;
    int next_flush    = 500000;

    printf("\n🚀 GENERATION %s\n", append_mode ? "RESUMED" : "STARTED");
    printf("========================================\n");
    printf("Output:      %s  [%s]\n", outfile, append_mode ? "APPEND" : "NEW");
    printf("Mode:        %s\n", final_only ? "FINAL-ONLY (snapshot)" : "ALL-INTERVALS");
    printf("Walkers:     %d\n", nwalkers);
    printf("Steps/walk:  %d\n", steps_to_run);
    printf("Interval:    %s\n", final_only ? "N/A" : "every N steps");
    printf("Step bits:   %d\n", STEP_BITS);
    printf("Base iter:   %lld\n", walkers[0].iter);
    printf("Target iter: %lld\n", walkers[0].iter + steps_to_run);
    printf("========================================\n");

    for (int step = 1; step <= steps_to_run; step++) {

        /* เดินทุก walker */
        for (int w = 0; w < nwalkers; w++) {
            Walker *wk = &walkers[w];
            if (!get_x(&wk->pk, x)) continue;
            memset(step_scalar, 0, 32);
            calc_step_scalar(x, step_scalar, STEP_BITS);
            add_scalar(wk->gsub.b, step_scalar);
            if (!tweak_sub_scalar(&wk->pk, step_scalar)) continue;
            wk->iter++;
        }

        /* บันทึกตาม interval (เฉพาะ !final_only) */
        if (!final_only && step % interval == 0) {
            save_snapshot(f, walkers, nwalkers);
            if (step >= next_flush) {
                fflush(f);
                printf("💾 Flushed at iter=%lld\n", walkers[0].iter);
                next_flush = step + 500000;
            }
        }

        /* Progress */
        if (step >= next_display) {
            time_t now     = time(NULL);
            double elapsed = difftime(now, start_time);
            double speed   = elapsed > 0 ? step / elapsed : 0;
            double percent = (double)step / steps_to_run * 100.0;
            int    eta     = speed > 0 ? (int)((steps_to_run - step) / speed) : 0;
            printf("📊 %6.1f%% | %.0f steps/s | iter=%lld | ETA: ",
                   percent, speed, walkers[0].iter);
            if      (eta < 60)   printf("%ds", eta);
            else if (eta < 3600) printf("%d:%02dm", eta/60, eta%60);
            else                 printf("%d:%02d:%02dh", eta/3600,(eta%3600)/60,eta%60);
            printf("\n");
            next_display = step + 100000;
        }
    }

    /* final_only: เปิดไฟล์ + เขียน snapshot สุดท้าย */
    if (final_only) {
        f = fopen(outfile, "w");
        if (!f) { printf("❌ Cannot open: %s\n", outfile); return; }
        fprintf(f, "iter,pubkey,hex_G_sub\n");
        save_snapshot(f, walkers, nwalkers);
    }

    fclose(f);

    time_t end_time   = time(NULL);
    int total_elapsed = (int)difftime(end_time, start_time);
    double avg_speed  = total_elapsed > 0 ? steps_to_run / (double)total_elapsed : 0;

    printf("\n✅ DONE\n");
    printf("========================================\n");
    printf("Output:     %s\n", outfile);
    printf("Walkers:    %d\n", nwalkers);
    printf("Final iter: %lld\n", walkers[0].iter);
    printf("Rows saved: %s\n", final_only ? "1 snapshot" : "all intervals");
    printf("Time:       %d:%02d:%02d\n",
           total_elapsed/3600,(total_elapsed%3600)/60,total_elapsed%60);
    printf("Avg speed:  %.0f steps/s  (%.0f w-steps/s)\n",
           avg_speed, avg_speed * nwalkers);
    printf("========================================\n");
}

/* ============================================================
   HELP
   ============================================================ */
static void show_help(const char *prog) {
    printf("Baby Steps Generator  SUB  (multi-walker)\n");
    printf("==========================================\n\n");
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -s, --steps N            จำนวน steps ที่ต้องเดิน   (required)\n");
    printf("  -i, --interval N         บันทึกทุก N steps         (default: 1)\n");
    printf("  --step-bits N            bits สำหรับ step size      (default: 120)\n");
    printf("  -o, --output FILE        ไฟล์ output CSV\n");
    printf("  --start-key KEY          pubkey เริ่มต้น (single walker, 66 hex)\n");
    printf("  --start-iter N           iter เริ่มต้น             (default: 0)\n");
    printf("  --initial-gsub HEX       g_sub เริ่มต้น            (default: 0x0)\n");
    printf("  --start-from-file FILE   multi-walker: โหลดจาก CSV → output ใหม่\n");
    printf("  --resume                 ต่อจาก --output เดิม\n");
    printf("  --final-only             บันทึกแค่ snapshot สุดท้าย (ไฟล์เล็กมาก)\n");
    printf("  -h, --help               show help\n\n");
    printf("Output format:  iter,pubkey,hex_G_sub\n\n");
    printf("Examples:\n\n");
    printf("  # 1) Single walker fresh\n");
    printf("  %s --steps 2600000 --step-bits 20 \\\n", prog);
    printf("     --output DB.csv \\\n");
    printf("     --start-key 03633cbe3ec02b9401c5effa144c5b4d22f87940259634858fc7e59b1c09937852\n\n");
    printf("  # 2) Multi-walker snap: iter 4600000 → 4620000 (snapshot เดียว)\n");
    printf("  %s --steps 20000 --step-bits 20 \\\n", prog);
    printf("     --start-from-file snap_4600000.csv \\\n");
    printf("     --output snap_4620000.csv \\\n");
    printf("     --final-only\n\n");
    printf("  # 3) Multi-walker DB: iter 4600000 → 4620000 (บันทึกทุก step)\n");
    printf("  %s --steps 20000 --interval 1 --step-bits 20 \\\n", prog);
    printf("     --start-from-file snap_4600000.csv \\\n");
    printf("     --output DB_4600000_4620000.csv\n\n");
    printf("  # 4) Resume ต่อจาก output เดิม\n");
    printf("  %s --steps 5000000 --interval 1 --step-bits 20 \\\n", prog);
    printf("     --output DB.csv --resume\n");
}

/* ============================================================
   MAIN
   ============================================================ */
int main(int argc, char **argv) {
    int           steps           = -1;
    int           interval        = 1;
    long long     start_iter      = 0;
    const char   *outfile         = "baby_steps.csv";
    const char   *start_key       = NULL;
    const char   *start_from_file = NULL;
    int           resume          = 0;
    int           final_only      = 0;   /* ✅ ใหม่ */
    scalar256_t   init_gsub;
    memset(init_gsub.b, 0, 32);

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];
        if      (!strcmp(arg,"-h")||!strcmp(arg,"--help"))         { show_help(argv[0]); return 0; }
        else if (!strcmp(arg,"-s")||!strcmp(arg,"--steps"))        { if(i+1<argc)steps=atoi(argv[++i]);       else{printf("❌ Missing %s\n",arg);return 1;} }
        else if (!strcmp(arg,"-i")||!strcmp(arg,"--interval"))     { if(i+1<argc)interval=atoi(argv[++i]);    else{printf("❌ Missing %s\n",arg);return 1;} }
        else if (!strcmp(arg,"-o")||!strcmp(arg,"--output"))       { if(i+1<argc)outfile=argv[++i];           else{printf("❌ Missing %s\n",arg);return 1;} }
        else if (!strcmp(arg,"--start-key"))                       { if(i+1<argc)start_key=argv[++i];         else{printf("❌ Missing --start-key\n");return 1;} }
        else if (!strcmp(arg,"--start-iter"))                      { if(i+1<argc)start_iter=atoll(argv[++i]); else{printf("❌ Missing --start-iter\n");return 1;} }
        else if (!strcmp(arg,"--initial-gsub"))                    { if(i+1<argc)init_gsub=parse_scalar256(argv[++i]); else{printf("❌ Missing --initial-gsub\n");return 1;} }
        else if (!strcmp(arg,"--step-bits"))                       { if(i+1<argc)STEP_BITS=atoi(argv[++i]);  else{printf("❌ Missing --step-bits\n");return 1;} }
        else if (!strcmp(arg,"--resume"))                          { resume=1; }
        else if (!strcmp(arg,"--final-only"))                      { final_only=1; }   /* ✅ */
        else if (!strcmp(arg,"--start-from-file"))                 { if(i+1<argc)start_from_file=argv[++i];  else{printf("❌ Missing --start-from-file\n");return 1;} }
        else { printf("❌ Unknown: %s\n",arg); show_help(argv[0]); return 1; }
    }

    if (steps <= 0)                  { printf("❌ --steps N required (N>0)\n"); return 1; }
    if (interval <= 0)               { printf("❌ interval > 0\n"); return 1; }
    if (STEP_BITS<=0||STEP_BITS>256) { printf("❌ step-bits 1..256\n"); return 1; }

    /* ================================================================
       โหลด walkers
       ================================================================ */
    Walker   *walkers    = NULL;
    int       nwalkers   = 0;
    int       append_mode = 0;
    long long base_iter  = 0;

    if (resume) {
        if (!load_walkers_from_csv(outfile, &walkers, &nwalkers, &base_iter)) return 1;
        append_mode = 1;
        final_only  = 0;   /* resume ต้องบันทึก interval */

    } else if (start_from_file) {
        if (!load_walkers_from_csv(start_from_file, &walkers, &nwalkers, &base_iter)) return 1;
        append_mode = 0;

    } else {
        if (!start_key || strlen(start_key)!=66) {
            printf("❌ --start-key (66 hex) required\n"); return 1;
        }
        walkers = (Walker*)malloc(sizeof(Walker));
        if (!walkers) { printf("❌ malloc\n"); return 1; }
        walkers[0].iter = start_iter;
        walkers[0].gsub = init_gsub;
        if (!setup_pubkey(start_key, &walkers[0].pk)) {
            printf("❌ Invalid start-key\n"); free(walkers); return 1;
        }
        nwalkers    = 1;
        append_mode = 0;
        base_iter   = start_iter;
    }

    /* display */
    char gsub_disp[65];
    scalar256_to_trimhex(&walkers[0].gsub, gsub_disp, sizeof(gsub_disp));

    printf("========================================\n");
    printf("  BABY STEPS GENERATOR (SUB) multi\n");
    printf("========================================\n");
    printf("Mode:        %s%s\n",
           resume ? "RESUME" : (start_from_file ? "FROM-FILE" : "FRESH"),
           final_only ? " + FINAL-ONLY" : "");
    printf("Output:      %s\n", outfile);
    printf("Walkers:     %d\n", nwalkers);
    printf("Steps:       %d\n", steps);
    printf("Step bits:   %d\n", STEP_BITS);
    printf("Base iter:   %lld\n", base_iter);
    printf("Target iter: %lld\n", base_iter + steps);
    printf("gsub[0]:     0x%s\n", gsub_disp);
    printf("========================================\n");

    if (!init_secp256k1()) { printf("❌ secp256k1 init\n"); free(walkers); return 1; }

    generate_baby_steps_multi(outfile, interval, steps,
                               walkers, nwalkers, append_mode, final_only);

    cleanup_secp256k1();
    free(walkers);
    return 0;
}