/*
   mitm_build_256.c  —  v16 (FIXED CSV verification + last step info)
*/

#include "mitm_common.h"
#include <signal.h>
#include <math.h>

#ifdef _OPENMP
#include <omp.h>
#endif

static volatile int g_stop = 0;
static void sig_stop(int s) { (void)s; g_stop = 1; }

#define TBUF_CAP (1 << 18)
typedef struct { BabyEntry buf[TBUF_CAP]; int cnt; } TBuf;

static BabyEntry         *g_entries = NULL;
static volatile uint64_t  g_ent_cnt = 0;
static omp_lock_t         g_lock;

static void flush_buf(TBuf *tb) {
    if (tb->cnt == 0) return;
    omp_set_lock(&g_lock);
    uint64_t base = g_ent_cnt;
    g_ent_cnt += (uint64_t)tb->cnt;
    omp_unset_lock(&g_lock);
    memcpy(g_entries + base, tb->buf, (size_t)tb->cnt * sizeof(BabyEntry));
    tb->cnt = 0;
}

static inline void push_entry(TBuf *tb, uint64_t xk, uint8_t parity, const scalar256_t *acc, int wi) {
    BabyEntry *e = &tb->buf[tb->cnt++];
    e->xkey = xk;
    e->parity = parity;
    memcpy(e->acc, acc->b, 32);
    e->walker = (uint32_t)wi;
    
    if (tb->cnt == TBUF_CAP) flush_buf(tb);
}

static int cmp_entry(const void *a, const void *b) {
    const BabyEntry *ea = (const BabyEntry*)a;
    const BabyEntry *eb = (const BabyEntry*)b;
    if (ea->xkey < eb->xkey) return -1;
    if (ea->xkey > eb->xkey) return 1;
    if (ea->parity < eb->parity) return -1;
    if (ea->parity > eb->parity) return 1;
    return 0;
}

static int save_baby(const char *fn,
                     const StartKey *walkers, int n_walkers,
                     int baby_bits, int step_bits,
                     BabyEntry *entries, uint64_t n_entries) {
    FILE *fp = fopen(fn, "wb");
    if (!fp) { perror(fn); return 0; }
    BabyHeader hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.magic = BABY_MAGIC;
    hdr.n_walkers = (uint32_t)n_walkers;
    hdr.baby_bits = (uint32_t)baby_bits;
    hdr.step_bits = (uint32_t)step_bits;
    hdr.n_entries = n_entries;
    fwrite(&hdr, sizeof(hdr), 1, fp);
    for (int i = 0; i < n_walkers; i++) {
        BabyWalker wr;
        memset(&wr, 0, sizeof(wr));
        memcpy(wr.pubkey_hex, walkers[i].pubkey, 67);
        memcpy(wr.g_sub, walkers[i].g_sub.b, 32);
        fwrite(&wr, sizeof(wr), 1, fp);
    }
    fwrite(entries, sizeof(BabyEntry), (size_t)n_entries, fp);
    fclose(fp);
    return 1;
}

static void usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s --start-keys FILE --output FILE\n"
        "          [--baby-bits N]  default 15, max 30\n"
        "          [--step-bits N]  default 20, range 0..128\n\n", prog);
    exit(1);
}

int main(int argc, char *argv[]) {
    printf("🔨 mitm_build_256  v16  (FIXED CSV verification + last step info)\n");
    printf("==================================================================\n\n");

    const char *start_keys_file = NULL;
    const char *output_file = "baby.bin";
    int baby_bits = 15, step_bits = 20;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--start-keys") && i+1<argc) start_keys_file = argv[++i];
        else if (!strcmp(argv[i], "--output") && i+1<argc) output_file = argv[++i];
        else if (!strcmp(argv[i], "--baby-bits") && i+1<argc) baby_bits = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--step-bits") && i+1<argc) step_bits = atoi(argv[++i]);
        else { fprintf(stderr, "Unknown: %s\n", argv[i]); usage(argv[0]); }
    }
    if (!start_keys_file) usage(argv[0]);
    
    if (baby_bits < 1 || baby_bits > 30) { 
        fprintf(stderr, "❌ baby-bits must be 1..30\n"); 
        return 1; 
    }
    if (step_bits < 0 || step_bits > 128) { 
        fprintf(stderr, "❌ step-bits must be 0..128\n"); 
        return 1; 
    }

    signal(SIGINT, sig_stop);
    signal(SIGTERM, sig_stop);
    omp_init_lock(&g_lock);

    StartKey *walkers = NULL; int n_walkers = 0;
    if (!load_start_keys(start_keys_file, &walkers, &n_walkers)) {
        fprintf(stderr, "❌ Failed to load start keys\n");
        return 1;
    }
    printf("[+] %d walker(s) loaded\n", n_walkers);

    secp256k1_context *ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    if (!ctx) { fprintf(stderr, "❌ secp256k1 init\n"); return 1; }

    uint64_t steps_pw = UINT64_C(1) << baby_bits;
    uint64_t total_ent = (uint64_t)n_walkers * steps_pw;
    double mem_mb = (double)total_ent * sizeof(BabyEntry) / 1048576.0;

    printf("   baby_bits=%d  step_bits=%d\n", baby_bits, step_bits);
    printf("   steps/walker=%llu  walkers=%d  total=%llu\n",
           (unsigned long long)steps_pw, n_walkers, (unsigned long long)total_ent);
    printf("   Entry array: %.0f MB\n", mem_mb);
    if (mem_mb > 32768.0) { fprintf(stderr, "⚠️ >32 GB\n"); return 1; }

#ifdef _OPENMP
    printf("   OpenMP threads: %d\n", omp_get_max_threads());
#else
    printf("   OpenMP: disabled\n");
#endif
    printf("\n");

    // ========== CSV VERIFICATION (แสดง accumulated sum) ==========
    printf("================================================================================\n");
    printf("CSV VERIFICATION (iter, pubkey, accumulated_sum = hex_G_sub)\n");
    printf("================================================================================\n");
    printf("iter,pubkey,hex_G_sub\n");
    
    for (int wi = 0; wi < n_walkers && wi < 1; wi++) {
        secp256k1_pubkey pk;
        if (!pub_parse_hex(ctx, walkers[wi].pubkey, &pk)) continue;
        
        // iter 0: accumulated_sum = 0
        char pub0[67];
        pub_ser_hex(ctx, &pk, pub0);
        printf("0,%s,0x0\n", pub0);
        
        uint64_t accumulated = 0;
        uint64_t step_values[10] = {0};
        
        for (int s = 1; s <= 4; s++) {
            uint8_t pub33[33];
            pub_ser33(ctx, &pk, pub33);
            
            __uint128_t step = calc_step128(pub33, step_bits);
            step_values[s-1] = (uint64_t)step;
            accumulated += (uint64_t)step;
            
            if (!pub_tweak_sub_step(ctx, &pk, step)) break;
            
            char pub_hex[67];
            pub_ser_hex(ctx, &pk, pub_hex);
            printf("%d,%s,0x%lx\n", s, pub_hex, accumulated);
        }
        
        printf("# step_values: ");
        for (int i = 0; i < 4; i++) {
            printf("0x%lx ", step_values[i]);
        }
        printf("\n");
    }
    printf("================================================================================\n\n");
    
    // ========== END CSV VERIFICATION ==========

    // ตัวแปรสำหรับบันทึก last step info
    char last_pubkey[67] = {0};
    scalar256_t last_acc = s256_zero();
    int last_walker = -1;
    int last_step_saved = 0;

    g_entries = (BabyEntry*)malloc(total_ent * sizeof(BabyEntry));
    if (!g_entries) { fprintf(stderr, "❌ OOM\n"); return 1; }
    g_ent_cnt = 0;
    time_t t0 = time(NULL);

#ifdef _OPENMP
    #pragma omp parallel
#endif
    {
        TBuf *tb = (TBuf*)malloc(sizeof(TBuf));
        if (!tb) { fprintf(stderr, "OOM tbuf\n"); exit(1); }
        tb->cnt = 0;

#ifdef _OPENMP
        #pragma omp for schedule(dynamic, 1)
#endif
        for (int wi = 0; wi < n_walkers; wi++) {
            if (g_stop) continue;

            secp256k1_pubkey pk;
            if (!pub_parse_hex(ctx, walkers[wi].pubkey, &pk)) {
                fprintf(stderr, "⚠️ invalid pubkey walker[%d]\n", wi);
                continue;
            }

            scalar256_t acc = s256_zero();

            for (uint64_t s = 0; s < steps_pw && !g_stop; s++) {
                uint8_t pub33[33];
                pub_ser33(ctx, &pk, pub33);
                push_entry(tb, x_trunc(pub33), pub33[0], &acc, wi);

                __uint128_t step = calc_step128(pub33, step_bits);
                if (!pub_tweak_sub_step(ctx, &pk, step)) {
                    fprintf(stderr, "\n⚠️ tweak_sub failed at wi=%d s=%llu\n",
                            wi, (unsigned long long)s);
                    break;
                }
                acc = s256_add_u128_modn(&acc, step);
            }

            // บันทึกข้อมูล step สุดท้ายของ walker แรก
            if (wi == 0 && !last_step_saved) {
                pub_ser_hex(ctx, &pk, last_pubkey);
                last_acc = acc;
                last_walker = wi;
                last_step_saved = 1;
            }

#ifdef _OPENMP
            #pragma omp critical
#endif
            {
                double el = difftime(time(NULL), t0);
                int pct = (int)((long long)(wi+1)*100 / n_walkers);
                char acc_hex[65];
                s256_to_hex(&acc, acc_hex);
                printf("\r   [%3d%%] walker %d/%d | entries=%llu | acc=0x%s | %.0fs  ",
                       pct, wi+1, n_walkers,
                       (unsigned long long)g_ent_cnt, acc_hex, el);
                fflush(stdout);
            }
        }
        flush_buf(tb);
        free(tb);
    }
    printf("\n");

    if (g_stop) printf("⚠️ Interrupted — partial table\n");

    uint64_t n_entries = g_ent_cnt;
    printf("📊 Entries: %llu\n", (unsigned long long)n_entries);

    // แสดงและบันทึกข้อมูล step สุดท้าย
    if (last_step_saved) {
        char last_acc_hex[65];
        s256_to_hex(&last_acc, last_acc_hex);
        
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║                    LAST STEP INFORMATION                        ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        printf("║ walker = %d\n", last_walker);
        printf("║ pubkey = %s\n", last_pubkey);
        printf("║ acc    = 0x%s\n", last_acc_hex);
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        
        FILE *fp = fopen("last_step.txt", "w");
        if (fp) {
            fprintf(fp, "walker=%d\n", last_walker);
            fprintf(fp, "pubkey=%s\n", last_pubkey);
            fprintf(fp, "acc=0x%s\n", last_acc_hex);
            fclose(fp);
            printf("\n✅ Saved last step info to last_step.txt\n");
        }
    }

    printf("🔄 Sorting by xkey+parity...\n");
    qsort(g_entries, (size_t)n_entries, sizeof(BabyEntry), cmp_entry);
    printf("✅ Done\n");

    printf("💾 Saving → %s\n", output_file);
    if (save_baby(output_file, walkers, n_walkers,
                  baby_bits, step_bits, g_entries, n_entries)) {
        double sz = (double)(sizeof(BabyHeader) + (size_t)n_walkers * sizeof(BabyWalker)
                    + n_entries * sizeof(BabyEntry)) / 1048576.0;
        printf("✅ Saved (%.1f MB)\n", sz);
    } else {
        fprintf(stderr, "❌ Save failed\n");
    }

    printf("⏱ Total: %.0f s\n", difftime(time(NULL), t0));

    free(g_entries);
    free(walkers);
    omp_destroy_lock(&g_lock);
    secp256k1_context_destroy(ctx);
    return 0;
}