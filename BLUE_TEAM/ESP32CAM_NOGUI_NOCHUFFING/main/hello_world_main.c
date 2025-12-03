#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "nvs_flash.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_timer.h" 
#include "esp_netif.h"
#include "mbedtls/md.h"      
#include "mbedtls/sha1.h"
#include "arpa/inet.h" 

// --- CONFIGURAZIONE ---
#define FLASH_GPIO 4
#define ATTACK_THRESHOLD 3 

// MAC ADDRESS (Dai tuoi snippet precedenti)
uint8_t target_camera_mac[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA};
uint8_t target_router_mac[] = {0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA}; 

// --- GLOBALI ---
volatile bool alarm_triggered = false;
volatile int packet_counter = 0;
volatile int64_t last_packet_time = 0;

volatile uint16_t sniffer_seq_num = 0;      
volatile uint8_t  sniffer_replay_ctr[8];   
//DA CAMBIARE 
volatile bool trigger_fake_response = false;

volatile bool target_found = false;       
volatile int current_channel = 1;        
//DA CAMBIARE
volatile int locked_channel = 12;          

uint8_t packet_buffer[512]; 

// Callback dummy per Raw TX
bool ieee80211_raw_frame_sanity_check(void *payload, void *len) { return true; }

// --- STRUTTURE DATI ---
// Sostituisci la vecchia wifi_qos_hdr_t con questa:
typedef struct __attribute__((packed)) {
    uint16_t frame_control; 
    uint16_t duration;
    uint8_t  addr1[6]; 
    uint8_t  addr2[6]; 
    uint8_t  addr3[6];
    uint16_t seq_ctrl; 
    // uint16_t qos_ctrl; <--- RIMOSSO (Non serve per Data frames standard)
} wifi_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  dsap; uint8_t  ssap; uint8_t  control;
    uint8_t  org_code[3]; uint16_t ether_type; 
} llc_snap_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  version; uint8_t  type; uint16_t length; 
} eapol_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t  desc_type; uint16_t key_info; uint16_t key_length;
    uint8_t  replay_counter[8];
    uint8_t  nonce[32]; uint8_t  iv[16]; uint8_t  rsc[8]; uint8_t  id[8];
    uint8_t  mic[16]; uint16_t data_len;
} eapol_key_frame_t;

// --- CALCOLO MIC (Firma valida con chiave fake) ---
// --- FIX CALCOLO MIC ---
void calculate_mic_dynamic(eapol_hdr_t *eapol) {
    uint8_t fake_kck[16];
    memset(fake_kck, 0xAA, 16); 
    
    uint16_t body_len = ntohs(eapol->length);
    size_t total_calc_len = 4 + body_len;

    // FIX: Accedi al campo MIC tramite la struttura, non con offset manuali
    eapol_key_frame_t *kf = (eapol_key_frame_t *)(eapol + 1);
    
    // Salviamo il MIC attuale (dovrebbe essere 0) per sicurezza, anche se memset lo azzera
    memset(kf->mic, 0, 16);

    uint8_t output[20];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    
    mbedtls_md_init(&ctx); 
    mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, fake_kck, 16);
    // HMAC calcolato su tutto l'EAPOL (Header + Body)
    mbedtls_md_hmac_update(&ctx, (uint8_t*)eapol, total_calc_len);
    mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);

    // Copia il risultato nel campo corretto della struttura
    memcpy(kf->mic, output, 16);
}

// --- GENERATORE UNIFICATO MSG 1-4 ---
// msg_num: 1, 2, 3, o 4
// use_hijack: true = usa Seq esatto + Retry bit (per cecchino)
// replay_offset: somma questo valore al replay counter (per il flood)
// --- GENERATORE UNIFICATO MSG 1-4 (FIXED: NO QoS ERROR) ---
void send_smart_eapol(int msg_num, bool use_hijack, int replay_offset) {
    memset(packet_buffer, 0, 512);
    uint8_t *cursor = packet_buffer;

    // Usa la nuova struttura senza QoS
    wifi_hdr_t *wh = (wifi_hdr_t*)cursor;
    
    // MODIFICA FONDAMENTALE: Usa 0x0008 (Data Standard) invece di 0x0088 (QoS)
    // Questo evita l'errore "unsupport fram QoS" del driver ESP32
    wh->frame_control = 0x0008; 

    // Logica Direzione (Router->Cam o Cam->Router)
    if (msg_num == 1 || msg_num == 3) { 
        wh->frame_control |= 0x0200; // FromDS (Downlink)
        memcpy(wh->addr1, target_camera_mac, 6); // Dest: Cam
        memcpy(wh->addr2, target_router_mac, 6); // Src:  Router (BSSID)
    } else { 
        wh->frame_control |= 0x0100; // ToDS (Uplink)
        memcpy(wh->addr1, target_router_mac, 6); // Dest: Router
        memcpy(wh->addr2, target_camera_mac, 6); // Src:  Cam
    }
    memcpy(wh->addr3, target_router_mac, 6); // BSSID

    // --- SEQUENCE LOGIC ---
    if (use_hijack && (msg_num == 2 || msg_num == 4)) {
        // CLONE: Stesso numero di sequenza della camera + Retry Bit
        wh->seq_ctrl = (sniffer_seq_num << 4);
        wh->frame_control |= 0x0800; // Retry bit = 1
    } else {
        // FLOOD: Seq casuale o incrementale
        wh->seq_ctrl = ((sniffer_seq_num + (esp_random() % 200)) << 4);
    }
    
    // Nota: Non settiamo più qos_ctrl perché non esiste nella struttura wifi_hdr_t
    cursor += sizeof(wifi_hdr_t); // Avanza di 24 byte (invece di 26)

    llc_snap_hdr_t *llc = (llc_snap_hdr_t*)cursor;
    llc->dsap = 0xAA; llc->ssap = 0xAA; llc->control = 0x03;
    llc->ether_type = htons(0x888E); 
    cursor += sizeof(llc_snap_hdr_t);

    eapol_hdr_t *eh = (eapol_hdr_t*)cursor;
    eh->version = 1; eh->type = 3; 
    cursor += sizeof(eapol_hdr_t);

    eapol_key_frame_t *kf = (eapol_key_frame_t*)cursor;
    
    // --- REPLAY COUNTER LOGIC ---
    uint64_t current_rc = 0;
    for(int k=0; k<8; k++) current_rc = (current_rc << 8) | sniffer_replay_ctr[k];
    current_rc += replay_offset; 
    for(int k=7; k>=0; k--) { kf->replay_counter[k] = current_rc & 0xFF; current_rc >>= 8; }

    uint8_t rsn_ie[] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};

    uint16_t key_info = 0; uint16_t key_len = 0; uint16_t key_data_len = 0;
    uint8_t *key_data_ptr = (uint8_t*)(kf + 1); 

    if (msg_num == 1) { 
        key_info = 0x008A; key_len = 32; 
    } 
    else if (msg_num == 2) { 
        key_info = 0x010A; memcpy(key_data_ptr, rsn_ie, sizeof(rsn_ie)); key_data_len = sizeof(rsn_ie);
    } 
    else if (msg_num == 3) { 
        key_info = 0x13CA; key_len = 16; key_data_len = 32; 
    } 
    else { 
        key_info = 0x030A; 
    }

    kf->desc_type = 2; kf->key_info = htons(key_info);
    kf->key_length = htons(key_len); kf->data_len = htons(key_data_len);
    for(int i=0; i<32; i++) kf->nonce[i] = esp_random(); 

    cursor += sizeof(eapol_key_frame_t) + key_data_len;
    eh->length = htons(sizeof(eapol_key_frame_t) + key_data_len);

    if (key_info & 0x0100) calculate_mic_dynamic(eh);

    size_t packet_size = cursor - packet_buffer;
    
    // Invio (ora dovrebbe funzionare senza errore QoS)
    esp_wifi_80211_tx(WIFI_IF_STA, packet_buffer, packet_size, true);
}

// --- EAPOL START (Reset/Jammer) ---
void send_eapol_start() {
    memset(packet_buffer, 0, 100);
    packet_buffer[0]=0x08; packet_buffer[1]=0x01; // Data Type
    memcpy(&packet_buffer[4], target_router_mac, 6); // To: Router
    memcpy(&packet_buffer[10], target_camera_mac, 6); // From: Camera
    memcpy(&packet_buffer[16], target_router_mac, 6); // BSSID
    
    // Hijack Sequence + 1 per anticipare
    uint16_t seq = sniffer_seq_num + 1;
    packet_buffer[22] = (seq & 0x0F) << 4; packet_buffer[23] = (seq >> 4) & 0xFF;

    packet_buffer[24]=0xAA; packet_buffer[25]=0xAA; packet_buffer[26]=0x03;
    packet_buffer[30]=0x88; packet_buffer[31]=0x8E;
    packet_buffer[32]=0x01; packet_buffer[33]=0x01; // EAPOL Start
    
    esp_wifi_80211_tx(WIFI_IF_STA, packet_buffer, 36, true);
}

// --- SNIFFER CALLBACK ---
void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;
    if (pkt->rx_ctrl.sig_len < 24) return;

    // Parsing Header (Check QoS)
    uint16_t frame_ctrl = payload[0] | (payload[1] << 8);
    uint8_t frame_type = (frame_ctrl >> 2) & 0x03;
    uint8_t frame_subtype = (frame_ctrl >> 4) & 0x0F;
    int hdr_len = 24;
    if (frame_type == 2 && (frame_subtype & 0x08)) hdr_len = 26;

    // Identificazione
    bool is_from_cam = (memcmp(&payload[10], target_camera_mac, 6) == 0);
    bool is_to_cam   = (memcmp(&payload[4], target_camera_mac, 6) == 0);
    bool is_from_router = (memcmp(&payload[10], target_router_mac, 6) == 0);

    // 1. AUTO-SCAN
    if (!target_found) {
        if (is_from_cam || is_to_cam) {
            target_found = true;
            locked_channel = current_channel;
            printf("\n--- TARGET FOUND CH %d ---\n", locked_channel);
        }
        return; 
    }

    // 2. DATA HIJACKING (Sequence Num)
    if (is_from_cam) {
        sniffer_seq_num = (payload[22] | (payload[23] << 8)) >> 4;
    }

    // 3. REACTIVE TARGETING (Cerca Msg 1)
    if (is_from_router && is_to_cam) {
        int eth_offset = hdr_len + 6;
        if (eth_offset + 2 < pkt->rx_ctrl.sig_len) {
            if (payload[eth_offset] == 0x88 && payload[eth_offset+1] == 0x8E) {
                // Check Key Info (Msg 1 ha MIC bit = 0)
                int key_info_offset = eth_offset + 7;
                uint16_t key_info = (payload[key_info_offset] << 8) | payload[key_info_offset+1];
                
                if (!(key_info & 0x0100)) { // Msg 1 detected!
                    int replay_offset = key_info_offset + 4;
                    memcpy((void*)sniffer_replay_ctr, &payload[replay_offset], 8);
                    trigger_fake_response = true; // ATTIVA REAZIONE
                }
            }
        }
    }

    // 4. ATTACK DETECTION (Deauth Flood)
    if (frame_type == 0 && (frame_subtype == 0xC || frame_subtype == 0xA)) {
         if (is_to_cam || is_from_cam) {
             int64_t now = esp_timer_get_time();
             if (now - last_packet_time > 1000000) packet_counter = 0;
             last_packet_time = now;
             packet_counter++;
             if (packet_counter >= ATTACK_THRESHOLD) alarm_triggered = true;
         }
    }
}

void channel_hopper_task(void *pvParameter) {
    while(1) {
        if (!target_found) {
            current_channel++; if (current_channel > 13) current_channel = 1;
            esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            vTaskDelay(200 / portTICK_PERIOD_MS); 
        } else { vTaskDelay(10000 / portTICK_PERIOD_MS); }
    }
}

// --- MAIN LOGIC ---
void app_main(void) {
    gpio_pad_select_gpio(FLASH_GPIO);
    gpio_set_direction(FLASH_GPIO, GPIO_MODE_OUTPUT);
    nvs_flash_init(); esp_netif_init(); esp_event_loop_create_default();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg); esp_wifi_set_mode(WIFI_MODE_STA); esp_wifi_start();

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);
    xTaskCreate(&channel_hopper_task, "channel_hopper", 2048, NULL, 5, NULL);

    printf("Sentinel IDS - V9.2 (20s Jam + Full 4-Way Fake Sequence)\n");

    while (1) {
        
       
        if (alarm_triggered && target_found) {
            printf("\n>>> SOTTO ATTACCO! SEQUENZA 4-WAY FAKE ATTIVA <<<\n");
            gpio_set_level(FLASH_GPIO, 1);
            
            int64_t start_attack_time = esp_timer_get_time();
            int pkt_idx = 0; 

             while (esp_timer_get_time() - start_attack_time < 20000000) {
               //fuori         // C. CHECK CECCHINO (Nel caso la camera provi comunque)
            if (trigger_fake_response) {
                send_smart_eapol(2, true, 0);
                ets_delay_us(50);
                send_smart_eapol(2, true, 0);
                trigger_fake_response = false;
                printf(">>> SNIPER SHOT: Hijacked Msg2 Inviato! <<<\n");
            }
            // 2. IMPORTANTE: SALVA IL WATCHDOG!
                // Senza questa riga, l'ESP32 crasha dopo 5 secondi perché il ciclo while è troppo lungo.
                vTaskDelay(10 / portTICK_PERIOD_MS);
            }
            
            printf(">>> DIFESA TERMINATA. RESET STATO. <<<\n");
            gpio_set_level(FLASH_GPIO, 0);
            alarm_triggered = false;
            packet_counter = 0;
        } 
        
        vTaskDelay(1); 
    }
}