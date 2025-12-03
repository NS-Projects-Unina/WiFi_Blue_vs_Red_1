#include <string.h>
#include <ctype.h> // Necessario per isxdigit
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/gpio.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_system.h"
#include "esp_timer.h" 
#include "esp_netif.h"
#include "nvs_flash.h"
#include "mbedtls/md.h"       
#include "mbedtls/sha1.h"
#include "arpa/inet.h" 
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_attr.h" 

// --- CONFIGURAZIONE ---
#define FLASH_GPIO 4 
#define ATTACK_THRESHOLD 3 
#define SCAN_TIME_MS 400 
#define MAGIC_KEY 0xA5A5A5A5 

// Tasto per forzare la config (Tasto BOOT sulla scheda)
#define BOOT_BUTTON_GPIO 0 

// --- VARIABILI RTC ---
RTC_NOINIT_ATTR uint8_t  rtc_cam_mac[6];
RTC_NOINIT_ATTR uint8_t  rtc_rt_mac[6];
RTC_NOINIT_ATTR uint32_t rtc_magic_flag; 

// Globali
uint8_t target_camera_mac[6]; 
uint8_t target_router_mac[6]; 

volatile bool alarm_triggered = false;
volatile int packet_counter = 0;
volatile int64_t last_packet_time = 0;
volatile uint16_t sniffer_seq_num = 0;      
volatile uint8_t  sniffer_replay_ctr[8];   
volatile bool trigger_fake_response = false;
volatile bool target_found = false;       
volatile int current_channel = 1;        
uint8_t packet_buffer[512]; 

// --- STRUTTURE HEADER ---
typedef struct __attribute__((packed)) {
    uint16_t frame_control; uint16_t duration; uint8_t addr1[6]; uint8_t addr2[6]; uint8_t addr3[6]; uint16_t seq_ctrl; 
} wifi_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t dsap; uint8_t ssap; uint8_t control; uint8_t org_code[3]; uint16_t ether_type; 
} llc_snap_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t version; uint8_t type; uint16_t length; 
} eapol_hdr_t;

typedef struct __attribute__((packed)) {
    uint8_t desc_type; uint16_t key_info; uint16_t key_length; uint8_t replay_counter[8]; uint8_t nonce[32]; uint8_t iv[16]; uint8_t rsc[8]; uint8_t id[8]; uint8_t mic[16]; uint16_t data_len;
} eapol_key_frame_t;

// --- FUNZIONE DECODIFICA URL (FIX FONDAMENTALE) ---
void url_decode(char *dst, const char *src) {
    char a, b;
    while (*src) {
        if ((*src == '%') && ((a = src[1]) && (b = src[2])) && (isxdigit((int)a) && isxdigit((int)b))) {
            if (a >= 'a') a -= 'a'-'A';
            if (a >= 'A') a -= ('A' - 10);
            else a -= '0';
            if (b >= 'a') b -= 'a'-'A';
            if (b >= 'A') b -= ('A' - 10);
            else b -= '0';
            *dst++ = 16*a+b;
            src+=3;
        } else if (*src == '+') {
            *dst++ = ' ';
            src++;
        } else {
            *dst++ = *src++;
        }
    }
    *dst++ = '\0';
}

void parse_mac(char* str, uint8_t* out) {
    unsigned int temp[6];
    // Ora sscanf funzionerà perché url_decode ha trasformato %3A in :
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]) == 6) {
        for(int i=0; i<6; i++) out[i] = (uint8_t)temp[i];
    } else if (sscanf(str, "%x-%x-%x-%x-%x-%x", &temp[0], &temp[1], &temp[2], &temp[3], &temp[4], &temp[5]) == 6) {
         for(int i=0; i<6; i++) out[i] = (uint8_t)temp[i];
    } else {
        printf("ERRORE PARSING MAC: %s\n", str);
    }
}

const char* html = "<!DOCTYPE html><body><h2>Sentinel Config</h2><form action='/set' method='post'>"
"Camera MAC (es. AA:BB:CC:11:22:33): <input name='cam'><br><br>"
"Router MAC (es. 11:22:33:AA:BB:CC): <input name='rt'><br><br>"
"<input type='submit' value='SALVA E RIAVVIA'></form></body>";

esp_err_t get_handler(httpd_req_t *req) {
    httpd_resp_send(req, html, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t post_handler(httpd_req_t *req) {
    char buf[512]; // Aumentato buffer per sicurezza
    char decoded_buf[512]; // Buffer per la stringa decodificata

    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret > 0) {
        buf[ret] = 0; 
        
        // 1. DECODIFICA L'INTERO MESSAGGIO (Trasforma %3A in :)
        url_decode(decoded_buf, buf);
        printf("Dati ricevuti (Decoded): %s\n", decoded_buf); // Debug nel seriale

        // 2. CERCA I PARAMETRI NELLA STRINGA PULITA
        char *p_cam = strstr(decoded_buf, "cam=");
        char *p_rt = strstr(decoded_buf, "rt=");
        
        if (p_cam) parse_mac(p_cam + 4, rtc_cam_mac);
        if (p_rt)  parse_mac(p_rt + 3, rtc_rt_mac);
        
        rtc_magic_flag = MAGIC_KEY; 
    }
    httpd_resp_send(req, "Configurati! Riavvio...", HTTPD_RESP_USE_STRLEN);
    vTaskDelay(1000 / portTICK_PERIOD_MS);
    esp_restart(); 
    return ESP_OK;
}

void run_config_mode() {
    printf(">>> MODALITA' CONFIGURAZIONE (AP) <<<\n");
    printf(">>> Crea hotspot 'SENTINEL_SETUP'. Vai su 192.168.4.1 <<<\n");
    
    esp_netif_create_default_wifi_ap();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg);
    esp_wifi_set_mode(WIFI_MODE_AP);
    
    wifi_config_t ap_config = {
        .ap = {
            .ssid = "SENTINEL_SETUP",
            .ssid_len = strlen("SENTINEL_SETUP"),
            .channel = 1,
            .max_connection = 4,
            .authmode = WIFI_AUTH_OPEN
        }
    };
    
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    esp_wifi_start();

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    httpd_start(&server, &config);
    httpd_uri_t uri_get = { .uri = "/", .method = HTTP_GET, .handler = get_handler };
    httpd_uri_t uri_post = { .uri = "/set", .method = HTTP_POST, .handler = post_handler };
    httpd_register_uri_handler(server, &uri_get);
    httpd_register_uri_handler(server, &uri_post);

    while(1) { vTaskDelay(1000 / portTICK_PERIOD_MS); }
}

// --- ATTACCO ---
void calculate_mic_dynamic(eapol_hdr_t *eapol) {
    uint8_t fake_kck[16]; memset(fake_kck, 0xAA, 16); 
    uint16_t body_len = ntohs(eapol->length);
    eapol_key_frame_t *kf = (eapol_key_frame_t *)(eapol + 1);
    memset(kf->mic, 0, 16);
    uint8_t output[20];
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_init(&ctx); mbedtls_md_setup(&ctx, info, 1);
    mbedtls_md_hmac_starts(&ctx, fake_kck, 16);
    mbedtls_md_hmac_update(&ctx, (uint8_t*)eapol, 4 + body_len);
    mbedtls_md_hmac_finish(&ctx, output);
    mbedtls_md_free(&ctx);
    memcpy(kf->mic, output, 16);
}

void send_smart_eapol(int msg_num, bool use_hijack, int replay_offset) {
    memset(packet_buffer, 0, 512);
    uint8_t *cursor = packet_buffer;
    wifi_hdr_t *wh = (wifi_hdr_t*)cursor;
    wh->frame_control = 0x0008; 
    if (msg_num == 1 || msg_num == 3) { 
        wh->frame_control |= 0x0200; memcpy(wh->addr1, target_camera_mac, 6); memcpy(wh->addr2, target_router_mac, 6); 
    } else { 
        wh->frame_control |= 0x0100; memcpy(wh->addr1, target_router_mac, 6); memcpy(wh->addr2, target_camera_mac, 6); 
    }
    memcpy(wh->addr3, target_router_mac, 6); 
    if (use_hijack && (msg_num == 2 || msg_num == 4)) {
        wh->seq_ctrl = (sniffer_seq_num << 4); wh->frame_control |= 0x0800; 
    } else {
        wh->seq_ctrl = ((sniffer_seq_num + (esp_random() % 200)) << 4);
    }
    cursor += sizeof(wifi_hdr_t); 
    llc_snap_hdr_t *llc = (llc_snap_hdr_t*)cursor;
    llc->dsap = 0xAA; llc->ssap = 0xAA; llc->control = 0x03; llc->ether_type = htons(0x888E); 
    cursor += sizeof(llc_snap_hdr_t);
    eapol_hdr_t *eh = (eapol_hdr_t*)cursor; eh->version = 1; eh->type = 3; 
    cursor += sizeof(eapol_hdr_t);
    eapol_key_frame_t *kf = (eapol_key_frame_t*)cursor;
    uint64_t current_rc = 0;
    for(int k=0; k<8; k++) current_rc = (current_rc << 8) | sniffer_replay_ctr[k];
    current_rc += replay_offset; 
    for(int k=7; k>=0; k--) { kf->replay_counter[k] = current_rc & 0xFF; current_rc >>= 8; }
    uint8_t rsn_ie[] = {0x30, 0x14, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00};
    uint16_t key_info = 0; uint16_t key_len = 0; uint16_t key_data_len = 0;
    uint8_t *key_data_ptr = (uint8_t*)(kf + 1); 
    if (msg_num == 1) { key_info = 0x008A; key_len = 32; } 
    else if (msg_num == 2) { key_info = 0x010A; memcpy(key_data_ptr, rsn_ie, sizeof(rsn_ie)); key_data_len = sizeof(rsn_ie); } 
    else if (msg_num == 3) { key_info = 0x13CA; key_len = 16; key_data_len = 32; } 
    else { key_info = 0x030A; }
    kf->desc_type = 2; kf->key_info = htons(key_info);
    kf->key_length = htons(key_len); kf->data_len = htons(key_data_len);
    for(int i=0; i<32; i++) kf->nonce[i] = esp_random(); 
    cursor += sizeof(eapol_key_frame_t) + key_data_len;
    eh->length = htons(sizeof(eapol_key_frame_t) + key_data_len);
    if (key_info & 0x0100) calculate_mic_dynamic(eh);
    size_t packet_size = cursor - packet_buffer;
    esp_wifi_80211_tx(WIFI_IF_STA, packet_buffer, packet_size, true);
}

void sniffer_callback(void *buf, wifi_promiscuous_pkt_type_t type) {
    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    uint8_t *payload = pkt->payload;
    if (pkt->rx_ctrl.sig_len < 24) return;
    uint16_t frame_ctrl = payload[0] | (payload[1] << 8);
    uint8_t frame_type = (frame_ctrl >> 2) & 0x03; uint8_t frame_subtype = (frame_ctrl >> 4) & 0x0F;
    int hdr_len = 24;
    if (frame_type == 2 && (frame_subtype & 0x08)) hdr_len = 26;
    bool is_from_cam = (memcmp(&payload[10], target_camera_mac, 6) == 0);
    bool is_to_cam   = (memcmp(&payload[4], target_camera_mac, 6) == 0);
    bool is_from_router = (memcmp(&payload[10], target_router_mac, 6) == 0);

    if (!target_found) {
        if (is_from_cam || is_to_cam) {
            target_found = true; 
            printf("\n>>> TARGET TROVATO SU CANALE %d! BLOCCO FREQUENZA. <<<\n", current_channel);
        }
        return; 
    }
    if (is_from_cam) { sniffer_seq_num = (payload[22] | (payload[23] << 8)) >> 4; }
    if (is_from_router && is_to_cam) {
        int eth_offset = hdr_len + 6;
        if (eth_offset + 2 < pkt->rx_ctrl.sig_len) {
            if (payload[eth_offset] == 0x88 && payload[eth_offset+1] == 0x8E) {
                int key_info_offset = eth_offset + 7;
                uint16_t key_info = (payload[key_info_offset] << 8) | payload[key_info_offset+1];
                if (!(key_info & 0x0100)) { 
                    int replay_offset = key_info_offset + 4;
                    memcpy((void*)sniffer_replay_ctr, &payload[replay_offset], 8);
                    trigger_fake_response = true; 
                }
            }
        }
    }
    if (frame_type == 0 && (frame_subtype == 0xC || frame_subtype == 0xA)) {
         if (is_to_cam || is_from_cam) {
             int64_t now = esp_timer_get_time();
             if (now - last_packet_time > 1000000) packet_counter = 0;
             last_packet_time = now; packet_counter++;
             if (packet_counter >= ATTACK_THRESHOLD) alarm_triggered = true;
         }
    }
}

void channel_hopper_task(void *pvParameter) {
    while(1) {
        if (!target_found) {
            current_channel++; if (current_channel > 13) current_channel = 1;
            esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
            printf("Scansione CH %d...\n", current_channel); 
            vTaskDelay(SCAN_TIME_MS / portTICK_PERIOD_MS); 
        } else { vTaskDelay(10000 / portTICK_PERIOD_MS); }
    }
}

// --- MAIN LOGIC ---
void app_main(void) {
    gpio_pad_select_gpio(FLASH_GPIO); gpio_set_direction(FLASH_GPIO, GPIO_MODE_OUTPUT);
    
    // Tasto BOOT per reset config
    gpio_pad_select_gpio(BOOT_BUTTON_GPIO);
    gpio_set_direction(BOOT_BUTTON_GPIO, GPIO_MODE_INPUT);
    gpio_set_pull_mode(BOOT_BUTTON_GPIO, GPIO_PULLUP_ONLY);

    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    esp_netif_init(); esp_event_loop_create_default();

    // 1. CONTROLLO MANUALE
    if (gpio_get_level(BOOT_BUTTON_GPIO) == 0) {
        printf(">>> TASTO BOOT PREMUTO: CANCELLO CONFIGURAZIONE! <<<\n");
        rtc_magic_flag = 0; 
        for(int i=0; i<5; i++) { gpio_set_level(FLASH_GPIO, 1); vTaskDelay(10); gpio_set_level(FLASH_GPIO, 0); vTaskDelay(10); }
    }

    // 2. VERIFICA CONFIG
    if (rtc_magic_flag != MAGIC_KEY) {
        run_config_mode();
        return; 
    }

    // 3. AVVIO SNIFFER
    memcpy(target_camera_mac, rtc_cam_mac, 6);
    memcpy(target_router_mac, rtc_rt_mac, 6);

    printf(">>> CONFIGURAZIONE VALIDA - AVVIO SNIFFER (STA) <<<\n");
    printf("Target Cam: %02X:%02X:%02X:%02X:%02X:%02X\n", target_camera_mac[0], target_camera_mac[1], target_camera_mac[2], target_camera_mac[3], target_camera_mac[4], target_camera_mac[5]);

    esp_netif_create_default_wifi_sta(); 
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    esp_wifi_init(&cfg); 
    esp_wifi_set_mode(WIFI_MODE_STA); 
    esp_wifi_start();

    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);
    esp_wifi_set_promiscuous_rx_cb(&sniffer_callback);

    xTaskCreate(&channel_hopper_task, "channel_hopper", 2048, NULL, 5, NULL);

    printf("Sentinel IDS - SYSTEM ARMED\n");

    while (1) {
        if (alarm_triggered && target_found) {
            printf("\n>>> SOTTO ATTACCO! <<<\n");
            gpio_set_level(FLASH_GPIO, 1);
            int64_t start_attack_time = esp_timer_get_time();
            while (esp_timer_get_time() - start_attack_time < 20000000) {
                if (trigger_fake_response) {
                    for(int i=0; i<1000; i++) { send_smart_eapol(2, true, 0); ets_delay_us(50); }
                    trigger_fake_response = false;
                    printf(">>> SNIPER SHOT! <<<\n");
                }
                vTaskDelay(10 / portTICK_PERIOD_MS);
            }
            gpio_set_level(FLASH_GPIO, 0);
            alarm_triggered = false; packet_counter = 0;
        } 
        vTaskDelay(1); 
    }
}