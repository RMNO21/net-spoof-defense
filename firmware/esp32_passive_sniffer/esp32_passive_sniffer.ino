/*
 * NetSpoof-Defense: Passive ESP32 802.11 Management Frame Monitor
 * Author: RMNO21
 *
 * Strictly passive, read-only promiscuous sensor node.
 * Captures IEEE 802.11 Beacon, Probe Response, Deauth, and Disassoc frames
 * and streams structured ESP32_WMON JSON telemetry over UART at 115200 baud.
 * No Wi-Fi transmission or frame injection is performed.
 */

#include <Arduino.h>
#include "esp_wifi.h"
#include "esp_event.h"
#include "nvs_flash.h"

static uint8_t current_channel = 1;
static unsigned long last_hop_ms = 0;
static const unsigned long HOP_INTERVAL_MS = 250;

typedef struct __attribute__((packed)) {
  uint8_t fc0;
  uint8_t fc1;
  uint16_t duration;
  uint8_t addr1[6];
  uint8_t addr2[6];
  uint8_t addr3[6];
  uint16_t seq_ctrl;
} wifi_mgmt_hdr_t;

static void format_mac(const uint8_t *mac, char *out) {
  snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT || buf == nullptr) {
    return;
  }

  const wifi_promiscuous_pkt_t *ppkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint16_t len = ppkt->rx_ctrl.sig_len;
  if (len < sizeof(wifi_mgmt_hdr_t)) {
    return;
  }

  const wifi_mgmt_hdr_t *hdr = (const wifi_mgmt_hdr_t *)ppkt->payload;
  const uint8_t subtype = hdr->fc0 & 0xF0;

  const char *subtype_str = nullptr;
  if (subtype == 0x80) subtype_str = "beacon";
  else if (subtype == 0x50) subtype_str = "probe_resp";
  else if (subtype == 0xC0) subtype_str = "deauth";
  else if (subtype == 0xA0) subtype_str = "disassoc";
  else return;

  char dst_str[18], src_str[18], bssid_str[18];
  format_mac(hdr->addr1, dst_str);
  format_mac(hdr->addr2, src_str);
  format_mac(hdr->addr3, bssid_str);

  char ssid[33] = {0};
  uint16_t bi = 0;
  bool rsn = false;
  uint16_t reason = 0;
  uint8_t ch = ppkt->rx_ctrl.channel;

  const uint8_t *body = ppkt->payload + sizeof(wifi_mgmt_hdr_t);
  const uint16_t body_len = len - sizeof(wifi_mgmt_hdr_t);

  if (subtype == 0xC0 || subtype == 0xA0) {
    if (body_len >= 2) {
      reason = (uint16_t)body[0] | ((uint16_t)body[1] << 8);
    }
  } else if (body_len >= 12) {
    bi = (uint16_t)body[8] | ((uint16_t)body[9] << 8);
    uint16_t cap = (uint16_t)body[10] | ((uint16_t)body[11] << 8);
    rsn = (cap & 0x0010) != 0;

    uint16_t idx = 12;
    while (idx + 2 <= body_len) {
      uint8_t ie_id = body[idx];
      uint8_t ie_len = body[idx + 1];
      idx += 2;
      if (idx + ie_len > body_len) break;
      if (ie_id == 0 && ie_len > 0 && ie_len <= 32) {
        memcpy(ssid, body + idx, ie_len);
        ssid[ie_len] = '\0';
        for (uint8_t j = 0; j < ie_len; j++) {
          if (ssid[j] == '"' || ssid[j] == '\\' || ssid[j] < 0x20) ssid[j] = '_';
        }
      } else if (ie_id == 3 && ie_len >= 1) {
        ch = body[idx];
      } else if (ie_id == 48) {
        rsn = true;
      }
      idx += ie_len;
    }
  }

  Serial.printf(
      "{\"proto\":\"ESP32_WMON\",\"subtype\":\"%s\",\"ssid\":\"%s\",\"bssid\":\"%s\",\"src\":\"%s\",\"dst\":\"%s\",\"ch\":%u,\"rssi\":%d,\"bi\":%u,\"rsn\":%s,\"reason\":%u}\n",
      subtype_str, ssid, bssid_str, src_str, dst_str,
      (unsigned)ch, (int)ppkt->rx_ctrl.rssi, (unsigned)bi,
      rsn ? "true" : "false", (unsigned)reason);
}

void setup() {
  Serial.begin(115200);
  nvs_flash_init();
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();

  wifi_promiscuous_filter_t filter = {
      .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
  };
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
}

void loop() {
  unsigned long now = millis();
  if (now - last_hop_ms >= HOP_INTERVAL_MS) {
    last_hop_ms = now;
    current_channel = (current_channel % 13) + 1;
    esp_wifi_set_channel(current_channel, WIFI_SECOND_CHAN_NONE);
  }
}
