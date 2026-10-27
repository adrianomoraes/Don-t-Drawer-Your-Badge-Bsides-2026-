#include <Arduino_GFX_Library.h>
#include <NimBLEDevice.h>
#include <LittleFS.h>
#include <WiFi.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <vector>
#include <map>
#include <algorithm> 
#include <esp_wifi.h>
#include <driver/gpio.h>
#include <ArduinoJson.h>
#include <time.h>
#include <sys/time.h>
#include <esp_ieee802154.h> // [PHASE 1] Zigbee/Thread PHY

// --- OUR ISOLATED, COLLISION-FREE QR LIBRARY & LOGO ---
#include "SafeQR.h" 
#include "logo.h" 

// --- PINOUT ---
#define TFT_MOSI 19
#define TFT_SCK  21
#define TFT_CS   2
#define TFT_DC   4
#define TFT_RST  3
#define TFT_BL   5
#define PIN_KEEPALIVE 6

#define BTN_UP    7
#define BTN_DOWN  15
#define BTN_LEFT  9
#define BTN_RIGHT 18
#define BTN_A     22
#define BTN_B     23

// --- TACTICAL COLORS (BGR CORRECTED) ---
#define BLACK      0x0000
#define WHITE      0xFFFF
#define RED        0x001F  
#define GREEN      0x07E0  
#define DARKGREEN  0x01E0
#define YELLOW     0x07FF  
#define CYAN       0xFFE0  
#define GREY       0x7BEF
#define MAGENTA    0xF81F  
#define ORANGE     0x053F  
#define BLUE       0x88E0  
#define PURPLE     0xF80F  
#define LIME       0x47E0  
#define GOLD       0x03FF  
#define TEAL       0x87E0  


// --- CORE DATA STRUCTURES ---
struct Packet { 
  String mac; 
  String macPrefix; 
  String addr1;      // 802.11 Receiver / Destination Address
  int rssi; 
  String name; 
  String uuid; 
  String cid; 
  String dataType; 
  String ssid; 
  String bssid;     
  String rawHex;    
  String enc;       
  String vendor;    
};

struct RawWifiHit { 
  char mac[18]; 
  char addr1[18];   
  char bssid[18];   
  char ssid[33]; 
  char enc[8];
  char vendor[12]; 
  int rssi; 
  uint8_t subtype; 
};

// [PHASE 1] ZIGBEE / THREAD (802.15.4) SNIFFER BUFFER
struct RawZigbeeHit { 
  char mac[18]; 
  int rssi; 
};
volatile RawZigbeeHit zigbeeBuffer[10];
volatile int zigbeeHitWrite = 0;
volatile int zigbeeHitRead = 0;

// [PHASE 5] Upgraded Deep-Parsing RX Handler (MEMORY SAFE)
extern "C" void esp_ieee802154_receive_done(uint8_t *data, esp_ieee802154_frame_info_t *frame_info) {
  if (!data || data[0] < 5) {
      esp_ieee802154_receive(); 
      return; 
  }
  
  int next = (zigbeeHitWrite + 1) % 10;
  if (next != zigbeeHitRead) {
      zigbeeBuffer[zigbeeHitWrite].rssi = frame_info->rssi;
      
      uint16_t fcf = data[1] | (data[2] << 8);
      uint8_t destAddrMode = (fcf >> 10) & 0x03;
      uint16_t panId = 0x0000;
      int offset = 4; // Skip Length, FCF, Seq
      
      // Added strict bounds check to prevent malformed packets from crashing the ISR
      if ((destAddrMode == 2 || destAddrMode == 3) && data[0] >= 6) {
          panId = data[offset] | (data[offset+1] << 8);
      }
      
      // STRICT 13-BYTE LIMIT TO PREVENT BUFFER/STACK CORRUPTION
      if (panId != 0) {
          sprintf((char*)zigbeeBuffer[zigbeeHitWrite].mac, "802:%02x P%04x", data[1], panId);
      } else {
          sprintf((char*)zigbeeBuffer[zigbeeHitWrite].mac, "802:%02x:%02x:%02x", data[1], data[2], data[3]);
      }
      
      zigbeeHitWrite = next;
  }
  esp_ieee802154_receive(); // Re-arm
}

extern "C" void esp_ieee802154_receive_failed(uint16_t error) {
    esp_ieee802154_receive(); // Re-arm the receiver immediately on CRC failure
}
extern "C" void esp_ieee802154_receive_sfd_done(void) {
    // Required by ESP-IDF linker to clear the SFD interrupt
}

Arduino_DataBus *bus = new Arduino_ESP32SPI(TFT_DC, TFT_CS, TFT_SCK, TFT_MOSI, -1);
Arduino_GFX *gfx = new Arduino_ST7735(bus, TFT_RST, 1);

// --- SYSTEM STATE ---
enum State { RADAR_VIEW, MENU_VIEW, WIFI_PORTAL, LOG_VIEW, FOXHUNT_VIEW, RESET_CONFIRM_VIEW, INTEL_VIEW, SETUP_VIEW, ALIAS_EDIT_VIEW, ABOUT_VIEW };
State systemState = RADAR_VIEW;
bool intelShowRule = false; 

int radioMode = 0; // 0=BLE, 1=WIFI, 2=ZIGBEE
int radarZoomLevel = 0; 
unsigned long lastChannelHop = 0;
uint8_t wifiChannel = 1;

bool uiNeedsUpdate = true;            
unsigned long lastUiDraw = 0;      
unsigned long lastHistorySave = 0;

// --- SERIAL COMPANION API VARIABLES ---
bool serialStream = false;
String serialBuffer = "";

// 14 THREAT CATEGORIES
const int NUM_CATEGORIES = 14;
bool scanConfig[NUM_CATEGORIES] = {true, true, true, true, true, true, true, true, true, true, true, true, true, false};
const char* configNames[NUM_CATEGORIES] = {
  "Glasses", "Skimmers", "ALPR/Flock", "Drones", "Red Team", "Trackers",
  "Cams/Bugs", "Rogue AP", "WPA Exploit", "Wardrive", "Hotspots", "Infra", "Custom", "Catch-All"
};

const uint16_t configColors[NUM_CATEGORIES] = {
  CYAN, BLUE, YELLOW, MAGENTA, RED, WHITE,
  ORANGE, PURPLE, GREEN, GOLD, LIME, TEAL, GREY, GREY
};

int selectedMenu = 0;
int menuScrollOffset = 0;
const int VISIBLE_MENU_ITEMS = 9;
const int TOTAL_MENU_ITEMS = NUM_CATEGORIES + 6; 
unsigned long lastBtnPress = 0;
const int debounce = 200;

unsigned long lastKeepAlive = 0;
bool keepAlivePulsing = false;
bool pendingReboot = false;
unsigned long rebootTimer = 0;

// --- TIME HEIST & CONFIG ENGINE ---
bool timeSynced = false;
String timeTargetMac = "";
unsigned long lastTimeStealAttempt = 0;
String customSSID = "ThreatRadar-AP";
int proxThreshold = -25; 
int squelchLimit = -100; 
bool hardDrop = false;   

// CONFIG VARIABLES
int setupSelection = 0; 
bool setupEditMode = false;
bool timeEdited = false;
int setupYear = 2026, setupMonth = 1, setupDay = 1, setupHour = 12, setupMin = 0;
char setupSsid[17];
int setupSsidCursor = 0;
const char ssidCharset[] = " ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// ALIAS SYSTEM VARIABLES
std::map<String, String> deviceAliases;
char setupAlias[11];
int setupAliasCursor = 0;
String targetAliasMac = "";
int aliasCycleIndex = -1; 

// --- FOXHUNT & INTEL TARGETING ---
char targetMacStr[18] = "";
String targetDesc = "";
volatile int targetRssi = -100;
volatile unsigned long lastTargetUpdate = 0;

// --- FTM ENGINE VARIABLES ---
enum FtmState { FTM_IDLE, FTM_NEGOTIATING, FTM_SUCCESS, FTM_FAIL, FTM_CANCELED };
volatile FtmState ftmState = FTM_IDLE;
volatile float ftmDistance = -1.0;
unsigned long lastFtmRequestTime = 0;
unsigned long ftmMessageTimer = 0;
bool ftmNeedsFallback = false;

// --- RADAR FREEZE ENGINE ---
bool radarFrozen = false;
int frozenSelectedIndex = 0;
struct Threat { String mac; String protocol; String category; String desc; int rssi; unsigned long lastSeen; };
std::vector<Threat> activeThreats;
std::vector<Threat> frozenThreats; 

const byte DNS_PORT = 53;
DNSServer dnsServer;
WebServer server(80);

// --- MULTI-MATCH & REGEX RULES ENGINE ---
struct Rule {
  String category;
  String protocol;
  String label;
  bool useRegex;
  bool log_deep; 
  String name;
  String uuid;
  String cid;
  String dt;
  String mac;
  String any_mac; 
  String bssid;
  String ssid;
  String enc;
  String type;
  String vendor;
};
std::vector<Rule> threatRules;

void createDefaultRules() {
  File file = LittleFS.open("/rules.json", FILE_WRITE);
  if (file) {
    file.print("{\n  \"_last_updated\": \"");
    file.print("Factory Settings - ");
    file.print(__DATE__);
    file.print(" ");
    file.print(__TIME__);
    file.print("\",\n  \"rules\": [\n");

    // GLASSES
    file.print("    {\"cat\":\"Glasses\",\"proto\":\"BLE\",\"name\":\"ray-ban\",\"label\":\"Meta Ray-Bans\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"Glasses\",\"proto\":\"BLE\",\"name\":\"spectacles\",\"label\":\"Snap Spectacles\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"Glasses\",\"proto\":\"BLE\",\"uuid\":\"fd5f\",\"label\":\"Meta Ray-Bans (UUID)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"Glasses\",\"proto\":\"BLE\",\"cid\":\"0d53\",\"label\":\"Luxottica Eyewear\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"Glasses\",\"proto\":\"BLE\",\"cid\":\"03c2\",\"label\":\"Snap Spectacles (CID)\",\"log_deep\":true},\n");

    // SKIMMERS
    file.print("    {\"cat\":\"Skimmers\",\"proto\":\"BLE\",\"name\":\"hc-05\",\"label\":\"HC-05 Skimmer\"},\n");
    file.print("    {\"cat\":\"Skimmers\",\"proto\":\"BLE\",\"name\":\"hc-06\",\"label\":\"HC-06 Skimmer\"},\n");

    // DRONES
    file.print("    {\"cat\":\"Drones\",\"proto\":\"BLE\",\"uuid\":\"fffa\",\"label\":\"Drone Beacon\"},\n");
    file.print("    {\"cat\":\"Drones\",\"proto\":\"WIFI\",\"mac\":\"60:60:1f\",\"label\":\"DJI Drone (60:60:1f)\"},\n");
    file.print("    {\"cat\":\"Drones\",\"proto\":\"WIFI\",\"mac\":\"08:ea:40\",\"label\":\"DJI Drone (08:ea:40)\"},\n");
    file.print("    {\"cat\":\"Drones\",\"proto\":\"WIFI\",\"ssid\":\"spark-\",\"label\":\"DJI Spark AP\"},\n");
    file.print("    {\"cat\":\"Drones\",\"proto\":\"WIFI\",\"ssid\":\"mavic\",\"label\":\"DJI Mavic AP\"},\n");

    // TRACKERS
    file.print("    {\"cat\":\"Trackers\",\"proto\":\"BLE\",\"name\":\"itag\",\"label\":\"Generic Tracker\"},\n");
    file.print("    {\"cat\":\"Trackers\",\"proto\":\"BLE\",\"cid\":\"004c\",\"dt\":\"12\",\"label\":\"Apple AirTag / FindMy\"},\n");
    file.print("    {\"cat\":\"Trackers\",\"proto\":\"WIFI\",\"type\":\"4\",\"label\":\"Probing Client\"},\n");

    // RED TEAM
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"BLE\",\"uuid\":\"3082\",\"label\":\"Flipper Zero\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"BLE\",\"cid\":\"004c\",\"dt\":\"0f\",\"label\":\"Apple Spam (Nearby 0f)\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"BLE\",\"cid\":\"004c\",\"dt\":\"07\",\"label\":\"Apple Spam (AirPods 07)\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"BLE\",\"cid\":\"0075\",\"label\":\"Samsung Spam\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"BLE\",\"mac\":\"24:6f:28\",\"label\":\"Exposed ESP32\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"WIFI\",\"mac\":\"00:13:37\",\"label\":\"Hak5 Gear\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"WIFI\",\"ssid\":\"marauder\",\"label\":\"ESP32 Marauder\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"WIFI\",\"ssid\":\"pwned\",\"label\":\"Deauther Watch\"},\n");
    file.print("    {\"cat\":\"Red Team\",\"proto\":\"WIFI\",\"ssid\":\"pwnagotchi\",\"label\":\"Pwnagotchi\"},\n");

    // ALPR / FLOCK
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"BLE\",\"cid\":\"09c8\",\"label\":\"Flock ALPR (BLE)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"WIFI\",\"type\":\"4\",\"vendor\":\"50:6f:9a\",\"label\":\"Flock ALPR (IE Sig)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"WIFI\",\"ssid\":\"flock\",\"regex\":true,\"label\":\"Flock ALPR (SSID)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"WIFI\",\"any_mac\":\"70:c9:4e\",\"label\":\"Flock ALPR (70:c9:4e)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"WIFI\",\"any_mac\":\"3c:91:80\",\"label\":\"Flock ALPR (3c:91:80)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"WIFI\",\"any_mac\":\"d8:f3:bc\",\"label\":\"Flock ALPR (d8:f3:bc)\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"ALPR/Flock\",\"proto\":\"WIFI\",\"any_mac\":\"80:30:49\",\"label\":\"Flock ALPR (80:30:49)\",\"log_deep\":true},\n");

    // CAMS / BUGS
    file.print("    {\"cat\":\"Cams/Bugs\",\"proto\":\"WIFI\",\"ssid\":\"ipc-\",\"enc\":\"OPEN\",\"label\":\"Open IP Cam\"},\n");
    file.print("    {\"cat\":\"Cams/Bugs\",\"proto\":\"WIFI\",\"ssid\":\"cam_\",\"label\":\"Spy Cam AP\"},\n");
    file.print("    {\"cat\":\"Cams/Bugs\",\"proto\":\"WIFI\",\"ssid\":\"md81s\",\"label\":\"Mini DVR Cam\"},\n");
    file.print("    {\"cat\":\"Cams/Bugs\",\"proto\":\"WIFI\",\"ssid\":\"tuya_\",\"label\":\"Tuya Cam AP\"},\n");
    file.print("    {\"cat\":\"Cams/Bugs\",\"proto\":\"WIFI\",\"ssid\":\"carecam\",\"label\":\"CareCam Bug\"},\n");
    file.print("    {\"cat\":\"Cams/Bugs\",\"proto\":\"WIFI\",\"mac\":\"b0:f1:ec\",\"label\":\"Xiongmai Cam OUI\"},\n");

    // ROGUE AP
    file.print("    {\"cat\":\"Rogue AP\",\"proto\":\"WIFI\",\"ssid\":\"free wifi\",\"regex\":true,\"enc\":\"OPEN\",\"label\":\"Rogue Open AP\"},\n");
    file.print("    {\"cat\":\"Rogue AP\",\"proto\":\"WIFI\",\"ssid\":\"attwifi\",\"enc\":\"OPEN\",\"label\":\"Fake AT&T Honeypot\"},\n");
    file.print("    {\"cat\":\"Rogue AP\",\"proto\":\"WIFI\",\"ssid\":\"xfinitywifi\",\"enc\":\"OPEN\",\"label\":\"Fake Xfinity Honeypot\"},\n");
    file.print("    {\"cat\":\"Rogue AP\",\"proto\":\"WIFI\",\"ssid\":\"starbucks\",\"enc\":\"OPEN\",\"label\":\"Rogue Cafe AP\"},\n");
    file.print("    {\"cat\":\"Rogue AP\",\"proto\":\"WIFI\",\"ssid\":\"googlewifi\",\"enc\":\"OPEN\",\"label\":\"Fake Google AP\"},\n");

    // WPA EXPLOIT
    file.print("    {\"cat\":\"WPA Exploit\",\"proto\":\"WIFI\",\"type\":\"12\",\"label\":\"Deauth Burst!\",\"log_deep\":true},\n");
    file.print("    {\"cat\":\"WPA Exploit\",\"proto\":\"WIFI\",\"type\":\"10\",\"label\":\"Disassoc Flood!\"},\n");

    // WARDRIVE
    file.print("    {\"cat\":\"Wardrive\",\"proto\":\"WIFI\",\"ssid\":\"wigle\",\"label\":\"WiGLE Stalker\"},\n");
    file.print("    {\"cat\":\"Wardrive\",\"proto\":\"WIFI\",\"ssid\":\"kismet\",\"label\":\"Kismet Rig\"},\n");

    // HOTSPOTS
    file.print("    {\"cat\":\"Hotspots\",\"proto\":\"WIFI\",\"vendor\":\"00:17:f2\",\"label\":\"Apple Tethering\"},\n");
    file.print("    {\"cat\":\"Hotspots\",\"proto\":\"WIFI\",\"ssid\":\"iphone\",\"label\":\"iPhone Hotspot\"},\n");
    file.print("    {\"cat\":\"Hotspots\",\"proto\":\"WIFI\",\"ssid\":\"androidap\",\"label\":\"Android Hotspot\"},\n");
    file.print("    {\"cat\":\"Hotspots\",\"proto\":\"WIFI\",\"ssid\":\"mifi\",\"label\":\"MiFi Cellular Router\"},\n");
    file.print("    {\"cat\":\"Hotspots\",\"proto\":\"WIFI\",\"ssid\":\"nighthawk\",\"label\":\"Netgear Mobile AP\"},\n");
    file.print("    {\"cat\":\"Hotspots\",\"proto\":\"WIFI\",\"ssid\":\"gl-\",\"label\":\"GL.iNet Router\"},\n");

    // --- ZIGBEE / THREAD RULES ---
    file.print("    {\"cat\":\"Infra\",\"proto\":\"ZIGBEE\",\"mac\":\"802:00\",\"label\":\"802.15.4 Beacon\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"ZIGBEE\",\"mac\":\"802:41\",\"label\":\"Zigbee/Thread Data\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"ZIGBEE\",\"mac\":\"802:61\",\"label\":\"Zigbee/Thread Data\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"ZIGBEE\",\"mac\":\"802:03\",\"label\":\"Zigbee MAC Cmd\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"ZIGBEE\",\"mac\":\"802:\",\"label\":\"Unknown 802.15.4\"},\n");

    // --- AMAZON / SIDEWALK ECOSYSTEM ---
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"ssid\":\"amazon-\",\"label\":\"Echo Setup AP\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"any_mac\":\"f0:81:73\",\"label\":\"Amazon Echo (OUI)\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"any_mac\":\"fc:a1:83\",\"label\":\"Amazon Device (OUI)\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"BLE\",\"name\":\"echo\",\"label\":\"Amazon Echo\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"BLE\",\"name\":\"ring\",\"label\":\"Ring Camera/Doorbell\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"BLE\",\"cid\":\"0171\",\"label\":\"Amazon/Sidewalk Node\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"BLE\",\"uuid\":\"fdf4\",\"label\":\"Sidewalk Mesh\"},\n");

    // INFRA
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"ssid\":\"traffic\",\"label\":\"Traffic Sensor\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"ssid\":\"sensor_\",\"label\":\"Telemetry Grid\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"mac\":\"00:80:a3\",\"label\":\"Lantronix Device\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"ssid\":\"itron\",\"label\":\"Smart Meter Grid\"},\n");
    file.print("    {\"cat\":\"Infra\",\"proto\":\"WIFI\",\"vendor\":\"HE-WIFI6\",\"label\":\"Wi-Fi 6 Node\"}\n");
    file.print("  ]\n}");
    file.close();
  }
}

void loadRules() {
  threatRules.clear();
  File f = LittleFS.open("/rules.json", "r");
  if (!f) return;
  
  #if ARDUINOJSON_VERSION_MAJOR >= 7
    JsonDocument doc;
  #else
    DynamicJsonDocument doc(16384);
  #endif
  
  if (!deserializeJson(doc, f)) {
    JsonArray rules = doc["rules"];
    for (JsonObject r : rules) {
      Rule rule;
      rule.category = r["cat"].as<String>();
      rule.protocol = r["proto"].as<String>();
      rule.label = r["label"].as<String>();
      rule.useRegex = r.containsKey("regex") ? r["regex"].as<bool>() : false;
      rule.log_deep = r.containsKey("log_deep") ? r["log_deep"].as<bool>() : false; 
      
      if (r.containsKey("name"))    { rule.name = r["name"].as<String>(); rule.name.toLowerCase(); }
      if (r.containsKey("uuid"))    { rule.uuid = r["uuid"].as<String>(); rule.uuid.toLowerCase(); }
      if (r.containsKey("cid"))     { rule.cid = r["cid"].as<String>(); rule.cid.toLowerCase(); }
      if (r.containsKey("dt"))      { rule.dt = r["dt"].as<String>(); rule.dt.toLowerCase(); }
      if (r.containsKey("mac"))     { rule.mac = r["mac"].as<String>(); rule.mac.toLowerCase(); }
      if (r.containsKey("any_mac")) { rule.any_mac = r["any_mac"].as<String>(); rule.any_mac.toLowerCase(); }
      if (r.containsKey("bssid"))   { rule.bssid = r["bssid"].as<String>(); rule.bssid.toLowerCase(); }
      if (r.containsKey("ssid"))    { rule.ssid = r["ssid"].as<String>(); rule.ssid.toLowerCase(); }
      if (r.containsKey("enc"))     { rule.enc = r["enc"].as<String>(); rule.enc.toLowerCase(); }
      if (r.containsKey("type"))    { rule.type = r["type"].as<String>(); rule.type.toLowerCase(); }
      if (r.containsKey("vendor"))  { rule.vendor = r["vendor"].as<String>(); rule.vendor.toLowerCase(); }

      threatRules.push_back(rule);
    }
  }
  f.close();
}

void loadAliases() {
  deviceAliases.clear();
  File f = LittleFS.open("/aliases.json", "r");
  if (!f) return;
  #if ARDUINOJSON_VERSION_MAJOR >= 7
    JsonDocument doc;
  #else
    DynamicJsonDocument doc(4096);
  #endif
  if (!deserializeJson(doc, f)) {
    JsonObject obj = doc.as<JsonObject>();
    for (JsonPair kv : obj) {
      deviceAliases[kv.key().c_str()] = kv.value().as<String>();
    }
  }
  f.close();
}

void saveAlias(String mac, String name) {
  name.trim();
  if (name.length() == 0) {
    deviceAliases.erase(mac);
  } else {
    deviceAliases[mac] = name;
  }
  File f = LittleFS.open("/aliases.json", FILE_WRITE);
  if (f) {
    #if ARDUINOJSON_VERSION_MAJOR >= 7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(4096);
    #endif
    for (auto const& pair : deviceAliases) {
      doc[pair.first] = pair.second;
    }
    serializeJson(doc, f);
    f.close();
  }
}

bool isCategoryEnabled(String cat) {
  for (int i = 0; i < NUM_CATEGORIES; i++) {
    if (cat == configNames[i]) return scanConfig[i];
  }
  return false;
}

// --- THREAT TRACKING & DEEP INTEL ARCHITECTURE ---
struct ThreatHistory { 
  String mac; String protocol; String category; String desc; int peakRssi; int latestRssi; 
  unsigned long firstSeen; unsigned long lastSeen; int count; 
  String addr1;       
  String bssid;       
  String probes;      
  String rawPayload;  
  String gattInfo;    
  String enc;         
  String vendor;      
};

std::vector<ThreatHistory> historyLogs;

void saveHistoryState() {
  File f = LittleFS.open("/history.jsonl", FILE_WRITE);
  if (!f) return;
  for (const auto& h : historyLogs) {
    #if ARDUINOJSON_VERSION_MAJOR >= 7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(1024);
    #endif
    doc["mac"] = h.mac;
    doc["proto"] = h.protocol;
    doc["cat"] = h.category;
    doc["desc"] = h.desc;
    doc["pkRssi"] = h.peakRssi;
    doc["ltRssi"] = h.latestRssi;
    doc["count"] = h.count;
    doc["addr1"] = h.addr1;
    doc["bssid"] = h.bssid;
    doc["probes"] = h.probes;
    doc["raw"] = h.rawPayload;
    doc["gatt"] = h.gattInfo;
    doc["enc"] = h.enc;
    doc["vnd"] = h.vendor;
    serializeJson(doc, f);
    f.print("\n");
  }
  f.close();
}

void loadHistoryState() {
  File f = LittleFS.open("/history.jsonl", "r");
  if (!f) return;
  historyLogs.clear();
  while (f.available()) {
    String line = f.readStringUntil('\n');
    if (line.length() < 10) continue;
    #if ARDUINOJSON_VERSION_MAJOR >= 7
      JsonDocument doc;
    #else
      DynamicJsonDocument doc(1024);
    #endif
    DeserializationError err = deserializeJson(doc, line);
    if (!err) {
      ThreatHistory h;
      h.mac = doc["mac"].as<String>();
      h.protocol = doc["proto"].as<String>();
      h.category = doc["cat"].as<String>();
      h.desc = doc["desc"].as<String>();
      h.peakRssi = doc["pkRssi"].as<int>();
      h.latestRssi = doc["ltRssi"].as<int>();
      h.count = doc["count"].as<int>();
      h.addr1 = doc["addr1"].as<String>();
      h.bssid = doc["bssid"].as<String>();
      h.probes = doc["probes"].as<String>();
      h.rawPayload = doc["raw"].as<String>();
      h.gattInfo = doc["gatt"].as<String>();
      h.enc = doc["enc"].as<String>();
      h.vendor = doc["vnd"].as<String>();
      
      h.firstSeen = 0; 
      h.lastSeen = 0; 
      
      if (historyLogs.size() < 400) historyLogs.push_back(h);
    }
  }
  f.close();
}

// --- SERIAL COMMAND API ENGINE ---
void processSerialCommand(String cmd) {
  cmd.trim(); 
  String cmdUpper = cmd;
  cmdUpper.toUpperCase();

  if (cmdUpper == "HELP" || cmdUpper == "?" || cmdUpper == "CMD:HELP") {
    Serial.println("\n--- Threat Radar Serial API ---");
    Serial.println("Available Commands:");
    Serial.println("  HELP               - Show this help message");
    Serial.println("  CMD:LS             - List all files in flash memory (JSON)");
    Serial.println("  CMD:READ:/file.ext - Download/stream a specific file");
    Serial.println("  CMD:STREAM:ON      - Enable live JSON telemetry stream of detected threats");
    Serial.println("  CMD:STREAM:OFF     - Disable live telemetry stream");
    Serial.println("-------------------------------\n");
  }
  else if (cmdUpper == "CMD:LS") {
    File root = LittleFS.open("/");
    Serial.print("[");
    bool first = true;
    File file = root.openNextFile();
    while(file) {
      if (!first) Serial.print(",");
      String fName = String(file.name());
      if (!fName.startsWith("/")) fName = "/" + fName;
      Serial.printf("{\"name\":\"%s\",\"size\":%lu}", fName.c_str(), file.size());
      first = false;
      file = root.openNextFile();
    }
    Serial.println("]");
  } 
  else if (cmdUpper.startsWith("CMD:READ:")) {
    String path = cmd.substring(9);
    path.trim();
    if (LittleFS.exists(path)) {
      File f = LittleFS.open(path, "r");
      Serial.printf("START_FILE:%s:%lu\n", path.c_str(), f.size());
      uint8_t buf[256];
      while (f.available()) {
        size_t len = f.read(buf, sizeof(buf));
        Serial.write(buf, len);
      }
      f.close();
      Serial.println("\nEND_FILE");
    } else {
      Serial.println("ERR:FILE_NOT_FOUND");
    }
  } 
  else if (cmdUpper == "CMD:STREAM:ON") {
    serialStream = true;
    Serial.println("ACK:STREAM_ON");
  } 
  else if (cmdUpper == "CMD:STREAM:OFF") {
    serialStream = false;
    Serial.println("ACK:STREAM_OFF");
  }
  else if (cmd.length() > 0) {
    Serial.println("ERR:UNKNOWN_COMMAND (Type HELP for a list of commands)");
  }
}

bool logMenuOpen = false;
int logMenuSelection = 0; 
bool filterHideOld = false;
bool filterHideLowHits = false; 
int filterCategoryIndex = -1; 

int sortField = 0; 
int sortDir = 0;   

std::vector<int> filteredLogIndices;
int currentFilteredIndex = 0;

void applyFilters() {
  String currentMac = "";
  if (!filteredLogIndices.empty() && currentFilteredIndex < (int)filteredLogIndices.size()) {
    currentMac = historyLogs[filteredLogIndices[currentFilteredIndex]].mac;
  }

  filteredLogIndices.clear();
  unsigned long now = millis();
  
  for (size_t i = 0; i < historyLogs.size(); i++) {
    if (filterHideOld) {
      unsigned long age = (now >= historyLogs[i].lastSeen) ? (now - historyLogs[i].lastSeen) : 0;
      if (age > 300000) continue; 
    }
    if (filterHideLowHits) {
      if (historyLogs[i].count < 5) continue; 
    }
    if (filterCategoryIndex != -1) {
      if (historyLogs[i].category != configNames[filterCategoryIndex]) continue;
    }
    filteredLogIndices.push_back(i);
  }
  
  std::sort(filteredLogIndices.begin(), filteredLogIndices.end(), [](int a, int b) {
    if (sortField == 0) {
        return sortDir == 0 ? (historyLogs[a].lastSeen > historyLogs[b].lastSeen) : (historyLogs[a].lastSeen < historyLogs[b].lastSeen);
    } else if (sortField == 1) {
        return sortDir == 0 ? (historyLogs[a].peakRssi > historyLogs[b].peakRssi) : (historyLogs[a].peakRssi < historyLogs[b].peakRssi);
    } else {
        return sortDir == 0 ? (historyLogs[a].count > historyLogs[b].count) : (historyLogs[a].count < historyLogs[b].count);
    }
  });

  currentFilteredIndex = 0;
  if (currentMac != "") {
    for (size_t i = 0; i < filteredLogIndices.size(); i++) {
      if (historyLogs[filteredLogIndices[i]].mac == currentMac) {
        currentFilteredIndex = (int)i;
        break;
      }
    }
  }
}

void logEvent(String type, String mac, String desc, int rssi, String extra) {
  File file = LittleFS.open("/logs.csv", FILE_APPEND);
  if (file) { 
      file.printf("%s,%lu,%s,%s,%d,%s\n", type.c_str(), millis(), mac.c_str(), desc.c_str(), rssi, extra.c_str()); 
      file.close(); 
  }
}

void processThreat(Packet& pkt, String proto, String category, String threatType, bool shouldDeepLog) {
  unsigned long now = millis();
  String mac = pkt.mac;
  int rssi = pkt.rssi;

  if (shouldDeepLog) {
      File f = LittleFS.open("/deep_intel.csv", FILE_APPEND);
      if (f) {
          if (f.size() == 0) f.println("TimeMs,Proto,Cat,Threat,MAC,BSSID,DST,RSSI,Enc,Vendor,RawHex,SSID_Name");
          f.printf("%lu,%s,%s,%s,%s,%s,%s,%d,%s,%s,%s,%s\n",
              millis(), proto.c_str(), category.c_str(), threatType.c_str(),
              pkt.mac.c_str(), pkt.bssid.c_str(), pkt.addr1.c_str(), pkt.rssi,
              pkt.enc.c_str(), pkt.vendor.c_str(), pkt.rawHex.c_str(),
              (proto=="WIFI" ? pkt.ssid.c_str() : pkt.name.c_str())
          );
          f.close();
      }
  }

  if (serialStream) {
      #if ARDUINOJSON_VERSION_MAJOR >= 7
        JsonDocument sDoc;
      #else
        DynamicJsonDocument sDoc(512);
      #endif
      sDoc["ts"] = now;
      sDoc["mac"] = mac;
      sDoc["rssi"] = rssi;
      sDoc["proto"] = proto;
      sDoc["cat"] = category;
      sDoc["threat"] = threatType;
      if (pkt.ssid != "") sDoc["ssid"] = pkt.ssid;
      if (pkt.bssid != "") sDoc["bssid"] = pkt.bssid;
      if (pkt.addr1 != "") sDoc["dst"] = pkt.addr1;
      if (pkt.rawHex != "") sDoc["raw"] = pkt.rawHex;
      Serial.print("STREAM_HIT:");
      serializeJson(sDoc, Serial);
      Serial.println();
  }

  bool found = false;
  for (auto &t : activeThreats) {
    if (t.mac == mac) { 
      t.rssi = rssi; t.lastSeen = now; 
      t.desc = threatType; 
      t.category = category;
      found = true; break; 
    }
  }
  if(!found) {
    if (activeThreats.size() >= 50) {
        int oldestIdx = 0;
        for (size_t i = 1; i < activeThreats.size(); i++) {
            if (activeThreats[i].lastSeen < activeThreats[oldestIdx].lastSeen) oldestIdx = i;
        }
        activeThreats[oldestIdx] = {mac, proto, category, threatType, rssi, now};
    } else {
        activeThreats.push_back({mac, proto, category, threatType, rssi, now});
    }
    
    String extraData = "";
    if (deviceAliases.count(mac)) extraData += "ALIAS:" + deviceAliases[mac] + " "; 
    if (pkt.ssid != "") extraData += "SSID:" + pkt.ssid + " ";
    if (pkt.bssid != "" && pkt.bssid != "ff:ff:ff:ff:ff:ff" && pkt.bssid != "00:00:00:00:00:00") extraData += "BSSID:" + pkt.bssid + " ";
    if (pkt.addr1 != "" && pkt.addr1 != "ff:ff:ff:ff:ff:ff" && pkt.addr1 != "00:00:00:00:00:00") extraData += "DST:" + pkt.addr1;
    extraData.trim();
    if (extraData == "") extraData = "None";
    
    logEvent("DETECT", mac, threatType, rssi, extraData);
  }

  bool historyFound = false;
  for (auto &h : historyLogs) {
    if (h.mac == mac) {
       if (rssi > h.peakRssi) h.peakRssi = rssi;
       h.latestRssi = rssi; 
       h.lastSeen = now; 
       h.count++;
       h.desc = threatType; 
       h.category = category;
       
       if (pkt.ssid != "" && h.probes.indexOf(pkt.ssid) == -1) {
           if (h.probes.length() > 0) h.probes += ", ";
           h.probes += pkt.ssid;
           if (h.probes.length() > 25) h.probes = h.probes.substring(0, 25) + "..";
       }
       if (pkt.bssid != "" && pkt.bssid != "ff:ff:ff:ff:ff:ff" && pkt.bssid != "00:00:00:00:00:00") {
           h.bssid = pkt.bssid;
       }
       if (pkt.addr1 != "" && pkt.addr1 != "ff:ff:ff:ff:ff:ff" && pkt.addr1 != "00:00:00:00:00:00") {
           h.addr1 = pkt.addr1;
       }
       if (pkt.rawHex != "") h.rawPayload = pkt.rawHex;
       if (pkt.enc != "") h.enc = pkt.enc;
       if (pkt.vendor != "") h.vendor = pkt.vendor;
       
       historyFound = true;
       break;
    }
  }
  
  if (!historyFound) {
    if (historyLogs.size() >= 400) {
        int oldestIdx = 0;
        for (size_t i = 1; i < historyLogs.size(); i++) {
            if (historyLogs[i].lastSeen < historyLogs[oldestIdx].lastSeen) oldestIdx = i;
        }
        historyLogs[oldestIdx] = {mac, proto, category, threatType, rssi, rssi, now, now, 1, pkt.addr1, pkt.bssid, pkt.ssid, pkt.rawHex, "", pkt.enc, pkt.vendor};
    } else {
        historyLogs.push_back({mac, proto, category, threatType, rssi, rssi, now, now, 1, pkt.addr1, pkt.bssid, pkt.ssid, pkt.rawHex, "", pkt.enc, pkt.vendor});
    }
  }

  if (systemState == LOG_VIEW && !logMenuOpen) {
      if (!filteredLogIndices.empty() && currentFilteredIndex < (int)filteredLogIndices.size()) {
          if (historyLogs[filteredLogIndices[currentFilteredIndex]].mac == mac) {
              uiNeedsUpdate = true;
          }
      }
  }
}

// MULTI-MATCH & C6-OPTIMIZED WILDCARD ENGINE
void evaluatePacket(Packet& pkt, String proto) {
  if (hardDrop && pkt.rssi < squelchLimit) return; 

  String threatType = "";
  String matchedCategory = "";
  bool shouldDeepLog = false;
  
  for (const auto& rule : threatRules) {
    if (rule.protocol != proto) continue;
    if (!isCategoryEnabled(rule.category)) continue; 
    
    bool matches = true;

    // [PHASE 4 PATCH] Zero-Allocation Wildcard Matcher with Case Insensitivity
    auto textMatch = [&](const String& target, const String& pattern) {
      if (pattern == "") return true;
      
      String t = target; t.toLowerCase(); 
      
      if (rule.useRegex) {
        String p = pattern; p.replace(".*", "*");
        
        const char *pat = p.c_str();
        const char *str = t.c_str();
        const char *cp = NULL, *mp = NULL;
        
        while (*str && *pat != '*') {
          if (*pat != *str && *pat != '?') return false;
          pat++; str++;
        }
        while (*str) {
          if (*pat == '*') {
            if (!*++pat) return true;
            mp = pat; cp = str + 1;
          } else if (*pat == *str || *pat == '?') {
            pat++; str++;
          } else {
            pat = mp; str = cp++;
          }
        }
        while (*pat == '*') pat++;
        return !*pat;
      } else {
        return t.indexOf(pattern) >= 0;
      }
    };

    if (rule.name != "" && !textMatch(pkt.name, rule.name)) matches = false;
    if (matches && rule.uuid != "" && !textMatch(pkt.uuid, rule.uuid)) matches = false;
    if (matches && rule.cid != "" && pkt.cid != rule.cid) matches = false;
    if (matches && rule.dt != "" && pkt.dataType != rule.dt) matches = false;
    
    if (matches && rule.mac != "") {
      if (pkt.mac.indexOf(rule.mac) < 0 && pkt.macPrefix.indexOf(rule.mac) < 0) matches = false;
    }

    if (matches && rule.any_mac != "") {
      bool anyMatched = false;
      if (pkt.mac.indexOf(rule.any_mac) >= 0 || pkt.macPrefix.indexOf(rule.any_mac) >= 0) anyMatched = true;
      if (pkt.bssid.indexOf(rule.any_mac) >= 0) anyMatched = true;
      if (pkt.addr1.indexOf(rule.any_mac) >= 0) anyMatched = true;
      if (!anyMatched) matches = false;
    }

    if (matches && rule.bssid != "" && !textMatch(pkt.bssid, rule.bssid)) matches = false;
    if (matches && rule.ssid != "" && !textMatch(pkt.ssid, rule.ssid)) matches = false;
    if (matches && rule.enc != "" && !pkt.enc.equalsIgnoreCase(rule.enc)) matches = false;
    if (matches && rule.type != "" && pkt.dataType != rule.type) matches = false;
    if (matches && rule.vendor != "" && !textMatch(pkt.vendor, rule.vendor)) matches = false;
    
    if (matches) { 
      threatType = rule.label; 
      matchedCategory = rule.category;
      shouldDeepLog = rule.log_deep;
      break; 
    }
  }
  
  if (threatType == "") {
      if (proto == "BLE" && scanConfig[NUM_CATEGORIES - 1]) {
          threatType = (pkt.name != "") ? pkt.name : "Unknown BLE";
          matchedCategory = "Catch-All";
      } 
      else if (proto == "WIFI" && scanConfig[NUM_CATEGORIES - 1]) {
          if ((pkt.dataType == "8" || pkt.dataType == "5") && pkt.ssid != "") {
              threatType = pkt.ssid;
              matchedCategory = "Catch-All";
          }
      }
      else if (proto == "ZIGBEE" && scanConfig[NUM_CATEGORIES - 1]) {
          threatType = (pkt.name != "") ? pkt.name : "Unknown ZIGBEE";
          matchedCategory = "Catch-All";
      }
  }
  
  if (systemState == FOXHUNT_VIEW && strcasecmp(pkt.mac.c_str(), targetMacStr) == 0) {
      if (targetRssi <= -100) targetRssi = pkt.rssi;
      else targetRssi = (targetRssi * 2 + pkt.rssi) / 3;
      lastTargetUpdate = millis();
      uiNeedsUpdate = true;
  }

  if (threatType != "") processThreat(pkt, proto, matchedCategory, threatType, shouldDeepLog);
}

// --- WI-FI SNIFFER (WITH ADDR1 RECEIVER EXTRACTION) ---
volatile RawWifiHit wifiBuffer[10];
volatile int wifiHitWrite = 0;
volatile int wifiHitRead = 0;

void wifi_sniffer(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT) return;
  wifi_promiscuous_pkt_t *wPkt = (wifi_promiscuous_pkt_t *)buff;
  int pktLen = wPkt->rx_ctrl.sig_len;
  if (pktLen < 24) return;
  
  uint8_t *payload = wPkt->payload;
  uint8_t *addr1 = payload + 4;   
  uint8_t *mac   = payload + 10;  
  uint8_t *bssid = payload + 16;  
  
  char addr1Str[18];
  sprintf(addr1Str, "%02x:%02x:%02x:%02x:%02x:%02x", addr1[0], addr1[1], addr1[2], addr1[3], addr1[4], addr1[5]);

  char macStr[18]; 
  sprintf(macStr, "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  
  char bssidStr[18];
  sprintf(bssidStr, "%02x:%02x:%02x:%02x:%02x:%02x", bssid[0], bssid[1], bssid[2], bssid[3], bssid[4], bssid[5]);
  
  int rssi = wPkt->rx_ctrl.rssi;

  char ssidStr[33] = {0}; 
  char encStr[8] = "";
  char vendorStr[12] = ""; 
  
  uint8_t frame_subtype = (payload[0] & 0xF0) >> 4;
  uint8_t frame_type = (payload[0] & 0x0C) >> 2;

  if (frame_type == 0) {
    if (frame_subtype == 8 || frame_subtype == 5) {
      if (pktLen >= 36) {
        uint16_t cap = payload[34] | (payload[35] << 8);
        if ((cap & 0x0010) == 0) strcpy(encStr, "OPEN");
        else strcpy(encStr, "WPA2");

        int offset = 36;
        while (offset + 1 < pktLen) {
          uint8_t tagId = payload[offset];
          uint8_t tagLen = payload[offset + 1];
          if (offset + 2 + tagLen > pktLen) break;

          if (tagId == 0 && tagLen > 0 && tagLen <= 32 && ssidStr[0] == 0) {
            memcpy(ssidStr, payload + offset + 2, tagLen);
            ssidStr[tagLen] = '\0';
          } else if (tagId == 221 && tagLen >= 3 && vendorStr[0] == 0) {
            sprintf(vendorStr, "%02x:%02x:%02x", payload[offset + 2], payload[offset + 3], payload[offset + 4]);
          } 
          // --- [PHASE 3: WI-FI 6 HE DETECTION] ---
          else if (tagId == 255 && tagLen >= 1 && payload[offset + 2] == 35) {
            if (strlen(vendorStr) > 0 && strlen(vendorStr) < 9) strcat(vendorStr, "-HE");
            else if (vendorStr[0] == 0) strcpy(vendorStr, "HE-WIFI6");
          }
          // ---------------------------------------
          offset += 2 + tagLen;
        }
      }
    } 
    else if (frame_subtype == 4) {
      int offset = 24;
      while (offset + 1 < pktLen) {
        uint8_t tagId = payload[offset];
        uint8_t tagLen = payload[offset + 1];
        if (offset + 2 + tagLen > pktLen) break;
        
        if (tagId == 0 && tagLen > 0 && tagLen <= 32 && ssidStr[0] == 0) {
          memcpy(ssidStr, payload + offset + 2, tagLen);
          ssidStr[tagLen] = '\0';
        } else if (tagId == 221 && tagLen >= 3 && vendorStr[0] == 0) {
          sprintf(vendorStr, "%02x:%02x:%02x", payload[offset + 2], payload[offset + 3], payload[offset + 4]);
        }
        // --- [PHASE 3: WI-FI 6 HE DETECTION] ---
        else if (tagId == 255 && tagLen >= 1 && payload[offset + 2] == 35) {
          if (strlen(vendorStr) > 0 && strlen(vendorStr) < 9) strcat(vendorStr, "-HE");
          else if (vendorStr[0] == 0) strcpy(vendorStr, "HE-WIFI6");
        }
        // ---------------------------------------
        offset += 2 + tagLen;
      }
    }
  }

  int next = (wifiHitWrite + 1) % 10;
  if (next != wifiHitRead) {
      strncpy((char*)wifiBuffer[wifiHitWrite].mac, macStr, 17); 
      wifiBuffer[wifiHitWrite].mac[17] = '\0';

      strncpy((char*)wifiBuffer[wifiHitWrite].addr1, addr1Str, 17); 
      wifiBuffer[wifiHitWrite].addr1[17] = '\0';
      
      strncpy((char*)wifiBuffer[wifiHitWrite].bssid, bssidStr, 17);
      wifiBuffer[wifiHitWrite].bssid[17] = '\0';
      
      strncpy((char*)wifiBuffer[wifiHitWrite].ssid, ssidStr, 32); 
      wifiBuffer[wifiHitWrite].ssid[32] = '\0';

      strncpy((char*)wifiBuffer[wifiHitWrite].enc, encStr, 7);
      wifiBuffer[wifiHitWrite].enc[7] = '\0';

      strncpy((char*)wifiBuffer[wifiHitWrite].vendor, vendorStr, 11); 
      wifiBuffer[wifiHitWrite].vendor[11] = '\0';

      wifiBuffer[wifiHitWrite].rssi = rssi;
      wifiBuffer[wifiHitWrite].subtype = frame_subtype; 
      wifiHitWrite = next;
  }
}

// --- BLE SNIFFER ---
NimBLEScan* pBLEScan;
class ThreatScanner : public NimBLEScanCallbacks {
  void onResult(const NimBLEAdvertisedDevice* dev) {
    Packet pkt;
    pkt.mac = dev->getAddress().toString().c_str(); pkt.mac.toLowerCase();
    pkt.macPrefix = pkt.mac.substring(0, 8);
    pkt.addr1 = "";
    pkt.rssi = dev->getRSSI();
    
    if (!timeSynced && timeTargetMac == "") {
        if (dev->haveServiceUUID()) {
            if (dev->isAdvertisingService(NimBLEUUID((uint16_t)0x1805))) {
                timeTargetMac = dev->getAddress().toString().c_str();
            }
        }
    }
    
    if (dev->haveName()) { pkt.name = dev->getName().c_str(); pkt.name.toLowerCase(); }
    if (dev->haveServiceUUID()) { pkt.uuid = dev->getServiceUUID().toString().c_str(); pkt.uuid.toLowerCase(); }
    
    if (dev->haveManufacturerData()) {
      std::string md = dev->getManufacturerData();
      if (md.length() >= 3) {
        char cidBuf[5]; sprintf(cidBuf, "%04x", (md[1] << 8) | md[0]); pkt.cid = String(cidBuf);
        char dtBuf[3]; sprintf(dtBuf, "%02x", md[2]); pkt.dataType = String(dtBuf);
      }
    }
    
    std::vector<uint8_t> payload = dev->getPayload();
    const uint8_t* p = payload.data();
    size_t len = payload.size();
    
    String hexStr = "";
    for(size_t i = 0; i < len && i < 12; i++) { 
       char buf[3]; sprintf(buf, "%02x", p[i]); hexStr += buf;
    }
    pkt.rawHex = hexStr;
    
    evaluatePacket(pkt, "BLE");
  }
};

// --- RADIO SWAPPERS ---
static int internalActiveRadio = -1; // -1: None, 0: BLE, 1: WIFI, 2: ZIGBEE

void teardownRadios() {
  if (internalActiveRadio == 1) { 
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
  } 
  else if (internalActiveRadio == 0) { 
    if (pBLEScan) pBLEScan->stop();
  } 
  else if (internalActiveRadio == 2) { 
    esp_ieee802154_sleep();  
    esp_ieee802154_disable(); 
  }
  
  internalActiveRadio = -1;
  delay(50); // Allow the Coexistence Arbiter to route the antenna cleanly
}

void startBLE() {
  teardownRadios();
  internalActiveRadio = 0;
  
  NimBLEDevice::init("ThreatRadar");
  pBLEScan = NimBLEDevice::getScan();
  pBLEScan->setScanCallbacks(new ThreatScanner());
  pBLEScan->setActiveScan(true); 
  pBLEScan->setInterval(100); 
  pBLEScan->setWindow(99);
  
  pBLEScan->setMaxResults(0); pBLEScan->setDuplicateFilter(false); pBLEScan->start(0, false);  
}

void startWIFI() {
  teardownRadios();
  internalActiveRadio = 1;
  
  if (WiFi.getMode() != WIFI_STA) {
      WiFi.mode(WIFI_STA); 
      delay(10);
  }
  
  esp_wifi_set_ps(WIFI_PS_NONE); 
  
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer);
  esp_wifi_set_promiscuous(true); 
  esp_wifi_set_channel(wifiChannel, WIFI_SECOND_CHAN_NONE);
}

void startZIGBEE() {
  teardownRadios();
  internalActiveRadio = 2;
  
  esp_ieee802154_enable();
  esp_ieee802154_set_promiscuous(true);
  esp_ieee802154_set_rx_when_idle(true);
  esp_ieee802154_set_channel(11); 
  esp_ieee802154_receive();
}

void initPortalHardware();
void startPortal();
void stopPortal();
void drawAboutView(); 

// ====================================================================
// ZIGBEE ACTIVE INTERROGATION ENGINE (RTOS SHIELDED)
// ====================================================================
uint8_t zigbeeSeq = 0;

void zigbeeTxTask(void *pvParameters) {
    esp_ieee802154_transmit((uint8_t*)pvParameters, false);
    vTaskDelete(NULL); 
}

void sendZigbeeBeaconProbe() {
    static uint8_t pkt[] = {
        0x0B, 0x03, 0x08, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x00, 0x00 
    };
    pkt[3] = zigbeeSeq++; 
    xTaskCreate(zigbeeTxTask, "zTX", 4096, pkt, 2, NULL);
}

void sendTouchlinkProbe() {
    static uint8_t pkt[] = {
        0x23, 0x41, 0x88, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 
        0x0F, 0x32, 0x08, 0x0F, 0xC0, 0x5E, 0x10, 0x00, 0x11, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 0x00 
    };
    pkt[3] = zigbeeSeq; pkt[21] = zigbeeSeq++; 
    xTaskCreate(zigbeeTxTask, "zTX", 4096, pkt, 2, NULL);
}

extern "C" void esp_ieee802154_transmit_done(const uint8_t *frame, const uint8_t *ack, esp_ieee802154_frame_info_t *ack_info) {}
extern "C" void esp_ieee802154_transmit_failed(const uint8_t *frame, esp_ieee802154_tx_error_t error) {}

// ====================================================================
// 802.11mc FTM ENGINE
// ====================================================================
void ftmEventHandler(WiFiEvent_t event, WiFiEventInfo_t info) {
    if (event == ARDUINO_EVENT_WIFI_FTM_REPORT) {
        if (info.wifi_ftm_report.status == FTM_STATUS_SUCCESS) {
            ftmDistance = (float)info.wifi_ftm_report.dist_est / 100.0;
            ftmState = FTM_SUCCESS;
        } else {
            ftmState = FTM_FAIL;
            ftmMessageTimer = millis();
            ftmNeedsFallback = true;
        }
        uiNeedsUpdate = true;
    }
}

void triggerFtmRequest() {
    uint8_t mac[6];
    int values[6];
    if (6 == sscanf(targetMacStr, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5])) {
        for (int i = 0; i < 6; ++i) mac[i] = (uint8_t)values[i];
        
        esp_wifi_set_promiscuous(false); // Pause sniffer for FTM negotiation
        
        wifi_ftm_initiator_cfg_t ftmi_cfg = {0};
        ftmi_cfg.frm_count = 16;
        ftmi_cfg.burst_period = 2;
        memcpy(ftmi_cfg.resp_mac, mac, 6);
        ftmi_cfg.channel = wifiChannel;

        esp_wifi_ftm_initiate_session(&ftmi_cfg);
        lastFtmRequestTime = millis();
    } else {
        ftmState = FTM_FAIL;
        ftmNeedsFallback = true;
    }
}

void setup() {
  Serial.begin(115200); 
  
  pinMode(BTN_UP, INPUT_PULLUP); pinMode(BTN_DOWN, INPUT_PULLUP);
  pinMode(BTN_LEFT, INPUT_PULLUP); pinMode(BTN_RIGHT, INPUT_PULLUP);
  pinMode(BTN_A, INPUT_PULLUP); pinMode(BTN_B, INPUT_PULLUP); 
  pinMode(PIN_KEEPALIVE, OUTPUT); digitalWrite(PIN_KEEPALIVE, HIGH);
  pinMode(TFT_BL, OUTPUT); digitalWrite(TFT_BL, HIGH);

  gfx->begin();

  gfx->fillScreen(BLACK);
  gfx->draw16bitBeRGBBitmap(0, 0, (uint16_t*)foxhunter_logo, 160, 128);
  delay(2500);

  if (!LittleFS.begin(true)) while(1);

  if (LittleFS.exists("/time.txt")) {
      File tf = LittleFS.open("/time.txt", "r");
      if(tf) { 
          time_t savedTime = tf.readString().toInt(); 
          tf.close(); 
          if (savedTime > 1000000000) { 
              struct timeval tv; tv.tv_sec = savedTime + 1; tv.tv_usec = 0; 
              settimeofday(&tv, NULL); 
              timeSynced = true; 
          }
      }
      LittleFS.remove("/time.txt");
  }

  if (LittleFS.exists("/ssid.txt")) {
      File f = LittleFS.open("/ssid.txt", "r");
      if(f) { customSSID = f.readString(); customSSID.trim(); f.close(); }
  }

  if (LittleFS.exists("/prox.txt")) {
      File f = LittleFS.open("/prox.txt", "r");
      if(f) { proxThreshold = f.readString().toInt(); f.close(); }
  }
  
  if (LittleFS.exists("/squelch.txt")) {
      File f = LittleFS.open("/squelch.txt", "r");
      if(f) { squelchLimit = f.readString().toInt(); f.close(); }
  }
  if (LittleFS.exists("/hdrop.txt")) {
      File f = LittleFS.open("/hdrop.txt", "r");
      if(f) { hardDrop = (f.readString().toInt() == 1); f.close(); }
  }

  if (!LittleFS.exists("/logs.csv")) {
    File f = LittleFS.open("/logs.csv", FILE_WRITE);
    if(f) { f.println("Event,Timestamp,MAC,Type,RSSI,Extra"); f.close(); }
  }
  
  if (!LittleFS.exists("/rules.json")) createDefaultRules();
  loadRules();
  loadAliases(); 
  
  loadHistoryState();

  // Register the FTM callback globally
  WiFi.onEvent(ftmEventHandler);

  if (LittleFS.exists("/portal.txt")) {
    LittleFS.remove("/portal.txt"); 
    systemState = WIFI_PORTAL;
    initPortalHardware();
  } else {
    startBLE();
  }
}

void handleKeepAlive() {
  unsigned long now = millis();
  if (!keepAlivePulsing && (now - lastKeepAlive > 5000)) { digitalWrite(PIN_KEEPALIVE, LOW); keepAlivePulsing = true; lastKeepAlive = now; } 
  else if (keepAlivePulsing && (now - lastKeepAlive > 100)) { digitalWrite(PIN_KEEPALIVE, HIGH); keepAlivePulsing = false; lastKeepAlive = now; }
}

void triggerPowerOff() {
  gfx->fillScreen(BLACK); gfx->setTextColor(YELLOW); gfx->setCursor(10, 40); gfx->setTextSize(1); gfx->println("ENTERING SLEEP MODE");
  gfx->setTextColor(GREEN); gfx->setCursor(10, 60); gfx->println("USB Charging: FAST");
  gfx->setTextColor(GREY); gfx->setCursor(10, 80); gfx->println("Press RST to wake"); delay(3000);

  saveHistoryState(); 

  LittleFS.remove("/time.txt"); 
  digitalWrite(TFT_BL, LOW); gfx->displayOff(); WiFi.mode(WIFI_OFF); NimBLEDevice::deinit(true);
  
  // Safely shut down Zigbee if active before deep sleep
  if (radioMode == 2) esp_ieee802154_disable();
  
  pinMode(PIN_KEEPALIVE, INPUT); 
  gpio_hold_en((gpio_num_t)TFT_BL);
  esp_deep_sleep_start();
}

String formatTime(unsigned long ms) {
  unsigned long secs = ms / 1000; unsigned long mins = secs / 60;
  char buf[16]; sprintf(buf, "%02lu:%02lu:%02lu", mins / 60, mins % 60, secs % 60);
  return String(buf);
}

void drawIntelView();
void drawSetupView();
void drawAliasEdit();

void generateForensicReport() {
    File r = LittleFS.open("/report.csv", FILE_WRITE);
    if (!r) return;

    r.print("--- BLOCK 1: EVENT LOG ---\n");
    if (LittleFS.exists("/logs.csv")) { 
      File f = LittleFS.open("/logs.csv", "r"); 
      if(f) {
          uint8_t buf[256];
          while (f.available()) {
              size_t len = f.read(buf, sizeof(buf));
              r.write(buf, len);
          }
          f.close(); 
      }
    }
    
    r.print("\n--- BLOCK 2: DEEP INSPECT DATA ---\n");
    r.print("MAC,DST,BSSID,ENC,VENDOR,PROBES,GATT,RAW_HEX\n");
    for (const auto& h : historyLogs) {
        if (h.bssid != "" || h.addr1 != "" || h.probes != "" || h.gattInfo != "" || h.rawPayload != "") {
            r.printf("%s,%s,%s,%s,%s,\"%s\",\"%s\",\"%s\"\n", h.mac.c_str(), h.addr1.c_str(), h.bssid.c_str(), h.enc.c_str(), h.vendor.c_str(), h.probes.c_str(), h.gattInfo.c_str(), h.rawPayload.c_str());
        }
    }

    r.print("\n--- BLOCK 3: SESSION DETECTED DEVICES ---\n");
    r.print("MAC,ALIAS,PROTOCOL,CATEGORY,TYPE,PEAK_RSSI,HITS,FIRST_SEEN_MS,LAST_SEEN_MS\n");
    for (const auto& h : historyLogs) {
        String alias = deviceAliases.count(h.mac) ? deviceAliases[h.mac] : "";
        r.printf("%s,%s,%s,%s,%s,%d,%d,%lu,%lu\n", h.mac.c_str(), alias.c_str(), h.protocol.c_str(), h.category.c_str(), h.desc.c_str(), h.peakRssi, h.count, h.firstSeen, h.lastSeen);
    }
    
    r.print("\n--- BLOCK 4: DEEP INTEL STREAM (RAW PACKETS) ---\n");
    if (LittleFS.exists("/deep_intel.csv")) { 
      File df = LittleFS.open("/deep_intel.csv", "r"); 
      if(df) {
          uint8_t buf[256];
          while (df.available()) {
              size_t len = df.read(buf, sizeof(buf));
              r.write(buf, len);
          }
          df.close(); 
      }
    } else {
        r.print("No Deep Intel rules triggered.\n");
    }

    r.print("\n--- BLOCK 5: SAVED ALIASES ---\n");
    r.print("MAC,ALIAS\n");
    for (auto const& pair : deviceAliases) {
        r.printf("%s,%s\n", pair.first.c_str(), pair.second.c_str());
    }

    r.close();
}

void loop() {
  handleKeepAlive(); 
  unsigned long now = millis();

  while (Serial.available() > 0) {
    char c = Serial.read();
    if (c == '\n' || c == '\r') {
      if (serialBuffer.length() > 0) {
        processSerialCommand(serialBuffer);
        serialBuffer = "";
      }
    } else {
      serialBuffer += c;
    }
  }

  if (now - lastHistorySave > 300000) {
      saveHistoryState();
      lastHistorySave = now;
  }

  if (pendingReboot && (now - rebootTimer > 2000)) {
    ESP.restart(); 
  }

  static bool zigbeeJustEntered = true;
  if (internalActiveRadio == 2) {
      static unsigned long lastBeacon = 0;
      
      // Give the Coexistence Arbiter and Wi-Fi events 3 seconds to breathe!
      if (zigbeeJustEntered) {
          lastBeacon = millis(); 
          zigbeeJustEntered = false;
      }
      
      if (millis() - lastBeacon > 3000) { 
          lastBeacon = millis();
          sendZigbeeBeaconProbe();
      }
  } else {
      zigbeeJustEntered = true; // Re-arm the stagger for the next lap
  }

  if (!timeSynced && timeTargetMac != "" && radioMode == 0 && (now - lastTimeStealAttempt > 15000)) {
      lastTimeStealAttempt = now;
      pBLEScan->stop();
      
      NimBLEClient* pClient = NimBLEDevice::createClient();
      pClient->setConnectTimeout(3); 
      
      NimBLEAddress tgt(std::string(timeTargetMac.c_str()), 0);
      if (pClient->connect(tgt)) {
          NimBLERemoteService* pSvc = pClient->getService("1805");
          if (pSvc) {
              auto pChr = pSvc->getCharacteristic("2A2B");
              if (pChr && pChr->canRead()) {
                  std::string val = pChr->readValue();
                  if (val.length() >= 7) {
                      int year = val[0] | (val[1] << 8);
                      int month = val[2];
                      int day = val[3];
                      int hour = val[4];
                      int min = val[5];
                      int sec = val[6];

                      struct tm t = {0};
                      t.tm_year = year - 1900; t.tm_mon = month - 1; t.tm_mday = day;
                      t.tm_hour = hour; t.tm_min = min; t.tm_sec = sec; t.tm_isdst = -1;
                      time_t timeSinceEpoch = mktime(&t);

                      struct timeval tv; tv.tv_sec = timeSinceEpoch; tv.tv_usec = 0; settimeofday(&tv, NULL);
                      
                      timeSynced = true;
                      uiNeedsUpdate = true; 
                      
                      char tStr[24]; sprintf(tStr, "%04d-%02d-%02d %02d:%02d:%02d", year, month, day, hour, min, sec);
                      logEvent("SYNC", "SYSTEM", "BLE Time Sync", 0, tStr);
                  }
              }
          }
          pClient->disconnect();
      }
      NimBLEDevice::deleteClient(pClient);
      timeTargetMac = ""; 
      pBLEScan->start(0, false); 
  }

  // [PHASE 1] ZIGBEE BUFFER PROCESSOR
  while (zigbeeHitRead != zigbeeHitWrite) {
    Packet pkt;
    pkt.mac = String((const char*)zigbeeBuffer[zigbeeHitRead].mac);
    pkt.mac.toLowerCase();
    pkt.macPrefix = pkt.mac.substring(0, 8);
    pkt.rssi = zigbeeBuffer[zigbeeHitRead].rssi;
    pkt.name = "802.15.4 Node"; 
    pkt.dataType = "15.4";

    evaluatePacket(pkt, "ZIGBEE");
    zigbeeHitRead = (zigbeeHitRead + 1) % 10;
  }

  while (wifiHitRead != wifiHitWrite) {
    Packet pkt;
    pkt.mac = String((const char*)wifiBuffer[wifiHitRead].mac);
    pkt.mac.toLowerCase();
    pkt.macPrefix = pkt.mac.substring(0, 8);
    pkt.addr1 = String((const char*)wifiBuffer[wifiHitRead].addr1);
    pkt.addr1.toLowerCase();
    pkt.rssi = wifiBuffer[wifiHitRead].rssi;
    pkt.ssid = String((const char*)wifiBuffer[wifiHitRead].ssid);
    pkt.ssid.toLowerCase();
    pkt.bssid = String((const char*)wifiBuffer[wifiHitRead].bssid);
    pkt.bssid.toLowerCase();
    pkt.dataType = String(wifiBuffer[wifiHitRead].subtype); 
    pkt.enc = String((const char*)wifiBuffer[wifiHitRead].enc);
    pkt.vendor = String((const char*)wifiBuffer[wifiHitRead].vendor);

    evaluatePacket(pkt, "WIFI");
    wifiHitRead = (wifiHitRead + 1) % 10;
  }

  if ((radioMode == 1 || radioMode == 2) && (now - lastChannelHop > 250)) {
    if (radioMode == 1) {
        wifiChannel++; if (wifiChannel > 13) wifiChannel = 1;
        esp_wifi_set_channel(wifiChannel, WIFI_SECOND_CHAN_NONE); 
    } else if (radioMode == 2) {
        static uint8_t zigbeeChannel = 11;
        zigbeeChannel++; if (zigbeeChannel > 26) zigbeeChannel = 11;
        esp_ieee802154_set_channel(zigbeeChannel);
        esp_ieee802154_receive(); 
    }
    lastChannelHop = now;
  }

  if (systemState == RADAR_VIEW) {
    bool ghostRemoved = false;
    for (auto it = activeThreats.begin(); it != activeThreats.end(); ) {
      unsigned long elapsed = (now >= it->lastSeen) ? (now - it->lastSeen) : 0;
      if (elapsed > 10000) { it = activeThreats.erase(it); ghostRemoved = true; } else { ++it; }
    }
    
    if (radarFrozen) {
        if (uiNeedsUpdate) { 
            drawRadar(); 
            lastUiDraw = now; 
            uiNeedsUpdate = false; 
        }
    } else {
        if (uiNeedsUpdate || (now - lastUiDraw > 150)) { 
            drawRadar(); 
            lastUiDraw = now; 
            uiNeedsUpdate = false; 
        }
    }

    if (!radarFrozen) {
        if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) { systemState = MENU_VIEW; uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce)) { 
          systemState = LOG_VIEW; applyFilters(); uiNeedsUpdate = true; lastBtnPress = now; 
        }
        
        if (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce)) { 
            if (radarZoomLevel < 2) radarZoomLevel++; 
            uiNeedsUpdate = true; lastBtnPress = now; 
        }
        if (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce)) { 
            if (radarZoomLevel > 0) radarZoomLevel--; 
            uiNeedsUpdate = true; lastBtnPress = now; 
        }
        
        static unsigned long btnAPressTime = 0;
        static bool btnAHandled = false;
        
        if (digitalRead(BTN_A) == LOW) {
            if (btnAPressTime == 0) {
                btnAPressTime = now;
                btnAHandled = false;
            } else if (!btnAHandled && (now - btnAPressTime > 600)) {
                // [PHASE 1] 3-State Radio Toggle
                if (radioMode == 0) { startWIFI(); radioMode = 1; }
                else if (radioMode == 1) { startZIGBEE(); radioMode = 2; }
                else { startBLE(); radioMode = 0; }
                uiNeedsUpdate = true;
                btnAHandled = true;
            }
        } else {
            if (btnAPressTime > 0 && !btnAHandled && (now - btnAPressTime > 50)) {
                int closestRssi = -100;
                String closestMac = "";
                for (const auto& t : activeThreats) {
                    unsigned long elapsed = (now >= t.lastSeen) ? (now - t.lastSeen) : 0;
                    if (elapsed <= 10000 && t.rssi > closestRssi) {
                        closestRssi = t.rssi; closestMac = t.mac;
                    }
                }
                if (closestRssi >= proxThreshold && closestMac != "") {
                    filterHideOld = false; filterHideLowHits = false; filterCategoryIndex = -1; applyFilters(); 
                    for (size_t i = 0; i < filteredLogIndices.size(); i++) {
                        if (historyLogs[filteredLogIndices[i]].mac == closestMac) {
                            currentFilteredIndex = i; break;
                        }
                    }
                    intelShowRule = false;
                    systemState = INTEL_VIEW; uiNeedsUpdate = true;
                }
            }
            btnAPressTime = 0;
        }

        if (digitalRead(BTN_B) == LOW && (now - lastBtnPress > debounce)) {
            frozenThreats.clear();
            for (const auto& t : activeThreats) {
                if (now - t.lastSeen <= 10000) frozenThreats.push_back(t);
            }
            if (!frozenThreats.empty()) {
                radarFrozen = true;
                frozenSelectedIndex = 0;
                uiNeedsUpdate = true;
            }
            lastBtnPress = now;
        }
    } else {
        if (digitalRead(BTN_B) == LOW && (now - lastBtnPress > debounce)) { 
            radarFrozen = false; uiNeedsUpdate = true; lastBtnPress = now; 
        }
        if (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce)) {
            frozenSelectedIndex = (frozenSelectedIndex - 1 + frozenThreats.size()) % frozenThreats.size();
            uiNeedsUpdate = true; lastBtnPress = now;
        }
        if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) {
            frozenSelectedIndex = (frozenSelectedIndex + 1) % frozenThreats.size();
            uiNeedsUpdate = true; lastBtnPress = now;
        }
        if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
            if (!frozenThreats.empty()) {
                String tgtMac = frozenThreats[frozenSelectedIndex].mac;
                filterHideOld = false; filterHideLowHits = false; filterCategoryIndex = -1; applyFilters(); 
                for (size_t i = 0; i < filteredLogIndices.size(); i++) {
                    if (historyLogs[filteredLogIndices[i]].mac == tgtMac) {
                        currentFilteredIndex = i;
                        intelShowRule = false;
                        systemState = INTEL_VIEW;
                        radarFrozen = false;
                        uiNeedsUpdate = true;
                        break;
                    }
                }
            }
            lastBtnPress = now;
        }
    }
  } 
  
  else if (systemState == MENU_VIEW) {
    if (uiNeedsUpdate) { drawMenu(); uiNeedsUpdate = false; }
    if (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce)) { systemState = RADAR_VIEW; uiNeedsUpdate = true; lastBtnPress = now; }
    if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) { 
        if (selectedMenu == NUM_CATEGORIES + 5) {
            systemState = ABOUT_VIEW;
            uiNeedsUpdate = true;
            lastBtnPress = now;
        } else {
            systemState = SETUP_VIEW; 
            setupSelection = 0; setupEditMode = false; setupSsidCursor = 0;
            timeEdited = false;
            time_t nowTime; time(&nowTime); struct tm* tinfo = localtime(&nowTime);
            setupYear = tinfo->tm_year + 1900; setupMonth = tinfo->tm_mon + 1; setupDay = tinfo->tm_mday;
            setupHour = tinfo->tm_hour; setupMin = tinfo->tm_min;
            memset(setupSsid, ' ', 16); setupSsid[16] = '\0';
            for(int i=0; i<customSSID.length() && i<16; i++) setupSsid[i] = customSSID[i];
            uiNeedsUpdate = true; lastBtnPress = now; 
        }
    }
    
    if (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce)) { 
        selectedMenu = (selectedMenu + 1) % TOTAL_MENU_ITEMS; 
        if (selectedMenu >= menuScrollOffset + VISIBLE_MENU_ITEMS) {
            menuScrollOffset = selectedMenu - VISIBLE_MENU_ITEMS + 1;
        } else if (selectedMenu == 0) {
            menuScrollOffset = 0;
        }
        uiNeedsUpdate = true; lastBtnPress = now; 
    }
    if (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce)) { 
        selectedMenu = (selectedMenu == 0) ? TOTAL_MENU_ITEMS - 1 : selectedMenu - 1; 
        if (selectedMenu < menuScrollOffset) {
            menuScrollOffset = selectedMenu;
        } else if (selectedMenu == TOTAL_MENU_ITEMS - 1) {
            menuScrollOffset = max(0, TOTAL_MENU_ITEMS - VISIBLE_MENU_ITEMS);
        }
        uiNeedsUpdate = true; lastBtnPress = now; 
    }
    
    if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) { 
      lastBtnPress = now;
      if (selectedMenu == 0) {
        for(int i=0; i<NUM_CATEGORIES; i++) scanConfig[i] = true;
        scanConfig[NUM_CATEGORIES - 1] = false; 
        uiNeedsUpdate = true;
      }
      else if (selectedMenu == 1) {
        for(int i=0; i<NUM_CATEGORIES; i++) scanConfig[i] = false;
        uiNeedsUpdate = true;
      }
      else if (selectedMenu >= 2 && selectedMenu < NUM_CATEGORIES + 2) { 
        int catIdx = selectedMenu - 2;
        scanConfig[catIdx] = !scanConfig[catIdx]; 
        uiNeedsUpdate = true; 
      }
      else if (selectedMenu == NUM_CATEGORIES + 2) { startPortal(); }
      else if (selectedMenu == NUM_CATEGORIES + 3) { systemState = RESET_CONFIRM_VIEW; uiNeedsUpdate = true; }
      else if (selectedMenu == NUM_CATEGORIES + 4) { triggerPowerOff(); }
      else if (selectedMenu == NUM_CATEGORIES + 5) { systemState = ABOUT_VIEW; uiNeedsUpdate = true; }
    }
  }

  else if (systemState == SETUP_VIEW) {
      if (uiNeedsUpdate) { drawSetupView(); uiNeedsUpdate = false; }
      
      if (!setupEditMode) {
          if (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce)) { systemState = MENU_VIEW; uiNeedsUpdate = true; lastBtnPress = now; }
          if (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce)) { setupSelection = (setupSelection + 1) % 11; uiNeedsUpdate = true; lastBtnPress = now; }
          if (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce)) { setupSelection = (setupSelection == 0) ? 10 : setupSelection - 1; uiNeedsUpdate = true; lastBtnPress = now; }
          if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
              if (setupSelection <= 8) { setupEditMode = true; }
              else if (setupSelection == 9) { 
                  if (timeEdited) {
                      struct tm t = {0};
                      t.tm_year = setupYear - 1900; t.tm_mon = setupMonth - 1; t.tm_mday = setupDay;
                      t.tm_hour = setupHour; t.tm_min = setupMin; t.tm_sec = 0; t.tm_isdst = -1;
                      time_t timeSinceEpoch = mktime(&t);
                      struct timeval tv; tv.tv_sec = timeSinceEpoch; tv.tv_usec = 0; settimeofday(&tv, NULL);
                      
                      timeSynced = true;
                      char tStr[24]; sprintf(tStr, "%04d-%02d-%02d %02d:%02d:%02d", setupYear, setupMonth, setupDay, setupHour, setupMin, 0);
                      logEvent("SYNC", "SYSTEM", "Manual Time Sync", 0, tStr);
                  }
                  
                  String s = String(setupSsid); s.trim();
                  if(s.length() > 0) { 
                      customSSID = s; 
                      File f = LittleFS.open("/ssid.txt", FILE_WRITE);
                      if(f) { f.print(customSSID); f.close(); }
                  }
                  
                  File f2 = LittleFS.open("/prox.txt", FILE_WRITE);
                  if(f2) { f2.print(proxThreshold); f2.close(); }
                  
                  File f3 = LittleFS.open("/squelch.txt", FILE_WRITE);
                  if(f3) { f3.print(squelchLimit); f3.close(); }
                  
                  File f4 = LittleFS.open("/hdrop.txt", FILE_WRITE);
                  if(f4) { f4.print(hardDrop ? 1 : 0); f4.close(); }
                  
                  timeSynced = true;
                  char tStr[24]; sprintf(tStr, "%04d-%02d-%02d %02d:%02d:%02d", setupYear, setupMonth, setupDay, setupHour, setupMin, 0);
                  logEvent("SYNC", "SYSTEM", "Manual Time Sync", 0, tStr);
                  
                  systemState = MENU_VIEW;
              }
              else if (setupSelection == 10) { systemState = MENU_VIEW; } 
              uiNeedsUpdate = true; lastBtnPress = now;
          }
      } else {
          if ((digitalRead(BTN_A) == LOW || digitalRead(BTN_B) == LOW) && (now - lastBtnPress > debounce)) { setupEditMode = false; uiNeedsUpdate = true; lastBtnPress = now; }
          
          bool up = (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce));
          bool dn = (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce));
          bool lf = (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce));
          bool rt = (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce));
          
          if (up || dn || lf || rt) {
              if (setupSelection >= 0 && setupSelection <= 4) {
                  if (up || dn) timeEdited = true;
              }
              if (setupSelection == 0) { if (up) setupYear++; if (dn) setupYear--; }
              else if (setupSelection == 1) { if (up) setupMonth++; if (dn) setupMonth--; if(setupMonth>12) setupMonth=1; if(setupMonth<1) setupMonth=12; }
              else if (setupSelection == 2) { if (up) setupDay++; if (dn) setupDay--; if(setupDay>31) setupDay=1; if(setupDay<1) setupDay=31; }
              else if (setupSelection == 3) { if (up) setupHour++; if (dn) setupHour--; if(setupHour>23) setupHour=0; if(setupHour<0) setupHour=23; }
              else if (setupSelection == 4) { if (up) setupMin++; if (dn) setupMin--; if(setupMin>59) setupMin=0; if(setupMin<0) setupMin=59; }
              else if (setupSelection == 5) { if (up) proxThreshold++; if (dn) proxThreshold--; if(proxThreshold > -10) proxThreshold = -10; if(proxThreshold < -100) proxThreshold = -100; }
              else if (setupSelection == 6) { if (up) squelchLimit+=10; if (dn) squelchLimit-=10; if(squelchLimit > -30) squelchLimit = -30; if(squelchLimit < -100) squelchLimit = -100; }
              else if (setupSelection == 7) { if (up || dn) hardDrop = !hardDrop; }
              else if (setupSelection == 8) { 
                  if (lf && setupSsidCursor > 0) setupSsidCursor--;
                  if (rt && setupSsidCursor < 15) setupSsidCursor++;
                  if (up || dn) {
                      char c = setupSsid[setupSsidCursor];
                      const char* pos = strchr(ssidCharset, c);
                      int idx = pos ? (pos - ssidCharset) : 0;
                      int numChars = strlen(ssidCharset);
                      if (up) idx = (idx + 1) % numChars;
                      if (dn) idx = (idx - 1 + numChars) % numChars;
                      setupSsid[setupSsidCursor] = ssidCharset[idx];
                  }
              }
              uiNeedsUpdate = true; lastBtnPress = now;
          }
      }
  }

  else if (systemState == ALIAS_EDIT_VIEW) {
      if (uiNeedsUpdate) { drawAliasEdit(); uiNeedsUpdate = false; }
      
      if ((digitalRead(BTN_A) == LOW) && (now - lastBtnPress > debounce)) { 
          saveAlias(targetAliasMac, String(setupAlias));
          systemState = LOG_VIEW; 
          uiNeedsUpdate = true; 
          lastBtnPress = now; 
      }
      else if ((digitalRead(BTN_B) == LOW) && (now - lastBtnPress > debounce)) { 
          systemState = LOG_VIEW; 
          uiNeedsUpdate = true; 
          lastBtnPress = now; 
      }
      else {
          bool up = (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce));
          bool dn = (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce));
          bool lf = (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce));
          bool rt = (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce));
          
          if (lf) { 
              if (setupAliasCursor > 0) {
                  setupAliasCursor--; 
              } else {
                  std::vector<String> uniqueAliases;
                  for (auto const& pair : deviceAliases) {
                      String a = pair.second;
                      a.trim();
                      if (a.length() > 0 && std::find(uniqueAliases.begin(), uniqueAliases.end(), a) == uniqueAliases.end()) {
                          uniqueAliases.push_back(a);
                      }
                  }
                  if (!uniqueAliases.empty()) {
                      std::sort(uniqueAliases.begin(), uniqueAliases.end());
                      aliasCycleIndex = (aliasCycleIndex + 1) % uniqueAliases.size();
                      String selected = uniqueAliases[aliasCycleIndex];
                      memset(setupAlias, ' ', 10);
                      for (int i = 0; i < selected.length() && i < 10; i++) {
                          setupAlias[i] = selected[i];
                      }
                      setupAlias[10] = '\0';
                  }
              }
              uiNeedsUpdate = true; lastBtnPress = now; 
          }
          if (rt && setupAliasCursor < 9) { setupAliasCursor++; uiNeedsUpdate = true; lastBtnPress = now; }
          if (up || dn) {
              char c = setupAlias[setupAliasCursor];
              const char* pos = strchr(ssidCharset, c);
              int idx = pos ? (pos - ssidCharset) : 0;
              int numChars = strlen(ssidCharset);
              if (up) idx = (idx + 1) % numChars;
              if (dn) idx = (idx - 1 + numChars) % numChars;
              setupAlias[setupAliasCursor] = ssidCharset[idx];
              uiNeedsUpdate = true; lastBtnPress = now;
          }
      }
  }
  
  else if (systemState == RESET_CONFIRM_VIEW) {
    if (uiNeedsUpdate) { drawResetConfirm(); uiNeedsUpdate = false; }
    
    if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
      gfx->fillScreen(BLACK); gfx->setTextColor(RED); gfx->setTextSize(1);
      gfx->setCursor(10, 60); gfx->println("NUKING FILES...");
      LittleFS.remove("/rules.json");
      LittleFS.remove("/logs.csv");
      LittleFS.remove("/history.jsonl");
      LittleFS.remove("/deep_intel.csv");
      LittleFS.remove("/ssid.txt");
      LittleFS.remove("/prox.txt");
      LittleFS.remove("/squelch.txt");
      LittleFS.remove("/hdrop.txt");
      LittleFS.remove("/report.csv");
      LittleFS.remove("/aliases.json");
      LittleFS.remove("/time.txt");
      deviceAliases.clear();
      createDefaultRules();
      activeThreats.clear(); historyLogs.clear(); filteredLogIndices.clear(); currentFilteredIndex = 0;
      delay(1000); 
      ESP.restart(); 
    }
    if ((digitalRead(BTN_B) == LOW || digitalRead(BTN_LEFT) == LOW) && (now - lastBtnPress > debounce)) {
      systemState = MENU_VIEW; uiNeedsUpdate = true; lastBtnPress = now;
    }
  }

  else if (systemState == ABOUT_VIEW) {
    if (uiNeedsUpdate) { drawAboutView(); uiNeedsUpdate = false; }
    else {
      static unsigned long lastScrollTime = 0;
      if (now - lastScrollTime > 150) { 
        drawAboutView(); 
        lastScrollTime = now; 
      }
    }
    
    if ((digitalRead(BTN_B) == LOW || digitalRead(BTN_LEFT) == LOW) && (now - lastBtnPress > debounce)) {
      systemState = MENU_VIEW; 
      uiNeedsUpdate = true; 
      lastBtnPress = now;
    }
  }

  else if (systemState == WIFI_PORTAL) {
    dnsServer.processNextRequest(); 
    server.handleClient();
    
    if ((digitalRead(BTN_LEFT) == LOW || digitalRead(BTN_B) == LOW) && (now - lastBtnPress > debounce)) { 
      lastBtnPress = now;
      stopPortal(); 
    }
  }

  else if (systemState == LOG_VIEW) {
    if (uiNeedsUpdate) { drawLogPanel(); lastUiDraw = now; uiNeedsUpdate = false; }
    
    if (!logMenuOpen) {
        static unsigned long lastLogBlink = 0;
        if (now - lastLogBlink >= 1000) { uiNeedsUpdate = true; lastLogBlink = now; }

        if (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce)) { logMenuOpen = true; logMenuSelection = 0; uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) { systemState = RADAR_VIEW; uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce)) { if (filteredLogIndices.size() > 0) currentFilteredIndex = (currentFilteredIndex == 0) ? (int)filteredLogIndices.size() - 1 : currentFilteredIndex - 1; uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce)) { if (filteredLogIndices.size() > 0) currentFilteredIndex = (currentFilteredIndex + 1) % (int)filteredLogIndices.size(); uiNeedsUpdate = true; lastBtnPress = now; }
        
        if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
            if (!filteredLogIndices.empty()) {
                intelShowRule = false;
                systemState = INTEL_VIEW; 
                uiNeedsUpdate = true;
            }
            lastBtnPress = now;
        }

        if (digitalRead(BTN_B) == LOW && (now - lastBtnPress > debounce)) {
          if (!filteredLogIndices.empty()) {
            ThreatHistory t = historyLogs[filteredLogIndices[currentFilteredIndex]];
            strncpy(targetMacStr, t.mac.c_str(), 17); targetMacStr[17] = '\0';
            targetDesc = t.desc; targetRssi = -100; lastTargetUpdate = now;
            systemState = FOXHUNT_VIEW; uiNeedsUpdate = true;
            
            // --- FTM KICKOFF ---
            if (t.protocol == "WIFI" && internalActiveRadio == 1) {
                ftmState = FTM_NEGOTIATING;
                triggerFtmRequest();
            } else {
                ftmState = FTM_IDLE; 
            }
          }
          lastBtnPress = now;
        }
    } else {
        if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) { logMenuOpen = false; applyFilters(); uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_UP) == LOW && (now - lastBtnPress > debounce)) { logMenuSelection = (logMenuSelection == 0) ? 6 : logMenuSelection - 1; uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_DOWN) == LOW && (now - lastBtnPress > debounce)) { logMenuSelection = (logMenuSelection + 1) % 7; uiNeedsUpdate = true; lastBtnPress = now; }
        if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
            if (logMenuSelection == 0) { logMenuOpen = false; applyFilters(); }
            else if (logMenuSelection == 1) { 
                if (!filteredLogIndices.empty()) {
                    targetAliasMac = historyLogs[filteredLogIndices[currentFilteredIndex]].mac;
                    memset(setupAlias, ' ', 10);
                    setupAlias[10] = '\0';
                    if (deviceAliases.count(targetAliasMac)) {
                        String existing = deviceAliases[targetAliasMac];
                        for (int i=0; i<existing.length() && i<10; i++) setupAlias[i] = existing[i];
                    }
                    setupAliasCursor = 0;
                    aliasCycleIndex = -1;
                    systemState = ALIAS_EDIT_VIEW;
                    logMenuOpen = false;
                }
            }
            else if (logMenuSelection == 2) { filterHideOld = !filterHideOld; applyFilters(); }
            else if (logMenuSelection == 3) { filterHideLowHits = !filterHideLowHits; applyFilters(); }
            else if (logMenuSelection == 4) { 
                filterCategoryIndex++; 
                if (filterCategoryIndex >= NUM_CATEGORIES) filterCategoryIndex = -1; 
                applyFilters();
            }
            else if (logMenuSelection == 5) { sortField = (sortField + 1) % 3; applyFilters(); }
            else if (logMenuSelection == 6) { sortDir = (sortDir == 0) ? 1 : 0; applyFilters(); }
            uiNeedsUpdate = true; lastBtnPress = now;
        }
    }
  }

  else if (systemState == INTEL_VIEW) {
      if (uiNeedsUpdate && (now - lastUiDraw > 150)) { drawIntelView(); lastUiDraw = now; uiNeedsUpdate = false; }
      
      if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) {
          if (!intelShowRule) {
              intelShowRule = true;
              uiNeedsUpdate = true;
          }
          lastBtnPress = now;
      }

      if (digitalRead(BTN_LEFT) == LOW && (now - lastBtnPress > debounce)) {
          if (intelShowRule) {
              intelShowRule = false;
              uiNeedsUpdate = true;
          }
          lastBtnPress = now;
      }

      if (intelShowRule && digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
          ThreatHistory& t = historyLogs[filteredLogIndices[currentFilteredIndex]];
          bool isCatchAll = true;
          for (auto& r : threatRules) {
              if (r.label == t.desc && r.category == t.category) { isCatchAll = false; break; }
          }
          
          if (isCatchAll) {
              File f = LittleFS.open("/rules.json", "r");
              if (f) {
                  #if ARDUINOJSON_VERSION_MAJOR >= 7
                      JsonDocument doc;
                  #else
                      DynamicJsonDocument doc(16384);
                  #endif
                  deserializeJson(doc, f);
                  f.close();
                  
                  JsonObject newRule = doc["rules"].add<JsonObject>();
                  newRule["cat"] = "Custom";
                  newRule["proto"] = t.protocol;
                  newRule["label"] = "Saved: " + (t.desc.length() > 10 ? t.desc.substring(0, 10) : t.desc);
                  newRule["mac"] = t.mac;
                  
                  File fw = LittleFS.open("/rules.json", FILE_WRITE);
                  if (fw) {
                      serializeJson(doc, fw);
                      fw.close();
                      loadRules();
                      
                      gfx->fillRect(0, 116, 160, 12, GREEN);
                      gfx->setTextColor(BLACK); gfx->setCursor(5, 118); gfx->print("RULE SAVED!");
                      delay(500);
                      uiNeedsUpdate = true;
                  }
              }
          }
          lastBtnPress = now;
      }

      if (!intelShowRule && digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) {
          ThreatHistory& t = historyLogs[filteredLogIndices[currentFilteredIndex]];
          
          if (t.protocol == "ZIGBEE") {
              if (internalActiveRadio == 2) {
                  t.gattInfo = "TOUCHLINK PROBE FIRED!";
                  drawIntelView(); 
                  sendTouchlinkProbe();
                  delay(500); // Visual pause so you can see it fired
              } else {
                  t.gattInfo = "ERR: Switch to Zigbee First";
              }
              uiNeedsUpdate = true;
          } 
          else if (t.protocol == "BLE") {
              if (radioMode == 1 || radioMode == 2) {
                  t.gattInfo = "ERR: Switch to BLE Scan First";
              } else {
                  t.gattInfo = "INTERROGATING...";
                  drawIntelView(); 
                  
                  pBLEScan->stop();
                  String gattRes = "";
                  NimBLEClient* pClient = NimBLEDevice::createClient();
                  pClient->setConnectTimeout(3); 
                  
                  NimBLEAddress tgt(std::string(t.mac.c_str()), 0);
                  if (pClient->connect(tgt)) {
                      NimBLERemoteService* pSvc = pClient->getService("180A");
                      if (pSvc) {
                          auto pManuf = pSvc->getCharacteristic("2A29");
                          if (pManuf && pManuf->canRead()) {
                              gattRes += String(pManuf->readValue().c_str());
                          }
                          auto pModel = pSvc->getCharacteristic("2A24");
                          if (pModel && pModel->canRead()) {
                              if (gattRes != "") gattRes += " | ";
                              gattRes += String(pModel->readValue().c_str());
                          }
                      }
                      if (gattRes == "") gattRes = "Connected: No Device Info (0x180A)";
                      pClient->disconnect();
                  } else {
                      gattRes = "Connection Refused / Stealth";
                  }
                  NimBLEDevice::deleteClient(pClient);
                  
                  t.gattInfo = gattRes;
                  pBLEScan->start(0, false); 
              }
              uiNeedsUpdate = true;
          }
          lastBtnPress = now;
      }

      if (digitalRead(BTN_B) == LOW && (now - lastBtnPress > debounce)) { 
          intelShowRule = false;
          systemState = LOG_VIEW; 
          uiNeedsUpdate = true; 
          lastBtnPress = now; 
      }
  }

  else if (systemState == FOXHUNT_VIEW) {
    // --- FTM ENGINE LOGIC ---
    if (ftmNeedsFallback) {
        esp_wifi_set_promiscuous(true); // Resume passive sniffing
        ftmNeedsFallback = false;
    }

    if (ftmState == FTM_NEGOTIATING) {
        if (now - lastFtmRequestTime > 2500) { // Timeout
            ftmState = FTM_FAIL;
            ftmMessageTimer = now;
            ftmNeedsFallback = true;
            uiNeedsUpdate = true;
        }
        if (digitalRead(BTN_A) == LOW && (now - lastBtnPress > debounce)) { // Manual Cancel
            ftmState = FTM_CANCELED;
            ftmMessageTimer = now;
            ftmNeedsFallback = true;
            uiNeedsUpdate = true;
            lastBtnPress = now;
        }
    } 
    else if (ftmState == FTM_SUCCESS) {
        if (now - lastFtmRequestTime > 1500) { // Re-ping for live tracking
            triggerFtmRequest();
        }
    }

    // Standard RSSI tracking (only drop signal if not actively in an FTM state)
    if (now - lastTargetUpdate > 1500 && targetRssi > -100 && ftmState != FTM_SUCCESS && ftmState != FTM_NEGOTIATING) { 
        targetRssi -= 1; if (targetRssi < -100) targetRssi = -100; uiNeedsUpdate = true; lastTargetUpdate = now - 1400; 
    }

    if (uiNeedsUpdate && (now - lastUiDraw > 150)) { drawFoxhunt(); lastUiDraw = now; uiNeedsUpdate = false; }
    
    if (digitalRead(BTN_RIGHT) == LOW && (now - lastBtnPress > debounce)) { 
        systemState = LOG_VIEW; 
        if (ftmState != FTM_IDLE) { esp_wifi_set_promiscuous(true); } 
        ftmState = FTM_IDLE;
        uiNeedsUpdate = true; lastBtnPress = now; targetMacStr[0] = '\0'; 
    }

    // --- LEVEL 3: FOXHUNT VIEW TOUCHLINK TRIGGER ---
    if (digitalRead(BTN_B) == LOW && (now - lastBtnPress > debounce)) {
        if (internalActiveRadio == 2) { 
            sendTouchlinkProbe();
            gfx->fillRect(0, 116, 160, 12, RED);
            gfx->setTextColor(WHITE); gfx->setCursor(5, 118); gfx->print("TOUCHLINK PROBE FIRED!");
            delay(500); 
            uiNeedsUpdate = true;
        }
        lastBtnPress = now;
    }
  }
}

// --- UI DRAWING ---
void drawRadar() {
  unsigned long now = millis();
  
  static float old_sweepAngle = -1;
  static std::vector<Threat> oldThreats;
  static int old_zoomLevel = -1;
  static bool wasFrozen = false;
  static int old_frozenIndex = -1;
  static size_t lastThreatCount = 999;
  static int last_upSec = -1;

  bool forceFullRedraw = uiNeedsUpdate || (old_zoomLevel != radarZoomLevel) || (wasFrozen != radarFrozen);
  bool frozenChanged = (old_frozenIndex != frozenSelectedIndex);
  old_zoomLevel = radarZoomLevel;
  wasFrozen = radarFrozen;
  old_frozenIndex = frozenSelectedIndex;

  int cx = 80; int cy = 72; int max_r = 54;
  int min_rssi = -100, mid_rssi = -75, max_rssi = -50;
  if (radarZoomLevel == 1) { min_rssi = -75; mid_rssi = -50; max_rssi = -25; }
  else if (radarZoomLevel == 2) { min_rssi = -50; mid_rssi = -30; max_rssi = -10; }

  int upSec = (now / 1000) % 60;
  bool timeChanged = (upSec != last_upSec);
  last_upSec = upSec;

  if (forceFullRedraw) {
      gfx->fillRect(0, 12, 160, 116, BLACK); 

      if (radarFrozen) {
          gfx->fillRect(0, 0, 160, 12, YELLOW);
          gfx->setCursor(2, 2); gfx->setTextColor(BLACK); gfx->setTextSize(1);
          gfx->print("FROZEN");
          gfx->setCursor(100, 2);
          gfx->print("[B] to ext");
      } else {
          // [PHASE 1] Dynamic UI Top Bar
          uint16_t barColor = (radioMode == 0) ? PURPLE : ((radioMode == 1) ? ORANGE : TEAL);
          gfx->fillRect(0, 0, 160, 12, barColor);
          gfx->setCursor(8, 2); gfx->setTextColor(radioMode == 0 ? WHITE : BLACK); gfx->setTextSize(1);
          if (radioMode == 0) gfx->print("BLE SCAN > Hold [A] WIFI"); 
          else if (radioMode == 1) gfx->print("WIFI SCAN > Hold [A] ZIG");
          else gfx->print("ZIGBEE SCAN > Hold [A] BLE");
      }

      gfx->setCursor(112, 14); gfx->setTextColor(GREY); gfx->print("+/-[^v]");
      gfx->setCursor(124, 24); gfx->print("II [B]");
      
      if (!radarFrozen) {
          gfx->setTextColor(CYAN); gfx->setCursor(2, 108); gfx->print("UPTIME");
          gfx->setTextColor(CYAN); gfx->setCursor(134, 108); gfx->print("TIME"); 
      }
  } 
  
  else {
      if (old_sweepAngle >= 0 && !radarFrozen) {
          int old_sx = cx + max_r * cos(old_sweepAngle);
          int old_sy = cy + max_r * sin(old_sweepAngle);
          gfx->drawLine(cx, cy, old_sx, old_sy, BLACK);
      }
      
      for (const auto& t : oldThreats) {
          int clamped_rssi = constrain(t.rssi, min_rssi, max_rssi);
          int r = map(clamped_rssi, min_rssi, max_rssi, max_r, 5);
          float blipAngle = (t.lastSeen % 4000) * 2.0 * PI / 4000.0;
          int bx = cx + r * cos(blipAngle);
          int by = cy + r * sin(blipAngle);
          
          if (by < 14) by = 14; if (by > 120) by = 120;
          if (bx < 2) bx = 2; if (bx > 158) bx = 158;

          gfx->fillCircle(bx, by, 6, BLACK); 
          gfx->fillRect(bx + 3, by - 3, 20, 8, BLACK); 
      }

      if (radarFrozen && frozenChanged) {
          gfx->fillRect(0, 106, 160, 22, BLACK);
      } else if (!radarFrozen) {
          if (timeChanged) {
              gfx->fillRect(2, 118, 50, 10, BLACK);   
              gfx->fillRect(110, 118, 50, 10, BLACK); 
          }
          gfx->fillRect(44, 108, 70, 10, BLACK); 
      }
  }

  gfx->drawCircle(cx, cy, 18, DARKGREEN);
  gfx->drawCircle(cx, cy, 36, DARKGREEN);
  gfx->drawCircle(cx, cy, max_r, DARKGREEN);
  gfx->drawLine(cx - max_r, cy, cx + max_r, cy, DARKGREEN);
  gfx->drawLine(cx, cy - max_r, cx, cy + max_r, DARKGREEN);

  gfx->setTextColor(GREY, BLACK); 
  gfx->setCursor(cx + 2, cy - 18 - 4); gfx->print(max_rssi);
  gfx->setCursor(cx + 2, cy - 36 - 4); gfx->print(mid_rssi);
  gfx->setCursor(cx + 2, cy - 54 + 2); gfx->print(min_rssi);

  if (!radarFrozen) {
      float sweepAngle = (now % 4000) * 2.0 * PI / 4000.0;
      int sx = cx + max_r * cos(sweepAngle);
      int sy = cy + max_r * sin(sweepAngle);
      gfx->drawLine(cx, cy, sx, sy, GREEN);
      old_sweepAngle = sweepAngle;
  }

  int closestRssi = -100;
  int closestBx = -1;
  int closestBy = -1;

  const std::vector<Threat>& renderThreats = radarFrozen ? frozenThreats : activeThreats;
  oldThreats.clear();

  if (forceFullRedraw || lastThreatCount != renderThreats.size()) {
      gfx->fillRect(2, 14, 40, 10, BLACK);
      gfx->setCursor(2, 14); gfx->setTextColor(GREY); 
      gfx->print(renderThreats.size()); gfx->print(" TGT");
      lastThreatCount = renderThreats.size();
  }

  for (size_t i = 0; i < renderThreats.size(); i++) {
    const auto& t = renderThreats[i];
    unsigned long elapsed = (now >= t.lastSeen) ? (now - t.lastSeen) : 0;
    if (!radarFrozen && elapsed > 10000) continue; 
    
    if (!radarFrozen && t.rssi < squelchLimit) continue;
    if (!radarFrozen && t.rssi < min_rssi) continue;

    oldThreats.push_back(t);

    int clamped_rssi = constrain(t.rssi, min_rssi, max_rssi);
    int r = map(clamped_rssi, min_rssi, max_rssi, max_r, 5);

    float blipAngle = (t.lastSeen % 4000) * 2.0 * PI / 4000.0;
    int bx = cx + r * cos(blipAngle);
    int by = cy + r * sin(blipAngle);

    if (by < 14) by = 14; if (by > 120) by = 120;
    if (bx < 2) bx = 2; if (bx > 158) bx = 158;

    uint16_t color = WHITE;
    char glyph = '?';

    for (int j = 0; j < NUM_CATEGORIES; j++) {
        if (t.category == configNames[j]) {
            color = configColors[j];
            glyph = configNames[j][0];
            if (t.category == "Rogue AP") glyph = 'X';
            else if (t.category == "WPA Exploit") glyph = 'W';
            else if (t.category == "Wardrive") glyph = 'V';
            break;
        }
    }

    gfx->fillCircle(bx, by, 1, color); 

    if (!radarFrozen && elapsed < 300) gfx->drawCircle(bx, by, 3, color); 
    if (radarFrozen && i == frozenSelectedIndex) {
        gfx->drawCircle(bx, by, 5, YELLOW);
        gfx->drawCircle(bx, by, 6, YELLOW);
    }

    gfx->setTextColor(color); 
    gfx->setCursor(bx + 3, by - 3); 
    
    String dispText = String(glyph);
    if (deviceAliases.count(t.mac)) {
        String fullAlias = deviceAliases[t.mac];
        dispText = fullAlias.substring(0, 3);
    }
    gfx->print(dispText);
    
    if (t.rssi > closestRssi) {
        closestRssi = t.rssi; closestBx = bx; closestBy = by;
    }
  }

  if (radarFrozen && frozenThreats.size() > 0) {
      if (forceFullRedraw || frozenChanged) {
          String tgtMac = frozenThreats[frozenSelectedIndex].mac;
          String dispName = tgtMac;
          if (deviceAliases.count(tgtMac)) dispName = deviceAliases[tgtMac];
          
          gfx->setTextColor(YELLOW); gfx->setCursor(2, 108); gfx->print(dispName);
          gfx->setTextColor(CYAN); gfx->setCursor(2, 118); gfx->print(frozenThreats[frozenSelectedIndex].category);
          gfx->setTextColor(GREY); gfx->setCursor(110, 118); gfx->print("[A] SEL");
      }
  } 
  else {
      if (timeChanged || forceFullRedraw) {
          int upMin = ((now / (1000*60)) % 60); int upHr  = ((now / (1000*60*60)) % 24);
          char upStr[16]; sprintf(upStr, "%02d:%02d:%02d", upHr, upMin, upSec);
          
          gfx->setTextColor(GREY); gfx->setCursor(2, 118); gfx->print(upStr);

          if (timeSynced) {
              time_t nowTime; time(&nowTime); struct tm* tinfo = localtime(&nowTime);
              char tStr[16]; sprintf(tStr, "%02d:%02d:%02d", tinfo->tm_hour, tinfo->tm_min, tinfo->tm_sec);
              gfx->setCursor(110, 118); gfx->setTextColor(GREEN); gfx->print(tStr);
          } else {
              gfx->setCursor(122, 118); gfx->setTextColor(ORANGE); gfx->print("UNSYNC");
          }
      }

      if (!radarFrozen && closestRssi >= proxThreshold) {
          uint16_t alertColor = ((now / 250) % 2 == 0) ? RED : GREEN; 
          gfx->drawCircle(closestBx, closestBy, 4, alertColor);
          gfx->drawCircle(closestBx, closestBy, 5, alertColor);
          
          gfx->setTextColor(YELLOW); gfx->setCursor(44, 108); gfx->print("[A] INSPECT");
      }
  }
}

void drawMenu() {
  gfx->fillScreen(BLACK); 
  gfx->fillRect(0, 0, 160, 16, CYAN);
  gfx->setCursor(5, 4); gfx->setTextColor(BLACK); gfx->setTextSize(1); 
  gfx->print("< SETTINGS ");
  if (menuScrollOffset > 0) gfx->print("^ ");
  if (menuScrollOffset + VISIBLE_MENU_ITEMS < TOTAL_MENU_ITEMS) gfx->print("v ");
  gfx->print("[>] Setup");
  
  int y = 18; 
  int endIndex = min(menuScrollOffset + VISIBLE_MENU_ITEMS, TOTAL_MENU_ITEMS);

  for (int i = menuScrollOffset; i < endIndex; i++) { 
    gfx->setTextColor(i == selectedMenu ? YELLOW : WHITE); 
    gfx->setCursor(5, y); 
    gfx->print(i == selectedMenu ? "> " : "  "); 
    
    int16_t cx = gfx->getCursorX();
    int16_t cy = gfx->getCursorY();
    
    if (i == 0) {
        gfx->setTextColor(i == selectedMenu ? YELLOW : GREEN);
        gfx->print("Turn All ON");
    }
    else if (i == 1) {
        gfx->setTextColor(i == selectedMenu ? YELLOW : RED);
        gfx->print("Turn All OFF");
    }
    else if (i >= 2 && i < NUM_CATEGORIES + 2) {
        int catIdx = i - 2;
        gfx->fillRect(cx, cy + 1, 6, 6, configColors[catIdx]);
        gfx->setCursor(cx + 10, cy);
        
        gfx->setTextColor(i == selectedMenu ? YELLOW : WHITE);
        gfx->print(configNames[catIdx]);
        
        if (catIdx == NUM_CATEGORIES - 1) { 
            gfx->setTextColor(scanConfig[catIdx] ? RED : GREY); 
        } else {
            gfx->setTextColor(scanConfig[catIdx] ? GREEN : GREY); 
        }
        gfx->print(scanConfig[catIdx] ? " [ON]" : " [OFF]");
    } 
    else if (i == NUM_CATEGORIES + 2) {
        gfx->setTextColor(i == selectedMenu ? YELLOW : CYAN);
        gfx->print("Web Portal");
    }
    else if (i == NUM_CATEGORIES + 3) {
        gfx->setTextColor(i == selectedMenu ? YELLOW : ORANGE);
        gfx->print("Factory Reset");
    }
    else if (i == NUM_CATEGORIES + 4) {
        gfx->setTextColor(i == selectedMenu ? YELLOW : RED);
        gfx->print("Power Off");
    }
    else if (i == NUM_CATEGORIES + 5) {
        gfx->setTextColor(i == selectedMenu ? YELLOW : MAGENTA);
        gfx->print("About Foxhunter");
    }
    
    y += 11;
  }

  int trackHeight = 106;
  gfx->drawFastVLine(158, 18, trackHeight, GREY);
  int thumbHeight = max(10, (trackHeight * VISIBLE_MENU_ITEMS) / TOTAL_MENU_ITEMS);
  int thumbY = 18 + ((trackHeight - thumbHeight) * menuScrollOffset) / (TOTAL_MENU_ITEMS - VISIBLE_MENU_ITEMS);
  gfx->fillRect(157, thumbY, 3, thumbHeight, CYAN);
}

void drawAboutView() {
  unsigned long now = millis();
  
  if (uiNeedsUpdate) {
    gfx->fillScreen(BLACK);
    gfx->draw16bitBeRGBBitmap(0, -32, (uint16_t*)foxhunter_logo, 160, 96);
  }

  gfx->fillRect(0, 64, 160, 52, BLACK);
  int scrollY = 116 - ((now / 150) % 140);

  if (scrollY >= 64) {
    gfx->setTextColor(PURPLE);
    gfx->setCursor(10, scrollY);
    gfx->println("Foxhunter 8-Bit");
  }
  
  if (scrollY + 12 >= 64) {
    gfx->setTextColor(WHITE);
    gfx->setCursor(10, scrollY + 12);
    gfx->println("Created by:");
  }
  
  if (scrollY + 24 >= 64) {
    gfx->setTextColor(YELLOW);
    gfx->setCursor(10, scrollY + 24);
    gfx->println("Adriano Moraes");
  }
  
  gfx->setTextColor(GREY);
  if (scrollY + 44 >= 64) {
    gfx->setCursor(10, scrollY + 44);
    gfx->println("Designed to run on Bsides");
  }
  if (scrollY + 52 >= 64) {
    gfx->setCursor(10, scrollY + 52);
    gfx->println("Lisbon 2025 badge. ");
  }
  if (scrollY + 60 >= 64) {
    gfx->setCursor(10, scrollY + 60);
    gfx->println("Thanks to Pedro Umbelino");
  }
  if (scrollY + 68 >= 64) {
    gfx->setCursor(10, scrollY + 68);
    gfx->println("for the project and the");
  }
  if (scrollY + 76 >= 64) {
    gfx->setCursor(10, scrollY + 76);
    gfx->println("spare devices.");
  }

  gfx->fillRect(0, 116, 160, 12, BLACK);
  gfx->setTextColor(GREY);
  gfx->setCursor(5, 118);
  gfx->println("[<] Return to Menu");
}

void drawSetupView() {
  gfx->fillScreen(BLACK); gfx->fillRect(0, 0, 160, 16, ORANGE);
  gfx->setCursor(5, 4); gfx->setTextColor(BLACK); gfx->setTextSize(1); gfx->println("< MANUAL SETUP");

  const char* labels[] = {"Year:", "Mon:", "Day:", "Hour:", "Min:", "Prox:", "SQL:", "Drop:"};
  
  for(int i=0; i<8; i++) {
    int lx = (i < 5) ? 4 : 80;
    int vx = (i < 5) ? 36 : 112;
    int y = 22 + ((i < 5) ? i : (i - 5)) * 12;

    gfx->setTextColor(setupSelection == i ? YELLOW : CYAN);
    gfx->setCursor(lx, y); gfx->print(labels[i]);
    
    if (setupSelection == i && setupEditMode) gfx->setTextColor(RED);
    else gfx->setTextColor(WHITE);
    
    gfx->setCursor(vx, y); 
    if (i==0) gfx->printf("%04d", setupYear);
    else if (i==1) gfx->printf("%02d", setupMonth);
    else if (i==2) gfx->printf("%02d", setupDay);
    else if (i==3) gfx->printf("%02d", setupHour);
    else if (i==4) gfx->printf("%02d", setupMin);
    else if (i==5) gfx->printf("%ddBm", proxThreshold);
    else if (i==6) { if(squelchLimit <= -100) gfx->print("OFF"); else gfx->printf("%ddBm", squelchLimit); }
    else if (i==7) gfx->print(hardDrop ? "Hard" : "Soft");
  }

  int b_y = 86;
  gfx->setTextColor(setupSelection == 8 ? YELLOW : CYAN);
  gfx->setCursor(4, b_y); gfx->print("SSID:");
  
  for (int c=0; c<16; c++) {
     if (setupSsid[c] == '\0') break;
     if (setupSelection == 8 && setupEditMode && c == setupSsidCursor) {
        gfx->setTextColor(BLACK, RED); 
     } else {
        gfx->setTextColor(WHITE, BLACK);
     }
     gfx->setCursor(40 + (c * 6), b_y);
     gfx->print(setupSsid[c]);
  }
  gfx->setTextColor(WHITE, BLACK); 
  
  b_y += 16;
  gfx->setTextColor(setupSelection == 9 ? YELLOW : GREEN);
  gfx->setCursor(10, b_y); gfx->print(setupSelection == 9 ? "> SAVE <" : "  SAVE");
  
  gfx->setTextColor(setupSelection == 10 ? YELLOW : GREY);
  gfx->setCursor(80, b_y); gfx->print(setupSelection == 10 ? "> CANCEL <" : "  CANCEL");
}

void drawAliasEdit() {
  gfx->fillScreen(BLACK); 
  gfx->fillRect(0, 0, 160, 16, MAGENTA);
  gfx->setCursor(5, 4); gfx->setTextColor(BLACK); gfx->setTextSize(1); gfx->println("EDIT DEVICE ALIAS");

  gfx->setTextColor(WHITE); gfx->setCursor(10, 30); gfx->print("MAC: "); gfx->print(targetAliasMac);
  
  int y = 50;
  gfx->setTextColor(CYAN); gfx->setCursor(10, y); gfx->print("NAME:");
  
  for (int c=0; c<10; c++) {
     if (c == setupAliasCursor) {
        gfx->setTextColor(BLACK, RED); 
     } else {
        gfx->setTextColor(WHITE, BLACK);
     }
     gfx->setCursor(50 + (c * 6), y);
     gfx->print(setupAlias[c]);
  }
  gfx->setTextColor(WHITE, BLACK); 
  
  y += 30;
  gfx->setTextColor(YELLOW); gfx->setCursor(10, y); gfx->println("[A] SAVE ALIAS");
  y += 15;
  gfx->setTextColor(GREY); gfx->setCursor(10, y); gfx->println("[B] CANCEL");
}

void drawResetConfirm() {
  gfx->fillScreen(RED);
  gfx->setTextColor(WHITE);
  gfx->setTextSize(1);
  gfx->setCursor(10, 20); gfx->println("FACTORY RESET");
  gfx->setCursor(10, 40); gfx->println("This permanently wipes");
  gfx->setCursor(10, 50); gfx->println("all logs and rules.");
  
  gfx->setTextColor(YELLOW);
  gfx->setCursor(10, 80); gfx->println("[A] CONFIRM NUKE");
  gfx->setCursor(10, 100); gfx->println("[B] CANCEL");
}

void drawLogPanel() {
  unsigned long now = millis();
  gfx->fillScreen(BLACK); gfx->fillRect(0, 0, 160, 16, YELLOW);
  gfx->setCursor(5, 4); gfx->setTextColor(BLACK); gfx->setTextSize(1); gfx->print("DETECTED DEVICES ");
  
  if (filteredLogIndices.empty()) { 
      gfx->setTextColor(GREY); gfx->setCursor(10, 60); gfx->println("No Devices Found"); 
      if (logMenuOpen) goto DrawSlideMenu; 
      gfx->setTextColor(RED); gfx->setCursor(10, 110); 
      gfx->println("[>] Exit  [<] Filter"); 
      return; 
  }
  
  gfx->print(currentFilteredIndex + 1); gfx->print("/"); gfx->print(filteredLogIndices.size());
  
  {
      ThreatHistory t = historyLogs[filteredLogIndices[currentFilteredIndex]];
      
      int y = 25; gfx->setTextColor(CYAN); gfx->setCursor(0, y); gfx->print("TYPE:"); gfx->setTextColor(WHITE); gfx->setCursor(31, y); gfx->print(t.desc);
      y += 14; 
      
      gfx->setTextColor(CYAN); gfx->setCursor(0, y); 
      if (deviceAliases.count(t.mac) && (now / 2000) % 2 == 0) {
          gfx->print("TAG:"); gfx->setTextColor(YELLOW); gfx->setCursor(31, y); gfx->print(deviceAliases[t.mac]);
      } else {
          gfx->print("MAC:"); gfx->setTextColor(GREY); gfx->setCursor(31, y); gfx->print(t.mac);
      }
      
      y += 14; gfx->setTextColor(CYAN); gfx->setCursor(0, y); gfx->print("HITS:"); gfx->setTextColor(YELLOW); gfx->setCursor(31, y); gfx->print(t.count); gfx->print(" pkts");
      
      y += 14; gfx->setTextColor(CYAN); gfx->setCursor(0, y); gfx->print("PWR:"); 
      gfx->setTextColor(t.peakRssi > -70 ? RED : YELLOW); gfx->setCursor(31, y); gfx->print("Pk:"); gfx->print(t.peakRssi);
      gfx->setTextColor(t.latestRssi > -70 ? RED : YELLOW); gfx->setCursor(86, y); gfx->print("Lt:"); gfx->print(t.latestRssi);
      
      y += 14; gfx->setTextColor(CYAN); gfx->setCursor(0, y); gfx->print("FRST:"); gfx->setTextColor(WHITE); gfx->setCursor(31, y); gfx->print(formatTime(t.firstSeen));
      y += 14; gfx->setTextColor(CYAN); gfx->setCursor(0, y); gfx->print("LAST:"); gfx->setTextColor(WHITE); gfx->setCursor(31, y); gfx->print(formatTime(t.lastSeen));
      
      gfx->setTextColor(GREY); gfx->setCursor(2, 115); 
      gfx->println("[A] More [B] Hunt [<]Filt"); 
  }

DrawSlideMenu:
  if (logMenuOpen) {
      gfx->fillRect(0, 16, 120, 112, BLACK); 
      gfx->drawRect(0, 16, 120, 112, CYAN);  
      
      int my = 18;
      gfx->setTextColor(logMenuSelection == 0 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 0 ? "> " : "  "); gfx->println("Close Menu");
      
      my += 14;
      gfx->setTextColor(logMenuSelection == 1 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 1 ? "> " : "  "); gfx->println("Tag/Alias Device");

      my += 14;
      gfx->setTextColor(logMenuSelection == 2 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 2 ? "> " : "  "); gfx->print("Inact 5m: ");
      gfx->setTextColor(filterHideOld ? GREY : GREEN); gfx->println(filterHideOld ? "[hid]" : "[shw]");
      
      my += 14;
      gfx->setTextColor(logMenuSelection == 3 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 3 ? "> " : "  "); gfx->print("Low Hits: ");
      gfx->setTextColor(filterHideLowHits ? GREY : GREEN); gfx->println(filterHideLowHits ? "[hid]" : "[shw]");

      my += 14;
      gfx->setTextColor(logMenuSelection == 4 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 4 ? "> " : "  "); gfx->print("Cat: ");
      gfx->setTextColor(filterCategoryIndex != -1 ? CYAN : GREY); 
      String catStr = filterCategoryIndex == -1 ? "ALL" : configNames[filterCategoryIndex];
      gfx->println(catStr.substring(0, 7));
      
      my += 14;
      gfx->setTextColor(logMenuSelection == 5 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 5 ? "> " : "  "); gfx->print("Sort By: ");
      gfx->setTextColor(CYAN); 
      if (sortField == 0) gfx->println("TIME");
      else if (sortField == 1) gfx->println("POWER");
      else gfx->println("HITS");

      my += 14;
      gfx->setTextColor(logMenuSelection == 6 ? YELLOW : WHITE); gfx->setCursor(5, my); gfx->print(logMenuSelection == 6 ? "> " : "  "); gfx->print("Order:   ");
      gfx->setTextColor(CYAN); gfx->println(sortDir == 0 ? "DESC v" : "ASC ^");
      
      gfx->setTextColor(GREY); gfx->setCursor(5, 115); gfx->println("[A] Toggle/Cycle");
  }
}

void drawIntelView() {
  gfx->fillScreen(BLACK); 
  gfx->fillRect(0, 0, 160, 16, MAGENTA);
  gfx->setCursor(5, 4); gfx->setTextColor(BLACK); gfx->setTextSize(1);
  
  if (intelShowRule) {
      gfx->print("RULE CONDITIONS");
  } else {
      gfx->print("DEEP INSPECT");
  }
  
  ThreatHistory t = historyLogs[filteredLogIndices[currentFilteredIndex]];
  
  int y = 23; 
  gfx->setTextColor(WHITE); gfx->setCursor(0, y); gfx->print(t.mac);
  
  if (deviceAliases.count(t.mac)) {
      y += 12; 
      gfx->setTextColor(YELLOW); gfx->setCursor(0, y); 
      gfx->print("TAG: "); gfx->print(deviceAliases[t.mac]);
  }
  
  y += 13; gfx->setTextColor(CYAN); gfx->setCursor(0, y); gfx->print("ID:"); gfx->setTextColor(YELLOW); gfx->setCursor(21, y); gfx->print(t.desc);
  
  y += 15;
  
  if (intelShowRule) {
      gfx->setTextColor(GREY); gfx->setCursor(5, y); gfx->print("-------------------------");
      y += 11;
      
      Rule* matchedRule = nullptr;
      for (auto& r : threatRules) {
          if (r.label == t.desc && r.category == t.category) {
              matchedRule = &r; break;
          }
      }
      
      if (matchedRule) {
          auto printCond = [&](String k, String v) {
              if (v != "") {
                  gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print(k);
                  gfx->setTextColor(WHITE); gfx->setCursor(55, y); gfx->print(v);
                  y += 11;
              }
          };
          printCond("PROTO:", matchedRule->protocol);
          if (matchedRule->log_deep) printCond("DEEP LOG:", "ACTIVE");
          printCond("SSID:", matchedRule->ssid);
          printCond("MAC:", matchedRule->mac);
          printCond("ANY_MAC:", matchedRule->any_mac);
          printCond("BSSID:", matchedRule->bssid);
          printCond("NAME:", matchedRule->name);
          printCond("UUID:", matchedRule->uuid);
          printCond("CID:", matchedRule->cid);
          printCond("DT:", matchedRule->dt);
          printCond("TYPE:", matchedRule->type);
          printCond("ENC:", matchedRule->enc);
          printCond("VEND:", matchedRule->vendor);
          
          gfx->setTextColor(GREY); gfx->setCursor(5, 115); gfx->print("[<] Back to Intel");
      } else {
          gfx->setTextColor(RED); gfx->setCursor(5, y); gfx->print("DYNAMIC CATCH-ALL");
          y += 11; gfx->setTextColor(GREY); gfx->setCursor(5, y); gfx->print("No static rule matched.");
          
          gfx->setTextColor(YELLOW); gfx->setCursor(5, 115); gfx->print("[A] Save Custom Rule");
      }
  } else {
      if (t.protocol == "WIFI") {
         gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("BSSID:");
         gfx->setTextColor(WHITE); gfx->setCursor(45, y); gfx->print(t.bssid != "" ? t.bssid : "Broadcast");
         
         y += 11;
         gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("DST:");
         gfx->setTextColor(WHITE); gfx->setCursor(45, y); gfx->print(t.addr1 != "" ? t.addr1 : "Broadcast");

         y += 11;
         gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("SEC:");
         gfx->setTextColor(t.enc == "OPEN" ? RED : GREEN); gfx->setCursor(35, y); gfx->print(t.enc != "" ? t.enc : "ENC");
         if (t.vendor != "") {
             gfx->setTextColor(CYAN); gfx->setCursor(80, y); gfx->print("VND:");
             gfx->setTextColor(YELLOW); gfx->setCursor(110, y); gfx->print(t.vendor);
         }
         
         y += 12; gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("SSID/PROBES:");
         y += 11; gfx->setTextColor(GREY); gfx->setCursor(10, y); gfx->print(t.probes != "" ? t.probes : "None Extracted");
         
         gfx->setTextColor(GREY); gfx->setCursor(2, 115); gfx->print("[B] Ret  [RGT] Rule");
      } 
      else if (t.protocol == "ZIGBEE") {
         gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("NETWORK PHY:");
         y += 11; gfx->setTextColor(WHITE); gfx->setCursor(15, y); gfx->print("IEEE 802.15.4");
         y += 15; gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("NODE SIGNATURE:");
         y += 11; gfx->setTextColor(GREY); gfx->setCursor(15, y); gfx->print(t.mac);
         
         gfx->setTextColor(GREY); gfx->setCursor(2, 115); 
         gfx->print("[B] Ret"); 
      }
      else {
         gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("RAW TELEMETRY:");
         y += 11; gfx->setTextColor(GREY); gfx->setCursor(15, y); gfx->print(t.rawPayload != "" ? t.rawPayload : "No Extended Data");
         y += 15; gfx->setTextColor(CYAN); gfx->setCursor(5, y); gfx->print("GATT PROFILE:");
         y += 11; gfx->setTextColor(GREY); gfx->setCursor(15, y); gfx->print(t.gattInfo != "" ? t.gattInfo : "Hidden/Encrypted");
         
         gfx->setTextColor(GREY); gfx->setCursor(2, 115); 
         gfx->print("[A] Poke [B] Ret [>] Rule"); 
      }
  }
}

void drawFoxhunt() {
  gfx->fillScreen(BLACK); gfx->fillRect(0, 0, 160, 16, GREEN);
  gfx->setCursor(5, 4); gfx->setTextColor(BLACK); gfx->setTextSize(1); gfx->print("FOXHUNT ACTIVE");
  int y = 25; gfx->setTextColor(WHITE); gfx->setCursor(5, y); gfx->print(targetDesc);
  y += 15; gfx->setTextColor(GREY); gfx->setCursor(5, y); gfx->print(targetMacStr);
  
  unsigned long now = millis();
  
  // --- FTM UI OVERLAYS ---
  if (ftmState == FTM_NEGOTIATING) {
      y += 25; gfx->setTextColor(YELLOW); gfx->setCursor(5, y); gfx->print("Negotiating FTM...");
      y += 28; gfx->setTextColor(GREY); gfx->setCursor(20, y); gfx->print("[A] Cancel FTM");
  } 
  else if (ftmState == FTM_SUCCESS) {
      y += 25; gfx->setTextColor(CYAN); gfx->setCursor(30, y); gfx->setTextSize(2);
      gfx->print(ftmDistance, 1); gfx->print(" m"); gfx->setTextSize(1);
      y += 28; gfx->setTextColor(GREEN); gfx->setCursor(25, y); gfx->print("Precision Lock");
  }
  else {
      // FTM Fallback Tags
      if (ftmState == FTM_FAIL && (now - ftmMessageTimer < 3000)) {
          gfx->fillRect(110, 0, 50, 16, RED); gfx->setTextColor(WHITE); gfx->setCursor(115, 4); gfx->print("No FTM");
      } else if (ftmState == FTM_CANCELED && (now - ftmMessageTimer < 3000)) {
          gfx->fillRect(110, 0, 50, 16, ORANGE); gfx->setTextColor(BLACK); gfx->setCursor(115, 4); gfx->print("Abort");
      }
      
      // Standard RSSI Geiger Counter
      y += 25; int pct = map(targetRssi, -100, -30, 0, 100); pct = constrain(pct, 0, 100); int barW = (pct * 140) / 100;
      gfx->drawRect(10, y, 140, 20, WHITE);
      if (barW > 0) { uint16_t barColor = GREEN; if (pct > 75) barColor = RED; else if (pct > 40) barColor = YELLOW; gfx->fillRect(10, y, barW, 20, barColor); }
      y += 28; gfx->setTextColor(WHITE); gfx->setCursor(45, y);
      if (targetRssi <= -100) gfx->print("SIGNAL LOST"); else { gfx->print("RSSI: "); gfx->print(targetRssi); gfx->print(" dBm"); }
  }
  
  gfx->setTextColor(GREY); gfx->setCursor(5, 115); gfx->print("[>] Cancel Hunt");
  if (internalActiveRadio == 2) { gfx->setCursor(100, 115); gfx->print("[B] Poke"); }
}

String getFileSizeStr(const char* path) {
  size_t s = 0;
  if (LittleFS.exists(path)) {
      File f = LittleFS.open(path, "r");
      if(f) { s = f.size(); f.close(); }
  }
  if (s >= 1048576) return String(s / 1048576.0, 1) + " MB";
  if (s >= 1024) return String(s / 1024.0, 1) + " KB";
  return String(s) + " B";
}

String getPortalHTML() {
  String sizeRep = getFileSizeStr("/report.csv");
  String sizeLog = getFileSizeStr("/logs.csv");
  String sizeDeep = getFileSizeStr("/deep_intel.csv");
  String sizeHist = getFileSizeStr("/history.jsonl");

  String html = "<!DOCTYPE HTML><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>";
  html += "<style>body{font-family:Arial;background:#121212;color:white;text-align:center;padding:20px;}";
  html += "button{padding:15px;font-size:16px;background:#00AA55;color:white;border:none;border-radius:5px;width:100%;margin-top:10px;font-weight:bold;cursor:pointer;}";
  html += "input,select{background:#000;color:#0f0;border:1px solid #444;padding:8px;border-radius:4px;width:100%;box-sizing:border-box;}";
  html += "label{font-size:12px;color:#aaa;}";
  html += ".danger{background:#F800;color:white;}.card{background:#1e1e1e;padding:20px;border-radius:10px;margin-bottom:15px;}";
  html += "textarea{width:100%;height:350px;background:#000;color:#0f0;font-family:monospace;border:1px solid #444;padding:10px;box-sizing:border-box;font-size:12px;}</style></head><body>";
  html += "<h2>Threat Radar OS v6.8 (C6 Opt)</h2>";
  html += "<p style='color:#7BEF;font-size:12px;margin-top:-15px;'>Serial API Companion Active</p>";
  
  html += "<div class='card'>";
  html += "<form action='/download' method='GET'><button type='submit' style='margin-bottom:10px;'>Download Combined Report (" + sizeRep + ")</button></form>";
  html += "<div style='display:flex; gap:10px; margin-bottom:15px;'>";
  html += "<form action='/dl_logs' method='GET' style='flex:1;'><button type='submit' style='background:#053F; font-size:12px; margin:0;'>Raw Logs<br>(" + sizeLog + ")</button></form>";
  html += "<form action='/dl_deep' method='GET' style='flex:1;'><button type='submit' style='background:#053F; font-size:12px; margin:0;'>Deep Intel<br>(" + sizeDeep + ")</button></form>";
  html += "<form action='/dl_history' method='GET' style='flex:1;'><button type='submit' style='background:#053F; font-size:12px; margin:0;'>History<br>(" + sizeHist + ")</button></form>";
  html += "</div>";
  html += "<form action='/clear' method='POST'><button type='submit' class='danger' style='margin-top:0;'>Clear All Logs & Intel</button></form></div>";
  
  html += "<div class='card'><h3>Rule Builder</h3>";
  html += "<div style='display:grid;grid-template-columns:1fr 1fr;gap:10px;text-align:left;margin-bottom:10px;'>";
  html += "<div><label>Category</label><select id='r_cat'><option>Custom</option><option>ALPR/Flock</option><option>Trackers</option><option>Red Team</option><option>Cams/Bugs</option><option>Rogue AP</option><option>WPA Exploit</option><option>Wardrive</option><option>Hotspots</option><option>Infra</option><option>Glasses</option><option>Skimmers</option><option>Drones</option></select></div>";
  html += "<div><label>Protocol</label><select id='r_proto' onchange='toggleFields()'><option>WIFI</option><option>BLE</option><option>ZIGBEE</option></select></div>";
  html += "<div style='grid-column: span 2;'><label>Threat Label</label><input type='text' id='r_lbl' placeholder='e.g., Custom Threat' oninput='checkLabelDuplicate()'>";
  html += "<div id='lbl_msg' style='font-size:11px; margin-top:4px; display:none;'></div></div>";
  
  html += "<div><label>Transmitter MAC</label><input type='text' id='r_mac' placeholder='e.g., 00:11:22'></div>";
  
  html += "<div class='wf_only'><label>SSID</label><input type='text' id='r_ssid' placeholder='Network Name'></div>";
  html += "<div class='wf_only'><label>BSSID</label><input type='text' id='r_bssid' placeholder='Router MAC'></div>";
  html += "<div class='wf_only'><label>ANY_MAC (Echo)</label><input type='text' id='r_any_mac' placeholder='Target MAC'></div>";
  html += "<div class='wf_only'><label>Vendor OUI</label><input type='text' id='r_vendor' placeholder='e.g., 50:6f:9a'></div>";
  html += "<div class='wf_only'><label>Frame Type</label><input type='text' id='r_type' placeholder='e.g., 4 or 12'></div>";
  html += "<div class='wf_only'><label>Encryption</label><input type='text' id='r_enc' placeholder='OPEN or WPA2'></div>";

  html += "<div class='ble_only'><label>Device Name</label><input type='text' id='r_name' placeholder='e.g., Flipper'></div>";
  html += "<div class='ble_only'><label>BLE UUID</label><input type='text' id='r_uuid' placeholder='e.g., fd5f'></div>";
  html += "<div class='ble_only'><label>Company ID (CID)</label><input type='text' id='r_cid' placeholder='e.g., 004c'></div>";
  html += "<div class='ble_only'><label>Data Type (DT)</label><input type='text' id='r_dt' placeholder='e.g., 12 or 0f'></div>";

  html += "<div style='grid-column: span 2; display:flex; align-items:center; gap:10px;'><input type='checkbox' id='r_logdeep' style='width:auto;'><label>Log Deep Intel (Save Raw Packets to CSV)</label></div>";
  html += "</div><button type='button' onclick='addRule()' style='background-color:#053F;color:white;'>Append to Editor</button></div>";

  html += "<div class='card'><h3>Rules Engine (JSON)</h3>";
  
  html += "<form action='/confirm_reset' method='GET'><button type='submit' class='danger' style='margin-bottom:10px;'>Factory Reset Rules</button></form>";
  
  html += "<div><textarea name='rules' id='rulesArea'>";
  
  File f = LittleFS.open("/rules.json", "r");
  if(f) {
    html += f.readString();
    f.close();
  }
  
  html += "</textarea><button type='button' onclick='submitRules()' style='background-color:#FFE0;color:black;'>Save & Reload Rules</button></div></div>";
  
  html += "<script>";
  html += "function submitRules() {";
  html += "  var payload = document.getElementById('rulesArea').value;";
  html += "  fetch('/save_rules', {";
  html += "    method: 'POST',";
  html += "    headers: { 'Content-Type': 'text/plain' },";
  html += "    body: payload";
  html += "  }).then(function(res) { return res.text(); })";
  html += "  .then(function(html) { document.open(); document.write(html); document.close(); })";
  html += "  .catch(function(err) { alert('Failed to connect to badge.'); });";
  html += "}";

  html += "function toggleFields() {";
  html += "  var p = document.getElementById('r_proto').value;";
  html += "  var wfs = document.querySelectorAll('.wf_only');";
  html += "  var bles = document.querySelectorAll('.ble_only');";
  html += "  wfs.forEach(function(el) { el.style.display = (p === 'WIFI') ? 'block' : 'none'; });";
  html += "  bles.forEach(function(el) { el.style.display = (p === 'BLE') ? 'block' : 'none'; });";
  html += "}";
  html += "function getAllLabels() {";
  html += "  var labels = [];";
  html += "  try {";
  html += "    var d = JSON.parse(document.getElementById('rulesArea').value);";
  html += "    if(d.rules && Array.isArray(d.rules)) {";
  html += "      for(var i=0; i<d.rules.length; i++) { if(d.rules[i].label) labels.push(d.rules[i].label); }";
  html += "    }";
  html += "  } catch(e) {}";
  html += "  return labels;";
  html += "}";
  html += "function computeNextAvailableLabel(name, list) {";
  html += "  var lowerList = list.map(function(l){ return l.toLowerCase(); });";
  html += "  if(lowerList.indexOf(name.toLowerCase()) === -1) return name;";
  html += "  var match = name.match(/^(.*?)(?:\\s+(\\d+))?$/);";
  html += "  var base = (match && match[1]) ? match[1].trim() : name.trim();";
  html += "  var count = 2;";
  html += "  while(true) {";
  html += "    var cand = base + ' ' + count;";
  html += "    if(lowerList.indexOf(cand.toLowerCase()) === -1) return cand;";
  html += "    count++;";
  html += "  }";
  html += "}";
  html += "function checkLabelDuplicate() {";
  html += "  var input = document.getElementById('r_lbl');";
  html += "  var msg = document.getElementById('lbl_msg');";
  html += "  var val = input.value.trim();";
  html += "  if(!val) { msg.style.display = 'none'; return; }";
  html += "  var labels = getAllLabels();";
  html += "  var lowerList = labels.map(function(l){ return l.toLowerCase(); });";
  html += "  if(lowerList.indexOf(val.toLowerCase()) !== -1) {";
  html += "    var nextName = computeNextAvailableLabel(val, labels);";
  html += "    msg.innerHTML = \"<span style='color:#FFB000;'>Name already in use. Suggestion: <a href='javascript:void(0)' onclick='applySuggestion(\\\"\" + nextName + \"\\\")' style='color:#FFE0;text-decoration:underline;font-weight:bold;'>\" + nextName + \"</a></span>\";";
  html += "    msg.style.display = 'block';";
  html += "  } else {";
  html += "    msg.style.display = 'none';";
  html += "  }";
  html += "}";
  html += "function applySuggestion(suggested) {";
  html += "  document.getElementById('r_lbl').value = suggested;";
  html += "  checkLabelDuplicate();";
  html += "}";
  html += "function addRule() {";
  html += "  try {";
  html += "    var t=document.getElementById('rulesArea');";
  html += "    var d=JSON.parse(t.value);";
  html += "    var p=document.getElementById('r_proto').value;";
  html += "    var rawLbl = document.getElementById('r_lbl').value.trim() || 'Custom Threat';";
  html += "    var labels = [];";
  html += "    if(d.rules && Array.isArray(d.rules)) { for(var i=0; i<d.rules.length; i++) { if(d.rules[i].label) labels.push(d.rules[i].label); } }";
  html += "    var finalLbl = computeNextAvailableLabel(rawLbl, labels);";
  html += "    var r={";
  html += "      cat:document.getElementById('r_cat').value,";
  html += "      proto:p,";
  html += "      label:finalLbl";
  html += "    };";
  html += "    if(document.getElementById('r_logdeep').checked) r.log_deep=true;";
  html += "    var m=document.getElementById('r_mac').value.trim(); if(m) r.mac=m;";
  html += "    if (p === 'WIFI') {";
  html += "      var s=document.getElementById('r_ssid').value.trim(); if(s) r.ssid=s;";
  html += "      var b=document.getElementById('r_bssid').value.trim(); if(b) r.bssid=b;";
  html += "      var a=document.getElementById('r_any_mac').value.trim(); if(a) r.any_mac=a;";
  html += "      var v=document.getElementById('r_vendor').value.trim(); if(v) r.vendor=v;";
  html += "      var y=document.getElementById('r_type').value.trim(); if(y) r.type=y;";
  html += "      var e=document.getElementById('r_enc').value.trim(); if(e) r.enc=e;";
  html += "    } else if (p === 'BLE') {";
  html += "      var n=document.getElementById('r_name').value.trim(); if(n) r.name=n;";
  html += "      var u=document.getElementById('r_uuid').value.trim(); if(u) r.uuid=u;";
  html += "      var c=document.getElementById('r_cid').value.trim(); if(c) r.cid=c;";
  html += "      var dt=document.getElementById('r_dt').value.trim(); if(dt) r.dt=dt;";
  html += "    }";
  html += "    d.rules.push(r);";
  html += "    t.value=JSON.stringify(d,null,2);";
  html += "    document.getElementById('r_lbl').value = '';";
  html += "    document.getElementById('lbl_msg').style.display = 'none';";
  html += "    t.scrollIntoView({behavior:'smooth'});";
  html += "  } catch(e) { alert('Syntax error in JSON box. Reset rules first.'); }";
  html += "}";
  html += "window.onload = function() {";
  html += "  toggleFields();";
  html += "  try{var t=document.getElementById('rulesArea');t.value=JSON.stringify(JSON.parse(t.value),null,2);}catch(e){}";
  html += "};";
  html += "var dt=new Date();fetch('/sync?t='+(Math.floor(dt.getTime()/1000)-(dt.getTimezoneOffset()*60)));";
  html += "</script>";
  html += "</body></html>";
  return html;
}

void initPortalHardware() {
  WiFi.mode(WIFI_AP); 
  delay(100);
  WiFi.setTxPower(WIFI_POWER_8_5dBm);
  WiFi.softAPConfig(IPAddress(192, 168, 4, 1), IPAddress(192, 168, 4, 1), IPAddress(255, 255, 255, 0));
  WiFi.softAP(customSSID.c_str(), NULL, 1, 0, 4); 
  delay(200);

  dnsServer.start(DNS_PORT, "*", WiFi.softAPIP());
  
  server.on("/", []() { 
    server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
    server.sendHeader("Pragma", "no-cache");
    server.sendHeader("Expires", "0");
    server.send(200, "text/html", getPortalHTML()); 
  });

  server.on("/confirm_reset", []() {
    String html = "<!DOCTYPE HTML><html><head><meta name='viewport' content='width=device-width, initial-scale=1'>";
    html += "<style>body{font-family:Arial;background:#121212;color:white;text-align:center;padding:50px;}";
    html += "button{padding:15px;font-size:16px;border:none;border-radius:5px;width:100%;max-width:300px;margin-top:15px;font-weight:bold;cursor:pointer;}";
    html += ".danger{background:#F800;color:white;} .safe{background:#00AA55;color:white;}</style></head><body>";
    html += "<h2 style='color:#F800;'>WARNING: FACTORY RESET</h2>";
    html += "<p>This will permanently wipe all logs, aliases, and custom rules.</p>";
    html += "<form action='/reset_rules' method='POST'><button type='submit' class='danger'>YES, NUKE IT</button></form>";
    html += "<form action='/' method='GET'><button type='submit' class='safe'>CANCEL & RETURN</button></form>";
    html += "</body></html>";
    server.send(200, "text/html", html);
  });

  server.on("/dl_logs", []() {
    if (LittleFS.exists("/logs.csv")) { 
      File f = LittleFS.open("/logs.csv", "r"); 
      server.sendHeader("Cache-Control", "no-cache");
      server.streamFile(f, "text/csv"); 
      f.close(); 
    } else {
      server.send(404, "text/plain", "No event logs found.");
    }
  });

  server.on("/dl_deep", []() {
    if (LittleFS.exists("/deep_intel.csv")) { 
      File f = LittleFS.open("/deep_intel.csv", "r"); 
      server.sendHeader("Cache-Control", "no-cache");
      server.streamFile(f, "text/csv"); 
      f.close(); 
    } else {
      server.send(404, "text/plain", "No Deep Intel data found.");
    }
  });

  server.on("/dl_history", []() {
    if (LittleFS.exists("/history.jsonl")) { 
      File f = LittleFS.open("/history.jsonl", "r"); 
      server.sendHeader("Cache-Control", "no-cache");
      server.streamFile(f, "application/json"); 
      f.close(); 
    } else {
      server.send(404, "text/plain", "No history state found.");
    }
  });

  server.on("/sync", []() {
      if(server.hasArg("t")) {
          time_t t = server.arg("t").toInt();
          struct timeval tv;
          tv.tv_sec = t;
          tv.tv_usec = 0;
          settimeofday(&tv, NULL);
          timeSynced = true;
          uiNeedsUpdate = true;
          
          time_t nowTime; time(&nowTime); struct tm* tinfo = localtime(&nowTime);
          char tStr[24]; sprintf(tStr, "%04d-%02d-%02d %02d:%02d:%02d", tinfo->tm_year+1900, tinfo->tm_mon+1, tinfo->tm_mday, tinfo->tm_hour, tinfo->tm_min, tinfo->tm_sec);
          logEvent("SYNC", "SYSTEM", "Portal Time Sync", 0, tStr);
          
          server.send(200, "text/plain", "OK");
      } else {
          server.send(400, "text/plain", "Bad Request");
      }
  });
  
  server.on("/save_rules", HTTP_POST, []() {
    String payload = "";
    
    if (server.hasArg("plain")) {
        payload = server.arg("plain");
    } 
    else if (server.hasArg("rules")) {
        payload = server.arg("rules");
    }

    if (payload.length() > 0) {
      File f = LittleFS.open("/rules.json", FILE_WRITE);
      if (f) {
          f.print(payload); 
          f.close();
          loadRules(); 
          server.send(200, "text/html", "<html><body style='background:#000;color:#0f0;font-family:monospace;text-align:center;padding:50px;'><h2>RULES UPDATED</h2><script>setTimeout(function(){window.location.href='/';}, 1500);</script></body></html>");
      } else {
          server.send(500, "text/plain", "Failed to write to LittleFS");
      }
    } else { 
      server.send(400, "text/plain", "Bad Request: No rules data received"); 
    }
  });

  server.on("/reset_rules", HTTP_POST, []() {
    LittleFS.remove("/rules.json");
    LittleFS.remove("/logs.csv");
    LittleFS.remove("/history.jsonl");
    LittleFS.remove("/deep_intel.csv");
    LittleFS.remove("/aliases.json");
    deviceAliases.clear();
    createDefaultRules();
    loadRules();
    
    server.send(200, "text/html", "<html><body style='background:#000;color:#0f0;font-family:monospace;text-align:center;padding:50px;'><h2>FACTORY RESET TRIGGERED</h2><p>The badge is rebooting...</p><p>Reconnect in 5 seconds.</p></body></html>");
    pendingReboot = true;
    rebootTimer = millis();
  });

  server.on("/download", []() {
    if (LittleFS.exists("/report.csv")) { 
      File f = LittleFS.open("/report.csv", "r"); 
      server.sendHeader("Cache-Control", "no-cache, no-store, must-revalidate");
      server.streamFile(f, "text/csv"); 
      f.close(); 
    } else {
      server.send(404, "text/plain", "No report generated yet.");
    }
  });
  
  server.on("/clear", HTTP_POST, []() {
    File f = LittleFS.open("/logs.csv", FILE_WRITE);
    if(f) { f.println("Event,Timestamp,MAC,Type,RSSI,Extra"); f.close(); } 
    LittleFS.remove("/report.csv");
    LittleFS.remove("/history.jsonl");
    LittleFS.remove("/deep_intel.csv");
    activeThreats.clear(); historyLogs.clear(); filteredLogIndices.clear(); currentFilteredIndex = 0;
    server.send(200, "text/html", "<html><body style='background:#000;color:#0f0;font-family:monospace;text-align:center;padding:50px;'><h2>LOGS & INTEL CLEARED</h2><script>setTimeout(function(){window.location.href='/';}, 1500);</script></body></html>");
  });
  
  server.onNotFound([]() { server.sendHeader("Location", "http://192.168.4.1/"); server.send(302, "text/plain", ""); });
  server.begin();
  
  gfx->fillScreen(BLACK); 
  gfx->setCursor(5, 15); gfx->setTextColor(YELLOW); gfx->setTextSize(2); gfx->println("PORTAL");
  gfx->setTextColor(WHITE); gfx->setTextSize(1); 
  gfx->setCursor(5, 45); gfx->println("SSID:"); 
  gfx->setTextColor(CYAN); gfx->setCursor(5, 55); gfx->println(customSSID);
  gfx->setTextColor(WHITE); gfx->setCursor(5, 75); gfx->println("IP:"); 
  gfx->setTextColor(CYAN); gfx->setCursor(5, 85); gfx->println("192.168.4.1");
  gfx->setTextColor(GREY); gfx->setCursor(5, 115); gfx->println("[<] or [B] Exit");

  QRCode qrcode;
  uint8_t qrcodeData[qrcode_getBufferSize(3)];
  String qrStr = "WIFI:S:" + customSSID + ";T:nopass;;";
  qrcode_initText(&qrcode, qrcodeData, 3, 0, qrStr.c_str());
  
  int scale = 2;       
  int qr_x = 95;       
  int qr_y = 35;       
  
  gfx->fillRect(qr_x - 4, qr_y - 4, (qrcode.size * scale) + 8, (qrcode.size * scale) + 8, WHITE);
  
  for (uint8_t y = 0; y < qrcode.size; y++) {
    for (uint8_t x = 0; x < qrcode.size; x++) {
      if (qrcode_getModule(&qrcode, x, y)) {
        gfx->fillRect(qr_x + (x * scale), qr_y + (y * scale), scale, scale, BLACK);
      }
    }
  }
}

void startPortal() {
  gfx->fillScreen(BLACK);
  gfx->setTextColor(YELLOW); gfx->setTextSize(1);
  gfx->setCursor(10, 50); gfx->println("CONFIGURING PORTAL...");
  
  saveHistoryState(); 
  
  gfx->setCursor(10, 70); gfx->println("Compiling Report...");
  generateForensicReport();
  
  if (radioMode == 0) {
      pBLEScan->stop();
      NimBLEDevice::deinit(true);
  } else if (radioMode == 2) {
      esp_ieee802154_disable();
  } else {
      esp_wifi_set_promiscuous(false);
      esp_wifi_set_promiscuous_rx_cb(NULL);
  }
  
  WiFi.mode(WIFI_OFF);
  delay(100);
  
  systemState = WIFI_PORTAL;
  initPortalHardware();
}

void stopPortal() {
  server.stop();
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_OFF);

  gfx->fillScreen(BLACK);
  gfx->setTextColor(YELLOW); gfx->setTextSize(1);
  gfx->setCursor(10, 60); gfx->println("RETURNING TO RADAR...");
  
  delay(100);
  systemState = RADAR_VIEW;
  uiNeedsUpdate = true;
  
  if (radioMode == 0) startBLE();
  else if (radioMode == 2) startZIGBEE();
  else startWIFI();
}
