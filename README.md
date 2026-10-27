# Don't Drawer Your Badge: Foxhunter 8-Bit 🦊📡

Turning the BSides Lisbon ESP32-C6 badge into a Multi-Spectrum Threat Radar. 

![Foxhunter 8-Bit Logo](Foxhunter_logo.jpeg)

This repository contains the source code and documentation for **Foxhunter 8-Bit**, a custom firmware designed to repurpose a conference badge into a pocket RF sensor capable of monitoring 2.4GHz traffic across Wi-Fi, BLE, and Zigbee protocols. 

Presented at **BSides Lisbon 2026** by Adriano Dias Moraes.

---

## 📂 Repository Structure

- `Foxhunter 8bit/`: The main source code for the Multi-Spectrum Threat Radar firmware.
- `Bsides badge 2025 dump/`: Original files, firmware dump, and reference material from the stock badge.
- `Foxhunter_logo.jpeg`: The official logo for the project.

---

## 🛡️ About the Hardware Badge

The BSides Lisbon 2025 badge was designed by Pedro Umbelino ([kripthor](https://www.linkedin.com/pulse/hardware-badges-analog-seppuku-pedro-umbelino-x6r3e/)) to be a fully functional, battery-powered game pad with state-of-the-art Wi-Fi. It features the ESP32-C6 microcontroller, 6 buttons, USB charging, a color LCD, and breakout pins.

### The "Analog Seppuku" & Power Delivery Issue

During the 2025 conference, roughly 6% of the badges catastrophically failed—summoning "magic smoke"—due to issues with the battery management IC (the IP5305T) and the associated inductor. 

As detailed in Pedro's post-mortem analysis:
1. **Inductor Saturation:** The inductors had wide spreads in saturation current. Units on the low end entered saturation earlier, producing higher current spikes during Wi-Fi bursts.
2. **IC Suitability:** The IP5305T was primarily designed for power banks (which demand stable, low-transient current), whereas this board operates with Wi-Fi transmission bursts, requiring an IC capable of handling fast, high di/dt load transients.
3. **Tolerance Stacking:** Minor variations in PCB trace impedance, solder joints, and component placement resulted in a feedback loop of heat and degradation for some boards.

**Pragmatic Fix:** To prevent this project from frying your badge, **ditch the internal Li-Po battery entirely.** Run the badge 100% tethered over USB using a standard power bank.

---

## 🎯 Features

Foxhunter 8-Bit utilizes a passive radar and "foxhunt" architecture:

1. **Wi-Fi 6 (802.11 b/g/n/ax)**: Promiscuous mode capturing raw management frames (Beacons, Probe Requests, Deauths) across channels 1–14 to map infrastructure and spot rogue APs.
2. **BLE 5.0 / 5.3**: Passive listening on advertising channels (37, 38, 39) to parse raw PDUs, manufacturer payloads, and track devices like Apple AirTags.
3. **IEEE 802.15.4 (Zigbee / Thread)**: Sniffing raw MAC primitives and beacons.
4. **Foxhunt UI & Radar HUD**: Plots targets on radar rings and tracks live signal peaks. Physical proximity is estimated by smoothing raw RSSI spikes using a Weighted Moving Average (WMA) filter.

---

## 🛠️ Hardware & Pinout Reference

Through black-box reverse engineering, the badge components were mapped to the ESP32-C6 GPIOs. 

For official documentation on the microcontroller, refer to the Espressif Systems datasheet:
🔗 [ESP32-C6-MINI-1 / MINI-1U Datasheet (PDF)](https://documentation.espressif.com/esp32-c6-mini-1_mini-1u_datasheet_en.pdf)

### Inputs (Tactile Buttons)
*   **UP**: GPIO 7
*   **DOWN**: GPIO 15
*   **LEFT**: GPIO 9 *(Crucial for Bootloader recovery - see troubleshooting)*
*   **RIGHT**: GPIO 18
*   **Button A**: GPIO 22
*   **Button B**: GPIO 23

### 1.47-inch TFT Display (ST7789 via SPI)
*   **MOSI**: 19
*   **SCK**: 21
*   **CS**: 2
*   **DC**: 4
*   **RST**: 3
*   **BL (Backlight)**: 5

*Note: Avoid reconfiguring GPIO 12 and GPIO 13, as these act as native USB pins. Messing with these in your code will break serial communication.*

---

## 💾 How to Backup the Original Firmware

Before installing Foxhunter 8-Bit, you may want to back up your badge's current flash memory so you can restore the original game later. 

> **Note on pre-existing dump:** A factory dump obtained directly from my own stock badge is already included in this repository under the `Bsides badge 2025 dump/` folder. If you simply want a clean backup, you can use that file instead of manually dumping your own!

If you still want to back up your specific badge's current state (using `esptool.py`), follow these steps:

1. **Install esptool:** If you don't have it installed, run:
   ```bash
   pip install esptool
   ```
2. **Read the Flash:** Run the following command to dump the entire 4MB flash to a file named `original_firmware.bin`:
   ```bash
   esptool.py -p <YOUR_PORT> -b 460800 read_flash 0x0 0x400000 original_firmware.bin
   ```
   *(Replace `<YOUR_PORT>` with your actual serial port, e.g., `/dev/ttyACM0` on Linux/macOS or `COM3` on Windows).*
3. **Restore (Optional):** If you ever want to revert back using your dump (or the one provided in the repository), run:
   ```bash
   esptool.py -p <YOUR_PORT> -b 460800 write_flash 0x0 original_firmware.bin
   ```

---

## 🚀 How to Run and Install

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/adrianomoraes/Don-t-Drawer-Your-Badge-Bsides-2026-.git](https://github.com/adrianomoraes/Don-t-Drawer-Your-Badge-Bsides-2026-.git)
   ```
2. **Open the Environment:**
   Open the `Foxhunter 8bit/` folder in the Arduino IDE (or PlatformIO, if configured). Make sure your board manager is set up for the **ESP32-C6**.
3. **Install Dependencies:**
   Ensure you have the required display libraries installed. The screen runs smoothly using the `Adafruit_ST7789` library (initialized with custom SPI pins, `tft.init(240, 320)`, and `tft.setRotation(1)`).
4. **Compile & Flash:**
   Connect the badge via USB and hit upload.

### 🚑 Troubleshooting: The Hardware Rescue Method
If you flash code that bricks the native USB (e.g., misconfiguring GPIO 12/13) and you lose serial connection, do not panic:
1. Unplug the USB.
2. Press and **hold the LEFT button** (which is wired to the GPIO 9 hardware strapping pin).
3. Plug the USB back in while holding the button.
4. The board will force the ROM Bootloader mode, bypassing the bad firmware and allowing you to re-flash safely.
