# Distributed Aries Agent Implementation for IoT Devices (ESP32)

This repository contains the implementation of protocols necessary to distribute an Aries JavaScript agent (CredoTS), enabling resource-constrained IoT devices, such as the ESP32, to function as agents, even if they do not possess the full computational capacity to run one autonomously.

Through this approach, the IoT device delegates certain agent responsibilities to a distributed system while still maintaining essential cryptographic operations on the device itself, ensuring a secure and efficient operation.

## Features

- **Distributed agent architecture** leveraging Aries JavaScript (CredoTS) protocols.
- **Optimized for ESP32** devices with limited computational resources.
- **Enables IoT devices** to act as agents by offloading agent-related tasks to a distributed CredoTS system.
- **Cryptographic key storage and operations** are handled locally on the IoT device, ensuring security.

## Setup

### Hardware and Development Environment

- **Board**: ESP32 Dev Module
- **Development Environment**: [Arduino IDE](https://www.arduino.cc/en/software)

### Required Libraries

Before running the sketch on the ESP32, the following libraries need to be installed:

1. **ArduinoJson** by Benoit Blanchon. The library can be found [here](https://github.com/bblanchon/ArduinoJson).
2. **PubSubClient** by Nick O'Leary. The library can be found [here](https://github.com/knolleary/pubsubclient/commits/master).

These libraries can be installed directly via the Arduino IDE's Library Manager or manually by downloading them from the provided GitHub links.

### Network Configuration

Before uploading the sketch to your ESP32, ensure that you configure your network settings by editing the `parameters.h` file. This file should include your WiFi credentials and any other relevant network information:

```
#define WIFI_SSID "YourNetworkSSID"
#define WIFI_PASSWORD "YourNetworkPassword"
```
This configuration step is essential to allow the device to connect to the network and operate as a distributed agent.

## Usage

1. **Install the required libraries.**
2. **Configure the network settings** in `parameters.h`.
3. **Upload the sketch** to the ESP32 device using Arduino IDE.
4. Once uploaded, the ESP32 will act as a **distributed Aries agent**, capable of performing agent operations despite its resource limitations.

## Contribution

Feel free to fork this repository, submit pull requests, or open issues. Contributions that enhance functionality or expand the agent's capabilities are highly encouraged!
