#ifndef _PARAMETERS_H_
#define _PARAMETERS_H_

#define DEBUG 1

//PARAMETRI SCHEDA
#define BOARD_UID "1234"
#define BOARD_NAME "myesp32"

//PARAMETRI DI RETE
#define WIFI_SSID "WIFI-SSID"
#define WIFI_PASSWORD "WIFI-PASSWORD"

//PARAMETRI MQTT
#define BROKER_ADDRESS "broker.hivemq.com"
#define BROKER_PORT 1883
#define PUBKEY_REQUEST_Pattern "/pubKey/request"
#define PUBKEY_RESPONSE_Pattern "/pubKey/response"
#define SIGNATURE_REQUEST_Pattern "/signatureExchange/request"
#define SIGNATURE_RESPONSE_Pattern "/signatureExchange/response"
#define CEK_REQUEST_Pattern "/distribuitedUnpack/request"
#define CEK_RESPONSE_Pattern "/distribuitedUnpack/response"
#define DISTRIBUITED_PACK_REQUEST_Pattern "/distribuitedPack/request"
#define DISTRIBUITED_PACK_RESPONSE_Pattern "/distribuitedPack/response"

#endif
