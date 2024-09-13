#include "parameters.h"
#include <WiFi.h>
#include <PubSubClient.h>
#include <sodium.h>
#include <Arduino.h>
#include <ArduinoJson.h>
#include <Base64.h>


const char* ssid = WIFI_SSID;
const char* password = WIFI_PASSWORD;

// Buffers per le chiavi pubblica e privata
unsigned char privateKey[crypto_sign_SECRETKEYBYTES];
unsigned char publicKey[crypto_sign_PUBLICKEYBYTES];

WiFiClient wifiClient;
PubSubClient client(wifiClient);

void setup() {
  
  #if (DEBUG>0)
    Serial.begin(115200);
    while(!Serial){
      delay(500);
      if(millis() > 20000) break;
    }
    Serial.println("Booting ESP32 MQTT Client");
  #endif

  if (sodium_init() == -1) {
    Serial.println("Libsodium initialization failed!");
    ESP.restart();
  }

  client.setServer(BROKER_ADDRESS,BROKER_PORT);
  client.setCallback(callback);
  client.setBufferSize(2048);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  int attempt = 0;
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print("Attempting to connect to WiFi");
    Serial.print(" (attempt ");
    Serial.print(attempt);
    Serial.println(")");
    attempt++;
    delay(5000);

    if (attempt >= 10) { // Dopo 10 tentativi, riavvia
      Serial.println("Connection Failed! Rebooting...");
      ESP.restart();
    }
  }

  Serial.println("Connection Ready");
  Serial.print("IP address: ");
  Serial.println(WiFi.localIP());

}

void loop() {
  
  if(WiFi.status() != WL_CONNECTED) {
    WiFi.reconnect();
  }

  if(!client.connected()){
    mqtt_reconnect();
  }

  client.loop();

}

void callback(char* topic, byte* payload, unsigned int length){
  Serial.println("Message arrived at [");
  Serial.println(topic);
  Serial.println("] ");

  // Crea un buffer per il payload
  char buffer[length + 1]; // +1 per il carattere null-terminator
  memcpy(buffer, payload, length);
  buffer[length] = '\0'; // Aggiungi il null-terminator
  
  // Stampa il payload
  Serial.println(buffer);
  
  // Parsing del payload JSON
  StaticJsonDocument<1024> doc; //controllare la dimensione massima online
  DeserializationError error = deserializeJson(doc, buffer);
  
  if (error) {
    Serial.print("Errore di parsing JSON: ");
    Serial.println(error.c_str());
    return;
  }

  // Estrarre il tipo dal JSON
  const char* type = doc["@type"];
  Serial.println(type);

  if (strcmp(type, "https://didcomm.org/pubkey_exchange/1.0/request") == 0) {
    process_pubkey_request(doc);
  } else if (strcmp(type, "https://didcomm.org/signature_exchange/1.0/request") == 0) {
    process_signature_exchange_request(doc);
  }else if (strcmp(type, "https://didcomm.org/distribuited_unpack/1.0/request") == 0) {
    process_distribuited_unpack_request(doc);
  }else if (strcmp(type, "https://didcomm.org/distribuited_pack/1.0/request") == 0) {
    process_distribuited_pack_request(doc);
  } else {
    Serial.println("Unable to process message type");
  }
  
}

void process_pubkey_request(StaticJsonDocument<1024>& received_doc){
  Serial.println("Received Public Key request");
  // Creazione del documento JSON
  StaticJsonDocument<1024> doc;
  doc["@type"] = "https://didcomm.org/pubkey_exchange/1.0/response";
  doc["@id"] = received_doc["@id"];
  doc["contextId"] = received_doc["contextId"];

  // Converti la chiave pubblica in una stringa esadecimale
  createKey();
  char publicKeyHex[crypto_sign_PUBLICKEYBYTES * 2 + 1];
  for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++) {
    sprintf(&publicKeyHex[i * 2], "%02x", publicKey[i]);
  }
  doc["publicKey"] = publicKeyHex;


  // Serializzazione del documento JSON
  char jsonBuffer[1024];
  size_t n = serializeJson(doc, jsonBuffer);

  // Pubblica il messaggio MQTT
  char* PUBKEYRESPONSE = getTopic(PUBKEY_RESPONSE_Pattern);
  client.publish(PUBKEYRESPONSE, jsonBuffer, n);
  return;
}

void process_signature_exchange_request(StaticJsonDocument<1024>& received_doc){
  Serial.println("Received Signature exchange request");
  // Creazione del documento JSON
  StaticJsonDocument<1024> doc;
  doc["@type"] = "https://didcomm.org/signature_exchange/1.0/response";
  doc["@id"] = received_doc["@id"];
  doc["dataId"] = received_doc["dataId"];

  // La stringa da firmare
  const char *message = received_doc["data"].as<const  char*>();

  if (message == nullptr) {
    Serial.println("Errore: il puntatore 'data' è nullo.");
    return;
  }

  // Buffer per la firma
  unsigned char signature[crypto_sign_BYTES];

  // Buffer per il messaggio firmato
  unsigned char signedMessage[crypto_sign_BYTES + strlen(message)];

  // Firma il messaggio
  unsigned long long signedMessageLen;
  crypto_sign(signedMessage, &signedMessageLen, (const unsigned char *) message, strlen(message), privateKey);

  // Copia la firma dal messaggio firmato
  memcpy(signature, signedMessage, crypto_sign_BYTES);

  // Converti la firma in formato esadecimale per la visualizzazione
  char hexSignature[crypto_sign_BYTES * 2 + 1];
  sodium_bin2hex(hexSignature, sizeof(hexSignature), signature, crypto_sign_BYTES);

  // Stampa la firma
  Serial.print("Firma: ");
  Serial.println(hexSignature);

  doc["data"] = hexSignature;

  // Serializzazione del documento JSON
  char jsonBuffer[1024];
  size_t n = serializeJson(doc, jsonBuffer);

  // Pubblica il messaggio MQTT
  char* SIGNATURERESPONSE = getTopic(SIGNATURE_RESPONSE_Pattern);
  client.publish(SIGNATURERESPONSE, jsonBuffer, n);
  return;
}

void process_distribuited_unpack_request(StaticJsonDocument<1024>& received_doc){
  Serial.println("Received Distribuited Unpack request");

  // Creazione del documento JSON
  StaticJsonDocument<1024> doc;
  doc["@type"] = "https://didcomm.org/distribuited_unpack/1.0/response";
  doc["@id"] = received_doc["@id"];
  doc["dataId"] = received_doc["dataId"];

  // La chiave da decifrare in esadecimale
  const char *encrypted_key = received_doc["encryptedKey"];

  // La chiave del mittente cifrata in esadecimale
  const char *sender_key = received_doc["senderKey"];

  // il nonce in esadecimale
  const char *nonce_hex = received_doc["nonce"];

  // Decodifica del nonce da esadicimale a buffer
  size_t nonce_length = strlen(nonce_hex) / 2;
  unsigned char nonce[nonce_length];
  for (size_t i = 0; i < nonce_length; i++) {
      sscanf(&nonce_hex[i * 2], "%2hhx", &nonce[i]);
  }

  // Decodifica della chiave del mittente cifrata da esadicimale a buffer
  size_t sender_key_length = strlen(sender_key) / 2;
  unsigned char encryptedSenderKey[sender_key_length];
  for (size_t i = 0; i < sender_key_length; i++) {
      sscanf(&sender_key[i * 2], "%2hhx", &encryptedSenderKey[i]);
  }

  //conversione chiave pubblica dal formato Ed25519 al formato X25519 
  unsigned char recip_x[crypto_box_PUBLICKEYBYTES];
  crypto_sign_ed25519_pk_to_curve25519(recip_x, publicKey);

  // Conversione chiave privata dal formato Ed25519 al formato X25519
  unsigned char private_x[crypto_box_SECRETKEYBYTES];
  crypto_sign_ed25519_sk_to_curve25519(private_x, privateKey);

  //decifratura della chiave del mittente
  uint8_t senderKey[32];
  if (crypto_box_seal_open(senderKey,encryptedSenderKey, sizeof(encryptedSenderKey), recip_x, private_x) != 0) {
    Serial.println("Decryption failed");
    return;
  } else {
    Serial.println("Decryption successful");
  }

  //conversione della chiave del mittente dal formato Ed25519 al formato X25519 
  unsigned char sender_x[crypto_box_PUBLICKEYBYTES];
  crypto_sign_ed25519_pk_to_curve25519(sender_x, senderKey);

  // Decodifica della chiave cifrata da esadicimale a buffer
  size_t encrypted_key_length = strlen(encrypted_key) / 2;
  unsigned char encryptedKey[encrypted_key_length];
  for (size_t i = 0; i < encrypted_key_length; i++) {
      sscanf(&encrypted_key[i * 2], "%2hhx", &encryptedKey[i]);
  }

  //Decifratura
  unsigned char payloadKey[crypto_box_SEEDBYTES];  // Lunghezza della chiave decifrata
  if (crypto_box_open_easy(payloadKey, encryptedKey, sizeof(encryptedKey), nonce, sender_x, private_x) != 0) {
    Serial.println("Decryption failed");
  } else {
    Serial.println("Decryption successful");
  }

  //Conversione da buffer a hex
  char payloadKeyHex[crypto_box_SEEDBYTES * 2 + 1]; // +1 per il terminatore null
  const char hexChars[] = "0123456789abcdef";
  for (size_t i = 0; i < crypto_box_SEEDBYTES; ++i) {
    payloadKeyHex[i * 2] = hexChars[(payloadKey[i] >> 4) & 0x0F];
    payloadKeyHex[i * 2 + 1] = hexChars[payloadKey[i] & 0x0F];
  }
  payloadKeyHex[crypto_box_SEEDBYTES * 2] = '\0'; // Aggiunge il terminatore null

  doc["payloadKey"] = payloadKeyHex;

  //Conversione senderKey da buffer a hex
  char senderKeyHex[(32 * 2) + 1]; // +1 per il terminatore null
  for (size_t i = 0; i < 32; ++i) {
    senderKeyHex[i * 2] = hexChars[(senderKey[i] >> 4) & 0x0F];
    senderKeyHex[i * 2 + 1] = hexChars[senderKey[i] & 0x0F];
  }
  senderKeyHex[32 * 2] = '\0'; // Aggiunge il terminatore null

  doc["senderKey"] = senderKeyHex;

  // Serializzazione del documento JSON
  char jsonBuffer[1024];
  size_t n = serializeJson(doc, jsonBuffer);

  // Pubblica il messaggio MQTT
  char* CEKRESPONSE = getTopic(CEK_RESPONSE_Pattern);
  client.publish(CEKRESPONSE, jsonBuffer, n);
  return;
}

void process_distribuited_pack_request(StaticJsonDocument<1024>& received_doc){
  Serial.println("Received Distribuited Pack request");

  // Creazione del documento JSON
  StaticJsonDocument<1024> doc;
  doc["@type"] = "https://didcomm.org/distribuited_pack/1.0/response";
  doc["@id"] = received_doc["@id"];
  doc["dataId"] = received_doc["dataId"];

  // La recipient key in esadecimale
  const char *recipient_key_hex = received_doc["recipientKey"];

  // La Content Encription Key in esadecimale
  const char *cek_hex = received_doc["cek"];

  Serial.println("cek esadecimale ricevuto ");
  Serial.println(cek_hex);

  // Decodifica della recipient key da esadicimale a buffer
  size_t recipient_key_length = strlen(recipient_key_hex) / 2;
  unsigned char recipientKey[recipient_key_length];
  for (size_t i = 0; i < recipient_key_length; i++) {
      sscanf(&recipient_key_hex[i * 2], "%2hhx", &recipientKey[i]);
  }

  // Decodifica della Content Encription Key da esadicimale a buffer
  size_t cek_length = strlen(cek_hex) / 2;
  unsigned char cek[cek_length];
  for (size_t i = 0; i < cek_length; i++) {
      sscanf(&cek_hex[i * 2], "%2hhx", &cek[i]);
  }

  // Conversione di recipient key dal formato Ed25519 al formato X25519 
  unsigned char targetExchangeKey[crypto_box_PUBLICKEYBYTES];
  crypto_sign_ed25519_pk_to_curve25519(targetExchangeKey, recipientKey);

  // Conversione chiave privata dal formato Ed25519 al formato X25519
  unsigned char private_x[crypto_box_SECRETKEYBYTES];
  crypto_sign_ed25519_sk_to_curve25519(private_x, privateKey);

  // Generazione di un nonce casuale
  unsigned char nonce[crypto_box_NONCEBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  // Buffer per il messaggio cifrato
  unsigned char encryptedCek[crypto_box_MACBYTES + sizeof(cek)];

  // Cifra il messaggio
  if (crypto_box_easy(encryptedCek, cek,sizeof(cek), nonce, targetExchangeKey, private_x) != 0) {
      Serial.println("Encryption failed");
  } else {
      Serial.println("Encryption successful");
  }

  //Conversione di encryptedCek da buffer a hex
  char encryptedCekHex[(sizeof(encryptedCek) * 2) + 1]; // +1 per il terminatore null
  const char hexChars[] = "0123456789abcdef";
  for (size_t i = 0; i < sizeof(encryptedCek); ++i) {
    encryptedCekHex[i * 2] = hexChars[(encryptedCek[i] >> 4) & 0x0F];
    encryptedCekHex[i * 2 + 1] = hexChars[encryptedCek[i] & 0x0F];
  }
  encryptedCekHex[sizeof(encryptedCek) * 2] = '\0'; // Aggiunge il terminatore null

  doc["encryptedCek"] = encryptedCekHex;

  //Conversione del nonce da buffer a hex
  char nonceHex[crypto_box_NONCEBYTES * 2 + 1]; // +1 per il terminatore null
  for (size_t i = 0; i < crypto_box_NONCEBYTES; ++i) {
    nonceHex[i * 2] = hexChars[(nonce[i] >> 4) & 0x0F];
    nonceHex[i * 2 + 1] = hexChars[nonce[i] & 0x0F];
  }
  nonceHex[crypto_box_NONCEBYTES * 2] = '\0'; // Aggiunge il terminatore null

  doc["nonce"] = nonceHex;

  // Serializzazione del documento JSON
  char jsonBuffer[1024];
  size_t n = serializeJson(doc, jsonBuffer);

  // Pubblica il messaggio MQTT
  char* DISTRIBUITEDPACKRESPONSE = getTopic(DISTRIBUITED_PACK_RESPONSE_Pattern);
  client.publish(DISTRIBUITEDPACKRESPONSE, jsonBuffer, n);
  return;
}

void mqtt_reconnect(){
  while(!client.connected()){
    if (client.connect(BOARD_NAME)) {
      Serial.println("MQTT Client Ready");
      char* PUBKEYREQUEST = getTopic(PUBKEY_REQUEST_Pattern);
      char* SIGNATUREREQUEST = getTopic(SIGNATURE_REQUEST_Pattern);
      char* CEKREQUEST = getTopic(CEK_REQUEST_Pattern);
      char* DISTRIBUITEDPACKREQUEST = getTopic(DISTRIBUITED_PACK_REQUEST_Pattern);
      client.subscribe(PUBKEYREQUEST);
      client.subscribe(SIGNATUREREQUEST);
      client.subscribe(CEKREQUEST);
      client.subscribe(DISTRIBUITEDPACKREQUEST);
    } else {
      Serial.println("failed, rc=");
      Serial.println(client.state());
      Serial.println("Try again in 5 seconds");
      delay(5000);
    }
  }
}

void createKey(){
  
  // Genera la coppia di chiavi
  crypto_sign_keypair(publicKey, privateKey);
  
  // Stampa la chiave pubblica
  Serial.println("Public Key:");
  for (int i = 0; i < crypto_sign_PUBLICKEYBYTES; i++) {
    Serial.printf("%02x", publicKey[i]);
  }
  Serial.println();

  // Stampa la chiave privata
  Serial.println("Private Key:");
  for (int i = 0; i < crypto_sign_SECRETKEYBYTES; i++) {
    Serial.printf("%02x", privateKey[i]);
  }
  Serial.println();

}

char* getTopic( const char* pattern) {
    char* topic = new char[strlen(BOARD_UID) + strlen(pattern) + 1];
    strcpy(topic, BOARD_UID);
    strcat(topic, pattern);
    return topic;
}

