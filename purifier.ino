#include <ESP8266WiFi.h>
#include <WiFiUdp.h>
#include <string>
#include "purifier.h"
                            
const std::string s_token = "ffffffffffffffffffffffffffffffff";
WiFiUDP s_udp;

IPAddress s_purifier_ip(192,168,1,2);

void setup()
{
    Serial.begin(9600);
    delay(100);

    Serial.print("Connecting to ");

    const char *ssid = "SSID";
    const char *password = "password";
    Serial.println(ssid);
    WiFi.mode(WIFI_STA);
    WiFi.begin(ssid, password);

    while (WiFi.status() != WL_CONNECTED)
    {
        delay(500);
        Serial.print(".");
    }

    Serial.println("");
    Serial.println("WiFi connected");

    delay(100);
    s_udp.begin(54320);
}

void loop()
{
    handle_purifier(s_udp, s_purifier_ip, s_token);
}
