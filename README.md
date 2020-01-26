# eps8266-arduino-xiaomi-airpurifier
Sanple code for controlling xiaomi air purifier device via esp8266(arduino environment)

Depends:
https://github.com/esp8266/Arduino
https://github.com/bblanchon/ArduinoJson
https://github.com/intrbiz/arduino-crypto
https://github.com/tzikis/ArduinoMD5

Setup:
Find air purifier token somehow(e.g https://github.com/Maxmudjon/com.xiaomi-miio/blob/master/docs/obtain_token.md or https://www.home-assistant.io/integrations/vacuum.xiaomi_miio/ - "Retrieving the Access Token")
Modify purifier.ino with proper values:
  -token(hex)
  -purifier ip
  -network ssid
  -network password
Upload on esp8266(or wherever you want)
