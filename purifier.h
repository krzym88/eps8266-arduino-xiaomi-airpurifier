#include "ArduinoMD5/MD5.cpp"
#include "arduino-crypto/Crypto.cpp"
#include <ArduinoJson.h>
#include <WiFiUdp.h>
#include <string>
#include <vector>
#include <list>

using bin_t = std::vector<uint8_t>;
using hex_t = std::string;

namespace
{
    template <typename T>
    inline std::vector<T> operator+(const std::vector<T> &A, const std::vector<T> &B)
    {
        std::vector<T> AB;
        AB.reserve( A.size() + B.size() );        
        AB.insert( AB.end(), A.begin(), A.end() );
        AB.insert( AB.end(), B.begin(), B.end() );
        return AB;
    }
}


bin_t hex_to_bin(const hex_t& input)
{
    static const char* const lut = "0123456789abcdef";
    size_t len = input.size();
    if (len & 1) return bin_t();
    
    bin_t output;
    output.reserve(len / 2);
    for (size_t i = 0; i < len; i += 2)
    {
        char a = input[i];
        const char* p = std::lower_bound(lut, lut + 16, a);
        if (*p != a) return bin_t();

        char b = input[i + 1];
        const char* q = std::lower_bound(lut, lut + 16, b);
        if (*q != b) return bin_t();

        output.push_back(((p - lut) << 4) | (q - lut));
    }
    return output;
}

hex_t bin_to_hex(const bin_t& input)
{
    static const char* const lut = "0123456789abcdef";
    size_t len = input.size();

    hex_t output;
    output.reserve(2 * len);
    for (size_t i = 0; i < len; ++i)
    {
        const unsigned char c = input[i];
        output.push_back(lut[c >> 4]);
        output.push_back(lut[c & 15]);
    }
    return output;
}

std::string Pkcs7Padding(const std::string& in)
{
    char npad = 16 - in.size() % 16;
    char* pad = &npad;

    std::string out = in;
    for (char i = 0; i < npad; i++)
        out += npad;

    return out;
}

hex_t md5(const bin_t& in)
{
    unsigned char* hash = MD5::make_hash((char*)in.data(), in.size());
    char* md5str = MD5::make_digest(hash, 16);
    free(hash);
    hex_t out(md5str, md5str + strlen(md5str));
    free(md5str);
    return out;
}

void schedule_discover(WiFiUDP& udp, IPAddress& ip)
{
    bin_t hello_bytes = hex_to_bin("21310020ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    udp.beginPacket(ip, 54321);
    udp.write(hello_bytes.data(), hello_bytes.size());
    udp.endPacket();
}

bin_t int16_to_bin(short i)
{
    bin_t result;
    result.reserve(2);
    result.push_back(((char*)&i)[1]);
    result.push_back(((char*)&i)[0]);
    return result;
}

bin_t int32_to_bin(unsigned i)
{
    bin_t result;
    result.reserve(4);
    result.push_back(((char*)&i)[3]);
    result.push_back(((char*)&i)[2]);
    result.push_back(((char*)&i)[1]);
    result.push_back(((char*)&i)[0]);
    return result;
}

bin_t encrypt(const std::string& in, const bin_t& token)
{
    bin_t key_bin = hex_to_bin(md5(token));
    bin_t iv_bin = hex_to_bin(md5(key_bin + token));
    AES aes(key_bin.data(), iv_bin.data(), AES::AES_MODE_128, AES::CIPHER_ENCRYPT);
    std::string in_padded = Pkcs7Padding(in);
    bin_t out;
    out.resize(in_padded.size());
    aes.processNoPad((uint8_t*)in_padded.c_str(), out.data(), in_padded.size());
    return out;
}

std::string decrypt(const bin_t& in, const bin_t& token)
{
    bin_t key_bin = hex_to_bin(md5(token));
    bin_t iv_bin = hex_to_bin(md5(key_bin + token));
    AES aes(key_bin.data(), iv_bin.data(), AES::AES_MODE_128, AES::CIPHER_DECRYPT);   
    uint8_t data_decrypted[in.size()];
    aes.processNoPad(in.data(), data_decrypted, in.size());
    return std::string(data_decrypted, data_decrypted + in.size());
}

unsigned int get_int(char* c, short offset)
{
    unsigned int n = *(unsigned int*)(c + offset);
    n = 	(n >> 24) |			
            ((n << 8) & 0x00FF0000) |
            ((n >> 8) & 0x0000FF00) |
            (n << 24);
    return n;
}

template<typename T>
void send_cmd(const std::string& cmd, const T& arg, unsigned device_id, unsigned ts, unsigned id, const bin_t& token, WiFiUDP& udp, IPAddress& ip)
{
    StaticJsonDocument<1024> doc;
    doc["id"] = id;
    doc["method"] = cmd.c_str();
    JsonArray params = doc.createNestedArray("params");
    params.add(arg);
    String _cmd_json;
    serializeJson(doc, _cmd_json);
    std::string cmd_json = std::string(_cmd_json.c_str()) + std::string(1,'\0');
    bin_t data = encrypt(cmd_json, token);
    short length = data.size() + 16/*header*/ + 16/*checksum*/;
    bin_t header = hex_to_bin("2131") + int16_to_bin(length) + hex_to_bin("00000000") + int32_to_bin(device_id) + int32_to_bin(ts + 1);
    bin_t checksum = hex_to_bin(md5(header + token + data));
    bin_t msg = header + checksum + data;
    udp.beginPacket(ip, 54321);
    udp.write(msg.data(), msg.size());
    udp.endPacket();    
}

enum class Result
{
    Ok,
    Nothing,
    Error
};

namespace
{

template<typename T = int>
Result read_response(unsigned& device_id, unsigned& ts, unsigned& id, const bin_t& token, WiFiUDP& udp, T* result = NULL)
{
    int packetSize = udp.parsePacket();
    if(packetSize == 0)
        return Result::Nothing;

    char response[1024];
    int length = udp.read(response, 1024);
    if (length > 0)
        response[length] = 0;

    if(length <=16)
    {
        id += 100;
        return Result::Error;
    }

    device_id = get_int(response, 8);
    ts = get_int(response, 12);

    bin_t header(response + 0, response + 16);
    bin_t checksum(response + 16, response + 32);
    bin_t data(response + 32, response + length);
    bin_t proper_checksum = hex_to_bin(md5(header + token + data));

    if(proper_checksum != checksum && checksum != hex_to_bin("00000000000000000000000000000000"))
    {
        hex_t proper_checksum_hex = bin_to_hex(proper_checksum);
        hex_t checksum_hex = bin_to_hex(checksum);

        Serial.printf("checksum error proper %s real %s\n", proper_checksum_hex.c_str(), checksum_hex.c_str());
        id += 100;
        return Result::Error;
    }

    std::string json_txt = decrypt(data, token);
    auto it = json_txt.find_last_of('}');
    json_txt = json_txt.substr(0,it + 1);
    
    StaticJsonDocument<512> doc;
    deserializeJson(doc, json_txt);
    const JsonObject args = doc.as<JsonObject>();
    if (args.containsKey("id"))
        id = args["id"].as<unsigned>();
    if (args.containsKey("error"))
    {
        Serial.println(args["error"].as<String>());
        return Result::Error;
    }
    if (args.containsKey("result"))
    {
        auto array = args["result"].as<JsonArray>();
        for(JsonVariant v : array)
        {
            if(v.is<T>())
            {
                if(result)
                    *result = v.as<T>();
                return Result::Ok;
            }
            else
            {
                Serial.println("wrong result type");
                id += 100;
                return Result::Error;
            }
        }
    }

    return Result::Ok;
}

}

enum class PuriferCommunicationState
{
    Start,
    DiscoverSend,
    DiscoverGet,
    AQISend,
    AQIGet,
    LevelSend,
    LevelGet
};

void handle_purifier(WiFiUDP& udp, IPAddress& ip, const hex_t& _token)
{
    static unsigned device_id = 0;
    static unsigned ts = 0;
    static unsigned id = 0;
    static PuriferCommunicationState state = PuriferCommunicationState::Start;
    static short aqi = 0;
    static std::list<short> levels = {0,0,0,0,0};
    static unsigned wait_cnt = 0;

    static unsigned long run_time = 0;

    if(run_time > millis())
        return;

    bin_t token = hex_to_bin(_token);
    

    switch (state)
    {
    case PuriferCommunicationState::Start:
    {
        state = PuriferCommunicationState::DiscoverSend;
        run_time = millis() + 20000;
        break;
    }
    case PuriferCommunicationState::DiscoverSend:
    {
        schedule_discover(udp, ip);
        wait_cnt = 100;
        state = PuriferCommunicationState::DiscoverGet;
        break;
    }
    case PuriferCommunicationState::DiscoverGet:
    {
        if(wait_cnt == 0)
        {
            Serial.println("discover timeout");
            state = PuriferCommunicationState::Start;
            break;
        }
        switch(read_response(device_id, ts, id, token, udp))
        {
            case Result::Nothing:
                wait_cnt--;
                run_time = millis() + 10;
                break;
            case Result::Ok:
                state = PuriferCommunicationState::AQISend;
                break;
            case Result::Error:
                state = PuriferCommunicationState::Start;
                break;
        }
        break;
    }
    case PuriferCommunicationState::AQISend:
    {
        send_cmd("get_prop", "aqi", device_id, ts, ++id, token, udp, ip);
        wait_cnt = 100;
        state = PuriferCommunicationState::AQIGet;
        break;
    }
    case PuriferCommunicationState::AQIGet:
    {
        if(wait_cnt == 0)
        {
            Serial.println("get aqi timeout");
            state = PuriferCommunicationState::Start;
            break;
        }
        switch(read_response(device_id, ts, id, token, udp, &aqi))
        {
            case Result::Nothing:
                wait_cnt--;
                run_time = millis() + 10;
                break;
            case Result::Ok:
                state = PuriferCommunicationState::LevelSend;
                break;
            case Result::Error:
                state = PuriferCommunicationState::Start;
                break;
        }
        break;
    }
    case PuriferCommunicationState::LevelSend:
    {
        short level = 0;
        if(aqi > 17)
            level = 14;
        else if(aqi > 2)
            level = (aqi - 3) / 1;

        levels.push_back(level);
        levels.pop_front();
        float avg_level = std::accumulate(levels.begin(), levels.end(), 0) / static_cast<float>(levels.size());
        send_cmd("set_level_favorite", static_cast<int>(std::roundf(avg_level)), device_id, ts, ++id, token, udp, ip);
        wait_cnt = 100;
        state = PuriferCommunicationState::LevelGet;
        break;
    }
    case PuriferCommunicationState::LevelGet:
    {
        if(wait_cnt == 0)
        {
            Serial.println("get level timeout");
            state = PuriferCommunicationState::Start;
            break;
        }
        String result_txt;
        switch(read_response(device_id, ts, id, token, udp, &result_txt))
        {
            case Result::Nothing:
                wait_cnt--;
                run_time = millis() + 10;
                break;
            case Result::Ok:
                if(result_txt == "ok")
                {
                    state = PuriferCommunicationState::Start;
                    break;
                }
            case Result::Error:
                state = PuriferCommunicationState::Start;
                break;
        }
        break;
    }
    default:
        break;
    }
}
