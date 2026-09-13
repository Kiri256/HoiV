#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

static void emit_ascii(const std::vector<unsigned char>& data, const char* needle) {
    const size_t n = std::char_traits<char>::length(needle);
    size_t count = 0;
    for (size_t i = 0; i + n < data.size(); ++i) {
        if (std::memcmp(data.data() + i, needle, n) == 0) {
            size_t begin = i;
            while (begin > 0 && data[begin - 1] >= 32 && data[begin - 1] < 127 && (i - begin) < 80) {
                --begin;
            }
            size_t end = i + n;
            while (end < data.size() && data[end] >= 32 && data[end] < 127 && (end - begin) < 160) {
                ++end;
            }
            std::printf("0x%08zx %.*s\n", i, static_cast<int>(end - begin), reinterpret_cast<const char*>(data.data() + begin));
            ++count;
            if (count >= 20) {
                break;
            }
        }
    }
    if (count == 0) {
        std::printf("MISSING %s\n", needle);
    }
}

int main(int argc, char** argv) {
    if (argc < 2) {
        return 1;
    }
    std::ifstream in(argv[1], std::ios::binary);
    if (!in) {
        return 2;
    }
    std::vector<unsigned char> data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    std::printf("size=%zu\n", data.size());
    const char* needles[] = {
        ".?AVCGameState",
        ".?AVCCountry",
        ".?AVCDivision",
        ".?AVCArmy",
        ".?AVCUnit",
        "CGameState",
        "CCountry",
        "CDivision",
        "HandleHourlyTick",
        "DailyUpdateSerial",
        "organisation",
        "organization",
        "player_country",
        "GetPlayer",
        "current country",
        "HOI4",
    };
    for (const char* needle : needles) {
        std::printf("--- %s ---\n", needle);
        emit_ascii(data, needle);
    }
    return 0;
}
