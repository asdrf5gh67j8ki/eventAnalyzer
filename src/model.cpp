#include "event_analyzer/core.hpp"
#include <charconv>
#include <chrono>
#include <limits>
#include <stdexcept>

namespace ea{
std::string lower_ascii(std::string_view value){
    std::string result(value);
    for(auto& c : result){
        if(c >= 'A' && c <= 'Z'){
            c = static_cast<char>(c + ('a' - 'A'));
        }
    }
    return result;
}
std::string normalize_host(std::string_view value){
    if(value.empty() || value.size() > 255){
        throw std::runtime_error("Computer must contain 1..255 bytes");
    }
    for(const unsigned char c : value){
        if(c <= 32 || c == 127){
            throw std::runtime_error("Computer contains whitespace or control characters");
        }
    }
    return lower_ascii(value);
}
std::string normalize_guid(std::string_view value){
    if(value.size() == 38 && value.front() == '{' && value.back() == '}'){
        value = value.substr(1, 36);
    }
    if(value.size() != 36){
        throw std::runtime_error("invalid process GUID length");
    }
    for(std::size_t i = 0; i < value.size(); ++i){
        const char c = value[i];
        const bool dash = i == 8 || i == 13 || i == 18 || i == 23;
        if(dash ? c != '-' : !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))){
            throw std::runtime_error("invalid process GUID format");
        }
    }
    return lower_ascii(value);
}
std::uint64_t parse_uint(std::string_view value, std::uint64_t maximum){
    std::uint64_t number = 0;
    const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), number);
    if(value.empty() || error != std::errc{} || end != value.data() + value.size() || number > maximum){
        throw std::runtime_error("invalid unsigned integer");
    }
    return number;
}
std::string normalize_time(std::string_view value){
    if(value.size() < 19 || value[4] != '-' || value[7] != '-' ||
       (value[10] != ' ' && value[10] != 'T') || value[13] != ':' || value[16] != ':'){
        throw std::runtime_error("UtcTime must be YYYY-MM-DD HH:MM:SS[.fraction][Z]");
    }
    const auto number = [&](std::size_t pos, std::size_t count){
        return static_cast<unsigned>(parse_uint(value.substr(pos, count), 9999));
    };
    const auto year = number(0, 4);
    const auto month = number(5, 2);
    const auto day = number(8, 2);
    const std::chrono::year_month_day date{std::chrono::year{static_cast<int>(year)}, std::chrono::month{month}, std::chrono::day{day}};
    if(year == 0 || !date.ok() || number(11, 2) > 23 || number(14, 2) > 59 || number(17, 2) > 59){
        throw std::runtime_error("UtcTime contains an invalid date or time");
    }
    auto tail = value.substr(19);
    if(!tail.empty() && tail.back() == 'Z'){
        tail.remove_suffix(1);
    }
    std::string fraction;
    if(!tail.empty()){
        if(tail.front() != '.' || tail.size() < 2 || tail.size() > 10){
            throw std::runtime_error("UtcTime fraction must contain 1..9 digits; offsets are unsupported");
        }
        fraction = tail.substr(1);
        for(char c : fraction){
            if(c < '0' || c > '9'){
                throw std::runtime_error("invalid UtcTime fraction");
            }
        }
    }
    fraction.resize(9, '0');
    std::string result(value.substr(0, 19));
    result[10] = 'T';
    return result + "." + fraction + "Z";
}
std::string image_name(std::string_view value){
    const auto pos = value.find_last_of("/\\");
    return lower_ascii(pos == std::string_view::npos ? value : value.substr(pos + 1));
}
std::string json_string(std::string_view value){
    constexpr char hex[] = "0123456789abcdef";
    std::string result = "\"";
    for(const unsigned char c : value){
        if(c == '"' || c == '\\'){
            result += '\\';
            result += static_cast<char>(c);
        }else if(c < 32 || c == 127){
            result += "\\u00";
            result += hex[c >> 4];
            result += hex[c & 15];
        }else{
            result += static_cast<char>(c);
        }
    }
    return result + '"';
}
std::string safe_text(std::string_view value){
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    for(const unsigned char c : value){
        if(c < 32 || c == 127){
            result += "\\u00";
            result += hex[c >> 4];
            result += hex[c & 15];
        }else{
            result += static_cast<char>(c);
        }
    }
    return result;
}
std::filesystem::path utf8_path(std::string_view value){
    std::u8string converted;
    converted.reserve(value.size());
    for(unsigned char c : value){ converted.push_back(static_cast<char8_t>(c)); }
    return std::filesystem::path(converted);
}
std::string path_utf8(const std::filesystem::path& path){
    const auto u8 = path.u8string();
    return {reinterpret_cast<const char*>(u8.data()), u8.size()};
}
namespace{
std::string optional_json(const std::optional<std::string>& value){
    return value ? json_string(*value) : "null";
}
}
std::string event_json(const event& e){
    return "{\"id\":" + std::to_string(e.id) + ",\"host\":" + json_string(e.host) +
        ",\"process_guid\":" + json_string(e.guid) + ",\"parent_guid\":" + optional_json(e.parent_guid) +
        ",\"time\":" + json_string(e.time) + ",\"pid\":" + std::to_string(e.pid) +
        ",\"parent_pid\":" + (e.parent_pid ? std::to_string(*e.parent_pid) : "null") +
        ",\"image\":" + json_string(e.image) + ",\"command_line\":" + optional_json(e.command_line) +
        ",\"reported_parent_image\":" + optional_json(e.parent_image) +
        ",\"user\":" + optional_json(e.user) + ",\"hashes\":" + optional_json(e.hashes) + "}";
}
std::string finding_json(const finding& f){
    return "{\"id\":" + std::to_string(f.id) + ",\"event_id\":" + std::to_string(f.event_id) +
        ",\"rule_id\":" + json_string(f.rule_id) + ",\"rule_version\":" + json_string(f.rule_version) +
        ",\"title\":" + json_string(f.title) + ",\"severity\":" + json_string(f.severity) +
        ",\"assessment\":\"suspicious; not confirmed malicious\",\"reason\":" + json_string(f.reason) +
        ",\"matched_fields\":" + f.fields_json + "}";
}
} // namespace ea
