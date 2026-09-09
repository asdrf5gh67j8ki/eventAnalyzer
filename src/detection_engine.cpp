#include "event_analyzer/core.hpp"
#include <algorithm>
#include <array>

namespace ea{
std::span<const rule> rules(){
    static const std::array<rule, 3> catalog{{
        {"office_spawns_powershell", "1", "Office application launched PowerShell", "medium",
         "The child record reports an Office parent and a PowerShell child image.",
         "Office automation, administrative macros, and authorized add-ins can produce this relationship."},
        {"office_spawns_script_host", "1", "Office application launched a script host", "medium",
         "The child record reports an Office parent and wscript.exe, cscript.exe, or mshta.exe as the child.",
         "Legacy business automation and authorized scripts can produce this relationship."},
        {"powershell_encoded_command", "1", "PowerShell used an encoded command argument", "low",
         "A PowerShell image has an explicit -enc, -encodedcommand, or -ec argument followed by a value.",
         "Administrative tooling and deployment systems commonly use encoded commands. No payload decoding or maliciousness inference is performed."}
    }};
    return catalog;
}
namespace{
bool office(std::string_view value){
    constexpr std::array names{"winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "msaccess.exe", "mspub.exe", "onenote.exe"};
    return std::find(names.begin(), names.end(), value) != names.end();
}
bool powershell(std::string_view value){ return value == "powershell.exe" || value == "pwsh.exe"; }
// Deliberately limited lexical tokenizer: quoted spaces are grouped. It is not
// a PowerShell parser and does not emulate shell expansion or execution.
std::vector<std::string> tokens(std::string_view command){
    std::vector<std::string> result;
    std::string token;
    char quote = 0;
    for(char c : command){
        if(c == '"' || c == '\''){
            if(quote == c){ quote = 0; }
            else if(quote == 0){ quote = c; }
            else{ token += c; }
        }else if((c == ' ' || c == '\t' || c == '\r' || c == '\n') && quote == 0){
            if(!token.empty()){ result.push_back(std::move(token)); token.clear(); }
        }else{ token += c; }
    }
    if(!token.empty()){ result.push_back(std::move(token)); }
    return result;
}
std::optional<std::string> encoded_switch(std::string_view command){
    const auto args = tokens(command);
    // A full Sysmon CommandLine includes the executable as token zero.
    for(std::size_t i = 1; i + 1 < args.size(); ++i){
        const auto arg = lower_ascii(args[i]);
        if(arg == "-command" || arg == "-c" || arg == "-file" || arg == "-f" || arg == "--"){
            break;
        }
        if(arg == "-enc" || arg == "-encodedcommand" || arg == "-ec"){
            if(!args[i + 1].empty() && args[i + 1].front() != '-'){
                return args[i];
            }
        }
    }
    return std::nullopt;
}
finding make_finding(const event& e, const rule& rule, std::string fields){
    return {0, e.id, rule.id, rule.revision, rule.title, rule.severity, rule.rationale, std::move(fields)};
}
}
std::vector<finding> detect(std::span<const event> events){
    std::vector<finding> result;
    const auto catalog = rules();
    for(const auto& e : events){
        const auto child = image_name(e.image);
        if(e.parent_image && office(image_name(*e.parent_image))){
            const auto fields = "{\"Image\":" + json_string(e.image) + ",\"ParentImage\":" + json_string(*e.parent_image) +
                ",\"parent_basis\":\"reported_by_child_event\"}";
            if(powershell(child)){ result.push_back(make_finding(e, catalog[0], fields)); }
            if(child == "wscript.exe" || child == "cscript.exe" || child == "mshta.exe"){
                result.push_back(make_finding(e, catalog[1], fields));
            }
        }
        if(powershell(child) && e.command_line){
            if(const auto flag = encoded_switch(*e.command_line)){
                result.push_back(make_finding(e, catalog[2], "{\"Image\":" + json_string(e.image) +
                    ",\"CommandLine\":" + json_string(*e.command_line) + ",\"switch\":" + json_string(*flag) + "}"));
            }
        }
    }
    return result;
}
} // namespace ea
