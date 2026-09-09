#include "event_analyzer/core.hpp"
#include <pugixml.hpp>
#include <fstream>
#include <limits>
#include <map>
#include <sstream>
#include <stdexcept>

namespace ea{
namespace{
constexpr std::string_view event_namespace = "http://schemas.microsoft.com/win/2004/08/events/event";
std::string_view local_name(std::string_view name){
    const auto colon = name.find(':');
    return colon == std::string_view::npos ? name : name.substr(colon + 1);
}
bool named(pugi::xml_node node, std::string_view name){
    if(node.type() != pugi::node_element || local_name(node.name()) != name){
        return false;
    }
    const std::string full = node.name();
    const auto colon = full.find(':');
    const auto declaration = colon == std::string::npos ? "xmlns" : "xmlns:" + full.substr(0, colon);
    for(auto scope = node; scope; scope = scope.parent()){
        if(const auto attr = scope.attribute(declaration.c_str())){
            return std::string_view(attr.value()) == event_namespace || (colon == std::string::npos && std::string_view(attr.value()).empty());
        }
    }
    return colon == std::string::npos;
}
pugi::xml_node child(pugi::xml_node node, std::string_view name, bool required = true){
    pugi::xml_node result;
    for(const auto c : node.children()){
        if(named(c, name)){
            if(result){
                throw std::runtime_error("duplicate element: " + std::string(name));
            }
            result = c;
        }
    }
    if(!result && required){
        throw std::runtime_error("missing element: " + std::string(name));
    }
    return result;
}
// XML text is UTF-8 after pugixml's encoding conversion. Reject invalid scalar
// values rather than passing terminal controls or malformed UTF-8 to output.
void validate_text(std::string_view value){
    if(value.size() > 65536){
        throw std::runtime_error("field exceeds 64 KiB");
    }
    for(std::size_t i = 0; i < value.size();){
        const auto first = static_cast<unsigned char>(value[i++]);
        std::uint32_t cp = first;
        unsigned extra = 0;
        std::uint32_t minimum = 0;
        if(first >= 0xc2 && first <= 0xdf){ extra = 1; cp &= 31; minimum = 0x80; }
        else if(first >= 0xe0 && first <= 0xef){ extra = 2; cp &= 15; minimum = 0x800; }
        else if(first >= 0xf0 && first <= 0xf4){ extra = 3; cp &= 7; minimum = 0x10000; }
        else if(first >= 0x80){ throw std::runtime_error("invalid UTF-8 field"); }
        for(unsigned n = 0; n < extra; ++n){
            if(i >= value.size() || (static_cast<unsigned char>(value[i]) & 0xc0) != 0x80){
                throw std::runtime_error("invalid UTF-8 field");
            }
            cp = (cp << 6) | (static_cast<unsigned char>(value[i++]) & 63);
        }
        if(cp < minimum || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ||
           (cp < 32 && cp != 9 && cp != 10 && cp != 13) || cp == 0xfffe || cp == 0xffff){
            throw std::runtime_error("invalid XML character in field");
        }
    }
}
std::string text(pugi::xml_node node){
    std::string result;
    for(const auto c : node.children()){
        if(c.type() == pugi::node_pcdata || c.type() == pugi::node_cdata){
            result += c.value();
        }else if(c.type() == pugi::node_element){
            throw std::runtime_error("nested element inside scalar field");
        }
    }
    validate_text(result);
    return result;
}
using fields = std::map<std::string, std::string>;
std::optional<std::string> optional_field(const fields& data, const char* name){
    const auto it = data.find(name);
    if(it == data.end() || it->second == "-"){
        return std::nullopt;
    }
    return it->second;
}
std::string required_field(const fields& data, const char* name){
    const auto value = optional_field(data, name);
    if(!value || value->empty()){
        throw std::runtime_error("missing required field: " + std::string(name));
    }
    return *value;
}
void append_identity(std::string& target, std::string_view value){
    target += std::to_string(value.size());
    target += ':';
    target += value;
}
}

import_batch parse_xml_bytes(std::string_view bytes, std::string source){
    if(bytes.size() > max_input_bytes){
        throw std::runtime_error("input exceeds 128 MiB limit");
    }
    pugi::xml_document doc;
    const auto parsed = doc.load_buffer(bytes.data(), bytes.size(), pugi::parse_default | pugi::parse_doctype);
    if(!parsed){
        throw std::runtime_error("XML parse error at offset " + std::to_string(parsed.offset) + ": " + parsed.description());
    }
    std::size_t roots = 0;
    for(const auto node : doc.children()){
        if(node.type() == pugi::node_doctype){
            throw std::runtime_error("DOCTYPE declarations are not supported");
        }
        if(node.type() == pugi::node_element){ ++roots; }
    }
    if(roots != 1){
        throw std::runtime_error("expected one XML document element");
    }
    import_batch batch;
    batch.path = std::move(source);
    const auto root = doc.document_element();
    std::size_t ordinal = 0;
    const auto process = [&](pugi::xml_node node){
        ++ordinal;
        if(ordinal > max_events){
            throw std::runtime_error("input exceeds 250000 record limit");
        }
        try{
            if(!named(node, "Event")){
                throw std::runtime_error("expected Event element in the Windows event namespace");
            }
            const auto system = child(node, "System");
            const auto provider = child(system, "Provider");
            if(std::string_view(provider.attribute("Name").value()) != "Microsoft-Windows-Sysmon"){
                ++batch.unsupported;
                return;
            }
            const auto event_id = parse_uint(text(child(system, "EventID")), 65535);
            if(event_id != 1){
                ++batch.unsupported;
                return;
            }
            fields data;
            for(const auto entry : child(node, "EventData").children()){
                if(entry.type() != pugi::node_element){ continue; }
                if(!named(entry, "Data") || !entry.attribute("Name")){
                    throw std::runtime_error("expected named Data element");
                }
                std::string name = entry.attribute("Name").value();
                validate_text(name);
                if(name.empty() || !data.emplace(name, text(entry)).second){
                    throw std::runtime_error("empty or duplicate EventData field name");
                }
            }
            imported_event record;
            auto& e = record.value;
            e.host = normalize_host(text(child(system, "Computer")));
            e.guid = normalize_guid(required_field(data, "ProcessGuid"));
            if(e.guid == "00000000-0000-0000-0000-000000000000"){
                throw std::runtime_error("ProcessGuid cannot be zero");
            }
            e.time = normalize_time(required_field(data, "UtcTime"));
            e.image = required_field(data, "Image");
            e.pid = static_cast<std::uint32_t>(parse_uint(required_field(data, "ProcessId"), UINT32_MAX));
            if(const auto parent = optional_field(data, "ParentProcessGuid"); parent && !parent->empty()){
                const auto guid = normalize_guid(*parent);
                if(guid != "00000000-0000-0000-0000-000000000000"){
                    e.parent_guid = guid;
                }
            }
            if(const auto pid = optional_field(data, "ParentProcessId"); pid && !pid->empty()){
                e.parent_pid = static_cast<std::uint32_t>(parse_uint(*pid, UINT32_MAX));
            }
            e.command_line = optional_field(data, "CommandLine");
            e.parent_image = optional_field(data, "ParentImage");
            e.user = optional_field(data, "User");
            e.hashes = optional_field(data, "Hashes");
            if(const auto id = child(system, "EventRecordID", false)){
                record.record_id = std::to_string(parse_uint(text(id), UINT64_MAX));
            }
            record.ordinal = ordinal;
            std::ostringstream xml;
            pugi::xml_document evidence;
            auto copy = evidence.append_copy(node);
            // Preserve namespace declarations inherited from an Events wrapper.
            for(auto scope = node.parent(); scope; scope = scope.parent()){
                for(const auto attr : scope.attributes()){
                    const std::string_view name = attr.name();
                    if((name == "xmlns" || name.starts_with("xmlns:")) && !copy.attribute(attr.name())){
                        copy.append_attribute(attr.name()).set_value(attr.value());
                    }
                }
            }
            copy.print(xml, "", pugi::format_raw);
            record.xml = xml.str();
            if(record.xml.size() > 1024 * 1024){
                throw std::runtime_error("record exceeds 1 MiB limit");
            }
            // EventRecordID and export path are provenance, not identity.
            // All EventData fields participate, including unknown fields.
            data["ProcessGuid"] = e.guid;
            data["UtcTime"] = e.time;
            data["ProcessId"] = std::to_string(e.pid);
            if(data.contains("ParentProcessGuid") && e.parent_guid){ data["ParentProcessGuid"] = *e.parent_guid; }
            if(e.parent_pid){ data["ParentProcessId"] = std::to_string(*e.parent_pid); }
            append_identity(record.identity, "sysmon:1:identity-v1");
            append_identity(record.identity, e.host);
            for(const auto& [name, value] : data){
                append_identity(record.identity, name);
                append_identity(record.identity, value);
            }
            batch.events.push_back(std::move(record));
        }catch(const std::runtime_error& error){
            batch.diagnostics.push_back({ordinal, error.what()});
        }
    };
    if(named(root, "Event")){
        process(root);
    }else if(named(root, "Events")){
        for(const auto node : root.children()){
            if(node.type() == pugi::node_element){ process(node); }
        }
    }else{
        throw std::runtime_error("expected Event or Events XML root");
    }
    return batch;
}
import_batch parse_xml(const std::filesystem::path& file){
    std::ifstream stream(file, std::ios::binary);
    if(!stream){ throw std::runtime_error("cannot open XML input"); }
    std::string bytes;
    char buffer[65536];
    while(stream){
        stream.read(buffer, sizeof(buffer));
        const auto count = static_cast<std::size_t>(stream.gcount());
        if(count > max_input_bytes - bytes.size()){
            throw std::runtime_error("input exceeds 128 MiB limit");
        }
        bytes.append(buffer, count);
    }
    if(!stream.eof()){ throw std::runtime_error("error reading XML input"); }
    return parse_xml_bytes(bytes, path_utf8(std::filesystem::absolute(file).lexically_normal()));
}
} // namespace ea
