#include "event_analyzer/core.hpp"
#include <functional>
#include <iostream>
#include <stdexcept>
#include <utility>

namespace{
void require(bool value, const char* message){
    if(!value){ throw std::runtime_error(message); }
}
void rejects(const std::function<void()>& f){
    bool failed = false;
    try{ f(); }catch(const std::exception&){ failed = true; }
    require(failed, "operation should have rejected input");
}
std::string guid(unsigned id){
    return "00000000-0000-0000-0000-" + std::string(12 - std::to_string(id).size(), '0') + std::to_string(id);
}
std::string xml(unsigned id = 1, std::string extra = "", std::string image = "C:\\Windows\\notepad.exe"){
    return "<Event><System><Provider Name=\"Microsoft-Windows-Sysmon\"/><EventID>1</EventID><EventRecordID>42</EventRecordID><Computer>LAB</Computer></System><EventData>"
        "<Data Name=\"ProcessId\">100</Data><Data Name=\"ProcessGuid\">{" + guid(id) + "}</Data>"
        "<Data Name=\"Image\">" + image + "</Data><Data Name=\"UtcTime\">2026-09-09 12:00:00.123</Data>" + extra + "</EventData></Event>";
}
ea::event e(unsigned id, unsigned parent = 0){
    ea::event result;
    result.id = id;
    result.host = "lab";
    result.guid = guid(id);
    result.time = "2026-09-09T12:00:00.000000000Z";
    result.pid = 100;
    result.image = "C:\\test.exe";
    if(parent){ result.parent_guid = guid(parent); }
    return result;
}
}
int main(){
    using test = std::pair<const char*, std::function<void()>>;
    const std::vector<test> tests{
        {"GUID canonicalization and validation", []{
            require(ea::normalize_guid("{A0000000-0000-0000-0000-000000000001}") == "a0000000-0000-0000-0000-000000000001", "GUID case");
            rejects([]{ ea::normalize_guid("invalid"); });
        }},
        {"UTC normalization and calendar validation", []{
            require(ea::normalize_time("2024-02-29T01:02:03Z") == "2024-02-29T01:02:03.000000000Z", "UTC normalization");
            require(ea::normalize_time("2024-02-29 01:02:03.123456789") == "2024-02-29T01:02:03.123456789Z", "precision");
            rejects([]{ ea::normalize_time("2025-02-29 01:02:03"); });
            rejects([]{ ea::normalize_time("2024-02-29 24:02:03"); });
            rejects([]{ ea::normalize_time("2024-02-29 01:02:03+01:00"); });
        }},
        {"strict numeric and host validation", []{
            rejects([]{ ea::parse_uint("-1", 100); });
            rejects([]{ ea::parse_uint("10x", 100); });
            rejects([]{ ea::parse_uint("101", 100); });
            rejects([]{ ea::normalize_host("a\nb"); });
        }},
        {"Windows image semantics on any host", []{
            require(ea::image_name("C:\\Windows\\PowerShell.EXE") == "powershell.exe", "basename");
            require(ea::image_name("C:/Windows/PWSH.EXE") == "pwsh.exe", "slash basename");
        }},
        {"parse reordered fields and missing optionals", []{
            const auto batch = ea::parse_xml_bytes(xml(), "test.xml");
            require(batch.events.size() == 1 && batch.diagnostics.empty(), "valid record");
            const auto& value = batch.events[0].value;
            require(value.host == "lab" && value.pid == 100 && !value.command_line && !value.parent_guid, "normalized fields");
        }},
        {"partial import diagnostics", []{
            const auto data = "<Events>" + xml() + xml(2, "<Data Name=\"Image\">duplicate</Data>") + "</Events>";
            const auto batch = ea::parse_xml_bytes(data, "test.xml");
            require(batch.events.size() == 1 && batch.diagnostics.size() == 1 && batch.diagnostics[0].ordinal == 2, "record-level failure");
        }},
        {"malformed document and DTD rejection", []{
            rejects([]{ ea::parse_xml_bytes("<Events><Event></Events>", "bad"); });
            rejects([]{ ea::parse_xml_bytes("<!DOCTYPE Events><Events/>", "bad"); });
            rejects([]{ ea::parse_xml_bytes("<Events/><Events/>", "bad"); });
        }},
        {"required fields reject rather than default", []{
            auto data = xml();
            const auto pos = data.find("<Data Name=\"ProcessId\">100</Data>");
            data.erase(pos, std::string("<Data Name=\"ProcessId\">100</Data>").size());
            const auto result = ea::parse_xml_bytes(data, "missing");
            require(result.events.empty() && result.diagnostics.size() == 1, "missing PID");
            require(ea::parse_xml_bytes(xml(0), "zero").events.empty(), "zero GUID");
        }},
        {"unsupported event reporting", []{
            auto data = xml();
            data.replace(data.find("<EventID>1"), 10, "<EventID>3");
            const auto result = ea::parse_xml_bytes(data, "other");
            require(result.unsupported == 1 && result.diagnostics.empty(), "unsupported count");
        }},
        {"XML namespace validation", []{
            auto data = xml();
            data.replace(0, 7, "<Event xmlns=\"http://schemas.microsoft.com/win/2004/08/events/event\">");
            require(ea::parse_xml_bytes(data, "ns").events.size() == 1, "default namespace");
            rejects([]{ ea::parse_xml_bytes("<Events xmlns=\"urn:foreign\"/>", "bad"); });
        }},
        {"field limit enforced", []{
            const auto result = ea::parse_xml_bytes(xml(1, "<Data Name=\"CommandLine\">" + std::string(65537, 'x') + "</Data>"), "big");
            require(result.events.empty() && result.diagnostics.size() == 1, "oversize field");
        }},
        {"XML character validation", []{
            const auto result = ea::parse_xml_bytes(xml(1, "<Data Name=\"CommandLine\">&#x1b;</Data>"), "control");
            require(result.events.empty() && result.diagnostics.size() == 1, "ESC must be rejected");
        }},
        {"duplicate events preserve multiple sources", []{
            ea::event_store store(":memory:", ea::open_mode::create);
            auto batch = ea::parse_xml_bytes(xml(), "first.xml");
            require(store.import(batch).inserted == 1, "insert");
            const auto repeated = store.import(batch);
            require(repeated.duplicates == 1 && repeated.sources_added == 0, "idempotent import");
            batch.path = "second.xml";
            require(store.import(batch).sources_added == 1, "alternate source");
            require(store.stats().events == 1 && store.stats().sources == 2, "counts");
        }},
        {"record ID is provenance not event identity", []{
            ea::event_store store(":memory:", ea::open_mode::create);
            auto first = xml();
            auto second = first;
            second.replace(second.find("<EventRecordID>42"), 16, "<EventRecordID>43");
            store.import(ea::parse_xml_bytes(first, "same.xml"));
            const auto summary = store.import(ea::parse_xml_bytes(second, "same.xml"));
            require(summary.duplicates == 1 && summary.sources_added == 1, "record ID provenance");
        }},
        {"conflicting identity is preserved and unresolved", []{
            ea::event_store store(":memory:", ea::open_mode::create);
            store.import(ea::parse_xml_bytes(xml(1), "a"));
            store.import(ea::parse_xml_bytes(xml(1, "<Data Name=\"CommandLine\">different</Data>"), "b"));
            require(store.stats().conflicts == 1, "conflict counter");
            auto values = store.events();
            values.push_back(e(2, 1));
            ea::process_index index(values);
            require(index.parent(values.back()).status == "ambiguous_parent_identity", "ambiguous parent");
            require(index.parent(values.front()).status == "ambiguous_child_identity", "ambiguous child");
        }},
        {"PID reuse never determines ancestry", []{
            std::vector values{e(2, 1), e(3), e(1)};
            ea::process_index index(values);
            require(index.parent(values[0]).value == &values[2], "GUID-selected parent");
        }},
        {"host isolation", []{
            std::vector values{e(2, 1), e(1)};
            values[1].host = "other";
            ea::process_index index(values);
            require(index.parent(values[0]).status == "parent_unobserved", "cross-host parent");
        }},
        {"missing parent remains unresolved", []{
            std::vector values{e(2, 1)};
            ea::process_index index(values);
            require(ea::walk_ancestry(values[0], index).stop_reason == "parent_unobserved", "missing ancestry");
        }},
        {"temporal and metadata contradictions", []{
            std::vector values{e(2, 1), e(1)};
            values[1].time = "2026-09-10T12:00:00.000000000Z";
            ea::process_index index(values);
            require(index.parent(values[0]).status == "parent_timestamp_after_child", "future parent");
            values[1].time = values[0].time;
            values[0].parent_pid = 99;
            require(index.parent(values[0]).status == "parent_pid_conflict", "PID conflict");
        }},
        {"cycles and depth are bounded", []{
            std::vector values{e(1, 2), e(2, 1)};
            ea::process_index index(values);
            require(ea::walk_ancestry(values[0], index).stop_reason == "cycle", "cycle detection");
            require(ea::walk_ancestry(values[0], index, 1).stop_reason == "depth_limit", "depth bound");
        }},
        {"Office PowerShell rule matches recorded fields", []{
            auto value = e(1);
            value.image = "C:\\Windows\\PowerShell.EXE";
            value.parent_image = "C:\\Office\\WINWORD.EXE";
            const std::vector values{value};
            const auto found = ea::detect(values);
            require(found.size() == 1 && found[0].rule_id == "office_spawns_powershell", "Office rule");
            require(found[0].fields_json.find("reported_by_child_event") != std::string::npos, "basis");
        }},
        {"benign names do not match by substring", []{
            auto value = e(1);
            value.image = "C:\\Windows\\powershell.exe.backup";
            value.parent_image = "C:\\Office\\winword.exe";
            require(ea::detect(std::vector{value}).empty(), "basename exact match");
        }},
        {"encoded command lexical limits", []{
            auto value = e(1);
            value.image = "powershell.exe";
            value.command_line = "powershell.exe -NoProfile -EncodedCommand QQ==";
            require(ea::detect(std::vector{value}).size() == 1, "encoded switch");
            value.command_line = "powershell.exe -Command Write-Output '-enc QQ=='";
            require(ea::detect(std::vector{value}).empty(), "script argument should not match");
            value.command_line = "powershell.exe -enc";
            require(ea::detect(std::vector{value}).empty(), "missing argument");
        }},
        {"scan idempotence and freshness", []{
            ea::event_store store(":memory:", ea::open_mode::create);
            const auto batch = ea::parse_xml_bytes(xml(1, "<Data Name=\"ParentImage\">WINWORD.EXE</Data>", "powershell.exe"), "a");
            store.import(batch);
            require(!store.stats().scan_current, "unscanned");
            require(store.scan() == 1, "initial scan");
            const auto first_id = store.alerts()[0].id;
            store.import(batch);
            require(store.stats().scan_current, "duplicate does not stale scan");
            require(store.scan() == 1 && store.alerts()[0].id == first_id, "stable alert ID");
            store.import(ea::parse_xml_bytes(xml(2), "b"));
            require(!store.stats().scan_current, "new event stales scan");
            require(store.scan() == 1 && store.stats().scan_current, "refresh scan");
        }},
        {"timeline and evidence retrieval", []{
            ea::event_store store(":memory:", ea::open_mode::create);
            store.import(ea::parse_xml_bytes(xml(), "evidence.xml"));
            require(store.timeline("lab").size() == 1 && store.timeline("other").empty(), "host filter");
            const auto value = store.events()[0];
            require(store.sources(value.id)[0].record_id == "42", "record reference");
            rejects([&]{ store.get_event(999); });
            rejects([&]{ store.get_alert(999); });
        }},
        {"safe output escaping", []{
            require(ea::json_string("a\n\"b") == "\"a\\u000a\\\"b\"", "JSON escaping");
            require(ea::safe_text("\x1b[31m") == "\\u001b[31m", "terminal escaping");
        }}
    };
    std::size_t failed = 0;
    for(const auto& [name, function] : tests){
        try{ function(); std::cout << "PASS " << name << '\n'; }
        catch(const std::exception& error){ ++failed; std::cerr << "FAIL " << name << ": " << error.what() << '\n'; }
    }
    std::cout << tests.size() - failed << '/' << tests.size() << " tests passed\n";
    return failed == 0 ? 0 : 1;
}
