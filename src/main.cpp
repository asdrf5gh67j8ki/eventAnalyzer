#include "event_analyzer/core.hpp"
#include <algorithm>
#include <iostream>
#include <limits>
#include <stdexcept>
#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#endif

namespace{
struct usage_error : std::runtime_error{ using std::runtime_error::runtime_error; };
struct options{
    std::filesystem::path database = "events.db";
    bool json = false;
    bool strict = false;
    bool raw = false;
    std::vector<std::string> args;
};
void help(){
    std::cout << R"(eventAnalyzer 1.0.0 - offline Sysmon process investigation

Usage: eventAnalyzer [--db PATH] [--json] COMMAND

  import FILE.xml [--strict]  Import Sysmon Event ID 1 XML records
  scan                       Evaluate the three built-in rules
  alerts                     List persisted alerts and scan freshness
  explain ALERT_ID           Show matched fields, sources and ancestry
  event EVENT_ID [--raw]      Inspect an event; --raw prints evidence XML
  tree EVENT_ID              Follow observed ancestry, child first
  timeline HOST              List process creations for one host in UTC order
  stats                      Show counts, identity conflicts and scan freshness
  rules                      Describe detection logic and false positives
  --help                     Show this help
  --version                  Show the application version

The default database is events.db. Only import creates a database.
--strict rejects the entire import if any record is invalid. Otherwise valid
records are committed and invalid records are reported with exit status 1.
--raw applies only to event and cannot be combined with --json.
Limits: 128 MiB input, 250000 records per file/database, 256 ancestry levels.
Findings indicate suspicious activity, not confirmed malicious execution.
Exit codes: 0 success, 1 operation failure/partial import, 2 invalid arguments.
)";
}
options parse_options(std::span<const std::string> args){
    options o;
    bool db_set = false;
    bool positional_only = false;
    for(std::size_t i = 0; i < args.size(); ++i){
        const auto& value = args[i];
        if(value == "--" && !positional_only){ positional_only = true; }
        else if(value == "--db" && !positional_only){
            if(db_set || ++i >= args.size() || args[i].empty()){ throw usage_error("--db requires one nonempty path"); }
            o.database = ea::utf8_path(args[i]);
            db_set = true;
        }else if(value == "--json" && !positional_only){ o.json = true; }
        else if(value == "--strict" && !positional_only){ o.strict = true; }
        else if(value == "--raw" && !positional_only){ o.raw = true; }
        else if(!positional_only && value.starts_with("--") && value != "--help" && value != "--version"){
            throw usage_error("unknown option: " + value);
        }else{ o.args.push_back(value); }
    }
    if(o.args.empty()){ o.args.push_back("--help"); }
    const auto& command = o.args[0];
    if(o.strict && command != "import"){ throw usage_error("--strict applies only to import"); }
    if(o.raw && (command != "event" || o.json)){ throw usage_error("--raw requires event without --json"); }
    return o;
}
ea::id_type positive_id(const std::string& value){
    try{
        const auto id = ea::parse_uint(value, static_cast<std::uint64_t>(std::numeric_limits<ea::id_type>::max()));
        if(id == 0){ throw usage_error("ID must be positive"); }
        return static_cast<ea::id_type>(id);
    }catch(const std::runtime_error&){ throw usage_error("ID must be a positive integer"); }
}
void count_args(const options& o, std::size_t count){
    if(o.args.size() != count){ throw usage_error("wrong argument count; use --help"); }
}
std::string boolean(bool value){ return value ? "true" : "false"; }
std::string sources_json(const std::vector<ea::source_record>& sources){
    std::string result = "[";
    bool first = true;
    for(const auto& s : sources){
        if(!first){ result += ','; }
        first = false;
        result += "{\"path\":" + ea::json_string(s.path) + ",\"ordinal\":" + std::to_string(s.ordinal) +
            ",\"event_record_id\":" + (s.record_id ? ea::json_string(*s.record_id) : "null") + "}";
    }
    return result + ']';
}
void event_line(const ea::event& e){
    std::cout << e.id << "  " << e.time << "  " << ea::safe_text(e.host) << "  PID=" << e.pid
              << "  " << ea::safe_text(e.image) << "  GUID=" << e.guid << '\n';
}
void print_ancestry(const ea::ancestry& ancestry, const ea::process_index& index){
    std::size_t depth = 0;
    for(const auto* e : ancestry.nodes){
        std::cout << "Depth " << depth++ << ": ";
        event_line(*e);
        if(index.ambiguous(*e)){ std::cout << "  Identity has conflicting records.\n"; }
    }
    std::cout << "Ancestry stopped: " << ancestry.stop_reason << '\n';
}
int run(const options& o){
    const auto& cmd = o.args[0];
    if(cmd == "--help"){ count_args(o, 1); help(); return 0; }
    if(cmd == "--version"){ count_args(o, 1); std::cout << ea::version << '\n'; return 0; }
    if(cmd == "rules"){
        count_args(o, 1);
        if(o.json){ std::cout << '['; }
        bool first = true;
        for(const auto& r : ea::rules()){
            if(o.json){
                if(!first){ std::cout << ','; }
                std::cout << "{\"id\":" << ea::json_string(r.id) << ",\"version\":" << ea::json_string(r.revision)
                          << ",\"title\":" << ea::json_string(r.title) << ",\"severity\":" << ea::json_string(r.severity)
                          << ",\"rationale\":" << ea::json_string(r.rationale)
                          << ",\"false_positives\":" << ea::json_string(r.false_positives) << '}';
            }else{
                std::cout << r.id << " v" << r.revision << " [" << r.severity << "]\n"
                          << r.rationale << "\nFalse positives: " << r.false_positives << "\n\n";
            }
            first = false;
        }
        if(o.json){ std::cout << "]\n"; }
        return 0;
    }
    if(cmd == "import"){
        count_args(o, 2);
        const auto batch = ea::parse_xml(ea::utf8_path(o.args[1]));
        const bool rejected = o.strict && !batch.diagnostics.empty();
        ea::import_summary summary;
        if(!rejected){
            ea::event_store store(o.database, ea::open_mode::create);
            summary = store.import(batch);
        }
        if(o.json){
            std::cout << "{\"inserted\":" << summary.inserted << ",\"duplicates\":" << summary.duplicates
                      << ",\"sources_added\":" << summary.sources_added << ",\"unsupported\":" << batch.unsupported
                      << ",\"rejected\":" << boolean(rejected) << ",\"diagnostics\":[";
            bool first = true;
            for(const auto& d : batch.diagnostics){
                if(!first){ std::cout << ','; }
                first = false;
                std::cout << "{\"ordinal\":" << d.ordinal << ",\"message\":" << ea::json_string(d.message) << '}';
            }
            std::cout << "]}\n";
        }else{
            std::cout << "Imported: " << summary.inserted << " | Duplicates: " << summary.duplicates
                      << " | Source references added: " << summary.sources_added << " | Unsupported: " << batch.unsupported << '\n';
            if(rejected){ std::cerr << "Strict import rejected; database unchanged.\n"; }
            for(const auto& d : batch.diagnostics){
                std::cerr << "Record " << d.ordinal << ": " << ea::safe_text(d.message) << '\n';
            }
        }
        return batch.diagnostics.empty() ? 0 : 1;
    }
    const bool single = cmd == "scan" || cmd == "alerts" || cmd == "stats";
    const bool double_arg = cmd == "explain" || cmd == "event" || cmd == "tree" || cmd == "timeline";
    if(!single && !double_arg){ throw usage_error("unknown command: " + cmd); }
    count_args(o, single ? 1 : 2);
    // Validate IDs before opening the case database.
    const auto id = double_arg && cmd != "timeline" ? positive_id(o.args[1]) : 0;
    ea::event_store store(o.database, cmd == "scan" ? ea::open_mode::read_write : ea::open_mode::read_only);
    if(cmd == "scan"){
        const auto found = store.scan();
        if(o.json){ std::cout << "{\"alerts\":" << found << ",\"scan_current\":true}\n"; }
        else{ std::cout << "Scan complete: " << found << " alerts.\n"; }
        return 0;
    }
    store.begin_read();
    if(cmd == "stats"){
        const auto s = store.stats();
        if(o.json){
            std::cout << "{\"events\":" << s.events << ",\"source_records\":" << s.sources << ",\"alerts\":" << s.alerts
                      << ",\"identity_conflicts\":" << s.conflicts << ",\"scan_current\":" << boolean(s.scan_current) << "}\n";
        }else{
            std::cout << "Events: " << s.events << "\nSource records: " << s.sources << "\nAlerts: " << s.alerts
                      << "\nConflicting process identities: " << s.conflicts << "\nScan current: " << boolean(s.scan_current) << '\n';
        }
        return 0;
    }
    if(cmd == "alerts"){
        const auto current = store.stats().scan_current;
        const auto alerts = store.alerts();
        if(o.json){ std::cout << "{\"scan_current\":" << boolean(current) << ",\"alerts\":["; }
        else if(!current){ std::cout << "Scan is absent or stale. Run scan for current results.\n"; }
        bool first = true;
        for(const auto& f : alerts){
            if(o.json){ if(!first){ std::cout << ','; } std::cout << ea::finding_json(f); }
            else{ std::cout << f.id << " [" << f.severity << "] " << f.title << " | event=" << f.event_id << '\n'; }
            first = false;
        }
        if(o.json){ std::cout << "]}\n"; }
        return 0;
    }
    if(cmd == "timeline"){
        const auto values = store.timeline(ea::normalize_host(o.args[1]));
        if(o.json){ std::cout << '['; }
        bool first = true;
        for(const auto& e : values){
            if(o.json){ if(!first){ std::cout << ','; } std::cout << ea::event_json(e); }
            else{ event_line(e); }
            first = false;
        }
        if(o.json){ std::cout << "]\n"; }
        return 0;
    }
    if(cmd == "event"){
        const auto e = store.get_event(id);
        const auto sources = store.sources(id);
        if(o.raw){
            std::cout << "<EvidenceRecords>\n";
            for(const auto& s : sources){ std::cout << s.xml << '\n'; }
            std::cout << "</EvidenceRecords>\n";
        }else if(o.json){
            std::cout << "{\"event\":" << ea::event_json(e) << ",\"sources\":" << sources_json(sources) << "}\n";
        }else{
            event_line(e);
            std::cout << "Command line: " << ea::safe_text(e.command_line.value_or("<unavailable>")) << '\n';
            for(const auto& s : sources){
                std::cout << "Source: " << ea::safe_text(s.path) << " | ordinal=" << s.ordinal
                          << " | EventRecordID=" << s.record_id.value_or("<unavailable>") << '\n';
            }
        }
        return 0;
    }
    const auto values = store.events();
    const ea::process_index index(values);
    const auto finding = cmd == "explain" ? std::optional<ea::finding>(store.get_alert(id)) : std::nullopt;
    const auto subject_id = finding ? finding->event_id : id;
    const auto it = std::find_if(values.begin(), values.end(), [&](const auto& e){ return e.id == subject_id; });
    if(it == values.end()){ throw std::runtime_error("event ID not found"); }
    const auto ancestry = ea::walk_ancestry(*it, index);
    if(o.json){
        std::cout << '{';
        if(finding){ std::cout << "\"alert\":" << ea::finding_json(*finding) << ",\"scan_current\":" << boolean(store.stats().scan_current) << ','; }
        std::cout << "\"ancestry\":[";
        bool first = true;
        for(const auto* e : ancestry.nodes){
            if(!first){ std::cout << ','; }
            first = false;
            std::cout << "{\"event\":" << ea::event_json(*e) << ",\"identity_ambiguous\":" << boolean(index.ambiguous(*e))
                      << ",\"sources\":" << sources_json(store.sources(e->id)) << '}';
        }
        std::cout << "],\"stop_reason\":" << ea::json_string(ancestry.stop_reason) << "}\n";
    }else{
        if(finding){
            std::cout << "Alert " << finding->id << ": " << finding->title << " [" << finding->severity << "]\n"
                      << "Rule: " << finding->rule_id << " v" << finding->rule_version << "\nReason: " << finding->reason
                      << "\nMatched fields: " << finding->fields_json
                      << "\nAssessment: suspicious activity; not confirmed malicious.\n";
            if(!store.stats().scan_current){ std::cout << "Scan is absent or stale. Run scan.\n"; }
        }
        print_ancestry(ancestry, index);
        for(const auto* e : ancestry.nodes){
            for(const auto& s : store.sources(e->id)){
                std::cout << "Evidence for event " << e->id << ": " << ea::safe_text(s.path) << " | ordinal=" << s.ordinal
                          << " | EventRecordID=" << s.record_id.value_or("<unavailable>") << '\n';
            }
        }
    }
    return 0;
}
int entry(std::span<const std::string> args){
    try{
        const auto status = run(parse_options(args));
        std::cout.flush();
        return std::cout ? status : 1;
    }
    catch(const usage_error& e){ std::cerr << "Arguments: " << ea::safe_text(e.what()) << '\n'; return 2; }
    catch(const std::exception& e){ std::cerr << "eventAnalyzer: " << ea::safe_text(e.what()) << '\n'; return 1; }
}
}
#ifdef _WIN32
int wmain(int argc, wchar_t* argv[]){
    SetConsoleOutputCP(CP_UTF8);
    std::vector<std::string> args;
    for(int i = 1; i < argc; ++i){
        const int count = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, nullptr, 0, nullptr, nullptr);
        if(count == 0){ std::cerr << "Invalid Unicode argument\n"; return 2; }
        std::string text(static_cast<std::size_t>(count), '\0');
        if(WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, argv[i], -1, text.data(), count, nullptr, nullptr) == 0){ return 2; }
        text.pop_back();
        args.push_back(std::move(text));
    }
    return entry(args);
}
#else
int main(int argc, char* argv[]){
    const std::vector<std::string> args(argv + 1, argv + argc);
    return entry(args);
}
#endif
