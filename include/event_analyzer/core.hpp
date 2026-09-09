#pragma once

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace ea{
inline constexpr std::string_view version = "1.0.0";
inline constexpr std::size_t max_input_bytes = 128 * 1024 * 1024;
inline constexpr std::size_t max_events = 250000;
using id_type = std::int64_t;

std::string lower_ascii(std::string_view value);
std::string normalize_host(std::string_view value);
std::string normalize_guid(std::string_view value);
std::string normalize_time(std::string_view value);
std::string image_name(std::string_view value);
std::string json_string(std::string_view value);
std::string safe_text(std::string_view value);
std::filesystem::path utf8_path(std::string_view value);
std::string path_utf8(const std::filesystem::path& path);
std::uint64_t parse_uint(std::string_view value, std::uint64_t maximum);

struct event{
    id_type id = 0;
    std::string host;
    std::string guid;
    std::optional<std::string> parent_guid;
    std::string time;
    std::uint32_t pid = 0;
    std::optional<std::uint32_t> parent_pid;
    std::string image;
    std::optional<std::string> command_line;
    std::optional<std::string> parent_image;
    std::optional<std::string> user;
    std::optional<std::string> hashes;
};
struct imported_event{
    event value;
    std::string identity;
    std::string xml;
    std::size_t ordinal = 0;
    std::optional<std::string> record_id;
};
struct diagnostic{
    std::size_t ordinal;
    std::string message;
};
struct import_batch{
    std::string path;
    std::vector<imported_event> events;
    std::vector<diagnostic> diagnostics;
    std::size_t unsupported = 0;
};
import_batch parse_xml(const std::filesystem::path& file);
import_batch parse_xml_bytes(std::string_view bytes, std::string source);

struct rule{
    std::string id;
    std::string revision;
    std::string title;
    std::string severity;
    std::string rationale;
    std::string false_positives;
};
std::span<const rule> rules();
struct finding{
    id_type id = 0;
    id_type event_id = 0;
    std::string rule_id;
    std::string rule_version;
    std::string title;
    std::string severity;
    std::string reason;
    std::string fields_json;
};
std::vector<finding> detect(std::span<const event> events);

struct parent_link{
    const event* value = nullptr;
    std::string status;
};
// Owns its index, borrows event storage. The caller keeps the span unchanged.
class process_index{
public:
    explicit process_index(std::span<const event> events);
    parent_link parent(const event& child) const;
    bool ambiguous(const event& value) const;
private:
    std::unordered_map<std::string, std::vector<const event*>> entries_;
};
struct ancestry{
    std::vector<const event*> nodes;
    std::string stop_reason;
};
ancestry walk_ancestry(const event& start, const process_index& index, std::size_t limit = 256);

struct source_record{
    std::string path;
    std::size_t ordinal;
    std::optional<std::string> record_id;
    std::string xml;
};
struct import_summary{
    std::size_t inserted = 0;
    std::size_t duplicates = 0;
    std::size_t sources_added = 0;
};
struct statistics{
    id_type events = 0;
    id_type sources = 0;
    id_type alerts = 0;
    id_type conflicts = 0;
    bool scan_current = false;
};
enum class open_mode{ read_only, read_write, create };

// RAII connection; public operations are atomic and use prepared statements.
class event_store{
public:
    explicit event_store(const std::filesystem::path& file, open_mode mode = open_mode::read_only);
    ~event_store();
    event_store(const event_store&) = delete;
    event_store& operator=(const event_store&) = delete;
    // Freeze a consistent read snapshot until connection destruction.
    void begin_read();
    import_summary import(const import_batch& batch);
    std::vector<event> events() const;
    std::vector<event> timeline(std::string_view host) const;
    event get_event(id_type id) const;
    std::vector<source_record> sources(id_type event_id) const;
    std::size_t scan();
    std::vector<finding> alerts() const;
    finding get_alert(id_type id) const;
    statistics stats() const;
private:
    struct impl;
    std::unique_ptr<impl> state_;
};

std::string event_json(const event& value);
std::string finding_json(const finding& value);
} // namespace ea
