#include "event_analyzer/core.hpp"
#include <sqlite3.h>
#include <limits>
#include <stdexcept>

namespace ea{
namespace{
[[noreturn]] void database_error(sqlite3* db, std::string_view action){
    throw std::runtime_error(std::string(action) + ": " + sqlite3_errmsg(db));
}
void execute(sqlite3* db, const char* sql){
    if(sqlite3_exec(db, sql, nullptr, nullptr, nullptr) != SQLITE_OK){ database_error(db, "database operation failed"); }
}
class statement{
public:
    statement(sqlite3* db, const char* sql) : db_(db){
        if(sqlite3_prepare_v2(db, sql, -1, &value_, nullptr) != SQLITE_OK){ database_error(db, "prepare failed"); }
    }
    ~statement(){ sqlite3_finalize(value_); }
    statement(const statement&) = delete;
    statement& operator=(const statement&) = delete;
    void bind(int index, std::string_view value){
        if(value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())){
            throw std::runtime_error("database value too large");
        }
        if(sqlite3_bind_text(value_, index, value.data(), static_cast<int>(value.size()), SQLITE_TRANSIENT) != SQLITE_OK){
            database_error(db_, "text binding failed");
        }
    }
    void bind(int index, id_type value){
        if(sqlite3_bind_int64(value_, index, value) != SQLITE_OK){ database_error(db_, "integer binding failed"); }
    }
    void bind(int index, const std::optional<std::string>& value){
        if(value){ bind(index, std::string_view(*value)); }else{ null(index); }
    }
    void null(int index){
        if(sqlite3_bind_null(value_, index) != SQLITE_OK){ database_error(db_, "NULL binding failed"); }
    }
    bool row(){
        const auto result = sqlite3_step(value_);
        if(result == SQLITE_ROW){ return true; }
        if(result == SQLITE_DONE){ return false; }
        database_error(db_, "statement failed");
    }
    void run(){
        if(row()){ throw std::runtime_error("unexpected database result row"); }
    }
    void reset(){
        if(sqlite3_reset(value_) != SQLITE_OK || sqlite3_clear_bindings(value_) != SQLITE_OK){ database_error(db_, "reset failed"); }
    }
    id_type integer(int column) const{ return sqlite3_column_int64(value_, column); }
    bool is_null(int column) const{ return sqlite3_column_type(value_, column) == SQLITE_NULL; }
    std::string text(int column) const{
        const auto* value = sqlite3_column_text(value_, column);
        const auto bytes = sqlite3_column_bytes(value_, column);
        return value ? std::string(reinterpret_cast<const char*>(value), static_cast<std::size_t>(bytes)) : std::string{};
    }
    std::optional<std::string> optional(int column) const{
        return is_null(column) ? std::nullopt : std::optional<std::string>(text(column));
    }
private:
    sqlite3* db_;
    sqlite3_stmt* value_ = nullptr;
};
class transaction{
public:
    explicit transaction(sqlite3* db) : db_(db){ execute(db_, "BEGIN IMMEDIATE"); }
    ~transaction(){ if(!committed_){ sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); } }
    transaction(const transaction&) = delete;
    transaction& operator=(const transaction&) = delete;
    void commit(){ execute(db_, "COMMIT"); committed_ = true; }
private:
    sqlite3* db_;
    bool committed_ = false;
};
id_type scalar(sqlite3* db, const char* sql){
    statement query(db, sql);
    if(!query.row()){ throw std::runtime_error("missing database metadata"); }
    return query.integer(0);
}
constexpr const char* event_columns = "id,host,guid,parent_guid,time,pid,parent_pid,image,command_line,parent_image,user,hashes";
event read_event(statement& query){
    event value;
    value.id = query.integer(0);
    value.host = query.text(1);
    value.guid = query.text(2);
    value.parent_guid = query.optional(3);
    value.time = query.text(4);
    value.pid = static_cast<std::uint32_t>(query.integer(5));
    if(!query.is_null(6)){ value.parent_pid = static_cast<std::uint32_t>(query.integer(6)); }
    value.image = query.text(7);
    value.command_line = query.optional(8);
    value.parent_image = query.optional(9);
    value.user = query.optional(10);
    value.hashes = query.optional(11);
    return value;
}
std::vector<event> read_events(statement& query){
    std::vector<event> result;
    while(query.row()){
        if(result.size() >= max_events){ throw std::runtime_error("analysis exceeds 250000 event limit; use a smaller case database"); }
        result.push_back(read_event(query));
    }
    return result;
}
constexpr const char* alert_columns = "id,event_id,rule_id,rule_version,title,severity,reason,fields_json";
finding read_finding(statement& query){
    return {query.integer(0), query.integer(1), query.text(2), query.text(3), query.text(4), query.text(5), query.text(6), query.text(7)};
}
}
struct event_store::impl{
    sqlite3* db = nullptr;
    ~impl(){ if(db){ sqlite3_close_v2(db); } }
};
event_store::event_store(const std::filesystem::path& file, open_mode mode) : state_(std::make_unique<impl>()){
    const auto path = path_utf8(file);
    const bool create = mode == open_mode::create;
    const int access = mode == open_mode::read_only ? SQLITE_OPEN_READONLY : SQLITE_OPEN_READWRITE;
    if(sqlite3_open_v2(path.c_str(), &state_->db, access | (create ? SQLITE_OPEN_CREATE : 0), nullptr) != SQLITE_OK){
        database_error(state_->db, "cannot open database");
    }
    auto* db = state_->db;
    sqlite3_extended_result_codes(db, 1);
    sqlite3_busy_timeout(db, 5000);
    sqlite3_db_config(db, SQLITE_DBCONFIG_DEFENSIVE, 1, nullptr);
    execute(db, "PRAGMA foreign_keys=ON; PRAGMA trusted_schema=OFF;");
    const auto app = scalar(db, "PRAGMA application_id");
    const auto version_number = scalar(db, "PRAGMA user_version");
    if(app == 0 && version_number == 0 && create){
        transaction tx(db);
        // Re-check under the write lock, including concurrent first opens.
        if(scalar(db, "PRAGMA application_id") == 0){
            if(scalar(db, "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'") != 0){
                throw std::runtime_error("refusing to initialize a nonempty unrelated database");
            }
            execute(db, R"SQL(
CREATE TABLE events(
 id INTEGER PRIMARY KEY, identity TEXT NOT NULL UNIQUE,
 host TEXT NOT NULL, guid TEXT NOT NULL, parent_guid TEXT,
 time TEXT NOT NULL, pid INTEGER NOT NULL, parent_pid INTEGER,
 image TEXT NOT NULL, command_line TEXT, parent_image TEXT, user TEXT, hashes TEXT
) STRICT;
CREATE INDEX events_process ON events(host,guid);
CREATE INDEX events_timeline ON events(host,time,id);
CREATE TABLE sources(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
 path TEXT NOT NULL, ordinal INTEGER NOT NULL, record_id TEXT, xml TEXT NOT NULL,
 UNIQUE(event_id,path,ordinal,xml)
) STRICT;
CREATE TABLE alerts(
 id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL REFERENCES events(id),
 rule_id TEXT NOT NULL, rule_version TEXT NOT NULL, title TEXT NOT NULL,
 severity TEXT NOT NULL, reason TEXT NOT NULL, fields_json TEXT NOT NULL,
 active INTEGER NOT NULL DEFAULT 1, UNIQUE(event_id,rule_id,rule_version)
) STRICT;
CREATE TABLE state(id INTEGER PRIMARY KEY CHECK(id=1), generation INTEGER NOT NULL,
 scanned_generation INTEGER NOT NULL, engine_version TEXT NOT NULL) STRICT;
INSERT INTO state VALUES(1,0,-1,'');
PRAGMA application_id=0x45564131;
PRAGMA user_version=1;
)SQL");
        }
        tx.commit();
    }
    if(scalar(db, "PRAGMA application_id") != 0x45564131 || scalar(db, "PRAGMA user_version") != 1){
        throw std::runtime_error("database is not a supported eventAnalyzer schema (version 1)");
    }
}
event_store::~event_store() = default;
void event_store::begin_read(){ execute(state_->db, "BEGIN"); }
import_summary event_store::import(const import_batch& batch){
    auto* db = state_->db;
    transaction tx(db);
    statement insert(db, "INSERT INTO events(identity,host,guid,parent_guid,time,pid,parent_pid,image,command_line,parent_image,user,hashes) VALUES(?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(identity) DO NOTHING");
    statement lookup(db, "SELECT id FROM events WHERE identity=?");
    statement source(db, "INSERT INTO sources(event_id,path,ordinal,record_id,xml) VALUES(?,?,?,?,?) ON CONFLICT(event_id,path,ordinal,xml) DO NOTHING");
    import_summary result;
    auto count = scalar(db, "SELECT count(*) FROM events");
    for(const auto& record : batch.events){
        const auto& e = record.value;
        insert.bind(1, std::string_view(record.identity));
        insert.bind(2, std::string_view(e.host));
        insert.bind(3, std::string_view(e.guid));
        insert.bind(4, e.parent_guid);
        insert.bind(5, std::string_view(e.time));
        insert.bind(6, static_cast<id_type>(e.pid));
        if(e.parent_pid){ insert.bind(7, static_cast<id_type>(*e.parent_pid)); }else{ insert.null(7); }
        insert.bind(8, std::string_view(e.image));
        insert.bind(9, e.command_line);
        insert.bind(10, e.parent_image);
        insert.bind(11, e.user);
        insert.bind(12, e.hashes);
        insert.run();
        const bool added = sqlite3_changes(db) != 0;
        if(added){
            ++result.inserted;
            if(++count > static_cast<id_type>(max_events)){ throw std::runtime_error("database exceeds 250000 event limit; import rolled back"); }
        }else{ ++result.duplicates; }
        insert.reset();
        lookup.bind(1, std::string_view(record.identity));
        if(!lookup.row()){ throw std::runtime_error("inserted event could not be found"); }
        const auto id = lookup.integer(0);
        lookup.reset();
        source.bind(1, id);
        source.bind(2, std::string_view(batch.path));
        source.bind(3, static_cast<id_type>(record.ordinal));
        source.bind(4, record.record_id);
        source.bind(5, std::string_view(record.xml));
        source.run();
        result.sources_added += static_cast<std::size_t>(sqlite3_changes(db));
        source.reset();
    }
    if(result.inserted){ execute(db, "UPDATE state SET generation=generation+1 WHERE id=1"); }
    tx.commit();
    return result;
}
std::vector<event> event_store::events() const{
    const auto sql = std::string("SELECT ") + event_columns + " FROM events ORDER BY time,host,guid,id";
    statement query(state_->db, sql.c_str());
    return read_events(query);
}
std::vector<event> event_store::timeline(std::string_view host) const{
    const auto sql = std::string("SELECT ") + event_columns + " FROM events WHERE host=? ORDER BY time,id";
    statement query(state_->db, sql.c_str());
    query.bind(1, std::string_view(host));
    return read_events(query);
}
event event_store::get_event(id_type id) const{
    const auto sql = std::string("SELECT ") + event_columns + " FROM events WHERE id=?";
    statement query(state_->db, sql.c_str());
    query.bind(1, id);
    if(!query.row()){ throw std::runtime_error("event ID not found"); }
    return read_event(query);
}
std::vector<source_record> event_store::sources(id_type event_id) const{
    statement query(state_->db, "SELECT path,ordinal,record_id,xml FROM sources WHERE event_id=? ORDER BY path,ordinal,id");
    query.bind(1, event_id);
    std::vector<source_record> result;
    while(query.row()){
        result.push_back({query.text(0), static_cast<std::size_t>(query.integer(1)), query.optional(2), query.text(3)});
    }
    return result;
}
std::size_t event_store::scan(){
    auto* db = state_->db;
    transaction tx(db);
    const auto values = events();
    const auto findings = detect(values);
    execute(db, "UPDATE alerts SET active=0");
    statement insert(db, R"SQL(INSERT INTO alerts(event_id,rule_id,rule_version,title,severity,reason,fields_json,active)
 VALUES(?,?,?,?,?,?,?,1) ON CONFLICT(event_id,rule_id,rule_version) DO UPDATE SET
 title=excluded.title,severity=excluded.severity,reason=excluded.reason,fields_json=excluded.fields_json,active=1)SQL");
    for(const auto& f : findings){
        insert.bind(1, f.event_id);
        insert.bind(2, std::string_view(f.rule_id));
        insert.bind(3, std::string_view(f.rule_version));
        insert.bind(4, std::string_view(f.title));
        insert.bind(5, std::string_view(f.severity));
        insert.bind(6, std::string_view(f.reason));
        insert.bind(7, std::string_view(f.fields_json));
        insert.run();
        insert.reset();
    }
    execute(db, "DELETE FROM alerts WHERE active=0");
    statement update(db, "UPDATE state SET scanned_generation=generation,engine_version=? WHERE id=1");
    update.bind(1, version);
    update.run();
    tx.commit();
    return findings.size();
}
std::vector<finding> event_store::alerts() const{
    const auto sql = std::string("SELECT ") + alert_columns + " FROM alerts ORDER BY id";
    statement query(state_->db, sql.c_str());
    std::vector<finding> result;
    while(query.row()){ result.push_back(read_finding(query)); }
    return result;
}
finding event_store::get_alert(id_type id) const{
    const auto sql = std::string("SELECT ") + alert_columns + " FROM alerts WHERE id=?";
    statement query(state_->db, sql.c_str());
    query.bind(1, id);
    if(!query.row()){ throw std::runtime_error("alert ID not found"); }
    return read_finding(query);
}
statistics event_store::stats() const{
    auto* db = state_->db;
    statistics result;
    // One statement gives a consistent snapshot for all counters.
    statement query(db, R"SQL(SELECT
 (SELECT count(*) FROM events), (SELECT count(*) FROM sources), (SELECT count(*) FROM alerts),
 (SELECT count(*) FROM (SELECT host,guid FROM events GROUP BY host,guid HAVING count(*)>1)),
 generation=scanned_generation AND engine_version=? FROM state WHERE id=1)SQL");
    query.bind(1, version);
    if(!query.row()){ throw std::runtime_error("database state missing"); }
    result.events = query.integer(0);
    result.sources = query.integer(1);
    result.alerts = query.integer(2);
    result.conflicts = query.integer(3);
    result.scan_current = query.integer(4) != 0;
    return result;
}
} // namespace ea
