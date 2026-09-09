#include "event_analyzer/core.hpp"
#include <unordered_set>

namespace ea{
namespace{
std::string key(std::string_view host, std::string_view guid){
    return std::string(host) + '\n' + std::string(guid);
}
}
process_index::process_index(std::span<const event> events){
    entries_.reserve(events.size());
    for(const auto& e : events){ entries_[key(e.host, e.guid)].push_back(&e); }
}
bool process_index::ambiguous(const event& value) const{
    const auto it = entries_.find(key(value.host, value.guid));
    return it != entries_.end() && it->second.size() != 1;
}
parent_link process_index::parent(const event& child) const{
    if(ambiguous(child)){ return {nullptr, "ambiguous_child_identity"}; }
    if(!child.parent_guid){ return {nullptr, "parent_guid_missing"}; }
    const auto it = entries_.find(key(child.host, *child.parent_guid));
    if(it == entries_.end()){ return {nullptr, "parent_unobserved"}; }
    if(it->second.size() != 1){ return {nullptr, "ambiguous_parent_identity"}; }
    const auto* parent = it->second.front();
    if(parent->time > child.time){ return {nullptr, "parent_timestamp_after_child"}; }
    if(child.parent_pid && *child.parent_pid != parent->pid){ return {nullptr, "parent_pid_conflict"}; }
    if(child.parent_image && !child.parent_image->empty() && lower_ascii(*child.parent_image) != lower_ascii(parent->image)){
        return {nullptr, "parent_image_conflict"};
    }
    return {parent, "resolved"};
}
ancestry walk_ancestry(const event& start, const process_index& index, std::size_t limit){
    ancestry result;
    std::unordered_set<std::string> visited;
    auto* current = &start;
    while(current){
        if(result.nodes.size() >= limit){ result.stop_reason = "depth_limit"; break; }
        if(!visited.insert(key(current->host, current->guid)).second){ result.stop_reason = "cycle"; break; }
        result.nodes.push_back(current);
        const auto link = index.parent(*current);
        if(!link.value){ result.stop_reason = link.status; break; }
        current = link.value;
    }
    return result;
}
} // namespace ea
