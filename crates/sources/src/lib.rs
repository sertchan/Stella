pub mod container;
pub mod ct;
pub mod labels;
pub mod pivot;
pub mod site;
pub mod toplist;
pub mod variants;

pub fn hosts_in(text: &[u8], re: &regex::bytes::Regex, group: usize) -> Vec<String> {
    let mut out: Vec<String> = re
        .captures_iter(text)
        .filter_map(|c| c.get(group))
        .filter_map(|m| stella_core::name::normalize(&String::from_utf8_lossy(m.as_bytes())))
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}
