use crate::commands::export::{METADATA_HEADER, select};
use crate::context::Context;
use anyhow::{Context as _, Result};
use std::fmt::Write as _;
use std::path::PathBuf;
use stella_core::list::{Format, render};

pub const LISTS_DIR: &str = "lists";
pub const COUNTS_FILE: &str = "counts.tsv";
pub const METADATA_FILE: &str = "metadata.tsv";

#[derive(clap::Args)]
pub struct PublishArgs {
    #[arg(
        long,
        default_value = LISTS_DIR,
        help = "Directory that gets one folder per list with every format and metadata.tsv"
    )]
    dir: PathBuf,
    #[arg(
        long,
        default_value_t = 3,
        help = "Picks a zone needs before the whole zone is listed, 0 turns it off"
    )]
    zones: usize,
}

pub fn run(ctx: &Context, args: &PublishArgs) -> Result<()> {
    let picks = select(ctx, false, true, args.zones)?;
    let modified = stella_core::now();
    let mut counts = String::from("list\tzones\thosts\tentries\n");
    for s in &picks.lists {
        let dir = args.dir.join(s.category.slug());
        std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
        for format in Format::ALL {
            let text = render(format, s.category, &s.entries(), modified);
            std::fs::write(dir.join(format.file_name()), text)?;
        }
        std::fs::write(
            dir.join(METADATA_FILE),
            format!("{METADATA_HEADER}{}", s.metadata),
        )?;
        let entries = s.entries().rules(Format::Domains).len();
        let _ = writeln!(
            counts,
            "{}\t{}\t{}\t{entries}",
            s.category.slug(),
            s.zones.len(),
            s.hosts.len()
        );
        eprintln!(
            "published {}: zones={} hosts={} entries={entries}",
            dir.display(),
            s.zones.len(),
            s.hosts.len()
        );
    }
    std::fs::write(args.dir.join(COUNTS_FILE), counts)?;
    eprintln!("skipped={}", picks.skipped);
    Ok(())
}
