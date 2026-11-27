mod commits;
mod fresh;
mod report;
mod source;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use report::Outcome;
use std::io::Read;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "stella-lint",
    version,
    about = "Quality gate for Stella sources, commits and dependencies"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(
        about = "Check every text file under a directory for comments, dashes, help text, markers, whitespace and size"
    )]
    Source {
        #[arg(default_value = ".", help = "Directory to check")]
        dir: PathBuf,
    },
    #[command(about = "Check one commit message file, as the commit-msg hook does")]
    Message {
        #[arg(help = "File with the commit message")]
        file: PathBuf,
    },
    #[command(about = "Check every commit in a git revision range, as CI does")]
    Range {
        #[arg(help = "Revision range such as origin/main..HEAD")]
        range: String,
    },
    #[command(
        about = "Check the commits of a push, reading the ref lines git gives the pre-push hook"
    )]
    Push {
        #[arg(default_value = "origin", help = "Remote that receives the push")]
        remote: String,
    },
    #[command(
        about = "Check that the lock files, direct dependencies, flake inputs and CI actions are on their newest stable release"
    )]
    Fresh {
        #[arg(default_value = ".", help = "Repository root")]
        dir: PathBuf,
        #[arg(
            long,
            default_value_t = 7,
            help = "Days a flake input may lag behind its branch"
        )]
        grace_days: i64,
        #[arg(long, help = "Skip the CI action check, which needs the GitHub API")]
        no_actions: bool,
    },
}

fn commits_outcome(ranges: &[String]) -> Result<Outcome> {
    let mut findings = Vec::new();
    let mut count = 0usize;
    for range in ranges {
        let crates = commits::crates_in(&std::env::current_dir()?);
        for c in commits::load(range)? {
            count += 1;
            findings.extend(commits::check_commit(&c, &crates));
        }
    }
    Ok(Outcome {
        tool: "stella-lint commits",
        checked: format!("{count} commit(s) in {}", ranges.join(" and ")),
        findings,
    })
}

fn run(cli: Cli) -> Result<bool> {
    let outcome = match cli.cmd {
        Cmd::Source { dir } => {
            let (n, findings) = source::check_tree(&dir)?;
            Outcome {
                tool: "stella-lint source",
                checked: format!("{n} files under {}", dir.display()),
                findings,
            }
        }
        Cmd::Message { file } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("read {}", file.display()))?;
            let crates = commits::crates_in(&std::env::current_dir()?);
            let mut findings = commits::check_message("new commit", &text, &crates);
            let subject = commits::clean(&text)
                .lines()
                .next()
                .unwrap_or("")
                .to_string();
            let files = commits::staged().unwrap_or_default();
            findings.extend(commits::scope_files(
                &format!("new commit \"{subject}\""),
                &subject,
                &files,
                &crates,
            ));
            Outcome {
                tool: "stella-lint message",
                checked: format!("the new commit message and {} staged file(s)", files.len()),
                findings,
            }
        }
        Cmd::Range { range } => commits_outcome(&[range])?,
        Cmd::Push { remote } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin)?;
            commits_outcome(&commits::push_ranges(&stdin, &remote))?
        }
        Cmd::Fresh {
            dir,
            grace_days,
            no_actions,
        } => {
            let mut findings = fresh::lock(&dir, "Cargo.lock")?;
            findings.extend(fresh::majors(&dir, "Cargo.toml")?);
            let fuzz = dir.join("fuzz");
            if fuzz.join("Cargo.lock").is_file() {
                findings.extend(fresh::lock(&fuzz, "fuzz/Cargo.lock")?);
            }
            findings.extend(fresh::flake(&dir, grace_days)?);
            if !no_actions {
                findings.extend(fresh::actions(&dir)?);
            }
            Outcome {
                tool: "stella-lint fresh",
                checked: "lock files, direct dependencies, flake inputs and CI actions".into(),
                findings,
            }
        }
    };
    Ok(outcome.emit())
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("stella-lint: could not finish the check: {e:#}");
            ExitCode::from(2)
        }
    }
}
