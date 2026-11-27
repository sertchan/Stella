mod commits;
mod outdated;
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
        about = "Check every text file for comments, lint attributes, dashes, help text, work markers, whitespace and size"
    )]
    Sources {
        #[arg(default_value = ".", help = "Directory to check")]
        dir: PathBuf,
    },
    #[command(
        name = "commit-msg",
        about = "Check a commit message file and the staged files, as the commit-msg hook does"
    )]
    CommitMsg {
        #[arg(help = "File with the commit message")]
        file: PathBuf,
    },
    #[command(about = "Check every commit in a git revision range, as CI does")]
    Commits {
        #[arg(help = "Revision range such as origin/main..HEAD")]
        range: String,
    },
    #[command(
        name = "pre-push",
        about = "Check the commits of a push from the ref lines git gives the pre-push hook"
    )]
    PrePush {
        #[arg(default_value = "origin", help = "Remote that receives the push")]
        remote: String,
    },
    #[command(
        about = "Check that lock files, direct dependencies, flake inputs and CI actions are on their newest stable release"
    )]
    Outdated {
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
    let crates = commits::crates_in(&std::env::current_dir()?);
    let mut findings = Vec::new();
    let mut count = 0usize;
    for range in ranges {
        for c in commits::load(range)? {
            count += 1;
            findings.extend(commits::check_commit(&c, &crates));
        }
    }
    Ok(Outcome {
        tool: "commitlint",
        checked: format!("{count} commit(s) in {}", ranges.join(" and ")),
        findings,
    })
}

fn run(cli: Cli) -> Result<bool> {
    let outcome = match cli.cmd {
        Cmd::Sources { dir } => {
            let (n, findings) = source::check_tree(&dir)?;
            Outcome {
                tool: "source-lint",
                checked: format!("{n} files under {}", dir.display()),
                findings,
            }
        }
        Cmd::CommitMsg { file } => {
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
                tool: "commitlint",
                checked: format!("the new commit message and {} staged file(s)", files.len()),
                findings,
            }
        }
        Cmd::Commits { range } => commits_outcome(&[range])?,
        Cmd::PrePush { remote } => {
            let mut stdin = String::new();
            std::io::stdin().read_to_string(&mut stdin)?;
            commits_outcome(&commits::push_ranges(&stdin, &remote))?
        }
        Cmd::Outdated {
            dir,
            grace_days,
            no_actions,
        } => Outcome {
            tool: "outdated",
            checked: "lock files, direct dependencies, flake inputs and CI actions".into(),
            findings: outdated::all(&dir, grace_days, !no_actions)?,
        },
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
