//! Git access, through the `git` executable rather than a library.
//!
//! Only committed objects are read, and snapshots come from the tree object,
//! so what a reviewer approved is what a Candidate can contain.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::model::Bump;

/// One commit, with the fields release notes and intent are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Commit {
    /// Full commit SHA.
    pub sha: String,
    /// Author name as recorded by git.
    pub author_name: String,
    /// Author email as recorded by git.
    pub author_email: String,
    /// First line of the commit message.
    pub subject: String,
    /// Remainder of the commit message.
    pub body: String,
}

/// What a tag points at, and whether it is annotated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagState {
    /// Commit the tag resolves to.
    pub target_sha: String,
    /// Whether the tag is an annotated tag object.
    pub annotated: bool,
}

impl Commit {
    /// The release step this commit's message declares, if any.
    pub fn conventional_bump(&self) -> Bump {
        conventional_bump(&self.subject, &self.body)
    }
}

/// A git repository, driven through the `git` executable.
#[derive(Debug, Clone)]
pub struct GitRepo {
    root: PathBuf,
}

impl GitRepo {
    /// Find the repository that contains a directory.
    pub fn discover(from: &Path) -> Result<Self> {
        let root = run(from, ["rev-parse", "--show-toplevel"])?;
        Ok(Self {
            root: PathBuf::from(root.trim()),
        })
    }

    /// Absolute path of the repository root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Commit that `HEAD` currently resolves to.
    pub fn head(&self) -> Result<String> {
        Ok(self.run(["rev-parse", "HEAD"])?.trim().to_owned())
    }

    /// Best guess at the default branch, falling back to `main`.
    pub fn default_branch(&self) -> Result<String> {
        if let Ok(value) = self.run(["symbolic-ref", "refs/remotes/origin/HEAD"])
            && let Some(branch) = value.trim().strip_prefix("refs/remotes/origin/")
        {
            return Ok(branch.to_owned());
        }
        if let Ok(value) = self.run(["branch", "--show-current"])
            && !value.trim().is_empty()
        {
            return Ok(value.trim().to_owned());
        }
        Ok("main".to_owned())
    }

    /// Resolve a ref to a commit, or `None` when it does not exist.
    pub fn resolve(&self, git_ref: &str) -> Result<Option<String>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["rev-parse", "--verify", &format!("{git_ref}^{{commit}}")])
            .output()
            .context("failed to invoke git")?;
        if output.status.success() {
            Ok(Some(String::from_utf8(output.stdout)?.trim().to_owned()))
        } else {
            Ok(None)
        }
    }

    /// Commit a local tag resolves to, if the tag exists.
    pub fn tag_sha(&self, tag: &str) -> Result<Option<String>> {
        self.resolve(&format!("refs/tags/{tag}"))
    }

    /// Local tag target and whether it is annotated.
    pub fn tag_state(&self, tag: &str) -> Result<Option<TagState>> {
        let Some(target_sha) = self.tag_sha(tag)? else {
            return Ok(None);
        };
        let kind = self
            .run(["cat-file", "-t", &format!("refs/tags/{tag}")])?
            .trim()
            .to_owned();
        Ok(Some(TagState {
            target_sha,
            annotated: kind == "tag",
        }))
    }

    /// Commit a tag on `origin` resolves to, if it exists there.
    pub fn remote_tag_sha(&self, tag: &str) -> Result<Option<String>> {
        Ok(self.remote_tag_state(tag)?.map(|state| state.target_sha))
    }

    /// Remote tag target and whether it is annotated.
    ///
    /// The peeled ref decides, so an annotated tag reports the commit it
    /// points at rather than the tag object.
    pub fn remote_tag_state(&self, tag: &str) -> Result<Option<TagState>> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args([
                "ls-remote",
                "--tags",
                "origin",
                &format!("refs/tags/{tag}"),
                &format!("refs/tags/{tag}^{{}}"),
            ])
            .output()
            .context("failed to inspect remote tags")?;
        if !output.status.success() {
            bail!(
                "git ls-remote failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let lines = String::from_utf8(output.stdout)?;
        let mut direct = None;
        let mut dereferenced = None;
        for line in lines.lines() {
            let mut fields = line.split_whitespace();
            let Some(sha) = fields.next() else { continue };
            let reference = fields.next().unwrap_or_default();
            if reference.ends_with("^{}") {
                dereferenced = Some(sha.to_owned());
            } else {
                direct = Some(sha.to_owned());
            }
        }
        Ok(dereferenced
            .map(|target_sha| TagState {
                target_sha,
                annotated: true,
            })
            .or_else(|| {
                direct.map(|target_sha| TagState {
                    target_sha,
                    annotated: false,
                })
            }))
    }

    /// Commits between a baseline and `HEAD`, newest first.
    ///
    /// `None` walks the whole history, which only happens before the first
    /// release.
    pub fn commits_since(&self, sha: Option<&str>) -> Result<Vec<Commit>> {
        let mut args = vec![
            "log".to_owned(),
            "--format=%H%x1f%an%x1f%ae%x1f%s%x1f%b%x1e".to_owned(),
        ];
        if let Some(sha) = sha {
            args.push(format!("{sha}..HEAD"));
        }
        let raw = self.run(args.iter().map(String::as_str))?;
        raw.split('\u{1e}')
            .filter(|record| !record.trim().is_empty())
            .map(|record| {
                let record = record.trim_start_matches(['\n', '\r']);
                let mut parts = record.splitn(5, '\u{1f}');
                Ok(Commit {
                    sha: required_part(&mut parts, "sha")?.to_owned(),
                    author_name: required_part(&mut parts, "author name")?.to_owned(),
                    author_email: required_part(&mut parts, "author email")?.to_owned(),
                    subject: required_part(&mut parts, "subject")?.to_owned(),
                    body: parts.next().unwrap_or_default().trim().to_owned(),
                })
            })
            .collect()
    }

    /// Return at most `limit` first-parent commits and whether more history
    /// exists. Callers can therefore fail closed instead of accidentally
    /// turning a missing baseline into an unbounded repository scan.
    pub fn rev_list_bounded(&self, limit: usize) -> Result<(Vec<String>, bool)> {
        if limit == 0 {
            bail!("git history search limit must be greater than zero");
        }
        let requested = limit
            .checked_add(1)
            .context("git history search limit overflow")?;
        let max_count = format!("--max-count={requested}");
        let mut commits: Vec<_> = self
            .run(["rev-list", "--first-parent", &max_count, "HEAD"])?
            .lines()
            .map(str::to_owned)
            .collect();
        let truncated = commits.len() > limit;
        commits.truncate(limit);
        Ok((commits, truncated))
    }

    /// Expand a commit's tree into a directory.
    ///
    /// Only the committed tree is expanded, so uncommitted and ignored
    /// working-tree files cannot reach a Candidate.
    pub fn archive(&self, sha: &str, destination: &Path) -> Result<()> {
        // Archiving the tree object avoids Git's commit-only global PAX
        // `comment` header. The strict snapshot parser resolves only safe
        // path extensions for long names and rejects all global metadata.
        let tree = format!("{sha}^{{tree}}");
        let output = Command::new("git")
            .args(["-c", "core.autocrlf=false", "-c", "core.eol=lf"])
            .arg("-C")
            .arg(&self.root)
            .args(["archive", "--format=tar", &tree])
            .output()
            .context("failed to archive git commit")?;
        if !output.status.success() {
            bail!(
                "git archive failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        crate::artifact::unpack_tar_bytes(
            &output.stdout,
            destination,
            crate::artifact::ArchiveLimits::default(),
        )
        .context("git archive contains an unsafe or oversized entry")?;
        Ok(())
    }

    /// Create a lightweight tag at a commit.
    pub fn create_tag(&self, tag: &str, sha: &str) -> Result<()> {
        // A lightweight tag needs no CI git identity and points directly at
        // the approved merge commit, which also simplifies conflict checks.
        self.run(["tag", tag, sha])?;
        Ok(())
    }

    /// Create an annotated tag at a commit, with a fixed committer identity.
    pub fn create_annotated_tag(&self, tag: &str, sha: &str, message: &str) -> Result<()> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.root)
            .args(["tag", "--annotate", tag, sha, "--message", message])
            .env("GIT_COMMITTER_NAME", "release-glz")
            .env(
                "GIT_COMMITTER_EMAIL",
                "release-glz@users.noreply.github.com",
            )
            .output()
            .context("failed to create annotated release tag")?;
        if !output.status.success() {
            bail!(
                "git could not create annotated tag `{tag}`: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    /// Push one tag to `origin`.
    pub fn push_tag(&self, tag: &str) -> Result<()> {
        self.run(["push", "origin", &format!("refs/tags/{tag}")])?;
        Ok(())
    }

    /// Run a git command in this repository and return its stdout.
    pub fn run<I, S>(&self, args: I) -> Result<String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        run(&self.root, args)
    }
}

fn run<I, S>(directory: &Path, args: I) -> Result<String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = Command::new("git")
        .arg("-C")
        .arg(directory)
        .args(args)
        .output()
        .context("failed to invoke git")?;
    if !output.status.success() {
        bail!(
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    Ok(String::from_utf8(output.stdout)?)
}

fn required_part<'a>(parts: &mut impl Iterator<Item = &'a str>, name: &str) -> Result<&'a str> {
    parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("git log record has no {name}"))
}

/// The release step a Conventional Commit message declares.
///
/// A `!` marker or a `BREAKING CHANGE:` trailer is major; `feat` is
/// minor; `fix` and `perf` are patch; anything else requires nothing.
pub fn conventional_bump(subject: &str, body: &str) -> Bump {
    let header = subject.split(':').next().unwrap_or(subject);
    let breaking = header.ends_with('!')
        || body.lines().any(|line| {
            line.starts_with("BREAKING CHANGE:") || line.starts_with("BREAKING-CHANGE:")
        });
    if breaking {
        return Bump::Major;
    }
    let kind = header.split('(').next().unwrap_or(header);
    match kind {
        "feat" => Bump::Minor,
        "fix" | "perf" => Bump::Patch,
        _ => Bump::None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conventional_commit_signals_are_ordered() {
        let cases = [
            ("docs: update", "", Bump::None),
            ("fix: a bug", "", Bump::Patch),
            ("perf(core): faster", "", Bump::Patch),
            ("feat(ui): add a button", "", Bump::Minor),
            ("feat(api)!: remove it", "", Bump::Major),
            (
                "refactor: internals",
                "BREAKING CHANGE: removed public API",
                Bump::Major,
            ),
        ];
        for (subject, body, bump) in cases {
            assert_eq!(conventional_bump(subject, body), bump, "{subject}");
        }
    }

    #[test]
    fn malformed_log_records_and_all_breaking_markers_are_explicit() {
        let mut empty = std::iter::empty();
        assert!(required_part(&mut empty, "sha").is_err());
        let mut only_sha = std::iter::once("sha");
        required_part(&mut only_sha, "sha").unwrap();
        assert!(required_part(&mut only_sha, "author").is_err());
        assert_eq!(conventional_bump("fix!: remove", ""), Bump::Major);
        assert_eq!(
            conventional_bump("chore: release", "BREAKING-CHANGE: remove"),
            Bump::Major
        );
        assert_eq!(conventional_bump("feat", ""), Bump::Minor);
        assert_eq!(conventional_bump("perf", ""), Bump::Patch);
    }
}
