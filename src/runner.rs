use std::collections::HashMap;
use std::process::Command;
use std::sync::Mutex;

use serde_json::Value;

use crate::error::AppError;

#[derive(Clone, Debug, Default)]
pub struct CommandResult {
    pub returncode: i32,
    pub stdout: String,
    pub stderr: String,
}

impl CommandResult {
    pub fn ok(stdout: impl Into<String>) -> Self {
        Self {
            returncode: 0,
            stdout: stdout.into(),
            stderr: String::new(),
        }
    }
}

pub trait Runner: Send + Sync {
    fn run(
        &self,
        cmd: &[String],
        check: bool,
        input: Option<&str>,
    ) -> Result<CommandResult, AppError>;
}

pub struct SystemRunner;

impl SystemRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SystemRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl Runner for SystemRunner {
    fn run(
        &self,
        cmd: &[String],
        check: bool,
        input: Option<&str>,
    ) -> Result<CommandResult, AppError> {
        tracing::info!("exec: {}", cmd.join(" "));
        let mut command = Command::new(&cmd[0]);
        command.args(&cmd[1..]);
        if input.is_some() {
            command.stdin(std::process::Stdio::piped());
        }
        command
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        let mut child = command.spawn().map_err(|error| {
            AppError::runtime(format!("Command failed to start: {}: {error}", cmd[0]))
        })?;
        if let Some(data) = input {
            use std::io::Write;
            if let Some(stdin) = child.stdin.as_mut() {
                stdin.write_all(data.as_bytes())?;
            }
        }
        let output = child.wait_with_output()?;
        let result = CommandResult {
            returncode: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
        };
        if !result.stderr.trim().is_empty() {
            tracing::warn!("{}", result.stderr.trim());
        }
        if check && result.returncode != 0 {
            return Err(AppError::runtime(format!(
                "Command failed with exit {}: {}",
                result.returncode,
                cmd.join(" ")
            )));
        }
        Ok(result)
    }
}

#[derive(Default)]
struct FakeState {
    commands: Vec<(Vec<String>, Option<String>)>,
    responses: HashMap<String, CommandResult>,
    failures: HashMap<String, usize>,
}

pub struct FakeRunner {
    state: Mutex<FakeState>,
}

impl Default for FakeRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeRunner {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(FakeState::default()),
        }
    }

    pub fn set_response(&self, command: &str, result: CommandResult) {
        self.state
            .lock()
            .expect("runner lock")
            .responses
            .insert(command.to_string(), result);
    }

    pub fn set_stdout(&self, command: &str, stdout: impl Into<String>) {
        self.set_response(command, CommandResult::ok(stdout));
    }

    /// Fail the next `count` runs whose joined command starts with `prefix`.
    pub fn fail_next(&self, prefix: &str, count: usize) {
        self.state
            .lock()
            .expect("runner lock")
            .failures
            .insert(prefix.to_string(), count);
    }

    pub fn commands(&self) -> Vec<Vec<String>> {
        self.state
            .lock()
            .expect("runner lock")
            .commands
            .iter()
            .map(|(command, _)| command.clone())
            .collect()
    }

    pub fn calls(&self) -> Vec<(Vec<String>, Option<String>)> {
        self.state.lock().expect("runner lock").commands.clone()
    }

    pub fn json_stdout(&self, command: &str, value: &Value) {
        self.set_stdout(command, serde_json::to_string(value).expect("json"));
    }
}

impl Runner for FakeRunner {
    fn run(
        &self,
        cmd: &[String],
        check: bool,
        input: Option<&str>,
    ) -> Result<CommandResult, AppError> {
        let joined = cmd.join(" ");
        let mut state = self.state.lock().expect("runner lock");
        state
            .commands
            .push((cmd.to_vec(), input.map(str::to_string)));
        let mut failure = false;
        for (prefix, count) in state.failures.iter_mut() {
            if joined.starts_with(prefix.as_str()) && *count > 0 {
                *count -= 1;
                failure = true;
                break;
            }
        }
        if failure {
            if check {
                return Err(AppError::runtime(format!(
                    "Command failed with exit 1: {joined}"
                )));
            }
            return Ok(CommandResult {
                returncode: 1,
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        if let Some(response) = state.responses.get(&joined) {
            return Ok(response.clone());
        }
        Ok(CommandResult::default())
    }
}
