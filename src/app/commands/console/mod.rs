//! `dbev --cli`: an interactive admin console in the terminal.
//!
//! It lists every instance with live status, creates instances, runs power
//! actions, deletes, shows container logs, takes and restores backups, and
//! (as root) reveals stored credentials. All changes go through the local
//! daemon API with the config token; see [`api`].

mod api;
mod app;
mod credentials;
mod form;
mod ui;

use std::{io::IsTerminal, path::PathBuf, sync::Arc, time::Duration};

use anyhow::{Context, bail};
use crossterm::event::{Event, EventStream, KeyEventKind};
use futures::StreamExt;
use tokio::sync::mpsc;

use crate::config::Config;

use self::{
    api::ApiClient,
    app::{App, Job, Outcome, Revealed},
};

const REFRESH_INTERVAL: Duration = Duration::from_secs(3);
const TICK_INTERVAL: Duration = Duration::from_millis(120);

pub(super) async fn run(config_path: PathBuf) -> anyhow::Result<()> {
    if !std::io::stdout().is_terminal() || !std::io::stdin().is_terminal() {
        bail!("dbev --cli needs an interactive terminal");
    }
    let config = crate::config::load::load_config(&config_path)
        .with_context(|| format!("failed to load config {}", config_path.display()))?;
    let client = ApiClient::from_config(&config)?;
    // Fail before taking over the screen when the daemon is unreachable.
    let system = client.system().await.with_context(|| {
        format!(
            "the daemon API at {} did not answer; is the daemon running?",
            client.base_url()
        )
    })?;

    let mut terminal = ratatui::try_init().context("failed to prepare the terminal")?;
    let result = event_loop(&mut terminal, Arc::new(config), client, system).await;
    ratatui::restore();
    result
}

async fn event_loop(
    terminal: &mut ratatui::DefaultTerminal,
    config: Arc<Config>,
    client: ApiClient,
    system: api::SystemInfo,
) -> anyhow::Result<()> {
    let mut app = App::new(client.base_url().to_string());
    let (sender, mut outcomes) = mpsc::unbounded_channel();
    app.on_outcome(Outcome::System(system));
    let runner = Runner {
        client,
        config,
        sender,
    };
    for job in app.refresh_jobs() {
        runner.spawn(&mut app, job);
    }

    let mut events = EventStream::new();
    let mut refresh = tokio::time::interval(REFRESH_INTERVAL);
    refresh.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut tick = tokio::time::interval(TICK_INTERVAL);
    while !app.quit {
        terminal.draw(|frame| ui::draw(frame, &app))?;
        let jobs = tokio::select! {
            event = events.next() => match event {
                Some(Ok(Event::Key(key))) if key.kind == KeyEventKind::Press => app.on_key(key),
                Some(Ok(_)) => Vec::new(),
                Some(Err(error)) => return Err(error).context("failed to read the terminal"),
                None => break,
            },
            Some(outcome) = outcomes.recv() => app.on_outcome(outcome),
            _ = refresh.tick() => app.refresh_jobs(),
            _ = tick.tick() => {
                app.tick();
                Vec::new()
            }
        };
        for job in jobs {
            runner.spawn(&mut app, job);
        }
    }
    Ok(())
}

struct Runner {
    client: ApiClient,
    config: Arc<Config>,
    sender: mpsc::UnboundedSender<Outcome>,
}

impl Runner {
    fn spawn(&self, app: &mut App, job: Job) {
        app.started(&job);
        let client = self.client.clone();
        let config = Arc::clone(&self.config);
        let sender = self.sender.clone();
        let instances = app.instances.clone();
        tokio::spawn(async move {
            let outcome = execute(&client, &config, &instances, job).await;
            // The console may have quit; a dropped result is fine.
            let _ = sender.send(outcome);
        });
    }
}

async fn execute(
    client: &ApiClient,
    config: &Config,
    instances: &[api::Instance],
    job: Job,
) -> Outcome {
    let label = job.label().unwrap_or_default();
    let done = |result: anyhow::Result<()>, refresh: bool| match result {
        Ok(()) => Outcome::Done {
            label: label.clone(),
            refresh,
        },
        Err(error) => Outcome::Failed {
            label: label.clone(),
            error: format!("{error:#}"),
        },
    };
    match job {
        Job::Refresh => match client.instances().await {
            Ok(instances) => Outcome::Instances(instances),
            Err(error) => Outcome::RefreshFailed(format!("{error:#}")),
        },
        Job::Progress(id) => match client.progress(&id).await {
            Ok(status) => Outcome::Progress(id, status),
            Err(error) => Outcome::RefreshFailed(format!("{error:#}")),
        },
        Job::Create(request) => done(client.create(&request).await, true),
        Job::Power(id, action) => done(client.power(&id, action).await, true),
        Job::Delete {
            instance_id,
            reason,
        } => done(client.delete(&instance_id, &reason).await, true),
        Job::Backup(id, mode) => done(client.backup(&id, mode).await.map(|_| ()), false),
        Job::Restore {
            instance_id,
            backup_id,
            reason,
        } => done(
            client.restore(&instance_id, &backup_id, &reason).await,
            true,
        ),
        Job::Logs(id) => match client.logs(&id).await {
            Ok(logs) => {
                let mut text = logs.stdout;
                if !logs.stderr.is_empty() {
                    if !text.is_empty() && !text.ends_with('\n') {
                        text.push('\n');
                    }
                    text.push_str(&logs.stderr);
                }
                Outcome::Logs(id, text)
            }
            Err(error) => Outcome::Failed {
                label: format!("logs of {id}"),
                error: format!("{error:#}"),
            },
        },
        Job::Backups(id) => match client.backups(&id).await {
            Ok(backups) => Outcome::Backups(id, backups),
            Err(error) => Outcome::Failed {
                label: format!("backups of {id}"),
                error: format!("{error:#}"),
            },
        },
        Job::Reveal(id) => {
            let Some(instance) = instances.iter().find(|instance| instance.instance_id == id)
            else {
                return Outcome::Failed {
                    label: format!("credentials of {id}"),
                    error: "the instance is no longer listed".to_string(),
                };
            };
            match credentials::reveal(config, &id).await {
                Ok(revealed) => Outcome::Revealed(Box::new(Revealed {
                    instance_id: id,
                    protocol: instance.protocol,
                    host: instance.public.host.clone(),
                    port: instance.public.port,
                    database: instance.database.name.clone(),
                    username: revealed.username,
                    password: revealed.password,
                    admin: revealed.admin,
                    shown_at: std::time::Instant::now(),
                })),
                Err(error) => Outcome::Failed {
                    label: format!("credentials of {id}"),
                    error: format!("{error:#}"),
                },
            }
        }
    }
}
