mod gpu;

use iced::widget::{button, checkbox, column, container, text, text_input};
use iced::{Alignment, Application, Command, Element, Length, Settings, Size, Subscription, Theme};
use sha2::{Digest, Sha256};
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Instant;

pub fn main() -> iced::Result {
    Sha256Cracker::run(Settings {
        window: iced::window::Settings {
            size: Size::new(600.0, 600.0),
            resizable: false,
            ..Default::default()
        },
        ..Default::default()
    })
}

struct Sha256Cracker {
    target_hash: String,
    is_cracking: bool,
    current_attempt: String,
    attempts_count: u64,
    hashes_per_second: f64,
    start_time: Option<Instant>,
    last_update: Option<Instant>,
    last_attempts: u64,
    found_match: Option<String>,
    status_message: String,
    worker_sender: Option<Sender<WorkerCommand>>,
    // Character set options
    include_lowercase: bool,
    include_uppercase: bool,
    include_numbers: bool,
    include_symbols: bool,
    min_length: String,
    max_length: String,
    use_gpu: bool,
}

#[derive(Debug, Clone)]
enum Message {
    TargetHashChanged(String),
    StartCracking,
    StopCracking,
    WorkerUpdate(WorkerUpdate),
    ToggleLowercase(bool),
    ToggleUppercase(bool),
    ToggleNumbers(bool),
    ToggleSymbols(bool),
    MinLengthChanged(String),
    MaxLengthChanged(String),
    ToggleGPU(bool),
}

#[derive(Debug, Clone)]
pub enum WorkerCommand {
    Stop,
}

#[derive(Debug, Clone)]
pub enum WorkerUpdate {
    Progress {
        current_attempt: String,
        attempts_count: u64,
    },
    Found {
        match_string: String,
        attempts_count: u64,
    },
}

impl Application for Sha256Cracker {
    type Executor = iced::executor::Default;
    type Message = Message;
    type Theme = Theme;
    type Flags = ();

    fn new(_flags: Self::Flags) -> (Self, Command<Message>) {
        (
            Self {
                target_hash: String::new(),
                is_cracking: false,
                current_attempt: String::new(),
                attempts_count: 0,
                hashes_per_second: 0.0,
                start_time: None,
                last_update: None,
                last_attempts: 0,
                found_match: None,
                status_message: String::from("Enter a SHA256 hash to crack"),
                worker_sender: None,
                include_lowercase: true,
                include_uppercase: true,
                include_numbers: true,
                include_symbols: false,
                min_length: String::from("1"),
                max_length: String::from("6"),
                use_gpu: false,
            },
            Command::none(),
        )
    }

    fn title(&self) -> String {
        String::from("SHA256 Cracker")
    }

    fn update(&mut self, message: Message) -> Command<Message> {
        match message {
            Message::TargetHashChanged(value) => {
                self.target_hash = value.trim().to_lowercase();
            }
            Message::ToggleLowercase(value) => {
                self.include_lowercase = value;
            }
            Message::ToggleUppercase(value) => {
                self.include_uppercase = value;
            }
            Message::ToggleNumbers(value) => {
                self.include_numbers = value;
            }
            Message::ToggleSymbols(value) => {
                self.include_symbols = value;
            }
            Message::MinLengthChanged(value) => {
                self.min_length = value;
            }
            Message::MaxLengthChanged(value) => {
                self.max_length = value;
            }
            Message::ToggleGPU(value) => {
                self.use_gpu = value;
            }
            Message::StartCracking => {
                if self.target_hash.len() != 64 {
                    self.status_message =
                        String::from("Error: Please enter a valid 64-character SHA256 hash");
                    return Command::none();
                }

                // Parse min and max lengths
                let min_len = match self.min_length.trim().parse::<usize>() {
                    Ok(val) if val > 0 => val,
                    _ => {
                        self.status_message =
                            String::from("Error: Min length must be a positive number");
                        return Command::none();
                    }
                };

                let max_len = match self.max_length.trim().parse::<usize>() {
                    Ok(val) if val > 0 => val,
                    _ => {
                        self.status_message =
                            String::from("Error: Max length must be a positive number");
                        return Command::none();
                    }
                };

                if min_len > max_len {
                    self.status_message =
                        String::from("Error: Min length cannot be greater than max length");
                    return Command::none();
                }

                // Build character set
                let mut charset = String::new();
                if self.include_lowercase {
                    charset.push_str("abcdefghijklmnopqrstuvwxyz");
                }
                if self.include_uppercase {
                    charset.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
                }
                if self.include_numbers {
                    charset.push_str("0123456789");
                }
                if self.include_symbols {
                    charset.push_str("!@#$%^&*()-_=+[]{}|;:,.<>?/~`");
                }

                if charset.is_empty() {
                    self.status_message =
                        String::from("Error: Please select at least one character set");
                    return Command::none();
                }

                self.is_cracking = true;
                self.attempts_count = 0;
                self.start_time = Some(Instant::now());
                self.last_update = Some(Instant::now());
                self.last_attempts = 0;
                self.found_match = None;
                self.status_message = String::from("Cracking in progress...");

                // Create channel for worker communication
                let (worker_tx, worker_rx) = mpsc::channel();
                self.worker_sender = Some(worker_tx);

                // Spawn worker thread (CPU or GPU)
                let target = self.target_hash.clone();
                let use_gpu = self.use_gpu;
                thread::spawn(move || {
                    if use_gpu {
                        crack_hash_worker_gpu(target, charset, min_len, max_len, worker_rx);
                    } else {
                        crack_hash_worker(target, charset, min_len, max_len, worker_rx);
                    }
                });
            }
            Message::StopCracking => {
                if let Some(sender) = &self.worker_sender {
                    let _ = sender.send(WorkerCommand::Stop);
                }
                self.is_cracking = false;
                self.worker_sender = None;
                self.status_message = String::from("Cracking stopped");
            }
            Message::WorkerUpdate(update) => {
                match update {
                    WorkerUpdate::Progress {
                        current_attempt,
                        attempts_count,
                    } => {
                        self.current_attempt = current_attempt;
                        self.attempts_count = attempts_count;

                        // Calculate hashes per second
                        if let Some(last_update) = self.last_update {
                            let elapsed = last_update.elapsed().as_secs_f64();
                            if elapsed >= 0.1 {
                                // Update every 100ms
                                let attempts_delta = self.attempts_count - self.last_attempts;
                                self.hashes_per_second = attempts_delta as f64 / elapsed;
                                self.last_update = Some(Instant::now());
                                self.last_attempts = self.attempts_count;
                            }
                        }
                    }
                    WorkerUpdate::Found {
                        match_string,
                        attempts_count,
                    } => {
                        self.found_match = Some(match_string.clone());
                        self.attempts_count = attempts_count;
                        self.is_cracking = false;
                        self.worker_sender = None;
                        self.status_message = format!("SUCCESS! Found match: {}", match_string);
                    }
                }
            }
        }

        Command::none()
    }

    fn view(&self) -> Element<Message> {
        let title = text("SHA256 Cracker")
            .size(40)
            .width(Length::Fill)
            .horizontal_alignment(iced::alignment::Horizontal::Center);

        let input_label = text("Target SHA256 Hash:").size(16);
        let hash_input = text_input("Enter 64-character SHA256 hash...", &self.target_hash)
            .on_input(Message::TargetHashChanged)
            .padding(10)
            .size(14);

        // Character set options
        let options_label = text("Character Sets:").size(16);

        let lowercase_option =
            checkbox("Lowercase (a-z)", self.include_lowercase).on_toggle(Message::ToggleLowercase);

        let uppercase_option =
            checkbox("Uppercase (A-Z)", self.include_uppercase).on_toggle(Message::ToggleUppercase);

        let numbers_option =
            checkbox("Numbers (0-9)", self.include_numbers).on_toggle(Message::ToggleNumbers);

        let symbols_option =
            checkbox("Symbols (!@#$...)", self.include_symbols).on_toggle(Message::ToggleSymbols);

        let gpu_option =
            checkbox("Use GPU (Experimental)", self.use_gpu).on_toggle(Message::ToggleGPU);

        let options_row = column![
            lowercase_option,
            uppercase_option,
            numbers_option,
            symbols_option,
            gpu_option,
        ]
        .spacing(5)
        .padding(5);

        // Length range options
        let length_label = text("String Length Range:").size(16);

        let min_length_input = text_input("Min", &self.min_length)
            .on_input(Message::MinLengthChanged)
            .padding(5)
            .size(14)
            .width(Length::Fixed(80.0));

        let max_length_input = text_input("Max", &self.max_length)
            .on_input(Message::MaxLengthChanged)
            .padding(5)
            .size(14)
            .width(Length::Fixed(80.0));

        let length_row = iced::widget::row![
            text("Min:").size(14),
            min_length_input,
            text("Max:").size(14),
            max_length_input,
        ]
        .spacing(10)
        .align_items(Alignment::Center);

        let start_stop_button = if self.is_cracking {
            button(text("Stop").size(18))
                .on_press(Message::StopCracking)
                .padding(10)
        } else {
            button(text("Start Cracking").size(18))
                .on_press(Message::StartCracking)
                .padding(10)
        };

        let status = text(&self.status_message)
            .size(16)
            .style(if self.found_match.is_some() {
                iced::theme::Text::Color(iced::Color::from_rgb(0.0, 1.0, 0.0))
            } else {
                iced::theme::Text::Default
            });

        let current_attempt_text = if self.is_cracking {
            text(format!("Current attempt: {}", self.current_attempt)).size(14)
        } else {
            text("").size(14)
        };

        let attempts_text = text(format!("Attempts: {}", self.attempts_count)).size(16);

        let hash_rate_text = if self.hashes_per_second > 1_000_000.0 {
            text(format!(
                "Hash rate: {:.2} MH/s",
                self.hashes_per_second / 1_000_000.0
            ))
            .size(16)
        } else if self.hashes_per_second > 1_000.0 {
            text(format!(
                "Hash rate: {:.2} KH/s",
                self.hashes_per_second / 1_000.0
            ))
            .size(16)
        } else {
            text(format!("Hash rate: {:.2} H/s", self.hashes_per_second)).size(16)
        };

        // Calculate estimated time
        let estimated_time_text = if self.is_cracking && self.hashes_per_second > 0.0 {
            // Parse lengths for calculation
            let min_len = self.min_length.parse::<usize>().unwrap_or(1);
            let max_len = self.max_length.parse::<usize>().unwrap_or(6);

            // Calculate total combinations for sequential search
            let charset_size = (if self.include_lowercase { 26 } else { 0 }
                + if self.include_uppercase { 26 } else { 0 }
                + if self.include_numbers { 10 } else { 0 }
                + if self.include_symbols { 29 } else { 0 }) as u64;

            let mut total_combinations = 0u64;
            for length in min_len..=max_len {
                if let Some(combinations) = charset_size.checked_pow(length as u32) {
                    total_combinations = total_combinations.saturating_add(combinations);
                } else {
                    // Overflow - use max value
                    total_combinations = u64::MAX;
                    break;
                }
            }

            let remaining = total_combinations.saturating_sub(self.attempts_count);
            let seconds_remaining = remaining as f64 / self.hashes_per_second;

            let time_str = if seconds_remaining > 31536000.0 {
                format!("{:.1} years", seconds_remaining / 31536000.0)
            } else if seconds_remaining > 86400.0 {
                format!("{:.1} days", seconds_remaining / 86400.0)
            } else if seconds_remaining > 3600.0 {
                format!("{:.1} hours", seconds_remaining / 3600.0)
            } else if seconds_remaining > 60.0 {
                format!("{:.1} minutes", seconds_remaining / 60.0)
            } else {
                format!("{:.1} seconds", seconds_remaining)
            };

            text(format!("Estimated time (worst case): {}", time_str)).size(16)
        } else {
            text("Estimated time: N/A").size(16)
        };

        let content = column![
            title,
            input_label,
            hash_input,
            options_label,
            options_row,
            length_label,
            length_row,
            start_stop_button,
            status,
            current_attempt_text,
            attempts_text,
            hash_rate_text,
            estimated_time_text,
        ]
        .spacing(10)
        .padding(20)
        .align_items(Alignment::Center);

        container(content)
            .width(Length::Fill)
            .height(Length::Fill)
            .center_x()
            .into()
    }

    fn subscription(&self) -> Subscription<Message> {
        if self.is_cracking {
            worker_subscription().map(Message::WorkerUpdate)
        } else {
            Subscription::none()
        }
    }

    fn theme(&self) -> Theme {
        Theme::Dark
    }
}

// Global channel for worker updates
static WORKER_CHANNEL: std::sync::OnceLock<(
    Sender<WorkerUpdate>,
    std::sync::Mutex<Receiver<WorkerUpdate>>,
)> = std::sync::OnceLock::new();

pub fn get_worker_channel() -> &'static (
    Sender<WorkerUpdate>,
    std::sync::Mutex<Receiver<WorkerUpdate>>,
) {
    WORKER_CHANNEL.get_or_init(|| {
        let (tx, rx) = mpsc::channel();
        (tx, std::sync::Mutex::new(rx))
    })
}

fn worker_subscription() -> Subscription<WorkerUpdate> {
    Subscription::from_recipe(WorkerSubscription)
}

struct WorkerSubscription;

impl iced_futures::subscription::Recipe for WorkerSubscription {
    type Output = WorkerUpdate;

    fn hash(&self, state: &mut iced_futures::core::Hasher) {
        use std::hash::Hash;
        std::any::TypeId::of::<Self>().hash(state);
    }

    fn stream(
        self: Box<Self>,
        _input: futures::stream::BoxStream<'static, (iced::Event, iced::event::Status)>,
    ) -> futures::stream::BoxStream<'static, Self::Output> {
        Box::pin(futures::stream::unfold((), |_| async {
            loop {
                // Poll the channel for updates
                let (_, rx) = get_worker_channel();
                if let Ok(guard) = rx.lock() {
                    if let Ok(update) = guard.try_recv() {
                        return Some((update, ()));
                    }
                }

                // Small delay to prevent busy waiting
                tokio::time::sleep(tokio::time::Duration::from_millis(10)).await;
            }
        }))
    }
}

fn crack_hash_worker(
    target_hash: String,
    charset: String,
    min_length: usize,
    max_length: usize,
    cmd_rx: Receiver<WorkerCommand>,
) {
    let (update_tx, _) = get_worker_channel();
    let charset_bytes: Vec<char> = charset.chars().collect();
    let mut attempts = 0u64;
    let mut last_update = Instant::now();

    // Sequential brute-force: try all combinations from min_length to max_length
    for length in min_length..=max_length {
        // Initialize indices array for this length
        let mut indices = vec![0usize; length];

        loop {
            // Check for stop command (non-blocking)
            if let Ok(WorkerCommand::Stop) = cmd_rx.try_recv() {
                return;
            }

            // Build current string from indices
            let candidate: String = indices.iter().map(|&i| charset_bytes[i]).collect();

            // Calculate SHA256 hash
            let mut hasher = Sha256::new();
            hasher.update(candidate.as_bytes());
            let result = hasher.finalize();
            let hash_string = format!("{:x}", result);

            attempts += 1;

            // Send progress update every 10000 attempts or 100ms
            if attempts % 10000 == 0 || last_update.elapsed().as_millis() >= 100 {
                let _ = update_tx.send(WorkerUpdate::Progress {
                    current_attempt: candidate.clone(),
                    attempts_count: attempts,
                });
                last_update = Instant::now();
            }

            // Check if we found a match
            if hash_string == target_hash {
                let _ = update_tx.send(WorkerUpdate::Found {
                    match_string: candidate,
                    attempts_count: attempts,
                });
                return;
            }

            // Increment to next combination (like counting in base-N)
            let mut pos = length - 1;
            let mut done = false;
            loop {
                indices[pos] += 1;
                if indices[pos] < charset_bytes.len() {
                    break;
                }
                indices[pos] = 0;
                if pos == 0 {
                    // Reached end of this length, move to next length
                    done = true;
                    break;
                }
                pos -= 1;
            }

            // If we've exhausted all combinations of this length, move to next length
            if done {
                break;
            }
        }
    }

    // Exhausted all possibilities without finding a match
    let _ = update_tx.send(WorkerUpdate::Progress {
        current_attempt: String::from("Search completed - no match found"),
        attempts_count: attempts,
    });
}

// GPU-accelerated worker
fn crack_hash_worker_gpu(
    target_hash: String,
    charset: String,
    min_length: usize,
    max_length: usize,
    cmd_rx: Receiver<WorkerCommand>,
) {
    gpu::crack_hash_gpu(target_hash, charset, min_length, max_length, cmd_rx);
}
