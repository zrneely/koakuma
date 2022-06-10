use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};

use eframe::{App, Frame};
use egui::Context;

use crate::{
    err::Error,
    mft,
    volumes::{VolumeInfo, VolumeIterator},
};

use self::{task::RunningTask, treemap::FilesystemData};

mod task;
mod treemap;

enum FilesystemAnalysisUpdate {
    Finished(FilesystemData),
    Update {
        segments_processed: u64,
        total_segments: u64,
    },
    Error(Error),
}

enum VolumeListUpdate {
    Finished(Vec<VolumeInfo>),
    Error(Error),
}

enum AppState {
    LoadingVolumeList(RunningTask<VolumeListUpdate>),
    SelectingDrive {
        all_drives: Vec<VolumeInfo>,
        selected_idx: usize,
        analyze_clicked: bool,
    },
    AnalyzingDrive {
        task: RunningTask<FilesystemAnalysisUpdate>,
        percent_complete: f32,
        total_entries: u64,
        processed_entries: u64,
    },
    AnalysisFinished,
}

pub struct KoakumaApp {
    state: AppState,
}
impl KoakumaApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        cc.egui_ctx.set_visuals(egui::Visuals::dark());
        KoakumaApp {
            state: KoakumaApp::create_volume_list_load_state(&cc.egui_ctx),
        }
    }
}
impl App for KoakumaApp {
    fn update(&mut self, ctx: &egui::Context, _: &mut Frame) {
        self.update_state(ctx);

        self.draw_loading_volume_list_state(ctx);
        self.draw_selecting_volume_state(ctx);
        self.draw_loading_analysis_state(ctx);
    }
}
impl KoakumaApp {
    fn create_volume_list_load_state(ctx: &Context) -> AppState {
        let task = task::spawn_task(ctx, sync_read_volume_list);
        AppState::LoadingVolumeList(task)
    }

    fn create_analyzing_drive_state(ctx: &Context, volume: VolumeInfo) -> AppState {
        AppState::AnalyzingDrive {
            task: task::spawn_task(ctx, move |cancel_flag, callback| {
                sync_parse_drive_contents(&volume, cancel_flag, callback)
            }),
            percent_complete: 0f32,
            total_entries: 0,
            processed_entries: 0,
        }
    }

    fn update_state(&mut self, ctx: &Context) {
        match self.state {
            AppState::LoadingVolumeList(ref task) => match task.get_most_recent_update() {
                Some(VolumeListUpdate::Finished(all_drives)) => {
                    self.state = AppState::SelectingDrive {
                        all_drives,
                        selected_idx: 0,
                        analyze_clicked: false,
                    };
                }
                Some(VolumeListUpdate::Error(err)) => {
                    todo!("handle error in volume list loading")
                }
                None => {}
            },
            AppState::SelectingDrive {
                analyze_clicked,
                ref all_drives,
                selected_idx,
            } => {
                if analyze_clicked {
                    self.state =
                        Self::create_analyzing_drive_state(ctx, all_drives[selected_idx].clone());
                }
            }
            AppState::AnalyzingDrive {
                ref task,
                ref mut percent_complete,
                ref mut total_entries,
                ref mut processed_entries,
            } => match task.get_most_recent_update() {
                Some(FilesystemAnalysisUpdate::Finished(_)) => {
                    println!("Analysis finished!");
                    self.state = AppState::AnalysisFinished;
                }
                Some(FilesystemAnalysisUpdate::Error(err)) => todo!("handle error in fs analysis"),
                Some(FilesystemAnalysisUpdate::Update {
                    segments_processed,
                    total_segments,
                }) => {
                    *percent_complete = (segments_processed as f32) / (total_segments as f32);
                    *total_entries = total_segments;
                    *processed_entries = segments_processed;
                }
                None => {}
            },
            AppState::AnalysisFinished => {}
        }
    }

    fn draw_loading_volume_list_state(&self, ctx: &Context) {
        if let AppState::LoadingVolumeList(_) = self.state {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Loading volumes...");
            });
        }
    }

    fn draw_selecting_volume_state(&mut self, ctx: &Context) {
        if let AppState::SelectingDrive {
            ref all_drives,
            ref mut selected_idx,
            ref mut analyze_clicked,
        } = self.state
        {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Select a volume to analyze:");

                egui::ComboBox::from_id_source("volume_selector")
                    .selected_text(format!("{}", all_drives[*selected_idx]))
                    .width(ui.available_width() - ui.spacing().item_spacing.x)
                    .show_ui(ui, |ui| {
                        for (i, volume) in all_drives.iter().enumerate() {
                            ui.selectable_value(selected_idx, i, format!("{}", volume));
                        }
                    });

                ui.add_space(5.0);

                if ui.button("Analyze!").clicked() {
                    *analyze_clicked = true;
                    ctx.request_repaint();
                }
            });
        }
    }

    fn draw_loading_analysis_state(&mut self, ctx: &Context) {
        if let AppState::AnalyzingDrive {
            percent_complete,
            total_entries,
            processed_entries,
            ref task,
        } = self.state
        {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Reading volume...");

                ui.add_space(5.0);

                let progress_bar = egui::ProgressBar::new(percent_complete).text(format!(
                    "{} / {} ({:.2}%)",
                    processed_entries,
                    total_entries,
                    percent_complete * 100f32
                ));
                ui.add(progress_bar);

                // ui.add_space(100.0);

                let button = egui::Button::new("Cancel");
                if ui.add(button).clicked() {
                    println!("Cancelling...");
                    task.cancel();
                }
            });
        }
    }
}

fn sync_read_volume_list<F>(cancel_flag: Arc<AtomicBool>, _progress_callback: F) -> VolumeListUpdate
where
    F: Fn(VolumeListUpdate),
{
    match sync_read_volume_list_helper(cancel_flag) {
        Ok(result) => VolumeListUpdate::Finished(result),
        Err(err) => VolumeListUpdate::Error(err),
    }
}

fn sync_read_volume_list_helper(cancel_flag: Arc<AtomicBool>) -> Result<Vec<VolumeInfo>, Error> {
    let iterator = VolumeIterator::new()?;
    let mut result = Vec::new();
    for drive in iterator {
        result.push(drive?);

        if cancel_flag.load(Ordering::SeqCst) {
            return Err(Error::OperationCancelled);
        }
    }

    result.sort_by_cached_key(<VolumeInfo as ToString>::to_string);

    Ok(result)
}

fn sync_parse_drive_contents<F>(
    volume: &VolumeInfo,
    cancel_flag: Arc<AtomicBool>,
    progress_callback: F,
) -> FilesystemAnalysisUpdate
where
    F: Fn(FilesystemAnalysisUpdate),
{
    match sync_parse_drive_contents_helper(volume, cancel_flag, progress_callback) {
        Ok(filesystem_data) => FilesystemAnalysisUpdate::Finished(filesystem_data),
        Err(err) => FilesystemAnalysisUpdate::Error(err),
    }
}

fn sync_parse_drive_contents_helper<F>(
    volume: &VolumeInfo,
    cancel_flag: Arc<AtomicBool>,
    progress_callback: F,
) -> Result<FilesystemData, Error>
where
    F: Fn(FilesystemAnalysisUpdate),
{
    let mut mft = mft::MasterFileTable::load(volume.get_handle()?, &volume.paths[0])?;
    let total_segments = mft.entry_count();
    progress_callback(FilesystemAnalysisUpdate::Update {
        segments_processed: 0,
        total_segments,
    });

    // Read entries in blocks of 500
    let mut filesystem_data =
        FilesystemData::new(mft.bytes_per_cluster(), mft.entry_count() as usize);
    let mut reached_end = false;
    let mut total_processed = 0;
    while !reached_end && !cancel_flag.load(Ordering::SeqCst) {
        for _ in 0..500 {
            filesystem_data.add_entry(match mft.next() {
                Some(val) => {
                    total_processed += 1;
                    val?
                }
                None => {
                    reached_end = true;
                    break;
                }
            });
        }

        progress_callback(FilesystemAnalysisUpdate::Update {
            segments_processed: total_processed,
            total_segments,
        });
    }

    let start = std::time::Instant::now();
    filesystem_data.populate_children();
    println!(
        "Populated children in {:?}",
        std::time::Instant::now() - start
    );

    if cancel_flag.load(Ordering::SeqCst) {
        Err(Error::OperationCancelled)
    } else {
        Ok(filesystem_data)
    }
}
