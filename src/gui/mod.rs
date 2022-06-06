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
    Filesystem,
};

use self::task::RunningTask;

mod task;

enum FilesystemAnalysisUpdate {
    Finished(()), // TODO: actual type lmao
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
    },
    AnalyzingDrive {
        task: RunningTask<FilesystemAnalysisUpdate>,
        percent_complete: f64,
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
    fn update(&mut self, ctx: &egui::Context, frame: &mut Frame) {
        self.update_state();

        self.draw_loading_volume_list_state(ctx);
        self.draw_selecting_volume_state(ctx);
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
            percent_complete: 0f64,
        }
    }

    fn update_state(&mut self) {
        match self.state {
            AppState::LoadingVolumeList(ref task) => match task.poll() {
                Some(VolumeListUpdate::Finished(all_drives)) => {
                    self.state = AppState::SelectingDrive {
                        all_drives,
                        selected_idx: 0,
                    };
                }
                Some(VolumeListUpdate::Error(err)) => {
                    todo!("handle error in volume list loading")
                }
                None => {}
            },
            AppState::SelectingDrive { .. } => {}
            AppState::AnalyzingDrive {
                ref task,
                ref mut percent_complete,
            } => match task.poll() {
                Some(FilesystemAnalysisUpdate::Finished(_)) => {
                    todo!("handle results of fs analysis")
                }
                Some(FilesystemAnalysisUpdate::Error(err)) => todo!("handle error in fs analysis"),
                Some(FilesystemAnalysisUpdate::Update { segments_processed, total_segments }) => {
                    *percent_complete = (segments_processed as f64) / (total_segments as f64);
                }
                None => {},
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
        let mut analyze_target = None;
        if let AppState::SelectingDrive {
            ref all_drives,
            ref mut selected_idx,
        } = self.state
        {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.label("Select a volume to analyze:");

                egui::ComboBox::from_id_source("volume_selector")
                    .selected_text(format!("{}", all_drives[*selected_idx]))
                    .show_ui(ui, |ui| {
                        for (i, volume) in all_drives.iter().enumerate() {
                            ui.selectable_value(selected_idx, i, format!("{}", volume));
                        }
                    });

                if ui.button("Analyze!").clicked() {
                    analyze_target = Some(all_drives[*selected_idx].clone());
                }
            });
        }

        if let Some(analyze_target) = analyze_target {
            self.state = Self::create_analyzing_drive_state(ctx, analyze_target);
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
        Ok(_) => FilesystemAnalysisUpdate::Finished(()),
        Err(err) => FilesystemAnalysisUpdate::Error(err),
    }
}

fn sync_parse_drive_contents_helper<F>(
    volume: &VolumeInfo,
    cancel_flag: Arc<AtomicBool>,
    progress_callback: F,
) -> Result<(), Error>
where
    F: Fn(FilesystemAnalysisUpdate),
{
    let mft = mft::MasterFileTable::load(volume.get_handle()?, &volume.paths[0])?;

    std::thread::sleep(std::time::Duration::from_secs(5));

    Ok(())
}
