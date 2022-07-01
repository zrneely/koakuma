use std::{
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
};

use egui::Context;

pub struct RunningTask<T: Send + 'static> {
    progress: Arc<Mutex<Option<T>>>,
    cancel_flag: Arc<AtomicBool>,
}
impl<T: Send + 'static> Clone for RunningTask<T> {
    fn clone(&self) -> Self {
        Self {
            progress: Arc::clone(&self.progress),
            cancel_flag: Arc::clone(&self.cancel_flag),
        }
    }
}
impl<T: Send + 'static> RunningTask<T> {
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::Relaxed);
    }

    /// Returns None if there is no update since the last time asked
    pub fn get_most_recent_update(&self) -> Option<T> {
        self.progress.lock().unwrap().take()
    }
}

pub fn spawn_task<Task, Update>(ctx: &Context, task: Task) -> RunningTask<Update>
where
    Task: (Fn(Arc<AtomicBool>, Box<dyn Fn(Update) + Send>) -> Update) + Send + 'static,
    Update: Send + 'static,
{
    let ctx_for_remote = ctx.clone();
    let ctx_final = ctx.clone();

    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_flag_for_remote = cancel_flag.clone();

    let progress = Arc::new(Mutex::new(None));
    let progress_for_remote = progress.clone();
    let progress_final = progress.clone();

    thread::spawn(move || {
        let result = task(
            cancel_flag_for_remote,
            Box::new(move |update| {
                *progress_for_remote.lock().unwrap() = Some(update);
                ctx_for_remote.request_repaint();
            }),
        );

        *progress_final.lock().unwrap() = Some(result);
        ctx_final.request_repaint();
    });

    RunningTask {
        progress,
        cancel_flag,
    }
}
