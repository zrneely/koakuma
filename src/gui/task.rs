use std::{sync::{mpsc::{Receiver, self}, atomic::{AtomicBool, Ordering}, Arc}, thread};

use egui::Context;

pub struct RunningTask<T: Send + 'static> {
    update_receiver: Receiver<T>,
    cancel_flag: Arc<AtomicBool>,
}
impl<T: Send + 'static> RunningTask<T> {
    pub fn cancel(&self) {
        self.cancel_flag.store(true, Ordering::SeqCst);
    }

    pub fn poll(&self) -> Option<T> {
        self.update_receiver.try_recv().ok()
    }
}

pub fn spawn_task<Task,  Update>(ctx: &Context, task: Task) -> RunningTask<Update>
where
    Task: (Fn(Arc<AtomicBool>, Box<dyn Fn(Update) + Send>) -> Update) + Send + 'static,
    Update: Send + 'static,
{
    let (update_sender, update_receiver) = mpsc::channel();
    let final_update_sender = update_sender.clone();

    let ctx = ctx.clone();
    let cancel_flag = Arc::new(AtomicBool::new(false));
    let cancel_flag_for_remote = cancel_flag.clone();

    thread::spawn(move || {
        let result = task(cancel_flag_for_remote, Box::new(move |update| {
            update_sender.send(update).unwrap();
            ctx.request_repaint();
        }));

        final_update_sender.send(result).unwrap();
    });

    RunningTask { update_receiver, cancel_flag }
}