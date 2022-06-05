use eframe::{App, Frame};

pub struct KoakumaApp {}
impl KoakumaApp {
    pub fn new(cc: &eframe::CreationContext<'_>) -> Self {
        KoakumaApp {}
    }
}
impl App for KoakumaApp {
    fn update(&mut self, ctx: &egui::Context, frame: &mut Frame) {
        todo!()
    }
}
