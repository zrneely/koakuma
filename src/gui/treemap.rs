use std::{collections::VecDeque, sync::Arc};

use egui::{Color32, Galley, Pos2, Rgba, TextStyle, Widget};
use humansize::{file_size_opts, FileSize};
use treemap::{Mappable, TreemapLayout};

use crate::err::Error;

use super::filesystem::FilesystemData;

fn egui_to_treemap(inp: &egui::Rect) -> treemap::Rect {
    treemap::Rect {
        x: inp.left() as f64,
        y: inp.top() as f64,
        w: inp.width() as f64,
        h: inp.height() as f64,
    }
}

fn treemap_to_egui(inp: &treemap::Rect) -> egui::Rect {
    egui::Rect::from_min_size(
        egui::pos2(inp.x as f32, inp.y as f32),
        egui::vec2(inp.w as f32, inp.h as f32),
    )
}

fn get_random_color(base_color: random_color::Color) -> Color32 {
    let [r, g, b] = random_color::RandomColor::new()
        .hue(base_color)
        .to_rgb_array();
    Color32::from_rgb(r, g, b)
}

#[derive(Debug)]
struct DrawableRectangle {
    bounds: treemap::Rect,
    color: egui::Color32,
    text: Option<String>,        // file or dir name
    full_path: Option<String>,
    size: u64,
    node: u64,
    is_dir: bool,
}
impl Mappable for DrawableRectangle {
    fn size(&self) -> f64 {
        self.size as f64
    }

    fn bounds(&self) -> &treemap::Rect {
        &self.bounds
    }

    fn set_bounds(&mut self, bounds: treemap::Rect) {
        self.bounds = bounds;
    }
}
impl DrawableRectangle {
    fn new(node: u64, data: &FilesystemData) -> Result<Self, Error> {
        let is_dir = data.get_children(node)?.is_some();

        Ok(DrawableRectangle {
            bounds: treemap::Rect::default(),
            color: get_random_color(if is_dir {
                random_color::Color::Red
            } else {
                random_color::Color::Green
            }),
            text: data
                .get_filename(node)?
                .map(|str| str.to_string_lossy().to_string()),
            full_path: data
                .get_full_path(node)?
                .map(|str| str.to_string_lossy().to_string()),
            size: data.get_allocated_size_recursive(node)?,
            node,
            is_dir,
        })
    }
}

pub struct Treemap {
    data: FilesystemData,
    current_path: Option<VecDeque<String>>,
    current_dir: u64,
    // recurse_draw_depth: usize,
    rectangles: Option<Vec<DrawableRectangle>>,
    last_ui_bounds: Option<egui::Rect>,
    rectangle_positions_valid: bool,
    current_hovered: Option<(String, usize)>, // text, idx
}
impl Treemap {
    pub fn new(data: FilesystemData) -> Self {
        Treemap {
            current_path: None,
            current_dir: data.get_root_node(),
            rectangles: None,
            last_ui_bounds: None,
            rectangle_positions_valid: false,
            current_hovered: None,
            data,
        }
    }

    pub fn get_current_status_text(&self) -> Option<&str> {
        self.current_hovered.as_ref().map(|(text, _)| text.as_str())
    }

    fn set_directory(&mut self, dir: u64) -> Result<(), Error> {
        self.current_dir = dir;

        self.invalidate_rectangles();
        self.invalidate_path();

        Ok(())
    }

    fn set_ui_bounds(&mut self, bounds: &egui::Rect) {
        match self.last_ui_bounds {
            Some(ref mut last_bounds) if last_bounds != bounds => {
                println!("Requesting relayout: {:?} => {:?}", last_bounds, bounds);
                self.invalidate_rectangles();
                self.last_ui_bounds = Some(bounds.clone());
            }
            None => {
                self.last_ui_bounds = Some(bounds.clone());
            }

            Some(_) => {}
        }
    }

    fn invalidate_rectangles(&mut self) {
        self.rectangle_positions_valid = false;
        self.current_hovered = None;
    }

    fn invalidate_path(&mut self) {
        self.current_path = None;
        self.rectangles = None;
    }

    fn get_current_path(&mut self) -> Result<&VecDeque<String>, Error> {
        if let Some(ref current_path) = self.current_path {
            Ok(&current_path)
        } else {
            let mut new_path = VecDeque::new();
            let mut current_node = self.current_dir;
            loop {
                new_path.push_front(
                    self.data
                        .get_filename(current_node)?
                        .unwrap()
                        .to_string_lossy()
                        .to_string(),
                );
                let parent = self.data.get_parent(current_node)?;
                if parent == current_node {
                    break;
                }
                current_node = parent;
            }

            self.current_path = Some(new_path);

            Ok(&self.current_path.as_ref().unwrap())
        }
    }

    fn get_layout_items(&mut self, bounds: &egui::Rect) -> Result<&[DrawableRectangle], Error> {
        self.set_ui_bounds(bounds);

        if let Some(ref mut rectangles) = self.rectangles {
            if self.rectangle_positions_valid {
                Ok(rectangles.as_slice())
            } else {
                self.rectangle_positions_valid = true;
                TreemapLayout {}.layout_items(rectangles, egui_to_treemap(bounds));
                Ok(rectangles.as_slice())
            }
        } else {
            let mut rectangles = self.create_drawable_nodes()?;
            TreemapLayout {}.layout_items(&mut rectangles, egui_to_treemap(bounds));
            self.rectangles = Some(rectangles);
            self.rectangle_positions_valid = true;

            Ok(self.rectangles.as_ref().unwrap().as_slice())
        }
    }

    fn create_drawable_nodes(&self) -> Result<Vec<DrawableRectangle>, Error> {
        match self.data.get_children(self.current_dir)? {
            Some(children) => children
                .filter(|node| {
                    self.data
                        .get_allocated_size_recursive(*node)
                        .map(|size| size > 0)
                        .unwrap_or(false)
                })
                .map(|child_idx| DrawableRectangle::new(child_idx, &self.data))
                .collect(),
            None => Ok(Vec::new()),
        }
    }

    fn get_status_text_for_item(&self, item: usize) -> String {
        let item = &self.rectangles.as_ref().unwrap()[item];

        if let Some(ref full_path) = item.full_path {
            format!("{} ({})", full_path, item.size.file_size(file_size_opts::BINARY).unwrap())
        } else {
            format!(
                "(could not get full path) ({})",
                item.size.file_size(file_size_opts::BINARY).unwrap()
            )
        }
    }
}

impl Widget for &mut Treemap {
    fn ui(self, ui: &mut egui::Ui) -> egui::Response {
        let size = ui.available_size();
        let (rect, mut response) = ui.allocate_exact_size(size, egui::Sense::hover());

        let mut new_directory = None;
        let mut item_to_open = None;
        let mut hovered_item = None;
        {
            let items = match self.get_layout_items(&rect) {
                Ok(items) => items,
                Err(err) => {
                    let label = egui::Label::new(format!("Error: {:?}", err));
                    return label.ui(ui);
                }
            };

            for (idx, item) in items.iter().enumerate() {
                let item_response = ui.put(treemap_to_egui(&item.bounds), rectangle(item));

                if item_response.hovered() {
                    hovered_item = Some(idx);
                }

                if item.is_dir && item_response.double_clicked() {
                    new_directory = Some(item.node);
                    response.mark_changed();
                }

                if item_response.clicked_by(egui::PointerButton::Secondary) {
                    item_to_open = item.full_path.clone();
                }
            }
        }

        let mut updated_hover = None;
        if let Some(new_hovered_item) = hovered_item {
            if let Some((_, ref hovered_item)) = self.current_hovered {
                // if we are currently hovering something, and something was hovered last frame,
                // make sure they're the same
                if new_hovered_item != *hovered_item {
                    updated_hover = Some((
                        self.get_status_text_for_item(new_hovered_item),
                        new_hovered_item,
                    ));
                }
            } else {
                // if we are currently hovering something, and nothing was hovered last frame,
                // update what we're currently hovering
                updated_hover = Some((
                    self.get_status_text_for_item(new_hovered_item),
                    new_hovered_item,
                ));
            }
        } else if self.current_hovered.is_some() {
            // if we're not hovering anything, but last frame we were, clear the current hover state
            self.current_hovered = None;
            response.mark_changed();
        } else {
            // if we're not hovering anything, and last frame we weren't hovering anything, there is nothing to do
        }

        if let Some(item_to_open) = item_to_open {
            let mut command = std::process::Command::new("explorer.exe");
            // TODO: this doesn't work for paths with spaces
            command.arg(format!("/select,{}", item_to_open));
            command.spawn().unwrap();
        }

        if let Some(updated_hover) = updated_hover {
            self.current_hovered = Some(updated_hover);
            response.mark_changed();
        }

        if let Some(new_directory) = new_directory {
            self.set_directory(new_directory)
                .expect("Failed to set new directory!");
        }

        response
    }
}

fn rectangle(rect_data: &DrawableRectangle) -> impl Widget + '_ {
    move |ui: &mut egui::Ui| rectangle_ui(ui, rect_data)
}

fn rectangle_ui(ui: &mut egui::Ui, rect_data: &DrawableRectangle) -> egui::Response {
    let size = ui.available_size();
    let (rect, response) = ui.allocate_exact_size(size, egui::Sense::click());

    let stroke = egui::Stroke::new(1.0, rect_data.color);
    let color = if ui.ui_contains_pointer() {
        egui::Color32::from_rgb(
            rect_data.color.r().saturating_add(25),
            rect_data.color.g().saturating_add(25),
            rect_data.color.b().saturating_add(25),
        )
    } else {
        rect_data.color
    };

    let painter = ui.painter();
    painter.rect(rect, 2.0, color, stroke);

    let mut center = rect.center();
    let align_bottom = |galley: &Arc<Galley>, center: &mut Pos2, spacing: f32| {
        let mut position = center.clone();
        let size = galley.size();
        position.x -= size.x / 2.0;
        position.y -= size.y / 2.0;
        center.y += size.y + spacing;
        if size.x < rect.width() && size.y < rect.height() {
            Some(position)
        } else {
            None
        }
    };

    if let Some(ref text) = rect_data.text {
        let width = rect.width() - ui.spacing().button_padding.x * 2.0;
        let galley = painter.layout(
            text.clone(),
            TextStyle::Body.resolve(ui.style()),
            Rgba::BLACK.into(),
            width,
        );
        let previous_center = center;
        if let Some(center) = align_bottom(&galley, &mut center, 2.0) {
            painter.galley(center, galley);
        } else {
            center = previous_center;
        }

        let text = (rect_data.size as u64)
            .file_size(file_size_opts::BINARY)
            .unwrap();
        let galley = painter.layout_no_wrap(
            text,
            TextStyle::Small.resolve(ui.style()),
            Rgba::BLACK.into(),
        );
        if let Some(center) = align_bottom(&galley, &mut center, 5.0) {
            painter.galley(center, galley);
        }
    }

    response
}
