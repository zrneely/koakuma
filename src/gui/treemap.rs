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
    text: Option<String>, // file or dir name
    full_path: Option<String>,
    size: u64,
    file_count: u64,
    node_idx: u64,
    is_dir: bool,
    mode: TreemapMode,
}
impl Mappable for DrawableRectangle {
    fn size(&self) -> f64 {
        match self.mode {
            TreemapMode::BySize => self.size as f64,
            TreemapMode::ByChildCount => self.file_count as f64,
        }
    }

    fn bounds(&self) -> &treemap::Rect {
        &self.bounds
    }

    fn set_bounds(&mut self, bounds: treemap::Rect) {
        self.bounds = bounds;
    }
}
impl DrawableRectangle {
    fn new(node_idx: u64, data: &FilesystemData, mode: TreemapMode) -> Result<Self, Error> {
        let node = data.get_node(node_idx)?;
        let is_dir = node.has_children();

        Ok(DrawableRectangle {
            bounds: treemap::Rect::default(),
            color: get_random_color(if is_dir {
                random_color::Color::Red
            } else {
                random_color::Color::Green
            }),
            text: node
                .get_filename()
                .map(|str| str.to_string_lossy().to_string()),
            full_path: data
                .get_full_path(node_idx)?
                .map(|str| str.to_string_lossy().to_string()),
            size: node.get_allocated_size_recursive(),
            file_count: node.get_recursive_file_count(),
            node_idx,
            is_dir,
            mode,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TreemapMode {
    BySize,
    ByChildCount,
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
    mode: TreemapMode,
}
impl Treemap {
    pub fn new(data: FilesystemData, mode: TreemapMode) -> Self {
        Treemap {
            current_path: None,
            current_dir: data.get_root_node(),
            rectangles: None,
            last_ui_bounds: None,
            rectangle_positions_valid: false,
            current_hovered: None,
            data,
            mode,
        }
    }

    pub fn get_current_status_text(&self) -> Option<&str> {
        self.current_hovered.as_ref().map(|(text, _)| text.as_str())
    }

    pub fn set_mode(&mut self, mode: TreemapMode) {
        if self.mode != mode {
            self.mode = mode;
            self.invalidate_rectangles();
            self.invalidate_path();
        }
    }

    fn move_to_parent(&mut self) -> Result<(), Error> {
        let parent = self.data.get_node(self.current_dir)?.get_parent();
        self.set_directory(parent)
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
                self.last_ui_bounds = Some(*bounds);
            }
            None => {
                self.last_ui_bounds = Some(*bounds);
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
            Ok(current_path)
        } else {
            let mut new_path = VecDeque::new();
            let mut current_node = self.current_dir;
            loop {
                let node = self.data.get_node(current_node)?;
                new_path.push_front(node.get_filename().unwrap().to_string_lossy().to_string());
                let parent = node.get_parent();
                if parent == current_node {
                    break;
                }
                current_node = parent;
            }

            self.current_path = Some(new_path);

            Ok(self.current_path.as_ref().unwrap())
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
        match self.data.get_node(self.current_dir)?.get_children() {
            Some(children) => children
                .filter(|node| {
                    self.data
                        .get_node(*node)
                        .map(|node| node.get_allocated_size_recursive() > 0)
                        .unwrap_or(false)
                })
                .map(|child_idx| DrawableRectangle::new(child_idx, &self.data, self.mode))
                .collect(),
            None => Ok(Vec::new()),
        }
    }

    fn get_status_text_for_item(&self, item: usize) -> String {
        let item = &self.rectangles.as_ref().unwrap()[item];

        if let Some(ref full_path) = item.full_path {
            if item.file_count > 0 {
                format!(
                    "{} ({}) {{{} children}} [{}]",
                    full_path,
                    item.size.file_size(file_size_opts::BINARY).unwrap(),
                    item.file_count,
                    item.node_idx,
                )
            } else {
                format!(
                    "{} ({}) [{}]",
                    full_path,
                    item.size.file_size(file_size_opts::BINARY).unwrap(),
                    item.node_idx,
                )
            }
        } else {
            format!(
                "(could not get full path) ({}) [{}]",
                item.size.file_size(file_size_opts::BINARY).unwrap(),
                item.node_idx,
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
        let mut should_move_up = false;
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
                    new_directory = Some(item.node_idx);
                    response.mark_changed();
                }

                if item_response.clicked_by(egui::PointerButton::Middle) {
                    item_to_open = item.full_path.clone();
                }

                if item_response.clicked_by(egui::PointerButton::Secondary) {
                    should_move_up = true;
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
        } else if should_move_up {
            self.move_to_parent()
                .expect("Failed to move to parent directory!");
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
        let mut position = *center;
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

        let size_text = match rect_data.mode {
            TreemapMode::BySize => (rect_data.size as u64)
                .file_size(file_size_opts::BINARY)
                .unwrap(),
            TreemapMode::ByChildCount => format!("{} children", rect_data.file_count),
        };
        let galley = painter.layout_no_wrap(
            size_text,
            TextStyle::Small.resolve(ui.style()),
            Rgba::BLACK.into(),
        );
        if let Some(center) = align_bottom(&galley, &mut center, 5.0) {
            painter.galley(center, galley);
        }
    }

    response
}
