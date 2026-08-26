use uuid::Uuid;

use crate::{Color, Note, TagName};

/// A label an operator puts on accesses to select and revoke them in groups.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tag {
    id: Uuid,
    name: TagName,
    color: Option<Color>,
    note: Option<Note>,
}

impl Tag {
    /// Creates a tag with no color and no note.
    pub fn new(name: TagName) -> Self {
        Self {
            id: Uuid::now_v7(),
            name,
            color: None,
            note: None,
        }
    }

    /// Sets the color the panel marks this tag with.
    pub fn with_color(mut self, color: Color) -> Self {
        self.color = Some(color);
        self
    }

    /// Sets the operator note.
    pub fn with_note(mut self, note: Note) -> Self {
        self.note = Some(note);
        self
    }

    /// Identifier assigned at creation.
    pub fn id(&self) -> Uuid {
        self.id
    }

    /// Operator-facing name.
    pub fn name(&self) -> &TagName {
        &self.name
    }

    /// Color the panel marks this tag with, if one is set.
    pub fn color(&self) -> Option<&Color> {
        self.color.as_ref()
    }

    /// Operator note, if one is set.
    pub fn note(&self) -> Option<&Note> {
        self.note.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_tag_carries_only_its_name() {
        let tag = Tag::new(TagName::try_from("friends").unwrap());
        assert_eq!(tag.name().as_str(), "friends");
        assert_eq!(tag.color(), None);
        assert_eq!(tag.note(), None);
    }

    #[test]
    fn color_and_note_are_optional_extras() {
        let tag = Tag::new(TagName::try_from("resale").unwrap())
            .with_color(Color::try_from("#1a2b3c").unwrap())
            .with_note(Note::try_from("paid tier").unwrap());
        assert_eq!(tag.color().map(Color::as_str), Some("#1a2b3c"));
        assert_eq!(tag.note().map(Note::as_str), Some("paid tier"));
    }
}
