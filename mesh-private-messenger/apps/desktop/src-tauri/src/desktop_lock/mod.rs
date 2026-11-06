pub mod adapter;
pub mod controller;
pub mod native_policy;
pub mod native_protection;
pub mod wire;
pub mod receiver_scope;
pub mod commands;
pub mod bootstrap;
mod startup;
pub(crate) mod native_job;
pub(crate) mod resources;
pub(crate) mod private_wallet;
pub(crate) mod private_commands;
pub(crate) mod legacy_profile;
pub(crate) mod legacy_commands;

pub(crate) mod private_files;
pub(crate) mod private_choices;
pub(crate) mod private_exports;
pub(crate) mod private_destinations;
pub(crate) mod private_preview;
pub(crate) mod stage_startup;
pub(crate) mod native_panels;
pub(crate) mod private_backup_choices;
pub(crate) mod private_avatar_choices;
pub(crate) mod avatar_import;
pub(crate) mod file_commands;
mod file_reply;

pub(crate) mod notification_actions;
pub(crate) mod notification_commands;

pub(crate) mod native_notices;
pub(crate) mod notice_wire;

pub(crate) mod document;

mod incoming_files;
mod native_incoming;
