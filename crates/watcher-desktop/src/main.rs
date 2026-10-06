//! App Network Watcher opens on the debugger. There is no account screen.

use std::collections::BTreeSet;
use std::fs;
use std::time::Duration;

use iced::event::{self, Event};
use iced::keyboard::{self, key, Key};
use iced::widget::{
    button, checkbox, container, operation, row, scrollable, text, text_input, Column, Id, Row,
};
use iced::{color, window, Alignment, Background, Border, Color, Element, Font, Length, Shadow, Subscription, Task, Theme, Vector};
use watcher_desktop::{
    app_data_dir, check_approval, connect_android, debug_only_network_security_config,
    export_har, export_request, header_block, import_har, install_system_ca, json_lines,
    local_lan_ip, manifest_attribute, move_id, parse_header_block, qr_blocks, qr_payload,
    release_network_security_config, request_text, response_text, rule_from_exchange,
    traffic_rows, validate_openapi, Action, AdbDevice, BodyHandle, BreakpointDecision,
    ConnectRequest, ExportKind, FilterAlias, HttpVersion, Phase, Rule, Session, Tone,
};
use watcher_proxy::RunningProxy;

const FILTER_ID: &str = "traffic-filter";

fn main() -> iced::Result {
    iced::application(boot, update, view)
        .title("App Network Watcher")
        .subscription(subscription)
        .theme(theme)
        .window_size(iced::Size::new(1280.0, 800.0))
        .run()
}

struct Desk {
    runtime: tokio::runtime::Runtime,
    session: Session,
    proxy: Option<RunningProxy>,
    port: u16,
    filter: String,
    selected: Option<watcher_core::ExchangeId>,
    tab: Tab,
    collapsed: BTreeSet<String>,
    editors_for: Option<watcher_core::ExchangeId>,
    notice: String,
    android_banner: String,
    devices: Vec<AdbDevice>,
    serial: String,
    confirm_system: bool,
    already_rooted: bool,
    dark: bool,
    advertise: String,
    port_text: String,
    http_version: HttpVersion,
    passthrough: String,
    intercept_only: String,
    upstream: String,
    accept_invalid: bool,
    extra_ca_path: String,
    client_cert_path: String,
    client_key_path: String,
    alias_name: String,
    alias_query: String,
    bp_headers: String,
    bp_body: String,
    bp_status: String,
    client_method: String,
    client_url: String,
    client_headers: String,
    client_body: String,
    rule_name: String,
    rule_method: String,
    rule_host: String,
    rule_path: String,
    rule_status: String,
    rule_body: String,
    rule_delay: String,
    rule_location: String,
    rule_headers: String,
    file_path: String,
    openapi_path: String,
    openapi: Option<serde_json::Value>,
    openapi_report: String,
    export_preview: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Tab {
    Request,
    Response,
    Timing,
}

#[derive(Clone, Debug)]
enum Message {
    Poll,
    SelectDelta(i32),
    ClearFilter,
    FocusFilter,
    FilterChanged(String),
    Select(watcher_core::ExchangeId),
    Pin,
    Delete,
    ClearUnpinned,
    Tab(Tab),
    ToggleJson(String),
    SetDark(bool),
    RefreshDevices,
    SerialChanged(String),
    ConnectAndroid,
    CheckApproval,
    SetSystemConfirm(bool),
    SetRooted(bool),
    InstallSystemCa,
    ManualProxy,
    PortChanged(String),
    AdvertiseChanged(String),
    Version(HttpVersion),
    PassthroughChanged(String),
    InterceptOnlyChanged(String),
    UpstreamChanged(String),
    AcceptInvalid(bool),
    ExtraCaChanged(String),
    ClientCertChanged(String),
    ClientKeyChanged(String),
    ApplyProxy,
    AliasName(String),
    AliasQuery(String),
    SaveAlias,
    UseAlias(String),
    DeleteAlias(String),
    BreakpointHeaders(String),
    BreakpointBody(String),
    BreakpointStatus(String),
    Forward,
    Respond,
    DropCall,
    ClientMethod(String),
    ClientUrl(String),
    ClientHeaders(String),
    ClientBody(String),
    Send,
    RuleName(String),
    RuleMethod(String),
    RuleHost(String),
    RulePath(String),
    RuleStatus(String),
    RuleBody(String),
    RuleDelay(String),
    RuleLocation(String),
    RuleHeaders(String),
    AddRule(&'static str),
    RuleFromCall,
    ToggleRule(String),
    DeleteRule(String),
    MoveRule(String, bool),
    FilePath(String),
    ExportHar,
    ImportHar,
    OpenApiPath(String),
    LoadOpenApi,
    ExportCode(ExportKind),
    Copy(String),
}

fn boot() -> Desk {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    let session = Session::open(app_data_dir()).unwrap_or_else(|err| {
        let fallback = std::env::temp_dir().join("app-network-watcher");
        Session::open(&fallback).unwrap_or_else(|second| {
            panic!("session directory could not be opened: {err}; fallback: {second}")
        })
    });
    let settings = session.settings();
    let mut desk = Desk {
        runtime,
        session,
        proxy: None,
        port: settings.port,
        filter: String::new(),
        selected: None,
        tab: Tab::Request,
        collapsed: BTreeSet::new(),
        editors_for: None,
        notice: String::new(),
        android_banner: String::new(),
        devices: Vec::new(),
        serial: String::new(),
        confirm_system: false,
        already_rooted: false,
        dark: settings.dark_theme,
        advertise: local_lan_ip().unwrap_or_else(|| settings.advertise_host.clone()),
        port_text: settings.port.to_string(),
        http_version: settings.http_version,
        passthrough: settings.passthrough_hosts.join(", "),
        intercept_only: settings.intercept_only.join(", "),
        upstream: settings.upstream_proxy.clone().unwrap_or_default(),
        accept_invalid: settings.upstream_tls.accept_invalid_certs,
        extra_ca_path: String::new(),
        client_cert_path: String::new(),
        client_key_path: String::new(),
        alias_name: String::new(),
        alias_query: String::new(),
        bp_headers: String::new(),
        bp_body: String::new(),
        bp_status: "200".into(),
        client_method: "GET".into(),
        client_url: "http://127.0.0.1/".into(),
        client_headers: String::new(),
        client_body: String::new(),
        rule_name: "rule".into(),
        rule_method: String::new(),
        rule_host: String::new(),
        rule_path: String::new(),
        rule_status: "200".into(),
        rule_body: String::new(),
        rule_delay: "1000".into(),
        rule_location: "https://example.test/".into(),
        rule_headers: String::new(),
        file_path: String::new(),
        openapi_path: String::new(),
        openapi: None,
        openapi_report: String::new(),
        export_preview: String::new(),
    };
    desk.restart_proxy();
    desk
}

fn update(desk: &mut Desk, message: Message) -> Task<Message> {
    match message {
        Message::Poll => {
            if desk.selected.is_none() {
                let rows = traffic_rows(
                    &desk.session.exchanges(),
                    &desk.filter,
                    &desk.session.aliases(),
                );
                desk.selected = rows.last().map(|row| row.id);
            }
            desk.sync_editors();
        }
        Message::SelectDelta(delta) => {
            let rows = traffic_rows(&desk.session.exchanges(), &desk.filter, &desk.session.aliases());
            desk.selected = move_id(&rows, desk.selected, delta);
            desk.editors_for = None;
            desk.sync_editors();
        }
        Message::ClearFilter => desk.filter.clear(),
        Message::FocusFilter => return operation::focus(Id::new(FILTER_ID)),
        Message::FilterChanged(value) => desk.filter = value,
        Message::Select(id) => {
            desk.selected = Some(id);
            desk.editors_for = None;
            desk.sync_editors();
        }
        Message::Pin => {
            if let Some(id) = desk.selected {
                let pinned = desk
                    .session
                    .exchanges()
                    .into_iter()
                    .find(|item| item.id == id)
                    .map(|item| !item.pinned)
                    .unwrap_or(true);
                desk.session.set_pinned(id, pinned);
            }
        }
        Message::Delete => {
            if let Some(id) = desk.selected.take() {
                desk.session.delete(id);
                desk.editors_for = None;
            }
        }
        Message::ClearUnpinned => desk.session.clear_unpinned(),
        Message::Tab(tab) => desk.tab = tab,
        Message::ToggleJson(path) => {
            if !desk.collapsed.remove(&path) {
                desk.collapsed.insert(path);
            }
        }
        Message::SetDark(dark) => {
            desk.dark = dark;
            let mut settings = desk.session.settings();
            settings.dark_theme = dark;
            let _ = desk.session.update_settings(settings);
        }
        Message::RefreshDevices => match watcher_desktop::run_command("adb", &["devices".into(), "-l".into()]) {
            Ok(text) => {
                desk.devices = watcher_desktop::parse_devices(&text);
                if desk.serial.is_empty() {
                    if let Some(device) = desk.devices.first() {
                        desk.serial = device.serial.clone();
                    }
                }
                if desk.devices.is_empty() {
                    desk.notice = "No Android device is attached. Manual proxy mode can still capture a client on this computer.".into();
                }
            }
            Err(err) => desk.notice = err,
        },
        Message::SerialChanged(value) => desk.serial = value,
        Message::ConnectAndroid => {
            let request = ConnectRequest {
                serial: desk.serial.clone(),
                port: desk.port,
                ca_cer: desk.session.ca().cer_path().display().to_string(),
                fingerprint: desk.session.ca().fingerprint.clone(),
                apk: Some("android/app/build/outputs/apk/debug/app-debug.apk".into()),
            };
            desk.notice = connect_android(&request, watcher_desktop::run_command);
            desk.android_banner.clear();
        }
        Message::CheckApproval => {
            desk.android_banner = check_approval(&desk.serial, desk.port, watcher_desktop::run_command);
            desk.notice = desk.android_banner.clone();
        }
        Message::SetSystemConfirm(value) => desk.confirm_system = value,
        Message::SetRooted(value) => desk.already_rooted = value,
        Message::InstallSystemCa => {
            let emulator = desk
                .devices
                .iter()
                .find(|device| device.serial == desk.serial)
                .map(|device| device.emulator)
                .unwrap_or(false);
            desk.notice = install_system_ca(
                desk.confirm_system,
                emulator || desk.already_rooted,
                &desk.serial,
                &desk.session.ca().cert_path().display().to_string(),
                watcher_desktop::run_command,
            );
        }
        Message::ManualProxy => {
            desk.android_banner.clear();
            desk.restart_proxy();
            desk.notice = format!(
                "Manual proxy on 127.0.0.1:{}. No VPN is active.",
                desk.port
            );
        }
        Message::PortChanged(value) => desk.port_text = value,
        Message::AdvertiseChanged(value) => desk.advertise = value,
        Message::Version(version) => {
            desk.http_version = version;
            desk.apply_proxy();
        }
        Message::PassthroughChanged(value) => desk.passthrough = value,
        Message::InterceptOnlyChanged(value) => desk.intercept_only = value,
        Message::UpstreamChanged(value) => desk.upstream = value,
        Message::AcceptInvalid(value) => desk.accept_invalid = value,
        Message::ExtraCaChanged(value) => desk.extra_ca_path = value,
        Message::ClientCertChanged(value) => desk.client_cert_path = value,
        Message::ClientKeyChanged(value) => desk.client_key_path = value,
        Message::ApplyProxy => desk.apply_proxy(),
        Message::AliasName(value) => desk.alias_name = value,
        Message::AliasQuery(value) => desk.alias_query = value,
        Message::SaveAlias => {
            let mut aliases = desk.session.aliases();
            aliases.retain(|alias| alias.name != desk.alias_name);
            aliases.push(FilterAlias {
                name: desk.alias_name.trim().to_string(),
                query: desk.alias_query.clone(),
            });
            if let Err(err) = desk.session.update_aliases(aliases) {
                desk.notice = err.to_string();
            }
        }
        Message::UseAlias(name) => desk.filter = format!("alias:{name}"),
        Message::DeleteAlias(name) => {
            let mut aliases = desk.session.aliases();
            aliases.retain(|alias| alias.name != name);
            let _ = desk.session.update_aliases(aliases);
        }
        Message::BreakpointHeaders(value) => desk.bp_headers = value,
        Message::BreakpointBody(value) => desk.bp_body = value,
        Message::BreakpointStatus(value) => desk.bp_status = value,
        Message::Forward => desk.resume(BreakpointDecision::Forward {
            headers: parse_header_block(&desk.bp_headers),
            body: desk.bp_body.as_bytes().to_vec(),
        }),
        Message::Respond => desk.resume(BreakpointDecision::Respond {
            status: desk.bp_status.parse().unwrap_or(200),
            headers: parse_header_block(&desk.bp_headers),
            body: desk.bp_body.as_bytes().to_vec(),
        }),
        Message::DropCall => desk.resume(BreakpointDecision::Fail {
            message: "dropped from the debugger".into(),
        }),
        Message::ClientMethod(value) => desk.client_method = value,
        Message::ClientUrl(value) => desk.client_url = value,
        Message::ClientHeaders(value) => desk.client_headers = value,
        Message::ClientBody(value) => desk.client_body = value,
        Message::Send => {
            let result = desk.runtime.block_on(watcher_proxy::send_edited(
                desk.port,
                &desk.session.ca().cert_der,
                &desk.client_method,
                &desk.client_url,
                &parse_header_block(&desk.client_headers),
                desk.client_body.as_bytes(),
            ));
            desk.notice = match result {
                Ok(()) => "Edited request was sent through the local proxy.".into(),
                Err(err) => err,
            };
        }
        Message::RuleName(value) => desk.rule_name = value,
        Message::RuleMethod(value) => desk.rule_method = value,
        Message::RuleHost(value) => desk.rule_host = value,
        Message::RulePath(value) => desk.rule_path = value,
        Message::RuleStatus(value) => desk.rule_status = value,
        Message::RuleBody(value) => desk.rule_body = value,
        Message::RuleDelay(value) => desk.rule_delay = value,
        Message::RuleLocation(value) => desk.rule_location = value,
        Message::RuleHeaders(value) => desk.rule_headers = value,
        Message::AddRule(kind) => desk.add_rule(desk.action_for(kind), desk.rule_name.clone()),
        Message::RuleFromCall => {
            if let Some(exchange) = desk.selected_exchange() {
                let body = response_text(&desk.session, &exchange).0;
                let rule = rule_from_exchange(&exchange, &body);
                let mut rules = desk.session.rules();
                rules.rules.push(rule);
                if let Err(err) = desk.session.update_rules(rules) {
                    desk.notice = err.to_string();
                }
            }
        }
        Message::ToggleRule(id) => {
            let mut rules = desk.session.rules();
            if let Some(rule) = rules.rules.iter_mut().find(|rule| rule.id == id) {
                rule.enabled = !rule.enabled;
            }
            let _ = desk.session.update_rules(rules);
        }
        Message::DeleteRule(id) => {
            let mut rules = desk.session.rules();
            rules.rules.retain(|rule| rule.id != id);
            let _ = desk.session.update_rules(rules);
        }
        Message::MoveRule(id, up) => {
            let mut rules = desk.session.rules();
            rules.move_rule(&id, up);
            let _ = desk.session.update_rules(rules);
        }
        Message::FilePath(value) => desk.file_path = value,
        Message::ExportHar => desk.notice = export_traffic(desk),
        Message::ImportHar => desk.notice = import_traffic(desk),
        Message::OpenApiPath(value) => desk.openapi_path = value,
        Message::LoadOpenApi => desk.notice = load_openapi(desk),
        Message::ExportCode(kind) => {
            if let Some(exchange) = desk.selected_exchange() {
                let body = request_text(&desk.session, &exchange);
                desk.export_preview = export_request(
                    kind,
                    &exchange.method,
                    &exchange.url,
                    &exchange.request_headers,
                    &body,
                );
            }
        }
        Message::Copy(value) => return iced::clipboard::write(value),
    }
    Task::none()
}

fn subscription(_desk: &Desk) -> Subscription<Message> {
    Subscription::batch([
        event::listen_with(on_key),
        iced::time::every(Duration::from_millis(200)).map(|_| Message::Poll),
    ])
}

fn on_key(event: Event, status: event::Status, _window: window::Id) -> Option<Message> {
    let Event::Keyboard(keyboard::Event::KeyPressed { key, .. }) = event else {
        return None;
    };
    match key {
        Key::Named(key::Named::ArrowUp) => Some(Message::SelectDelta(-1)),
        Key::Named(key::Named::ArrowDown) => Some(Message::SelectDelta(1)),
        Key::Named(key::Named::Escape) => Some(Message::ClearFilter),
        Key::Character(value)
            if value.as_str() == "/" && status == event::Status::Ignored =>
        {
            Some(Message::FocusFilter)
        }
        _ => None,
    }
}

fn theme(desk: &Desk) -> Theme {
    let (name, palette) = if desk.dark {
        (
            "Watcher Dark",
            iced::theme::Palette {
                background: color!(0x121418),
                text: color!(0xE7ECF3),
                primary: color!(0x2EC4B6),
                success: color!(0x3DDB8C),
                warning: color!(0xE6B450),
                danger: color!(0xE85D4C),
            },
        )
    } else {
        (
            "Watcher Light",
            iced::theme::Palette {
                background: color!(0xF4F6F8),
                text: color!(0x1A1D24),
                primary: color!(0x0F766E),
                success: color!(0x157A45),
                warning: color!(0xB7791F),
                danger: color!(0xC2412D),
            },
        )
    };
    Theme::custom(name.to_string(), palette)
}

fn view(desk: &Desk) -> Element<'_, Message> {
    let body = row![
        pane(left(desk), 280.0, desk.dark),
        pane(center(desk), 0.0, desk.dark).width(Length::Fill),
        pane(right(desk), 380.0, desk.dark),
    ]
    .spacing(8);
    container(body)
        .padding(8)
        .width(Length::Fill)
        .height(Length::Fill)
        .into()
}

fn left(desk: &Desk) -> Column<'_, Message> {
    let mut col = section("Intercept");
    col = col.push(text(desk.session.status()).size(12));
    col = col.push(text(format!("Manual client proxy  127.0.0.1:{}", desk.port)).size(12).font(Font::MONOSPACE));
    col = col.push(text(format!("CA  {}", desk.session.ca().fingerprint)).size(11).font(Font::MONOSPACE));
    col = col.push(text("HTTP/2 is offered to the app. Upstream requests are forwarded as HTTP/1.1.").size(11));
    col = col.push(text(desk.notice.clone()).size(12));
    if !desk.android_banner.is_empty() {
        col = col.push(text(desk.android_banner.clone()).size(12).color(color!(0x2EC4B6)));
    }
    col = col.push(row![
        button(text("Manual proxy").size(12)).on_press(Message::ManualProxy),
        button(text("Refresh devices").size(12)).on_press(Message::RefreshDevices),
    ].spacing(6));
    for device in &desk.devices {
        let kind = if device.emulator { "emulator" } else { "device" };
        col = col.push(
            button(text(format!("{kind}  {}  {}", device.serial, device.detail)).size(11).font(Font::MONOSPACE))
                .on_press(Message::SerialChanged(device.serial.clone())),
        );
    }
    col = col.push(field("ADB serial", &desk.serial, Message::SerialChanged));
    col = col.push(row![
        button(text("Connect Android").size(12)).on_press(Message::ConnectAndroid),
        button(text("Check approval").size(12)).on_press(Message::CheckApproval),
    ].spacing(6));
    col = col.push(text("Connect installs nothing until you approve the VPN and certificate prompts on the device. The VPN and CA are reported active only after both approvals.").size(11));
    col = col.push(text("Android 7+ ignores a user CA unless the app trusts it. For an app you ship, the base-config snippet trusts this CA in debug and release builds. debug-overrides trusts it only in debug builds. A system CA is a separate step for an emulator or a device that is already rooted. Apps that pin certificates fail visibly. This tool does not bypass pinning.").size(11));
    col = col.push(text(manifest_attribute()).size(11).font(Font::MONOSPACE));
    col = col.push(button(text("Copy manifest attribute").size(12)).on_press(Message::Copy(manifest_attribute().into())));
    col = col.push(text("Debug and release").size(12));
    col = col.push(text(release_network_security_config()).size(11).font(Font::MONOSPACE));
    col = col.push(button(text("Copy debug and release config").size(12)).on_press(Message::Copy(release_network_security_config().into())));
    col = col.push(text("Debug builds only").size(12));
    col = col.push(text(debug_only_network_security_config()).size(11).font(Font::MONOSPACE));
    col = col.push(button(text("Copy debug-only config").size(12)).on_press(Message::Copy(debug_only_network_security_config().into())));
    col = col.push(checkbox(desk.confirm_system).label("I confirm this is an emulator or an already-rooted device I own, and I want the CA in the system store.").on_toggle(Message::SetSystemConfirm));
    col = col.push(checkbox(desk.already_rooted).label("This device is already rooted, even if it is not an emulator.").on_toggle(Message::SetRooted));
    col = col.push(button(text("Install system CA").size(12)).on_press(Message::InstallSystemCa));
    let payload = qr_payload(&desk.advertise, desk.port, &desk.session.ca().fingerprint);
    col = col.push(text("QR setup, if ADB is not available").size(12));
    col = col.push(field("QR host", &desk.advertise, Message::AdvertiseChanged));
    col = col.push(text(payload.clone()).size(11).font(Font::MONOSPACE));
    col = col.push(text(qr_blocks(&payload)).size(8).font(Font::MONOSPACE));
    col = col.push(text("Proxy").size(13));
    col = col.push(field("Port", &desk.port_text, Message::PortChanged));
    col = col.push(row![
        button(text("Auto").size(12)).on_press(Message::Version(HttpVersion::Auto)),
        button(text("HTTP/1.1").size(12)).on_press(Message::Version(HttpVersion::Http1)),
        button(text("HTTP/2").size(12)).on_press(Message::Version(HttpVersion::Http2)),
    ].spacing(6));
    col = col.push(text(format!("Client HTTP version: {}", desk.http_version.label())).size(11));
    col = col.push(field("TLS passthrough hosts", &desk.passthrough, Message::PassthroughChanged));
    col = col.push(field("Intercept only these hosts", &desk.intercept_only, Message::InterceptOnlyChanged));
    col = col.push(field("Upstream proxy", &desk.upstream, Message::UpstreamChanged));
    col = col.push(checkbox(desk.accept_invalid).label("Accept invalid upstream certificates").on_toggle(Message::AcceptInvalid));
    col = col.push(field("Extra upstream CA file", &desk.extra_ca_path, Message::ExtraCaChanged));
    col = col.push(field("Upstream client certificate", &desk.client_cert_path, Message::ClientCertChanged));
    col = col.push(field("Upstream client key", &desk.client_key_path, Message::ClientKeyChanged));
    col = col.push(button(text("Apply proxy settings").size(12)).on_press(Message::ApplyProxy));
    col = col.push(checkbox(desk.dark).label("Dark theme").on_toggle(Message::SetDark));
    col
}

fn center(desk: &Desk) -> Column<'_, Message> {
    let exchanges = desk.session.exchanges();
    let aliases = desk.session.aliases();
    let rows = traffic_rows(&exchanges, &desk.filter, &aliases);
    let mut col = section("Traffic");
    col = col.push(
        text_input("Filter  status:404 method:GET host: path:  or alias:name", &desk.filter)
            .id(Id::new(FILTER_ID))
            .on_input(Message::FilterChanged)
            .font(Font::MONOSPACE)
            .size(13),
    );
    col = col.push(text("/ focuses the filter. Escape clears it. Up and Down move the selection.").size(11));
    col = col.push(row![
        button(text("Pin").size(12)).on_press(Message::Pin),
        button(text("Delete").size(12)).on_press(Message::Delete),
        button(text("Clear").size(12)).on_press(Message::ClearUnpinned),
    ].spacing(6));
    let mut alias_row = Row::new().spacing(6);
    for alias in &aliases {
        alias_row = alias_row.push(
            button(text(alias.name.clone()).size(11)).on_press(Message::UseAlias(alias.name.clone())),
        );
        alias_row = alias_row.push(
            button(text("x").size(11)).on_press(Message::DeleteAlias(alias.name.clone())),
        );
    }
    col = col.push(alias_row);
    col = col.push(row![
        field("Alias name", &desk.alias_name, Message::AliasName).width(Length::FillPortion(1)),
        field("Alias query", &desk.alias_query, Message::AliasQuery).width(Length::FillPortion(2)),
        button(text("Save filter").size(12)).on_press(Message::SaveAlias),
    ].spacing(6).align_y(Alignment::End));
    col = col.push(header_line());
    for row_item in rows {
        col = col.push(traffic_button(desk, &row_item));
    }
    if exchanges.is_empty() {
        col = col.push(text("No calls yet. Point a client at the manual proxy, or connect an Android device.").size(12));
    }
    col
}

fn right(desk: &Desk) -> Column<'_, Message> {
    let exchange = desk.selected_exchange();
    let mut col = section("Inspector");
    col = col.push(row![
        button(text("Request").size(12)).on_press(Message::Tab(Tab::Request)),
        button(text("Response").size(12)).on_press(Message::Tab(Tab::Response)),
        button(text("Timing").size(12)).on_press(Message::Tab(Tab::Timing)),
    ].spacing(6));
    if let Some(exchange) = exchange {
        let disk = match (&exchange.request_body, &exchange.response_body) {
            (BodyHandle::File { len, .. }, _) | (_, BodyHandle::File { len, .. }) => {
                format!("A body of {len} bytes is stored on disk and opened from there.")
            }
            _ => String::new(),
        };
        if !disk.is_empty() {
            col = col.push(text(disk).size(11));
        }
        match desk.tab {
            Tab::Request => {
                col = push_headers(col, &exchange.request_headers, desk.dark);
                col = push_body(col, &request_text(&desk.session, &exchange), desk);
            }
            Tab::Response => {
                col = push_headers(col, &exchange.response_headers, desk.dark);
                let (body, notes) = response_text(&desk.session, &exchange);
                col = push_body(col, &body, desk);
                if !notes.trim().is_empty() {
                    col = col.push(text(notes).size(11));
                }
            }
            Tab::Timing => {
                col = col.push(text(format!(
                    "Total {}    Time to first byte {}    Download {}",
                    ms(exchange.duration_ms),
                    ms(exchange.ttfb_ms),
                    ms(exchange.download_ms)
                )).size(12).font(Font::MONOSPACE));
                col = col.push(text("Connect and TLS durations are not reported separately by the capture engine.").size(11));
                col = col.push(text(exchange.protocol_note.clone()).size(12).font(Font::MONOSPACE));
                col = col.push(text(exchange.http_version.clone()).size(12).font(Font::MONOSPACE));
                col = col.push(text(exchange.timing_notes.clone()).size(12));
                if let Some(error) = &exchange.error {
                    col = col.push(text(error.clone()).size(12).color(color!(0xE85D4C)));
                }
            }
        }
        if matches!(exchange.phase, Phase::PausedRequest | Phase::PausedResponse) {
            col = col.push(text(format!("Paused ({:?}). Edit, then forward, respond, or drop.", exchange.phase)).size(12));
            col = col.push(field("Breakpoint status", &desk.bp_status, Message::BreakpointStatus));
            col = col.push(area("Breakpoint headers", &desk.bp_headers, Message::BreakpointHeaders));
            col = col.push(area("Breakpoint body", &desk.bp_body, Message::BreakpointBody));
            col = col.push(row![
                button(text("Forward").size(12)).on_press(Message::Forward),
                button(text("Respond").size(12)).on_press(Message::Respond),
                button(text("Drop").size(12)).on_press(Message::DropCall),
            ].spacing(6));
        }
        if let Some(spec) = &desk.openapi {
            let problems = validate_openapi(spec, &exchange.method, &exchange.path, exchange.status);
            let report = if problems.is_empty() {
                "OpenAPI: this call matches the file.".into()
            } else {
                problems.join("\n")
            };
            col = col.push(text(report).size(12));
        } else if !desk.openapi_report.is_empty() {
            col = col.push(text(desk.openapi_report.clone()).size(12));
        }
    } else {
        col = col.push(text("Select a call.").size(12));
    }
    col = col.push(text("Resend").size(13));
    col = col.push(field("Method", &desk.client_method, Message::ClientMethod));
    col = col.push(field("URL", &desk.client_url, Message::ClientUrl));
    col = col.push(area("Headers", &desk.client_headers, Message::ClientHeaders));
    col = col.push(area("Body", &desk.client_body, Message::ClientBody));
    col = col.push(button(text("Send through proxy").size(12)).on_press(Message::Send));
    col = col.push(row![
        button(text("curl").size(12)).on_press(Message::ExportCode(ExportKind::Curl)),
        button(text("fetch").size(12)).on_press(Message::ExportCode(ExportKind::Fetch)),
        button(text("python").size(12)).on_press(Message::ExportCode(ExportKind::PythonRequests)),
        button(text("OkHttp").size(12)).on_press(Message::ExportCode(ExportKind::OkHttp)),
        button(text("Copy export").size(12)).on_press(Message::Copy(desk.export_preview.clone())),
    ].spacing(6));
    if !desk.export_preview.is_empty() {
        col = col.push(text(desk.export_preview.clone()).size(11).font(Font::MONOSPACE));
    }
    col = col.push(text("Rules").size(13));
    col = col.push(field("Name", &desk.rule_name, Message::RuleName));
    col = col.push(field("Method", &desk.rule_method, Message::RuleMethod));
    col = col.push(field("Host contains", &desk.rule_host, Message::RuleHost));
    col = col.push(field("Path prefix", &desk.rule_path, Message::RulePath));
    col = col.push(field("Status", &desk.rule_status, Message::RuleStatus));
    col = col.push(field("Delay ms", &desk.rule_delay, Message::RuleDelay));
    col = col.push(field("Redirect location", &desk.rule_location, Message::RuleLocation));
    col = col.push(area("Header edits", &desk.rule_headers, Message::RuleHeaders));
    col = col.push(area("Body", &desk.rule_body, Message::RuleBody));
    col = col.push(row![
        button(text("Mock").size(12)).on_press(Message::AddRule("mock")),
        button(text("Transform").size(12)).on_press(Message::AddRule("transform")),
        button(text("Error").size(12)).on_press(Message::AddRule("error")),
        button(text("Timeout").size(12)).on_press(Message::AddRule("timeout")),
        button(text("Redirect").size(12)).on_press(Message::AddRule("redirect")),
        button(text("Breakpoint").size(12)).on_press(Message::AddRule("breakpoint")),
        button(text("From this call").size(12)).on_press(Message::RuleFromCall),
    ].spacing(4));
    for rule in desk.session.rules().rules {
        let id = rule.id.clone();
        col = col.push(text(format!("{}  {}  {}", if rule.enabled { "on" } else { "off" }, rule.name, action_label(&rule))).size(11).font(Font::MONOSPACE));
        col = col.push(row![
            button(text("enable").size(11)).on_press(Message::ToggleRule(id.clone())),
            button(text("up").size(11)).on_press(Message::MoveRule(id.clone(), true)),
            button(text("down").size(11)).on_press(Message::MoveRule(id.clone(), false)),
            button(text("delete").size(11)).on_press(Message::DeleteRule(id)),
        ].spacing(4));
    }
    col = col.push(text("HAR and OpenAPI").size(13));
    col = col.push(field("HAR or OpenAPI path", &desk.file_path, Message::FilePath));
    col = col.push(row![
        button(text("Export HAR").size(12)).on_press(Message::ExportHar),
        button(text("Import HAR").size(12)).on_press(Message::ImportHar),
    ].spacing(6));
    col = col.push(field("OpenAPI JSON file", &desk.openapi_path, Message::OpenApiPath));
    col = col.push(button(text("Load OpenAPI file").size(12)).on_press(Message::LoadOpenApi));
    col = col.push(text("OpenAPI is read from a file you supply. No API catalog is downloaded.").size(11));
    col
}

impl Desk {
    fn restart_proxy(&mut self) {
        if let Some(proxy) = self.proxy.take() {
            self.runtime.block_on(proxy.shutdown());
        }
        match self.runtime.block_on(RunningProxy::start(self.session.clone())) {
            Ok(proxy) => {
                self.port = proxy.port();
                self.port_text = self.port.to_string();
                self.proxy = Some(proxy);
            }
            Err(err) => self.notice = format!("Proxy did not start: {err}"),
        }
    }

    fn apply_proxy(&mut self) {
        let mut settings = self.session.settings();
        match self.port_text.parse::<u16>() {
            Ok(port) => settings.port = port,
            Err(_) => {
                self.notice = "Port must be a number from 0 to 65535. 0 asks the OS for a free port.".into();
                return;
            }
        }
        settings.http_version = self.http_version;
        settings.passthrough_hosts = split_list(&self.passthrough);
        settings.intercept_only = split_list(&self.intercept_only);
        settings.upstream_proxy = blank_none(&self.upstream);
        settings.upstream_tls.accept_invalid_certs = self.accept_invalid;
        match read_pem(&self.extra_ca_path) {
            Ok(pem) => settings.upstream_tls.extra_ca_pem = pem,
            Err(err) => {
                self.notice = err;
                return;
            }
        }
        match read_pem(&self.client_cert_path) {
            Ok(pem) => settings.upstream_tls.client_cert_pem = pem,
            Err(err) => {
                self.notice = err;
                return;
            }
        }
        match read_pem(&self.client_key_path) {
            Ok(pem) => settings.upstream_tls.client_key_pem = pem,
            Err(err) => {
                self.notice = err;
                return;
            }
        }
        settings.dark_theme = self.dark;
        settings.advertise_host = self.advertise.clone();
        if let Err(err) = self.session.update_settings(settings) {
            self.notice = err.to_string();
            return;
        }
        self.restart_proxy();
        self.notice = format!("Proxy restarted on port {}.", self.port);
    }

    fn selected_exchange(&self) -> Option<watcher_core::Exchange> {
        let id = self.selected?;
        self.session.exchanges().into_iter().find(|item| item.id == id)
    }

    fn sync_editors(&mut self) {
        let Some(exchange) = self.selected_exchange() else {
            return;
        };
        if self.editors_for == Some(exchange.id) {
            return;
        }
        self.editors_for = Some(exchange.id);
        let paused_response = exchange.phase == Phase::PausedResponse;
        let headers = if paused_response {
            &exchange.response_headers
        } else {
            &exchange.request_headers
        };
        self.bp_headers = header_block(headers);
        self.bp_body = if paused_response {
            response_text(&self.session, &exchange).0
        } else {
            request_text(&self.session, &exchange)
        };
        self.bp_status = exchange.status.unwrap_or(200).to_string();
        self.client_method = exchange.method.clone();
        self.client_url = exchange.url.clone();
        self.client_headers = header_block(&exchange.request_headers);
        self.client_body = request_text(&self.session, &exchange);
    }

    fn resume(&mut self, decision: BreakpointDecision) {
        let Some(id) = self.selected else {
            return;
        };
        if !self.session.resume(id, decision) {
            self.notice = "That call is not paused.".into();
        }
        self.editors_for = None;
    }

    fn action_for(&self, kind: &str) -> Action {
        let status = self.rule_status.parse().unwrap_or(200);
        let headers = parse_header_block(&self.rule_headers);
        match kind {
            "breakpoint" => Action::Breakpoint {
                request: true,
                response: true,
            },
            "error" => Action::Error {
                status,
                body: self.rule_body.clone(),
            },
            "timeout" => Action::Timeout {
                delay_ms: self.rule_delay.parse().unwrap_or(1000),
                status,
            },
            "redirect" => Action::Redirect {
                location: self.rule_location.clone(),
                status,
            },
            "transform" => Action::Transform {
                request_headers: headers,
                response_headers: Vec::new(),
                request_body: blank_none(&self.rule_body),
                response_body: None,
            },
            _ => Action::Mock {
                status,
                headers,
                body: self.rule_body.clone(),
            },
        }
    }

    fn add_rule(&mut self, action: Action, name: String) {
        let mut rule = Rule::new(name, action);
        rule.method = blank_none(&self.rule_method);
        rule.host_contains = blank_none(&self.rule_host);
        rule.path_prefix = blank_none(&self.rule_path);
        let mut rules = self.session.rules();
        rules.rules.push(rule);
        if let Err(err) = self.session.update_rules(rules) {
            self.notice = err.to_string();
        }
    }
}

fn export_traffic(desk: &Desk) -> String {
    if desk.file_path.trim().is_empty() {
        return "Set a HAR path first.".into();
    }
    match export_har(&desk.session.exchanges(), desk.session.bodies()) {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(text) => match fs::write(&desk.file_path, text) {
                Ok(()) => format!("HAR written to {}.", desk.file_path),
                Err(err) => format!("HAR was not written: {err}"),
            },
            Err(err) => format!("HAR was not encoded: {err}"),
        },
        Err(err) => format!("HAR export failed: {err}"),
    }
}

fn import_traffic(desk: &mut Desk) -> String {
    let text = match fs::read_to_string(&desk.file_path) {
        Ok(text) => text,
        Err(err) => return format!("HAR was not read: {err}"),
    };
    let value: serde_json::Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(err) => return format!("HAR is not JSON: {err}"),
    };
    match import_har(&value, desk.session.bodies()) {
        Ok(exchanges) => {
            let count = exchanges.len();
            for exchange in exchanges {
                desk.session.upsert(exchange);
            }
            format!("Imported {count} HAR entries.")
        }
        Err(err) => format!("HAR import failed: {err}"),
    }
}

fn load_openapi(desk: &mut Desk) -> String {
    let text = match fs::read_to_string(&desk.openapi_path) {
        Ok(text) => text,
        Err(err) => return format!("OpenAPI file was not read: {err}"),
    };
    match serde_json::from_str::<serde_json::Value>(&text) {
        Ok(value) => {
            desk.openapi = Some(value);
            desk.openapi_report.clear();
            "OpenAPI file loaded. Select a call to validate it.".into()
        }
        Err(err) => {
            desk.openapi = None;
            format!("OpenAPI file must be JSON. {err}")
        }
    }
}

fn section<'a>(title: &'a str) -> Column<'a, Message> {
    Column::new().spacing(6).push(text(title).size(16))
}

fn pane<'a>(content: Column<'a, Message>, width: f32, dark: bool) -> container::Container<'a, Message> {
    let panel = if dark { color!(0x1C1F26) } else { color!(0xFFFFFF) };
    let wrapped = container(scrollable(content).height(Length::Fill))
        .padding(8)
        .height(Length::Fill)
        .style(move |_theme| container::Style {
            text_color: None,
            background: Some(Background::Color(panel)),
            border: Border {
                color: Color::TRANSPARENT,
                width: 0.0,
                radius: 0.0.into(),
            },
            shadow: Shadow {
                color: Color::TRANSPARENT,
                offset: Vector::new(0.0, 0.0),
                blur_radius: 0.0,
            },
            snap: false,
        });
    if width > 0.0 {
        wrapped.width(Length::Fixed(width))
    } else {
        wrapped
    }
}

fn field<'a>(
    placeholder: &'a str,
    value: &'a str,
    message: impl Fn(String) -> Message + 'a,
) -> text_input::TextInput<'a, Message> {
    text_input(placeholder, value)
        .on_input(message)
        .font(Font::MONOSPACE)
        .size(12)
}

fn area<'a>(
    placeholder: &'a str,
    value: &'a str,
    message: impl Fn(String) -> Message + 'a,
) -> text_input::TextInput<'a, Message> {
    field(placeholder, value, message)
}

const COL_TIME: f32 = 100.0;
const COL_METHOD: f32 = 52.0;
const COL_STATUS: f32 = 44.0;
const COL_HOST: f32 = 96.0;
const COL_DURATION: f32 = 52.0;
const COL_SIZE: f32 = 48.0;

fn header_line() -> Row<'static, Message> {
    Row::new()
        .spacing(6)
        .push(mono("time", color!(0x9AA3B2)).width(Length::Fixed(COL_TIME)))
        .push(mono("method", color!(0x9AA3B2)).width(Length::Fixed(COL_METHOD)))
        .push(mono("status", color!(0x9AA3B2)).width(Length::Fixed(COL_STATUS)))
        .push(mono("host", color!(0x9AA3B2)).width(Length::Fixed(COL_HOST)))
        .push(mono("path", color!(0x9AA3B2)).width(Length::Fill))
        .push(mono("duration", color!(0x9AA3B2)).width(Length::Fixed(COL_DURATION)))
        .push(mono("size", color!(0x9AA3B2)).width(Length::Fixed(COL_SIZE)))
}

fn traffic_button<'a>(desk: &Desk, row_item: &watcher_desktop::TrafficRow) -> button::Button<'a, Message> {
    let selected = desk.selected == Some(row_item.id);
    let mark = if row_item.pinned { "P" } else { " " };
    let tone = tone_color(row_item.tone);
    let text_color = if desk.dark { color!(0xE7ECF3) } else { color!(0x1A1D24) };
    let line = Row::new()
        .spacing(6)
        .push(mono(format!("{mark} {}", row_item.time.clone()), text_color).width(Length::Fixed(COL_TIME)))
        .push(mono(row_item.method.clone(), text_color).width(Length::Fixed(COL_METHOD)))
        .push(mono(row_item.status.clone(), tone).width(Length::Fixed(COL_STATUS)))
        .push(mono(row_item.host.clone(), text_color).width(Length::Fixed(COL_HOST)))
        .push(mono(row_item.path.clone(), text_color).width(Length::Fill))
        .push(mono(row_item.duration.clone(), text_color).width(Length::Fixed(COL_DURATION)))
        .push(mono(row_item.size.clone(), text_color).width(Length::Fixed(COL_SIZE)));
    let mut button = button(line).on_press(Message::Select(row_item.id)).padding(2).width(Length::Fill);
    if selected {
        button = button.style(|_theme, _status| button::Style {
            background: Some(Background::Color(color!(0x2EC4B6))),
            text_color: color!(0x121418),
            ..button::Style::default()
        });
    }
    let _ = selected;
    button
}

fn push_headers<'a>(
    mut col: Column<'a, Message>,
    headers: &[(String, String)],
    dark: bool,
) -> Column<'a, Message> {
    let color = if dark { color!(0xE7ECF3) } else { color!(0x1A1D24) };
    for (name, value) in headers {
        col = col.push(mono(format!("{name}: {value}"), color));
    }
    col
}

fn push_body<'a>(mut col: Column<'a, Message>, body: &str, desk: &'a Desk) -> Column<'a, Message> {
    let color = if desk.dark { color!(0xE7ECF3) } else { color!(0x1A1D24) };
    if let Some(lines) = json_lines(body, &desk.collapsed) {
        for line in lines {
            let indent = "  ".repeat(line.depth);
            let label = format!("{indent}{}", line.text);
            if line.expandable {
                col = col.push(
                    button(mono(label, color!(0x2EC4B6)))
                        .on_press(Message::ToggleJson(line.path))
                        .padding(0),
                );
            } else {
                col = col.push(mono(label, color));
            }
        }
    } else {
        col = col.push(mono(body.to_string(), color));
    }
    col
}

fn mono<'a>(value: impl Into<String>, color: Color) -> iced::widget::Text<'a> {
    text(value.into()).font(Font::MONOSPACE).size(12).color(color)
}

fn tone_color(tone: Tone) -> Color {
    match tone {
        Tone::Success => color!(0x3DDB8C),
        Tone::Redirect => color!(0x6CB6FF),
        Tone::Client => color!(0xE6B450),
        Tone::Server => color!(0xE85D4C),
        Tone::Muted => color!(0x9AA3B2),
    }
}

fn action_label(rule: &Rule) -> String {
    match &rule.action {
        Action::Passthrough => "passthrough".into(),
        Action::Breakpoint { .. } => "breakpoint".into(),
        Action::Mock { status, .. } => format!("mock {status}"),
        Action::Transform { .. } => "transform".into(),
        Action::Error { status, .. } => format!("error {status}"),
        Action::Timeout { delay_ms, .. } => format!("timeout {delay_ms}ms"),
        Action::Redirect { status, .. } => format!("redirect {status}"),
    }
}

fn ms(value: Option<u64>) -> String {
    value.map(|item| format!("{item} ms")).unwrap_or_else(|| "-".into())
}

fn split_list(text: &str) -> Vec<String> {
    text.split(',')
        .map(|item| item.trim().to_string())
        .filter(|item| !item.is_empty())
        .collect()
}

fn blank_none(text: &str) -> Option<String> {
    let text = text.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

fn read_pem(path: &str) -> Result<Option<String>, String> {
    let path = path.trim();
    if path.is_empty() {
        return Ok(None);
    }
    fs::read_to_string(path).map(Some).map_err(|err| format!("{path} was not read: {err}"))
}
