# Progress

Checked on 2026-10-05. Commands were run from `watcher/` after `source "$HOME/.cargo/env"`.

## 1. Workspace, CA, proxy, exchange log

Landed: Apache-2.0 workspace (`watcher-core`, `watcher-proxy`, `watcher-desktop`). The CA stays in the app data directory. The proxy listens on `0.0.0.0` and records HTTP and HTTPS. Bodies over 10 MB go to disk.

Command: `cargo test --workspace -- --test-threads=8`

Result: exit 0. `tests/capture.rs` passed `captures_http_and_https_method_url_status_and_body` and `mock_breakpoint_and_passthrough`. `watcher-core` 13 tests passed, including the CA reload test and the large-body file test.

## 2. iced UI

Landed: the debugger opens into the intercept rail, the live table, and the request, response, and timing inspector. Filter, pin, delete, and clear are in the table. A new row is selected when nothing else is selected, so the inspector shows that call.

The manual client was dropping calls. It shut down the write side before the response, and the HTTP/1 server treated that as an incomplete request, so the session stayed empty. The client now reads the response with the write side still open, and the proxy allows an HTTP/1 half-close.

Command: `cargo test -p watcher-desktop --test live_table -- --nocapture`

Result: exit 0. `manual_proxy_request_appears_in_the_table` passed in 0.11s. It asserts method POST, path `/hello`, status 200, a JSON content-type, a request body containing `hello`, and a response body containing `echo`.

Command: launch `target/debug/app-network-watcher` with `WATCHER_DATA_DIR=/tmp/watcher-gui-data2`, then `curl -x http://127.0.0.1:8080` POST `http://127.0.0.1:<echo>/hello` with body `{"hello":true}`.

Result: the process listened on port 8080. curl printed `HTTP/1.1 200 OK` and body `echo`. A window capture showed one row: POST, 200, host `127.0.0.1`, path `/hello`, duration `0 ms`, size `18 B`. The request inspector showed `content-type: application/json`, `content-length: 14`, and the JSON body `hello: true`. The CA was not installed into the macOS trust store. The verification process was then stopped.

## 3. Android companion

Landed: Kotlin VPN companion under `watcher/android/`, ADB connect planning, QR payload, and the user-CA explanation. System-store install stays behind an explicit confirmation and was not run.

Command: `command -v adb`; `echo ANDROID_HOME`; `java -version`; check `~/Library/Android/sdk`.

Result: `adb` was not found. `ANDROID_HOME` was unset. `~/Library/Android/sdk` was missing. Java reported no runtime. The companion was not compiled, installed, or run. No device capture was taken. Desktop tests `parse_emulator_and_phone`, `system_store_refuses_without_confirmation`, and `connect_stops_when_no_device_is_attached` passed inside the workspace run.

## 4. Breakpoints, rules, HAR, resend, themes, OpenAPI

Landed in the same build, with no license check: breakpoints, mock, transform, error, timeout, and redirect rules, HAR import and export, resend, code export, TLS passthrough hosts, upstream proxy, light and dark theme, and OpenAPI JSON validation from a file the user supplies.

The same `cargo test --workspace` run passed `first_matching_rule_wins`, `empty_header_value_removes_the_header`, `har_round_trip_keeps_method_url_status_and_body`, `matches_templated_path_and_rejects_unknown_status`, `curl_and_okhttp_include_method_and_url`, `structured_filter_and_alias`, `http2_preference_offers_h2`, `whitelist_and_passthrough`, and `release_config_trusts_user_cas_for_every_build_type`.

Debug and release: the snippet shown as "Debug and release" uses `<base-config>` with system and user trust anchors, so an app you ship can trust this CA in both build types. The debug-only snippet uses `<debug-overrides>`. An unmodified release build on a stock phone still ignores a user CA. A system CA is only for an emulator or a device that is already rooted, and only after the confirmation control is checked. Apps that pin certificates fail visibly. No pinning bypass was added.

## Not done

iOS was not started. The only iOS strings found are inside the `aws-lc` build output, not in this app. `httptoolkit-main/` was not modified.

A search of the project sources found `license = "Apache-2.0"` in the Cargo manifests and the Apache text in `LICENSE`. It found no `paywall`, `is_pro`, or billing gate in the app source.
