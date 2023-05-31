fn main() {
    let mut target_board: Option<String> = None;

    for (name, _) in std::env::vars() {
        let prefix = "CARGO_FEATURE_TARGET_BOARD_";
        if name.starts_with("CARGO_FEATURE_TARGET_BOARD_") {
            let suffix = name[prefix.len()..].to_string();
            if let Some(previous) = &target_board {
                panic!(
                    "multiple target board features defined (at least {} and {})",
                    show_feature(previous),
                    show_feature(&suffix)
                );
            }

            target_board = Some(suffix);
        }
    }

    if target_board.is_none() {
        panic!("missing target-board-* feature");
    }
}

fn show_feature(envvar: &str) -> String {
    let mut name = "target-board-".to_string();
    name.push_str(&envvar.to_ascii_lowercase().replace('_', "-"));
    name
}
