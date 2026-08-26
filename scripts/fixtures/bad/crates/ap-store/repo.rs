fn stamp(base: &str) -> String {
    let mut out = base.to_owned();
    out.push_str("Z");
    out
}

fn query(label: &str) -> String {
    format!("SELECT id FROM client WHERE label = '{label}'")
}
