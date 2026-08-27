//! Prints the site a given seed builds, for looking at before it goes up.
//!
//!     cargo run -p ap-cover --example look -- 3
//!     cargo run -p ap-cover --example look -- 3 /contact

fn main() {
    let mut arguments = std::env::args().skip(1);
    let seed: u8 = arguments
        .next()
        .and_then(|text| text.parse().ok())
        .unwrap_or(0);
    let path = arguments.next().unwrap_or_else(|| "/".to_owned());

    let site = ap_cover::site([seed; 32]);
    let paths: Vec<&str> = site.paths().collect();
    eprintln!("seed {seed}: {}", paths.join(" "));

    match site.page(&path) {
        Some(page) => println!("{}", String::from_utf8_lossy(&page.bytes)),
        None => println!("{}", String::from_utf8_lossy(&site.missing().bytes)),
    }
}
