fn main() {
    let text = message(locale, "client-created").unwrap_or_default();
    println!("{text}");
}
