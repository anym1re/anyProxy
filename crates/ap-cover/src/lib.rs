//! The site a node shows anyone who is not a client of it.
//!
//! A node carrying clients inside ordinary web traffic has to be a site that
//! is really there. Anyone may follow the name out of curiosity — a scanner,
//! a censor, a person who mistyped — and what they find has to be dull,
//! complete and unremarkable.
//!
//! One site for every node would be worse than none: the same page on forty
//! addresses is a fingerprint that finds all forty at once. Every node builds
//! its own from its own identifier, so two nodes share nothing visible, and
//! one node looks the same every time it is asked.
//!
//! Nothing here imitates anyone real. The trades are ordinary, the names are
//! assembled from neutral words, and the contact details are of the forms
//! reserved for documentation. A cover that borrowed a real company's name
//! would put that company in the way of whatever comes looking.

use std::collections::BTreeMap;

mod copy;
mod serve;

pub use serve::serve;

/// One thing the site answers with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// What it is, as the header says.
    pub content_type: &'static str,
    /// The bytes themselves.
    pub bytes: Vec<u8>,
}

/// A whole site, as the paths it answers on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Site {
    pages: BTreeMap<String, Page>,
    /// What a visitor gets when they ask for something that is not here.
    ///
    /// Held apart from the rest so there is always one, whatever the seed
    /// arranged.
    missing: Page,
}

impl Site {
    /// What answers on this path, if anything does.
    pub fn page(&self, path: &str) -> Option<&Page> {
        let trimmed = path.split('?').next().unwrap_or(path);
        let trimmed = trimmed.trim_end_matches('/');
        let trimmed = if trimmed.is_empty() { "/" } else { trimmed };
        self.pages.get(trimmed)
    }

    /// Every path the site answers on.
    pub fn paths(&self) -> impl Iterator<Item = &str> {
        self.pages.keys().map(String::as_str)
    }

    /// What a visitor gets when they ask for something that is not here.
    pub fn missing(&self) -> &Page {
        &self.missing
    }
}

/// Builds a site from a seed.
///
/// The same seed always builds the same site, so a node looks the same
/// tomorrow as today; different seeds share no wording, no colours and no
/// arrangement.
pub fn site(seed: [u8; 32]) -> Site {
    let mut rolls = Rolls::from(seed);
    let trade = copy::TRADES[rolls.upto(copy::TRADES.len())];
    let look = Look::drawn(&mut rolls);
    let name = trade.name(&mut rolls);

    let mut chosen: Vec<&copy::Section> = Vec::new();
    for section in trade.sections {
        if rolls.chance(75) {
            chosen.push(section);
        }
    }
    if chosen.is_empty() {
        chosen.push(&trade.sections[0]);
    }
    // The order differs too: two nodes of the same trade do not read alike.
    for index in (1..chosen.len()).rev() {
        chosen.swap(index, rolls.upto(index + 1));
    }

    let mut pages = BTreeMap::new();
    let elsewhere: Vec<(String, String)> = trade
        .pages
        .iter()
        .map(|(path, title)| ((*path).to_owned(), (*title).to_owned()))
        .collect();

    pages.insert(
        "/".to_owned(),
        html(&render_front(
            &name, trade, &look, &chosen, &elsewhere, &mut rolls,
        )),
    );
    for (path, title) in &elsewhere {
        pages.insert(
            path.clone(),
            html(&render_inside(
                &name, trade, &look, title, &elsewhere, &mut rolls,
            )),
        );
    }
    pages.insert(
        "/style.css".to_owned(),
        Page {
            content_type: "text/css; charset=utf-8",
            bytes: look.stylesheet().into_bytes(),
        },
    );
    pages.insert(
        "/robots.txt".to_owned(),
        Page {
            content_type: "text/plain; charset=utf-8",
            bytes: b"User-agent: *\nDisallow:\n".to_vec(),
        },
    );

    Site {
        pages,
        missing: html(&render_missing(&name, &look, &elsewhere)),
    }
}

/// Wraps rendered markup as a page.
fn html(body: &str) -> Page {
    Page {
        content_type: "text/html; charset=utf-8",
        bytes: body.as_bytes().to_vec(),
    }
}

/// How a particular site looks: colours, type, and the shape of its corners.
struct Look {
    ink: &'static str,
    paper: &'static str,
    quiet: &'static str,
    accent: &'static str,
    face: &'static str,
    radius: u8,
    wide: u16,
}

impl Look {
    /// Draws a look from the seed.
    fn drawn(rolls: &mut Rolls) -> Self {
        const INKS: &[(&str, &str, &str)] = &[
            ("#1c1c1c", "#ffffff", "#5b5b5b"),
            ("#14202b", "#f7f9fb", "#4d6579"),
            ("#231f20", "#fbfaf7", "#6a625c"),
            ("#101a14", "#f6faf7", "#4a6154"),
            ("#1f1a24", "#faf8fc", "#645a70"),
        ];
        const ACCENTS: &[&str] = &[
            "#8a4b2a", "#2f5d50", "#3a4f7a", "#7a2f4a", "#55632c", "#6b4a86", "#a06a1f",
        ];
        const FACES: &[&str] = &[
            "Georgia, 'Times New Roman', serif",
            "'Helvetica Neue', Helvetica, Arial, sans-serif",
            "'Segoe UI', Tahoma, Verdana, sans-serif",
            "Palatino, 'Book Antiqua', Georgia, serif",
            "'Trebuchet MS', 'Lucida Grande', sans-serif",
        ];

        let (ink, paper, quiet) = INKS[rolls.upto(INKS.len())];
        Self {
            ink,
            paper,
            quiet,
            accent: ACCENTS[rolls.upto(ACCENTS.len())],
            face: FACES[rolls.upto(FACES.len())],
            radius: [0u8, 2, 4, 8][rolls.upto(4)],
            wide: [640u16, 720, 780, 860][rolls.upto(4)],
        }
    }

    /// The stylesheet, which differs with the look.
    fn stylesheet(&self) -> String {
        let Self {
            ink,
            paper,
            quiet,
            accent,
            face,
            radius,
            wide,
        } = self;
        format!(
            "*{{box-sizing:border-box}}\
             body{{margin:0;background:{paper};color:{ink};font-family:{face};\
             line-height:1.6;font-size:17px}}\
             .sheet{{max-width:{wide}px;margin:0 auto;padding:32px 20px 64px}}\
             header{{display:flex;flex-wrap:wrap;gap:16px;align-items:baseline;\
             justify-content:space-between;padding-bottom:20px;\
             border-bottom:1px solid {quiet}33}}\
             header a{{color:{ink};text-decoration:none;margin-left:16px}}\
             header a:hover{{color:{accent}}}\
             h1{{font-size:26px;margin:0;letter-spacing:-0.01em}}\
             h2{{font-size:20px;margin:36px 0 8px}}\
             p{{margin:12px 0}}\
             .lead{{font-size:20px;color:{quiet};margin:24px 0 8px}}\
             ul{{padding-left:20px}}\
             li{{margin:6px 0}}\
             .card{{border:1px solid {quiet}33;border-radius:{radius}px;\
             padding:16px 18px;margin:16px 0}}\
             .mark{{display:inline-block;width:14px;height:14px;\
             background:{accent};border-radius:{radius}px;margin-right:8px;\
             vertical-align:-1px}}\
             footer{{margin-top:48px;padding-top:20px;color:{quiet};font-size:15px;\
             border-top:1px solid {quiet}33}}\
             a{{color:{accent}}}\
             @media(max-width:520px){{body{{font-size:16px}}h1{{font-size:22px}}}}",
        )
    }
}

/// The front page.
fn render_front(
    name: &str,
    trade: &copy::Trade,
    look: &Look,
    sections: &[&copy::Section],
    elsewhere: &[(String, String)],
    rolls: &mut Rolls,
) -> String {
    let mut out = head(name, look, elsewhere, name);
    out.push_str(&format!(
        "<p class=\"lead\">{}</p>",
        escape(trade.lines[rolls.upto(trade.lines.len())])
    ));
    for section in sections {
        out.push_str(&format!("<h2>{}</h2>", escape(section.title)));
        for line in section.lines {
            out.push_str(&format!("<p>{}</p>", escape(line)));
        }
        if !section.points.is_empty() {
            out.push_str("<ul>");
            for point in section.points {
                out.push_str(&format!("<li>{}</li>", escape(point)));
            }
            out.push_str("</ul>");
        }
    }
    out.push_str(&foot(name, trade, rolls));
    out
}

/// Any page that is not the front one.
fn render_inside(
    name: &str,
    trade: &copy::Trade,
    look: &Look,
    title: &str,
    elsewhere: &[(String, String)],
    rolls: &mut Rolls,
) -> String {
    let mut out = head(name, look, elsewhere, title);
    let section = &trade.sections[rolls.upto(trade.sections.len())];
    out.push_str(&format!("<p class=\"lead\">{}</p>", escape(section.title)));
    for line in section.lines {
        out.push_str(&format!("<p>{}</p>", escape(line)));
    }
    out.push_str(&format!(
        "<div class=\"card\"><p>{}</p></div>",
        escape(trade.lines[rolls.upto(trade.lines.len())])
    ));
    out.push_str(&foot(name, trade, rolls));
    out
}

/// What a visitor sees when the path is not one of ours.
fn render_missing(name: &str, look: &Look, elsewhere: &[(String, String)]) -> String {
    let mut out = head(name, look, elsewhere, "Not found");
    out.push_str("<p class=\"lead\">That page is not here.</p>");
    out.push_str("<p>Try one of the links above.</p>");
    out.push_str("</div></body>");
    out
}

/// Everything above the content, including the navigation.
fn head(name: &str, look: &Look, elsewhere: &[(String, String)], title: &str) -> String {
    let mut links = String::new();
    for (path, label) in elsewhere {
        links.push_str(&format!(
            "<a href=\"{}\">{}</a>",
            escape(path),
            escape(label)
        ));
    }
    // The front page is titled by the name alone: a title reading "X — X" is
    // the sort of thing nobody writes on purpose.
    let titled = if title == name {
        escape(name)
    } else {
        format!("{} — {}", escape(title), escape(name))
    };
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{titled}</title>\
         <style>{}</style></head><body><div class=\"sheet\">\
         <header><h1><span class=\"mark\"></span>{name}</h1><nav>{links}</nav></header>",
        look.stylesheet(),
        titled = titled,
        name = escape(name),
        links = links,
    )
}

/// Everything below the content.
fn foot(name: &str, trade: &copy::Trade, rolls: &mut Rolls) -> String {
    // From the range held for fiction, so the number on the page reaches
    // nobody: Ofcom reserves 020 7946 0xxx for exactly this.
    let phone = format!("+44 20 7946 0{:03}", rolls.upto(1000));
    let year = 2019 + rolls.upto(7);
    format!(
        "<footer><p>{} · {}</p><p>{} — established {year}</p>\
         <p>{}</p></footer></div></body></html>",
        escape(name),
        escape(trade.where_they_are[rolls.upto(trade.where_they_are.len())]),
        escape(trade.trade),
        escape(&phone),
    )
}

/// Turns text into something safe to put in markup.
fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            _ => out.push(character),
        }
    }
    out
}

/// Numbers drawn from a seed, the same way every time.
///
/// Written out rather than taken from a library: what matters is that the same
/// node builds the same site for ever, which a generator that changes with a
/// dependency would not give.
struct Rolls {
    state: u64,
}

impl Rolls {
    /// Starts from a seed.
    fn from(seed: [u8; 32]) -> Self {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        for chunk in seed.chunks(8) {
            let mut piece = [0u8; 8];
            piece[..chunk.len()].copy_from_slice(chunk);
            state ^= u64::from_le_bytes(piece);
            state = state.wrapping_mul(0xbf58_476d_1ce4_e5b9);
        }
        Self { state }
    }

    /// The next number.
    fn next(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// A number below the given one.
    fn upto(&mut self, ceiling: usize) -> usize {
        if ceiling == 0 {
            return 0;
        }
        (self.next() % ceiling as u64) as usize
    }

    /// True about this often.
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_seed(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    #[test]
    fn the_same_node_builds_the_same_site_every_time() {
        assert_eq!(site(a_seed(7)), site(a_seed(7)));
    }

    #[test]
    fn two_nodes_share_nothing_a_visitor_would_see() {
        // The same page on forty addresses finds all forty at once.
        let one = site(a_seed(1));
        let other = site(a_seed(2));
        let front_of_one = one.page("/").unwrap();
        let front_of_other = other.page("/").unwrap();
        assert_ne!(front_of_one, front_of_other);

        let paths_of_one: Vec<&str> = one.paths().collect();
        let paths_of_other: Vec<&str> = other.paths().collect();
        assert_ne!(paths_of_one, paths_of_other, "two nodes answer alike");
    }

    #[test]
    fn a_site_has_a_front_page_and_the_pages_it_links_to() {
        let built = site(a_seed(3));
        assert!(built.page("/").is_some());
        for path in built.paths().collect::<Vec<_>>() {
            assert!(built.page(path).is_some());
        }
    }

    #[test]
    fn a_path_that_is_not_here_has_something_to_answer_with() {
        let built = site(a_seed(4));
        assert!(built.page("/nothing-like-this").is_none());
        assert!(!built.missing().bytes.is_empty());
    }

    #[test]
    fn a_trailing_slash_is_the_same_page() {
        let built = site(a_seed(5));
        let paths: Vec<String> = built.paths().map(str::to_owned).collect();
        let inside = paths.iter().find(|path| path.len() > 1).unwrap();
        assert_eq!(
            built.page(inside),
            built.page(&format!("{inside}/")),
            "a slash at the end changed the answer"
        );
    }

    #[test]
    fn a_query_is_not_part_of_the_path() {
        let built = site(a_seed(6));
        assert_eq!(built.page("/"), built.page("/?utm_source=somewhere"));
    }

    #[test]
    fn nothing_reaches_outside_the_node() {
        // A site that fetched a font or an image from somewhere else would
        // tell that somewhere else who visits, and would look nothing like the
        // small site it claims to be.
        for seed in 0..12u8 {
            let built = site(a_seed(seed));
            for path in built.paths().collect::<Vec<_>>() {
                let text = String::from_utf8_lossy(&built.page(path).unwrap().bytes).into_owned();
                for sign in ["http://", "https://", "//fonts", "cdn."] {
                    assert!(
                        !text.contains(sign),
                        "the site at {path} reaches out to {sign}"
                    );
                }
            }
        }
    }

    #[test]
    fn what_is_written_is_written_safely() {
        assert_eq!(
            escape("a & b < c > \"d\""),
            "a &amp; b &lt; c &gt; &quot;d&quot;"
        );
    }

    #[test]
    fn many_seeds_give_many_different_sites() {
        let mut seen = std::collections::BTreeSet::new();
        for seed in 0..40u8 {
            seen.insert(site(a_seed(seed)).page("/").unwrap().bytes.clone());
        }
        assert!(
            seen.len() >= 30,
            "forty nodes produced only {} different front pages",
            seen.len()
        );
    }
}
