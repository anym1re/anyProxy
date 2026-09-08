//! Every byte the site answers with, built here and nowhere else.
//!
//! A name is the operator's text and lands in three places — HTML, JSON and
//! JSON-LD inside a `<script>` — each with its own way of breaking. Each is
//! escaped for the place it lands in, and a test feeds a hostile name through
//! all three (0094).

use ap_core::i18n::message;
use ap_core::{Locale, NodeKindTag};

use crate::Config;
use crate::feed::PublicLink;

/// Everything that does not change with the feed.
#[derive(Debug, Clone)]
pub struct Statics {
    /// `/style.css`.
    pub style: &'static str,
    /// `/icon.svg`.
    pub icon: &'static str,
    /// `/robots.txt`.
    pub robots: String,
    /// `/sitemap.xml`.
    pub sitemap: String,
    /// `/llms.txt`.
    pub llms: String,
}

impl Statics {
    /// Builds the pages that depend on the configuration alone.
    pub fn build(config: &Config) -> Result<Self, ap_core::Error> {
        Ok(Self {
            style: STYLE,
            icon: ICON,
            robots: robots(config),
            sitemap: sitemap(config),
            llms: llms(config)?,
        })
    }
}

/// Escapes text for an HTML body or a double-quoted attribute.
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

/// Escapes JSON so it can sit inside a `<script>` without closing it.
///
/// `<`, `>` and `&` become their `\u` forms, which JSON allows anywhere in a
/// string and which no HTML parser reads as markup.
pub fn script_safe(json: &str) -> String {
    json.replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// The word for a method, in the visitor's language.
fn method_word(locale: Locale, method: NodeKindTag) -> Result<String, ap_core::Error> {
    message(locale, &format!("site-method-{}", method.as_stored()))
}

/// The OpenGraph spelling of a locale.
fn og_locale(locale: Locale) -> &'static str {
    match locale {
        Locale::Ru => "ru_RU",
        Locale::En => "en_US",
    }
}

/// The address of one page.
fn page_url(config: &Config, locale: Locale) -> String {
    format!("{}/{}/", config.public_url, locale.code())
}

/// One page, whole.
pub fn html(
    locale: Locale,
    config: &Config,
    links: &[PublicLink],
) -> Result<String, ap_core::Error> {
    let t = |key: &str| message(locale, key);
    let title = escape(&t("site-title")?);
    let description = escape(&t("site-description")?);
    let here = escape(&page_url(config, locale));
    let other = match locale {
        Locale::Ru => Locale::En,
        Locale::En => Locale::Ru,
    };
    let default_url = escape(&page_url(config, config.default_locale));
    let ru_url = escape(&page_url(config, Locale::Ru));
    let en_url = escape(&page_url(config, Locale::En));

    let mut out = String::with_capacity(4096);
    out.push_str("<!doctype html>\n");
    out.push_str(&format!("<html lang=\"{}\">\n<head>\n", locale.code()));
    out.push_str("<meta charset=\"utf-8\">\n");
    out.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    out.push_str(&format!("<title>{title}</title>\n"));
    out.push_str(&format!(
        "<meta name=\"description\" content=\"{description}\">\n"
    ));
    out.push_str(&format!("<link rel=\"canonical\" href=\"{here}\">\n"));
    out.push_str(&format!(
        "<link rel=\"alternate\" hreflang=\"ru\" href=\"{ru_url}\">\n"
    ));
    out.push_str(&format!(
        "<link rel=\"alternate\" hreflang=\"en\" href=\"{en_url}\">\n"
    ));
    out.push_str(&format!(
        "<link rel=\"alternate\" hreflang=\"x-default\" href=\"{default_url}\">\n"
    ));
    out.push_str("<link rel=\"stylesheet\" href=\"/style.css\">\n");
    out.push_str("<link rel=\"icon\" href=\"/icon.svg\" type=\"image/svg+xml\">\n");
    out.push_str("<meta property=\"og:type\" content=\"website\">\n");
    out.push_str(&format!(
        "<meta property=\"og:title\" content=\"{title}\">\n"
    ));
    out.push_str(&format!(
        "<meta property=\"og:description\" content=\"{description}\">\n"
    ));
    out.push_str(&format!("<meta property=\"og:url\" content=\"{here}\">\n"));
    out.push_str(&format!(
        "<meta property=\"og:locale\" content=\"{}\">\n",
        og_locale(locale)
    ));
    out.push_str(&format!(
        "<meta property=\"og:locale:alternate\" content=\"{}\">\n",
        og_locale(other)
    ));
    out.push_str("<script type=\"application/ld+json\">");
    out.push_str(&script_safe(&structured(locale, config, links)?));
    out.push_str("</script>\n");
    out.push_str("</head>\n<body>\n<header>\n");
    out.push_str(&format!(
        "<nav aria-label=\"{}\">\n",
        escape(&t("site-languages")?)
    ));
    for candidate in [Locale::Ru, Locale::En] {
        let current = if candidate == locale {
            " aria-current=\"page\""
        } else {
            ""
        };
        out.push_str(&format!(
            "<a href=\"/{code}/\" hreflang=\"{code}\" lang=\"{code}\"{current}>{}</a>\n",
            escape(&message(
                candidate,
                &format!("site-lang-{code}", code = candidate.code())
            )?),
            code = candidate.code(),
        ));
    }
    out.push_str("</nav>\n</header>\n<main>\n");
    out.push_str(&format!("<h1>{}</h1>\n", escape(&t("site-heading")?)));
    out.push_str(&format!("<p>{}</p>\n", escape(&t("site-lead")?)));
    out.push_str("<section aria-labelledby=\"links\">\n");
    out.push_str(&format!(
        "<h2 id=\"links\">{}</h2>\n",
        escape(&t("site-links")?)
    ));
    if links.is_empty() {
        out.push_str(&format!("<p>{}</p>\n", escape(&t("site-none")?)));
    } else {
        out.push_str("<ul class=\"links\">\n");
        for link in links {
            out.push_str("<li>\n");
            out.push_str(&format!("<h3>{}</h3>\n", escape(link.name().as_str())));
            out.push_str(&format!(
                "<p class=\"method\">{}</p>\n",
                escape(&method_word(locale, link.method())?)
            ));
            match link {
                PublicLink::Link { link, .. } => {
                    let href = escape(link);
                    out.push_str(&format!(
                        "<p><a class=\"open\" href=\"{href}\">{}</a></p>\n",
                        escape(&t("site-open")?)
                    ));
                    out.push_str(&format!("<p><code>{href}</code></p>\n"));
                }
                PublicLink::Account {
                    host,
                    port,
                    user,
                    password,
                    ..
                } => {
                    out.push_str("<dl>\n");
                    for (key, value) in [
                        ("site-host", host.as_str()),
                        ("site-port", &port.to_string()),
                        ("site-user", user.as_str()),
                        ("site-password", password.as_str()),
                    ] {
                        out.push_str(&format!(
                            "<dt>{}</dt>\n<dd><code>{}</code></dd>\n",
                            escape(&t(key)?),
                            escape(value)
                        ));
                    }
                    out.push_str("</dl>\n");
                }
            }
            out.push_str("</li>\n");
        }
        out.push_str("</ul>\n");
    }
    out.push_str("</section>\n");
    out.push_str(&format!(
        "<p><a href=\"/links.json\">{}</a></p>\n",
        escape(&t("site-machine")?)
    ));
    out.push_str("</main>\n</body>\n</html>\n");
    Ok(out)
}

/// The links as a JSON document, the same shape the feed has.
pub fn json(links: &[PublicLink]) -> String {
    let rows: Vec<serde_json::Value> = links.iter().map(row_json).collect();
    let mut text = serde_json::json!({ "links": rows }).to_string();
    text.push('\n');
    text
}

fn row_json(link: &PublicLink) -> serde_json::Value {
    match link {
        PublicLink::Link { name, method, link } => serde_json::json!({
            "name": name.as_str(), "method": method.as_stored(), "link": link,
        }),
        PublicLink::Account {
            name,
            method,
            host,
            port,
            user,
            password,
        } => serde_json::json!({
            "name": name.as_str(), "method": method.as_stored(),
            "host": host, "port": port, "user": user, "password": password,
        }),
    }
}

/// JSON-LD: the site and the list on it.
fn structured(
    locale: Locale,
    config: &Config,
    links: &[PublicLink],
) -> Result<String, ap_core::Error> {
    let items: Vec<serde_json::Value> = links
        .iter()
        .enumerate()
        .map(|(index, link)| {
            let mut item = serde_json::json!({
                "@type": "ListItem",
                "position": index + 1,
                "name": link.name().as_str(),
            });
            if let PublicLink::Link { link, .. } = link {
                item["url"] = serde_json::Value::String(link.clone());
            }
            item
        })
        .collect();
    let document = serde_json::json!({
        "@context": "https://schema.org",
        "@graph": [
            {
                "@type": "WebSite",
                "url": format!("{}/", config.public_url),
                "name": message(locale, "site-title")?,
                "description": message(locale, "site-description")?,
                "inLanguage": locale.code(),
            },
            {
                "@type": "ItemList",
                "url": page_url(config, locale),
                "name": message(locale, "site-links")?,
                "numberOfItems": links.len(),
                "itemListElement": items,
            }
        ]
    });
    Ok(document.to_string())
}

fn robots(config: &Config) -> String {
    format!(
        "User-agent: *\nAllow: /\n\nSitemap: {}/sitemap.xml\n",
        config.public_url
    )
}

fn sitemap(config: &Config) -> String {
    let mut out = String::from("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\" \
         xmlns:xhtml=\"http://www.w3.org/1999/xhtml\">\n",
    );
    for locale in [Locale::Ru, Locale::En] {
        out.push_str("<url>\n");
        out.push_str(&format!(
            "<loc>{}</loc>\n",
            escape(&page_url(config, locale))
        ));
        for alternate in [Locale::Ru, Locale::En] {
            out.push_str(&format!(
                "<xhtml:link rel=\"alternate\" hreflang=\"{}\" href=\"{}\"/>\n",
                alternate.code(),
                escape(&page_url(config, alternate))
            ));
        }
        out.push_str(&format!(
            "<xhtml:link rel=\"alternate\" hreflang=\"x-default\" href=\"{}\"/>\n",
            escape(&page_url(config, config.default_locale))
        ));
        out.push_str("</url>\n");
    }
    out.push_str("</urlset>\n");
    out
}

/// What an agent is told: what is here and where the list is.
///
/// English throughout, as the form is; the pages themselves come in both
/// languages and are named here.
fn llms(config: &Config) -> Result<String, ap_core::Error> {
    let base = &config.public_url;
    Ok(format!(
        "# {title}\n\n\
         > {description}\n\n\
         - [Links, Russian]({base}/ru/)\n\
         - [Links, English]({base}/en/)\n\
         - [Machine-readable list]({base}/links.json): JSON; `links[]` carries `name`, \
         `method` and either `link` or `host`, `port`, `user`, `password`.\n\n\
         Methods `faketls`, `web` and `mtproto` are opened in Telegram by their link. \
         Methods `socks5` and `http` are entered in Telegram's proxy settings by host, \
         port, user and password.\n",
        title = message(Locale::En, "site-title")?,
        description = message(Locale::En, "site-description")?,
    ))
}

const STYLE: &str = "\
:root{color-scheme:light dark;--fg:#1a1a1a;--bg:#fafafa;--muted:#5a5a5a;--line:#d8d8d8;--code:#efefef;--link:#0b57d0}\
@media(prefers-color-scheme:dark){:root{--fg:#ececec;--bg:#141414;--muted:#a8a8a8;--line:#333;--code:#222;--link:#8ab4f8}}\
html{font:16px/1.5 system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;color:var(--fg);background:var(--bg)}\
body{margin:0 auto;max-width:44rem;padding:1.5rem 1rem 3rem}\
header nav{display:flex;gap:1rem;font-size:.95rem}\
header nav a[aria-current]{font-weight:600;text-decoration:none}\
a{color:var(--link)}a:focus-visible{outline:3px solid var(--link);outline-offset:2px}\
h1{font-size:1.75rem;margin:1.5rem 0 .5rem}h2{font-size:1.25rem;margin:2rem 0 .75rem}\
h3{font-size:1.05rem;margin:0 0 .25rem}\
ul.links{list-style:none;margin:0;padding:0}\
ul.links li{border:1px solid var(--line);border-radius:.5rem;padding:1rem;margin:0 0 1rem}\
ul.links p{margin:.25rem 0}\
.method{color:var(--muted);font-size:.9rem}\
a.open{display:inline-block;padding:.5rem .9rem;border:1px solid var(--link);border-radius:.4rem;text-decoration:none;font-weight:600}\
code{display:block;padding:.5rem .6rem;border-radius:.3rem;background:var(--code);font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.85rem;overflow-wrap:anywhere}\
dl{display:grid;grid-template-columns:max-content 1fr;gap:.35rem .75rem;margin:.5rem 0 0}dt{color:var(--muted)}dd{margin:0}\
";

const ICON: &str = "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 32 32\">\
<circle cx=\"16\" cy=\"16\" r=\"12\" fill=\"none\" stroke=\"#0b57d0\" stroke-width=\"4\"/>\
<circle cx=\"16\" cy=\"16\" r=\"4\" fill=\"#0b57d0\"/></svg>\n";

#[cfg(test)]
mod tests {
    use super::*;
    use ap_core::LinkName;

    fn config() -> Config {
        Config::build(
            "https://links.example",
            "http://127.0.0.1:8090",
            ([127, 0, 0, 1], 0).into(),
            ([127, 0, 0, 1], 0).into(),
            60,
            Locale::Ru,
        )
        .unwrap()
    }

    #[test]
    fn a_hostile_name_stays_text_in_every_place_it_lands() {
        let name = "<script>alert(1)</script>\"&'</script>";
        let links = vec![PublicLink::Link {
            name: LinkName::try_from(name).unwrap(),
            method: NodeKindTag::Mtproto,
            link: "https://t.me/proxy?server=203.0.113.7&port=8443&secret=dd00".to_owned(),
        }];
        let page = html(Locale::En, &config(), &links).unwrap();
        assert!(!page.contains("<script>alert"), "the name became markup");
        assert!(
            page.contains("&lt;script&gt;alert(1)&lt;/script&gt;&quot;&amp;&#39;"),
            "the name was not escaped for HTML"
        );
        // Exactly one script: the JSON-LD, and it ends where it should.
        assert_eq!(page.matches("<script").count(), 1);
        assert_eq!(page.matches("</script>").count(), 1);
        let opening = "<script type=\"application/ld+json\">";
        let ld_start = page.find(opening).unwrap() + opening.len();
        let ld = &page[ld_start..];
        let ld = &ld[..ld.find("</script>").unwrap()];
        assert!(
            ld.contains("\\u003cscript\\u003e"),
            "the name closed the JSON-LD"
        );
        assert!(!ld.contains('<') && !ld.contains('>') && !ld.contains('&'));

        let document = json(&links);
        let parsed: serde_json::Value = serde_json::from_str(&document).unwrap();
        assert_eq!(parsed["links"][0]["name"], name);
    }

    #[test]
    fn both_languages_render_and_name_each_other() {
        for locale in Locale::all() {
            let page = html(locale, &config(), &[]).unwrap();
            assert!(page.starts_with("<!doctype html>"));
            assert!(page.contains(&format!("<html lang=\"{}\">", locale.code())));
            assert!(page.contains("hreflang=\"ru\" href=\"https://links.example/ru/\""));
            assert!(page.contains("hreflang=\"en\" href=\"https://links.example/en/\""));
            assert!(page.contains("hreflang=\"x-default\" href=\"https://links.example/ru/\""));
            assert_eq!(page.matches("<h1>").count(), 1);
        }
    }

    #[test]
    fn an_account_link_is_a_definition_list() {
        let links = vec![PublicLink::Account {
            name: LinkName::try_from("socks").unwrap(),
            method: NodeKindTag::Socks5,
            host: "203.0.113.8".to_owned(),
            port: 1080,
            user: "u".to_owned(),
            password: "p".to_owned(),
        }];
        let page = html(Locale::Ru, &config(), &links).unwrap();
        assert!(page.contains("<dl>"));
        assert!(page.contains("<dd><code>1080</code></dd>"));
        assert!(!page.contains("t.me"));
    }

    #[test]
    fn the_statics_name_the_configured_address_only() {
        let statics = Statics::build(&config()).unwrap();
        assert!(
            statics
                .robots
                .contains("Sitemap: https://links.example/sitemap.xml")
        );
        assert_eq!(statics.sitemap.matches("<url>").count(), 2);
        assert!(
            statics
                .sitemap
                .contains("<loc>https://links.example/en/</loc>")
        );
        assert!(statics.llms.contains("https://links.example/links.json"));
    }

    #[test]
    fn a_public_url_is_checked_before_anything_is_built() {
        for bad in [
            "http://links.example",
            "https://links.example/path",
            "https://links.example/?x",
            "https://<b>",
            "",
        ] {
            let refused = Config::build(
                bad,
                "http://127.0.0.1:8090",
                ([127, 0, 0, 1], 0).into(),
                ([127, 0, 0, 1], 0).into(),
                60,
                Locale::Ru,
            );
            assert_eq!(
                refused.err(),
                Some(crate::ConfigError::PublicUrl),
                "{bad:?}"
            );
        }
        assert_eq!(
            Config::build(
                "https://links.example/",
                "http://127.0.0.1:8090",
                ([127, 0, 0, 1], 0).into(),
                ([127, 0, 0, 1], 0).into(),
                60,
                Locale::Ru,
            )
            .unwrap()
            .public_url,
            "https://links.example"
        );
    }
}
