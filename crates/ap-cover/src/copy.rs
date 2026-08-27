//! The words a cover site is built from.
//!
//! Deliberately dull trades doing deliberately dull things. A cover that is
//! interesting invites a second look, and a second look is the one thing it
//! must not attract.
//!
//! Nothing here names anyone real. The names are assembled from ordinary
//! words, and the places are ordinary places rather than addresses that lead
//! anywhere.

/// A run of text on a page.
pub struct Section {
    /// What it is called.
    pub title: &'static str,
    /// The paragraphs under it.
    pub lines: &'static [&'static str],
    /// The list under those, when there is one.
    pub points: &'static [&'static str],
}

/// One kind of small business a node can appear to be.
pub struct Trade {
    /// What it does, in a couple of words.
    pub trade: &'static str,
    /// Words the first half of the name is drawn from.
    pub first: &'static [&'static str],
    /// Words the second half is drawn from.
    pub second: &'static [&'static str],
    /// Lines that could open a page.
    pub lines: &'static [&'static str],
    /// The runs of text the site is assembled from.
    pub sections: &'static [Section],
    /// The other pages, and what they are called.
    pub pages: &'static [(&'static str, &'static str)],
    /// Where it might be.
    pub where_they_are: &'static [&'static str],
}

impl Trade {
    /// Draws a name for one of these.
    pub fn name(&self, rolls: &mut crate::Rolls) -> String {
        format!(
            "{} {}",
            self.first[rolls.upto(self.first.len())],
            self.second[rolls.upto(self.second.len())]
        )
    }
}

/// Every trade a node can appear to be.
pub const TRADES: &[&Trade] = &[
    &SURVEYING,
    &BINDING,
    &TRANSLATION,
    &NURSERY,
    &REPAIR,
    &ARCHIVE,
];

const SURVEYING: Trade = Trade {
    trade: "Land and building surveys",
    first: &[
        "Hartwell", "Marlow", "Kesteven", "Ashfield", "Pentland", "Braemar",
    ],
    second: &[
        "Surveys",
        "Survey Partners",
        "Land Services",
        "Measured Surveys",
    ],
    lines: &[
        "Measured building surveys, topographic surveys and setting out for small and mid-sized projects.",
        "We measure what is there, and put it on a drawing that can be built from.",
        "Site surveys for architects, engineers and owners, across the region and beyond it when asked.",
    ],
    sections: &[
        Section {
            title: "What we do",
            lines: &[
                "Most of our work is measured building surveys: floor plans, elevations and sections of buildings that are already standing, drawn to the tolerance the job needs.",
            ],
            points: &[
                "Measured building surveys and floor plans",
                "Topographic and boundary surveys",
                "Setting out and as-built records",
                "Level and drainage surveys",
            ],
        },
        Section {
            title: "How we work",
            lines: &[
                "One surveyor visits, usually for half a day. Drawings follow within the week in the format your team already uses.",
                "We quote on the drawing you need rather than on the time it takes, so the figure you are given is the figure you pay.",
            ],
            points: &[],
        },
        Section {
            title: "Equipment",
            lines: &[
                "Total stations and a laser scanner for the larger jobs. For a single flat, a disto and a steady hand are usually quicker.",
            ],
            points: &[],
        },
    ],
    pages: &[("/services", "Services"), ("/contact", "Contact")],
    where_they_are: &["Yorkshire", "the East Midlands", "Cumbria", "the Borders"],
};

const BINDING: Trade = Trade {
    trade: "Bookbinding and repair",
    first: &["Quill", "Fenmore", "Ashby", "Tallow", "Rushmere", "Coppice"],
    second: &["Bindery", "Bookbinders", "Book Repair", "Binding Works"],
    lines: &[
        "Hand binding, rebacking and box making for libraries, collectors and anyone with a book that has come apart.",
        "We rebind, repair and box books, one at a time, by hand.",
        "A small bindery taking in repairs, theses and short runs.",
    ],
    sections: &[
        Section {
            title: "Repairs",
            lines: &[
                "Most books that come to us need a new spine, a hinge repaired, or the sewing replaced. We keep the original covering where it can be kept and match it where it cannot.",
            ],
            points: &[
                "Rebacking and reboarding",
                "Resewing and guarding",
                "Cloth and leather rebinding",
                "Clamshell boxes and slipcases",
            ],
        },
        Section {
            title: "Theses and short runs",
            lines: &[
                "Thesis binding to the usual university requirements, with lettering on the spine. Two weeks in term time, less outside it.",
            ],
            points: &[],
        },
        Section {
            title: "Bringing a book in",
            lines: &[
                "Bring the book, or send photographs of the spine and the joints. We will tell you what it needs and what it will cost before anything is taken apart.",
            ],
            points: &[],
        },
    ],
    pages: &[
        ("/repairs", "Repairs"),
        ("/prices", "Prices"),
        ("/contact", "Contact"),
    ],
    where_they_are: &["Norfolk", "the Welsh Marches", "Fife", "Somerset"],
};

const TRANSLATION: Trade = Trade {
    trade: "Technical translation",
    first: &[
        "Meridian",
        "Wordwright",
        "Fairhaven",
        "Northgate",
        "Levant",
        "Calder",
    ],
    second: &[
        "Translation",
        "Language Services",
        "Translations",
        "Technical Translation",
    ],
    lines: &[
        "Technical and legal translation between English, German, French and the Nordic languages.",
        "Documents translated by people who have read the standard they refer to.",
        "Certified translation for filings, tenders and technical documentation.",
    ],
    sections: &[
        Section {
            title: "Fields",
            lines: &[
                "We take work in fields where a wrong word is expensive: machinery documentation, standards, patents, and the contracts around them.",
            ],
            points: &[
                "Machinery and equipment documentation",
                "Standards and conformity assessment",
                "Patent specifications and prosecution",
                "Contracts, tenders and filings",
            ],
        },
        Section {
            title: "Certification",
            lines: &[
                "Certified translations carry a signed statement and are accepted by the registries and courts we work with. Say at the outset if you need one; adding it afterwards means printing it again.",
            ],
            points: &[],
        },
        Section {
            title: "Turnaround",
            lines: &[
                "Two to five working days for most documents. Longer texts are quoted with a date rather than a rate.",
            ],
            points: &[],
        },
    ],
    pages: &[("/fields", "Fields"), ("/contact", "Contact")],
    where_they_are: &["Hamburg", "Aarhus", "Leuven", "Tallinn"],
};

const NURSERY: Trade = Trade {
    trade: "Plant nursery",
    first: &[
        "Hollow Lane",
        "Beckside",
        "Old Orchard",
        "Millrace",
        "Longmeadow",
        "Stonecrop",
    ],
    second: &["Nursery", "Plant Nursery", "Nurseries", "Growers"],
    lines: &[
        "Hardy perennials, shrubs and hedging, grown here and sold from the field.",
        "A working nursery: what is ready is what is for sale.",
        "Bare-root hedging in season, container-grown shrubs the rest of the year.",
    ],
    sections: &[
        Section {
            title: "What is ready",
            lines: &[
                "Stock changes with the season, and we do not hold a catalogue that pretends otherwise. Ring before a long drive and we will tell you what is in the ground.",
            ],
            points: &[
                "Hardy perennials in nine-centimetre pots",
                "Bare-root hedging, November to March",
                "Container-grown shrubs and small trees",
                "Field-grown roses, lifted to order",
            ],
        },
        Section {
            title: "Opening",
            lines: &[
                "Open Thursday to Saturday through the growing season, and by arrangement in winter. The gate is on the lane rather than the main road.",
            ],
            points: &[],
        },
        Section {
            title: "Advice",
            lines: &[
                "We will say when a plant is wrong for the place you have in mind. It saves everyone a season.",
            ],
            points: &[],
        },
    ],
    pages: &[("/stock", "Stock"), ("/visiting", "Visiting")],
    where_they_are: &["Herefordshire", "Angus", "Devon", "County Down"],
};

const REPAIR: Trade = Trade {
    trade: "Instrument repair",
    first: &[
        "Gable",
        "Whitcombe",
        "Ardmore",
        "Sennen",
        "Larkspur",
        "Threlfall",
    ],
    second: &[
        "Instrument Repair",
        "Workshop",
        "Instrument Works",
        "Repairs",
    ],
    lines: &[
        "Repair and servicing of woodwind and brass instruments, for players and for schools.",
        "Pads, corks, dents and the things that go wrong in a case at the back of a cupboard.",
        "A workshop taking in instruments that have stopped working and sending them back playing.",
    ],
    sections: &[
        Section {
            title: "Servicing",
            lines: &[
                "A full service takes a week: pads replaced where they need it, keywork regulated, the body cleaned and checked for leaks.",
            ],
            points: &[
                "Pad replacement and regulation",
                "Dent removal and body work",
                "Cork and felt replacement",
                "Valve and slide servicing",
            ],
        },
        Section {
            title: "Schools",
            lines: &[
                "We collect and return in batches for schools and music services, and provide a written condition report for each instrument.",
            ],
            points: &[],
        },
        Section {
            title: "Before you bring it",
            lines: &[
                "Bring the case and the mouthpiece. Half of what people think is a fault turns out to be one or the other.",
            ],
            points: &[],
        },
    ],
    pages: &[
        ("/servicing", "Servicing"),
        ("/schools", "Schools"),
        ("/contact", "Contact"),
    ],
    where_they_are: &[
        "Greater Manchester",
        "the Black Country",
        "Tyneside",
        "South Wales",
    ],
};

const ARCHIVE: Trade = Trade {
    trade: "Records and archiving",
    first: &[
        "Fairhurst",
        "Grindley",
        "Camborne",
        "Tetbury",
        "Aldwych",
        "Kirkstall",
    ],
    second: &[
        "Records",
        "Archive Services",
        "Records Management",
        "Document Services",
    ],
    lines: &[
        "Scanning, cataloguing and storage of paper records for practices, estates and small institutions.",
        "Paper that has to be kept, kept properly and findable again.",
        "Retention schedules, scanning and secure destruction, for organisations without an archivist.",
    ],
    sections: &[
        Section {
            title: "Scanning and cataloguing",
            lines: &[
                "Documents are scanned at the resolution the material needs rather than the one that is quickest, and catalogued so that what you scanned can be found without knowing where it was filed.",
            ],
            points: &[
                "Bulk scanning with quality checks",
                "Cataloguing to an agreed schema",
                "Retention schedules and review dates",
                "Witnessed destruction with certificates",
            ],
        },
        Section {
            title: "Storage",
            lines: &[
                "Boxed storage in a dry building with a temperature that does not swing. Retrieval within one working day.",
            ],
            points: &[],
        },
        Section {
            title: "Getting started",
            lines: &[
                "Most projects begin with a survey of what you have. It is usually less than people fear and older than they expect.",
            ],
            points: &[],
        },
    ],
    pages: &[
        ("/scanning", "Scanning"),
        ("/storage", "Storage"),
        ("/contact", "Contact"),
    ],
    where_they_are: &["Lanarkshire", "Lincolnshire", "Kent", "Galway"],
};
