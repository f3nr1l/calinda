// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 René Onier

//! Countries of the sheet (J2 finishing touches, `annuaire.vue.pays`): the ISO 3166-1 list and
//! the three attributes that go with it.
//!
//! An Active Directory account carries its country in three attributes, that the Windows
//! console writes together: `c` (alpha-2 code), `co` (plain name) and `countryCode` (numeric
//! code, 0 without a country). The list comes from the iso-codes 4.16 package (code, number,
//! usual name), copied here once and for all. The names go through the catalogue; `co` gets
//! the name shown, in the language of the interface, as the Windows console does.

use crate::i18n::tr_marked;
use crate::views::normalize;

/// Marks a message for the catalogue; translated when shown.
#[allow(non_snake_case)]
const fn N_(text: &'static str) -> &'static str {
    text
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Country {
    /// ISO 3166-1 alpha-2, the value of `c`.
    pub code: String,
    /// ISO 3166-1 numeric, the value of `countryCode`.
    pub number: u32,
    /// Source name (message of the catalogue); `label` translates it.
    pub name: String,
}

impl Country {
    /// The name in the language of the interface, written in `co`.
    pub fn label(&self) -> String {
        tr_marked(&self.name)
    }
}

/// The three attributes of the country, always written together.
pub const ATTRIBUTES: [&str; 3] = ["c", "co", "countryCode"];

const TABLE: [(&str, u32, &str); 249] = [
    ("AW", 533, N_("Aruba")),
    ("AF", 4, N_("Afghanistan")),
    ("AO", 24, N_("Angola")),
    ("AI", 660, N_("Anguilla")),
    ("AX", 248, N_("Åland Islands")),
    ("AL", 8, N_("Albania")),
    ("AD", 20, N_("Andorra")),
    ("AE", 784, N_("United Arab Emirates")),
    ("AR", 32, N_("Argentina")),
    ("AM", 51, N_("Armenia")),
    ("AS", 16, N_("American Samoa")),
    ("AQ", 10, N_("Antarctica")),
    ("TF", 260, N_("French Southern Territories")),
    ("AG", 28, N_("Antigua and Barbuda")),
    ("AU", 36, N_("Australia")),
    ("AT", 40, N_("Austria")),
    ("AZ", 31, N_("Azerbaijan")),
    ("BI", 108, N_("Burundi")),
    ("BE", 56, N_("Belgium")),
    ("BJ", 204, N_("Benin")),
    ("BQ", 535, N_("Bonaire, Sint Eustatius and Saba")),
    ("BF", 854, N_("Burkina Faso")),
    ("BD", 50, N_("Bangladesh")),
    ("BG", 100, N_("Bulgaria")),
    ("BH", 48, N_("Bahrain")),
    ("BS", 44, N_("Bahamas")),
    ("BA", 70, N_("Bosnia and Herzegovina")),
    ("BL", 652, N_("Saint Barthélemy")),
    ("BY", 112, N_("Belarus")),
    ("BZ", 84, N_("Belize")),
    ("BM", 60, N_("Bermuda")),
    ("BO", 68, N_("Bolivia")),
    ("BR", 76, N_("Brazil")),
    ("BB", 52, N_("Barbados")),
    ("BN", 96, N_("Brunei Darussalam")),
    ("BT", 64, N_("Bhutan")),
    ("BV", 74, N_("Bouvet Island")),
    ("BW", 72, N_("Botswana")),
    ("CF", 140, N_("Central African Republic")),
    ("CA", 124, N_("Canada")),
    ("CC", 166, N_("Cocos (Keeling) Islands")),
    ("CH", 756, N_("Switzerland")),
    ("CL", 152, N_("Chile")),
    ("CN", 156, N_("China")),
    ("CI", 384, N_("Côte d'Ivoire")),
    ("CM", 120, N_("Cameroon")),
    ("CD", 180, N_("Congo, The Democratic Republic of the")),
    ("CG", 178, N_("Congo")),
    ("CK", 184, N_("Cook Islands")),
    ("CO", 170, N_("Colombia")),
    ("KM", 174, N_("Comoros")),
    ("CV", 132, N_("Cabo Verde")),
    ("CR", 188, N_("Costa Rica")),
    ("CU", 192, N_("Cuba")),
    ("CW", 531, N_("Curaçao")),
    ("CX", 162, N_("Christmas Island")),
    ("KY", 136, N_("Cayman Islands")),
    ("CY", 196, N_("Cyprus")),
    ("CZ", 203, N_("Czechia")),
    ("DE", 276, N_("Germany")),
    ("DJ", 262, N_("Djibouti")),
    ("DM", 212, N_("Dominica")),
    ("DK", 208, N_("Denmark")),
    ("DO", 214, N_("Dominican Republic")),
    ("DZ", 12, N_("Algeria")),
    ("EC", 218, N_("Ecuador")),
    ("EG", 818, N_("Egypt")),
    ("ER", 232, N_("Eritrea")),
    ("EH", 732, N_("Western Sahara")),
    ("ES", 724, N_("Spain")),
    ("EE", 233, N_("Estonia")),
    ("ET", 231, N_("Ethiopia")),
    ("FI", 246, N_("Finland")),
    ("FJ", 242, N_("Fiji")),
    ("FK", 238, N_("Falkland Islands (Malvinas)")),
    ("FR", 250, N_("France")),
    ("FO", 234, N_("Faroe Islands")),
    ("FM", 583, N_("Micronesia, Federated States of")),
    ("GA", 266, N_("Gabon")),
    ("GB", 826, N_("United Kingdom")),
    ("GE", 268, N_("Georgia")),
    ("GG", 831, N_("Guernsey")),
    ("GH", 288, N_("Ghana")),
    ("GI", 292, N_("Gibraltar")),
    ("GN", 324, N_("Guinea")),
    ("GP", 312, N_("Guadeloupe")),
    ("GM", 270, N_("Gambia")),
    ("GW", 624, N_("Guinea-Bissau")),
    ("GQ", 226, N_("Equatorial Guinea")),
    ("GR", 300, N_("Greece")),
    ("GD", 308, N_("Grenada")),
    ("GL", 304, N_("Greenland")),
    ("GT", 320, N_("Guatemala")),
    ("GF", 254, N_("French Guiana")),
    ("GU", 316, N_("Guam")),
    ("GY", 328, N_("Guyana")),
    ("HK", 344, N_("Hong Kong")),
    ("HM", 334, N_("Heard Island and McDonald Islands")),
    ("HN", 340, N_("Honduras")),
    ("HR", 191, N_("Croatia")),
    ("HT", 332, N_("Haiti")),
    ("HU", 348, N_("Hungary")),
    ("ID", 360, N_("Indonesia")),
    ("IM", 833, N_("Isle of Man")),
    ("IN", 356, N_("India")),
    ("IO", 86, N_("British Indian Ocean Territory")),
    ("IE", 372, N_("Ireland")),
    ("IR", 364, N_("Iran")),
    ("IQ", 368, N_("Iraq")),
    ("IS", 352, N_("Iceland")),
    ("IL", 376, N_("Israel")),
    ("IT", 380, N_("Italy")),
    ("JM", 388, N_("Jamaica")),
    ("JE", 832, N_("Jersey")),
    ("JO", 400, N_("Jordan")),
    ("JP", 392, N_("Japan")),
    ("KZ", 398, N_("Kazakhstan")),
    ("KE", 404, N_("Kenya")),
    ("KG", 417, N_("Kyrgyzstan")),
    ("KH", 116, N_("Cambodia")),
    ("KI", 296, N_("Kiribati")),
    ("KN", 659, N_("Saint Kitts and Nevis")),
    ("KR", 410, N_("South Korea")),
    ("KW", 414, N_("Kuwait")),
    ("LA", 418, N_("Laos")),
    ("LB", 422, N_("Lebanon")),
    ("LR", 430, N_("Liberia")),
    ("LY", 434, N_("Libya")),
    ("LC", 662, N_("Saint Lucia")),
    ("LI", 438, N_("Liechtenstein")),
    ("LK", 144, N_("Sri Lanka")),
    ("LS", 426, N_("Lesotho")),
    ("LT", 440, N_("Lithuania")),
    ("LU", 442, N_("Luxembourg")),
    ("LV", 428, N_("Latvia")),
    ("MO", 446, N_("Macao")),
    ("MF", 663, N_("Saint Martin (French part)")),
    ("MA", 504, N_("Morocco")),
    ("MC", 492, N_("Monaco")),
    ("MD", 498, N_("Moldova")),
    ("MG", 450, N_("Madagascar")),
    ("MV", 462, N_("Maldives")),
    ("MX", 484, N_("Mexico")),
    ("MH", 584, N_("Marshall Islands")),
    ("MK", 807, N_("North Macedonia")),
    ("ML", 466, N_("Mali")),
    ("MT", 470, N_("Malta")),
    ("MM", 104, N_("Myanmar")),
    ("ME", 499, N_("Montenegro")),
    ("MN", 496, N_("Mongolia")),
    ("MP", 580, N_("Northern Mariana Islands")),
    ("MZ", 508, N_("Mozambique")),
    ("MR", 478, N_("Mauritania")),
    ("MS", 500, N_("Montserrat")),
    ("MQ", 474, N_("Martinique")),
    ("MU", 480, N_("Mauritius")),
    ("MW", 454, N_("Malawi")),
    ("MY", 458, N_("Malaysia")),
    ("YT", 175, N_("Mayotte")),
    ("NA", 516, N_("Namibia")),
    ("NC", 540, N_("New Caledonia")),
    ("NE", 562, N_("Niger")),
    ("NF", 574, N_("Norfolk Island")),
    ("NG", 566, N_("Nigeria")),
    ("NI", 558, N_("Nicaragua")),
    ("NU", 570, N_("Niue")),
    ("NL", 528, N_("Netherlands")),
    ("NO", 578, N_("Norway")),
    ("NP", 524, N_("Nepal")),
    ("NR", 520, N_("Nauru")),
    ("NZ", 554, N_("New Zealand")),
    ("OM", 512, N_("Oman")),
    ("PK", 586, N_("Pakistan")),
    ("PA", 591, N_("Panama")),
    ("PN", 612, N_("Pitcairn")),
    ("PE", 604, N_("Peru")),
    ("PH", 608, N_("Philippines")),
    ("PW", 585, N_("Palau")),
    ("PG", 598, N_("Papua New Guinea")),
    ("PL", 616, N_("Poland")),
    ("PR", 630, N_("Puerto Rico")),
    ("KP", 408, N_("North Korea")),
    ("PT", 620, N_("Portugal")),
    ("PY", 600, N_("Paraguay")),
    ("PS", 275, N_("Palestine, State of")),
    ("PF", 258, N_("French Polynesia")),
    ("QA", 634, N_("Qatar")),
    ("RE", 638, N_("Réunion")),
    ("RO", 642, N_("Romania")),
    ("RU", 643, N_("Russian Federation")),
    ("RW", 646, N_("Rwanda")),
    ("SA", 682, N_("Saudi Arabia")),
    ("SD", 729, N_("Sudan")),
    ("SN", 686, N_("Senegal")),
    ("SG", 702, N_("Singapore")),
    (
        "GS",
        239,
        N_("South Georgia and the South Sandwich Islands"),
    ),
    (
        "SH",
        654,
        N_("Saint Helena, Ascension and Tristan da Cunha"),
    ),
    ("SJ", 744, N_("Svalbard and Jan Mayen")),
    ("SB", 90, N_("Solomon Islands")),
    ("SL", 694, N_("Sierra Leone")),
    ("SV", 222, N_("El Salvador")),
    ("SM", 674, N_("San Marino")),
    ("SO", 706, N_("Somalia")),
    ("PM", 666, N_("Saint Pierre and Miquelon")),
    ("RS", 688, N_("Serbia")),
    ("SS", 728, N_("South Sudan")),
    ("ST", 678, N_("Sao Tome and Principe")),
    ("SR", 740, N_("Suriname")),
    ("SK", 703, N_("Slovakia")),
    ("SI", 705, N_("Slovenia")),
    ("SE", 752, N_("Sweden")),
    ("SZ", 748, N_("Eswatini")),
    ("SX", 534, N_("Sint Maarten (Dutch part)")),
    ("SC", 690, N_("Seychelles")),
    ("SY", 760, N_("Syria")),
    ("TC", 796, N_("Turks and Caicos Islands")),
    ("TD", 148, N_("Chad")),
    ("TG", 768, N_("Togo")),
    ("TH", 764, N_("Thailand")),
    ("TJ", 762, N_("Tajikistan")),
    ("TK", 772, N_("Tokelau")),
    ("TM", 795, N_("Turkmenistan")),
    ("TL", 626, N_("Timor-Leste")),
    ("TO", 776, N_("Tonga")),
    ("TT", 780, N_("Trinidad and Tobago")),
    ("TN", 788, N_("Tunisia")),
    ("TR", 792, N_("Türkiye")),
    ("TV", 798, N_("Tuvalu")),
    ("TW", 158, N_("Taiwan")),
    ("TZ", 834, N_("Tanzania")),
    ("UG", 800, N_("Uganda")),
    ("UA", 804, N_("Ukraine")),
    ("UM", 581, N_("United States Minor Outlying Islands")),
    ("UY", 858, N_("Uruguay")),
    ("US", 840, N_("United States")),
    ("UZ", 860, N_("Uzbekistan")),
    ("VA", 336, N_("Holy See (Vatican City State)")),
    ("VC", 670, N_("Saint Vincent and the Grenadines")),
    ("VE", 862, N_("Venezuela")),
    ("VG", 92, N_("Virgin Islands, British")),
    ("VI", 850, N_("Virgin Islands, U.S.")),
    ("VN", 704, N_("Vietnam")),
    ("VU", 548, N_("Vanuatu")),
    ("WF", 876, N_("Wallis and Futuna")),
    ("WS", 882, N_("Samoa")),
    ("YE", 887, N_("Yemen")),
    ("ZA", 710, N_("South Africa")),
    ("ZM", 894, N_("Zambia")),
    ("ZW", 716, N_("Zimbabwe")),
];

fn country((code, number, name): (&str, u32, &str)) -> Country {
    Country {
        code: code.to_owned(),
        number,
        name: name.to_owned(),
    }
}

/// By name shown, without the accents (order of the drop-down list) (`pays_tries`).
pub fn sorted() -> Vec<Country> {
    let mut all: Vec<Country> = TABLE.into_iter().map(country).collect();
    all.sort_by_cached_key(|c| {
        let label = c.label();
        (normalize(&label), label)
    });
    all
}

/// The country of an alpha-2 code (`c`), without the case (`pays_de`).
pub fn by_code(code: &str) -> Option<Country> {
    let code = code.trim().to_uppercase();
    TABLE.into_iter().find(|(c, _, _)| *c == code).map(country)
}

/// The three attributes for a country, or without a country (`countryCode` at 0, as Windows)
/// (`valeurs_pays`).
pub fn values(country: Option<&Country>) -> [(&'static str, String); 3] {
    match country {
        None => [
            ("c", String::new()),
            ("co", String::new()),
            ("countryCode", "0".to_owned()),
        ],
        Some(c) => [
            ("c", c.code.clone()),
            ("co", c.label()),
            ("countryCode", c.number.to_string()),
        ],
    }
}

/// The country the attributes read say: by `c`, else by the name (`co`) (`pays_actuel`).
pub fn current(c: &str, co: &str) -> Option<Country> {
    if let Some(country) = by_code(c) {
        return Some(country);
    }
    let name = normalize(co);
    if name.is_empty() {
        return None;
    }
    TABLE
        .into_iter()
        .map(country)
        .find(|p| name == normalize(&p.name) || name == normalize(&p.label()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countries() {
        assert_eq!(TABLE.len(), 249);
        let france = by_code(" fr ").unwrap();
        assert_eq!((france.number, france.name.as_str()), (250, "France"));
        assert_eq!(current("", "france"), Some(france.clone()));
        assert_eq!(current("FR", ""), Some(france));
        assert_eq!(current("", ""), None);
        assert_eq!(values(None)[2].1, "0");
        assert_eq!(sorted().len(), 249);
    }
}
