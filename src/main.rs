use clap::Parser;
use colored::Colorize;
use regex::Regex;
use std::io::{self, BufRead};
use std::iter::FlatMap;
use std::str::Split;

struct Row {
    key: String,
    values: Vec<Value>,
}

#[derive(Debug)]
enum ValueType {
    Error,
    Safe,
    UnSafe,
    Plain,
}

struct Value {
    text: String,
    value_type: ValueType,
}

impl Value {
    fn from(text: &str) -> Value {
        Value {
            text: text.to_string(),
            value_type: Value::classify(text),
        }
    }

    fn classify(value: &str) -> ValueType {
        match value {
            "'self'" => ValueType::Safe,
            "'none'" => ValueType::Safe,
            "'unsafe-inline'" => ValueType::UnSafe,
            "'unsafe-eval'" => ValueType::UnSafe,
            // It is probably safe to use `data:` in images
            // but better be safe then sorry.
            // See: https://security.stackexchange.com/questions/94993/is-including-the-data-scheme-in-your-content-security-policy-safe/167244
            "data:" => ValueType::UnSafe,
            _ => match Value::is_url(value) {
                true => ValueType::Plain,
                _ => ValueType::Error,
            },
        }
    }

    fn is_url(value: &str) -> bool {
        let re = Regex::new(r"(https?://)?(\w+\.)+(\w)+").unwrap();
        re.is_match(value)
    }

    fn pretty(&self) -> String {
        match &self.value_type {
            ValueType::Error => self.text.black().on_red().to_string(),
            ValueType::UnSafe => self.text.red().to_string(),
            ValueType::Plain => self.text.normal().to_string(),
            ValueType::Safe => self.text.green().to_string(),
        }
    }
}

impl Row {
    fn from(line: &str) -> Option<Row> {
        let parts: Vec<_> = line.split_whitespace().collect();
        if parts.len() < 2 {
            return None;
        }
        let key = parts[0].to_string();
        let values: Vec<_> = parts[1..].iter().map(|s| Value::from(s)).collect();
        Some(Row { key, values })
    }

    fn to_colored_string(&self, separator: &str) -> String {
        format!(
            "{}{}{}",
            self.key.blue(),
            separator,
            self.values
                .iter()
                .map(|value| value.pretty())
                .collect::<Vec<_>>()
                .join(separator)
        )
    }
}

#[derive(Parser, Debug)]
#[clap(version, about, long_about = None)]
struct Args {
    /// Show one source per line
    #[clap(short, long)]
    multiline: bool,
}

fn main() {
    let args = Args::parse();

    let input = io::stdin();
    for line in input.lock().lines() {
        println!("{}", handle_line(&line.unwrap(), args.multiline));
    }
}

fn pretty_print(input: &str, multi_line: bool) -> String {
    let separator = if multi_line { "\n\t" } else { " " };
    let parts: Split<_> = input.split(';');
    let rows: FlatMap<_, _, _> = parts.flat_map(Row::from);
    rows.map(|row| row.to_colored_string(separator))
        .collect::<Vec<_>>()
        .join(";\n")
}

fn handle_line(input: &str, multi_line: bool) -> String {
    let normalised_input = input.to_lowercase();
    let values = normalised_input.split("content-security-policy:").nth(1);
    match values {
        None => pretty_print(input, multi_line),
        Some(value) => pretty_print(value, multi_line),
    }
}

#[cfg(test)]
mod tests {
    use crate::{handle_line, pretty_print, Value, ValueType};

    #[test]
    fn setup() {
        // Disable coloring for all tests. This makes it easier
        // to compare the output since there will be no escape
        // codes for the colors. Really, this should be in some
        // kind of `beforeAll` function though.
        colored::control::set_override(false);
    }

    #[test]
    fn it_returns_empty_for_empty_string() {
        let result = pretty_print(&String::from(""), false);
        assert_eq!(result, "");
    }

    #[test]
    fn it_adds_newlines() {
        let input = String::from("default-src 'self'; img-src https://*; child-src 'none';");
        let result = pretty_print(&input, false);
        let expected_value = "default-src 'self';\nimg-src https://*;\nchild-src 'none'";
        assert_eq!(result, expected_value);
    }

    // Examples taken from MDN: https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP
    #[test]
    fn it_extracts_from_header() {
        colored::control::set_override(false);
        let input = String::from("Content-Security-Policy: default-src 'self'");
        let result = handle_line(&input, false);
        let expected_value = "default-src 'self'";
        assert_eq!(result, expected_value);
    }

    #[test]
    fn it_extracts_from_header_example_2() {
        let input =
            String::from("Content-Security-Policy: default-src 'self' trusted.com *.trusted.com");
        let result = handle_line(&input, false);
        let expected_value = "default-src 'self' trusted.com *.trusted.com";
        assert_eq!(result, expected_value);
    }

    #[test]
    fn it_extracts_from_header_example_3() {
        let input = String::from("Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com");
        let result = handle_line(&input, false);
        let expected_value = "default-src 'self';\nimg-src *;\nmedia-src media1.com media2.com;\nscript-src userscripts.example.com";
        assert_eq!(result, expected_value);
    }

    #[test]
    fn it_extracts_from_header_example_3_with_multiline() {
        let input = String::from("Content-Security-Policy: default-src 'self'; img-src *; media-src media1.com media2.com; script-src userscripts.example.com");
        let result = handle_line(&input, true);
        let expected_value = "default-src\n\t'self';\nimg-src\n\t*;\nmedia-src\n\tmedia1.com\n\tmedia2.com;\nscript-src\n\tuserscripts.example.com";
        assert_eq!(result, expected_value);
    }

    #[test]
    fn value_classifies_unsafe_inline() {
        let value = Value::from("'unsafe-inline'");
        assert!(matches!(value.value_type, ValueType::UnSafe));
    }

    #[test]
    fn value_classifies_unknown_prop() {
        let value = Value::from("'unsafe-foobar'");
        assert!(matches!(value.value_type, ValueType::Error));
    }

    #[test]
    fn value_classifies_proper_url() {
        let value = Value::from("'https://foo.bar'");
        assert!(matches!(value.value_type, ValueType::Plain));
    }

    #[test]
    fn value_classifies_invalid_url() {
        let value = Value::from("'https://foo'");
        assert!(matches!(value.value_type, ValueType::Error));
    }
}
