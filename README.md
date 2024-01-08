# Re-Importer Tool

## Overview

The Re-Importer tool is designed to facilitate the importing of csv files generated from AWS Resource Explorer into Terraform configuration. It reads an exported CSV file from the AWS resource explorer and a JSON mapping file (optional) to generate Terraform import commands.

## Motivation
It is allways a pain trying to get existing infrastructure to terraform configuration. Tools like ```terraform import``` kind of work with spare peaces of infrastructure you want to bring to the terraform config, but when we talk about bringing an entire existing infrastructure, to terraform, we better use

## Features

- Parses CSV files exported from AWS Resource Explorer.
- Utilizes an optional JSON mapping file for AWS to Terraform resource type conversion.
- Generates a Terraform import file with formatted import commands.

## Requirements

- Rust
- Cargo (Rust's package manager)

## Installation

Clone the repository and build the project:

```bash
git clone [Your Repository URL]
cd re_importer
cargo build --release
```
## Usage
```bash
cargo run -- --csv-file <path-to-csv> [--resource-map <path-to-json>] [--output-file <path-to-output-file>]
```
## Arguments
* ``` --csv-file: Path to the CSV file exported from AWS Resource Explorer.```
* ```--resource-map: (Optional) Path to the JSON file with AWS to Terraform resource type mappings. If not provided, a default mapping is used.```
* ```--output-file: (Optional) Path to the output Terraform import file. Defaults to ./imports.tf.```
* ```--help: Displays usage information```

## License
* I never knew how to include a licence

## Author
