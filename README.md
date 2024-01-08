# Re-Importer Tool

## Overview

The Re-Importer tool is designed to facilitate the importing of csv files generated from AWS Resource Explorer into Terraform configuration. It reads an exported CSV file from the AWS resource explorer and a JSON mapping file (optional) to generate Terraform import commands.

## Motivation
It is allways a pain trying to get existing infrastructure to terraform configuration. Tools like ```terraform import``` kind of work with spare peaces of infrastructure you want to bring to the terraform config, but when we talk about bringing an entire existing infrastructure, to terraform, we better use import blocks.

To do it so, we need to create a set of import blocks like this:
```hcl
import {
  id = "igw-03d2807461dc08e60"
  to = aws_internet_gateway.igw-03d2807461dc08e60
}
```
And run the terraform experimental config generation:
```bash
terraform plan -generate-config-out=generated.tf 
``` 
This experimental feature works farly well, and i think we all hope to get improved inthe future, however, this still left us witht the manual task of create the import blocks for this feature to work. 

So since im not by any means AWS guru, or Terraform Master or any sort of expert, i created this small tool to help me parse AWS information and generate the import blocks.

The central point is the map from terraform AWS provider resourses to Resourse Explorer "Resource Type" field in the exported CVS file. I didn't find any good source of this translations, so i made one based [Alistair Mackay's](https://github.com/fireflycons) [PSCloudFormation](https://github.com/fireflycons/PSCloudFormation/blob/master/src/Firefly.PSCloudFormation/Resources/terraform-resource-map.json), so credit to him. Since AWS for an unknown reason decided that "Resource Type" column is not using the standar Resource types, so many of them are missing and others needs to be updated, so i've included the avility to pass a json map to replace the included one.

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


## Author
[Tadeo Armenta](https://github.com/cgtarmenta)

[HomePage](https://tadeoarmenta.com)