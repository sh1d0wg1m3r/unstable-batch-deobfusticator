
# Unstable Batch Deobfusticator

![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [License](#license)
- [Acknowledgements](#acknowledgements)

## Introduction

**Testing Batch Deobfusticator** is my custom Python tool designed to deobfuscate batch scripts that have been obfuscated using string substitution and escape character techniques. This project is directly inspired by [DissectMalware's batch_deobfuscator](https://github.com/DissectMalware/batch_deobfuscator).

While refining and enhancing the original script, I incorporated several optimizations to improve its efficiency and usability. Enjoy using this tool! Although the original version by DissectMalware is a bit more rudimentary, I highly respect their contribution to the open-source community and have given them a star for their excellent work.

## Features

- **String Substitution Deobfuscation:** Resolves variables and string manipulations to reveal the original commands.
- **Escape Character Handling:** Processes escape characters to accurately interpret obfuscated scripts.
- **PowerShell Command Interpretation:** Detects and decodes encoded PowerShell commands within batch scripts.
- **Command Extraction:** Identifies and extracts embedded commands and scripts for further analysis.
- **CPU Configuration Report:** Generates a simulated CPU configuration report to emulate a believable environment.
- **Logging:** Comprehensive logging to track the deobfuscation process and any issues encountered.
- **Interactive Mode:** Allows users to input single obfuscated commands for on-the-fly interpretation.

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/sh1d0wg1mer/testing-batch-deobfusticator.git
   cd testing-batch-deobfusticator
   ```

2. **Install Dependencies:**

   Ensure you have Python 3.6 or higher installed. Install the required Python packages using pip:

   ```bash
   pip install -r requirements.txt
   ```

   *If `requirements.txt` is not provided, you can install the necessary packages individually:*

   ```bash
   pip install argparse base64 logging
   ```

## Usage

### Deobfuscate a Batch Script

To deobfuscate an entire batch script, use the following command:

```bash
python unobfusticator.py --file path/to/obfuscated_file.bat --outdir output_directory
```

**Parameters:**

- `--file` or `-f`: Path to the obfuscated batch file.
- `--outdir` or `-o` (optional): Directory to store deobfuscated files. Defaults to `output`.

**Example:**

```bash
python unobfusticator.py --file ./scripts/obfuscated.bat --outdir ./deobfuscated_output
```

### Interactive Mode

If you prefer to interpret a single obfuscated command interactively, simply run:

```bash
python unobfusticator.py
```

You will be prompted to enter the obfuscated batch command:

```
Please enter an obfuscated batch command:
```

**Example Input:**

```
%~dp0^&echo Hello World
```

**Example Output:**

```
Normalized Command:
C:\Path\To\Script&echo Hello World
```

## Contributing

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or submit a pull request.

1. **Fork the Repository**
2. **Create a Feature Branch**

   ```bash
   git checkout -b feature/YourFeature
   ```

3. **Commit Your Changes**

   ```bash
   git commit -m "Add some feature"
   ```

4. **Push to the Branch**

   ```bash
   git push origin feature/YourFeature
   ```

5. **Open a Pull Request**

## License

This project is licensed under the [MIT License](LICENSE). You are free to use, modify, and distribute this software as per the terms of the license.

## Acknowledgements

- **DissectMalware:** A big thank you to [DissectMalware](https://github.com/DissectMalware) for creating the original [batch_deobfuscator](https://github.com/DissectMalware/batch_deobfuscator). Your work inspired this project, and I appreciate your efforts in contributing to the open-source community. A star has been added to your repository for your excellent work.
- **Open Source Community:** For providing invaluable resources and support that make projects like this possible.

---

Feel free to reach out on GitHub if you have any questions or feedback!
p.s lokxo stole a 
