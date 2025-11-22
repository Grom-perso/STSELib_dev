# STSELib Documentation

This directory contains the markdown documentation for STSELib. 

## Documentation Structure

The documentation is organized into the following sections:

### Core Documentation
- **Introduction** (`00_introduction.md`) - Overview of the STSELib middleware, architecture, and software layers
- **Software License** (`01_SOFTWARE LICENSE/`) - License information
- **Release Notes** (`02_RELEASE_NOTE/`) - Version history and changelog

### Configuration and Integration
- **Library Configuration** (`03_LIBRARY_CONFIGURATION/`) - Configuration parameters and settings guide
- **Porting Guide** (`04_PORTING_GUIDE/`) - Platform adaptation and PAL implementation guidelines

## Quick Navigation

- **[Documentation Index](INDEX.md)** - Complete index of all documentation files
- **[Main README](../../../README.md)** - Quick start guide and integration instructions

## Building HTML Documentation

To build the complete HTML documentation from source:

```bash
cd doc/resources/
doxygen STSELib.doxyfile
```

> **Note**: Doxygen version 1.14.0 is required

## Contributing to Documentation

When updating documentation:
- Follow the existing markdown formatting conventions
- Use consistent heading styles (## for main sections, ### for subsections)
- Include code examples where appropriate
- Update the INDEX.md file if adding new documents
- Ensure all internal links are correct

For more information on contributing, see [CONTRIBUTING.md](../../../CONTRIBUTING.md).
