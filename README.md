# STMicroelectronics Secure Element Library (STSELib)

![STSELib](doc/resources/Pictures/STSELib.png)

The STSELib middleware provides a complete set of high-level Application Programming Interface (API) functions for embedded system developers. This middleware abstracts the construction and sequencing of commands required to ensure device, accessory, and consumable brand protection using STMicroelectronics' STSAFE-A secure element family.

This middleware enables seamless integration of one or multiple STSAFE-A secure elements in various host MCU/MPU ecosystems.

## Architecture

The STSELib middleware is composed of three software modules as illustrated in the figure below. Each layer provides a different level of system abstraction to the embedded system developer.

![STSELib Architecture](doc/resources/Pictures/STSELib_arch.png)

### Software Layers

**Application Programming Interface (API) Layer**  
This software layer is the entry point for the system application. It provides a set of high-level functions allowing interaction with STMicroelectronics Secure Elements.

**Service Layer**  
Provides a set of product services that format all commands supported by the targeted secure element and reports responses to higher layers (API/Application). This layer can be used directly from the application (for advanced users).

**Core Layer**  
Contains generic definitions for ST Secure Elements and functions for communicating with the target secure element.

## Documentation

Complete HTML documentation can be:
- Downloaded as a standalone package from the STSELib GitHub repository [release section](https://github.com/STMicroelectronics/STSELib/releases)
- Compiled from the library sources by executing the following commands from the STSELib root directory:

```bash
cd Middleware/STSELib/doc/resources/
doxygen STSELib.doxyfile
```

> [!NOTE]
> Doxygen version 1.14.0 is required to build the documentation  

## Quick Start

### 1. Add STSELib as a Git Submodule

From your project root directory:

```bash
git submodule add https://github.com/STMicroelectronics/STSELib.git lib/stselib
git submodule update --init --recursive
```

> [!NOTE]
>
> Remember to add `lib/stselib` to your CMakeLists.txt include paths.

### 2. Required Configuration Files

Two header files are mandatory:
- [`stse_conf.h`](doc/resources/Markdown/03_LIBRARY_CONFIGURATION/03_LIBRARY_CONFIGURATION.md) - Library configuration
- [`stse_platform_generic.h`](doc/resources/Markdown/04_PORTING_GUIDE/PAL_files/stse_platform_generic.h.md) - Platform abstraction layer

### 3. Platform-Specific Implementation

For platform-specific integrations and STSafe use cases, you may need to implement additional platform abstraction layer (PAL) functions. Detailed specifications are available in:
- The [Porting Guide](doc/resources/Markdown/04_PORTING_GUIDE/03_PORTING_GUIDE.md)
- The HTML documentation included in the release package

Reference implementations for common STSE use cases can be found in the "Reference Examples" section below.

## Reference Examples

The following reference projects demonstrate STSELib integration and usage:

### STSAFE-A Examples
- [STSAFE-A120 Examples](https://github.com/STMicroelectronics/STSAFE-A120_examples) - Comprehensive examples for STSAFE-A120

### STSAFE-L Examples
- [STSAFE-L Echo](https://github.com/STMicroelectronics/STSAFE-L_echo) - Basic communication example
- [STSAFE-L Device Authentication](https://github.com/STMicroelectronics/STSAFE-L_device_authentication) - Device authentication implementation
- [STSAFE-L Secure Data Storage](https://github.com/STMicroelectronics/STSAFE-L_secure_data_storage) - Secure data storage use case
