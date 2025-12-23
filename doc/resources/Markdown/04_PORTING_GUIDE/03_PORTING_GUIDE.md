# Porting Guidelines

This section of the documentation provides a comprehensive description of the STSELib Platform Abstraction Layer (PAL), along with detailed guidance on the process to adapt the library to a specific host platform, whether it be a microcontroller or a microprocessor. The goal of these guidelines is to ensure a smooth and efficient porting process, enabling developers to leverage the capabilities of STSELib across various hardware platforms with minimal effort.

## Overview of STSELib Platform Abstraction

The STSELib Platform Abstraction Layer is designed to provide a consistent and high-level interface to the underlying hardware, abstracting away platform-specific details. This abstraction allows developers to write application code that is portable and reusable across different platforms. The PAL includes a set of APIs that facilitate interaction with common hardware features such as:
- Cryptographic library functions
- GPIO and power management
- Timers and delays
- Communication interfaces (I2C, ST1Wire)

![STSELib_PLAT](../Pictures/STSELib_PAL.png)


The STSELib embeds a platform abstraction header (stse_platform.h) listing all functions to be implemented by the application developer to adapt the library to a specific host microcontroller/microprocessor and toolchain.

This Platform Abstraction Layer decouples the STSELibrary Middleware from the underlying hardware and the toolchain used by the embedded system developers.


![PAL_integration](../Pictures/PAL_integration.png)

## Identifying Platform Abstraction Functions to Implement

To assist developers in identifying the callback functions to be developed and simplify the porting process, it is recommended to use an `stse_conf.h` file that activates only the configuration parameters required by the end application (see [Library Configuration](../03_LIBRARY_CONFIGURATION/03_LIBRARY_CONFIGURATION.md) section). By doing this, advanced IDEs such as STM32Cube IDE will highlight which platform functions need to be ported. Below is an extract of the platform configuration:

![PAL_pre_proc](../Pictures/PAL_pre_proc.png)


By enabling only the necessary configuration parameters, developers can focus on implementing the required platform-specific functions, ensuring a streamlined and efficient porting process.


## Platform Files Description

The following platform file architecture is recommended to simplify the porting of the library:

- @subpage stse_platform_generic
- @subpage stse_platform_delay
- @subpage stse_platform_crypto_init
- @subpage stse_platform_aes
- @subpage stse_platform_crc
- @subpage stse_platform_ecc
- @subpage stse_platform_hash
- @subpage stse_platform_random
- @subpage stse_platform_power
- @subpage stse_platform_i2c
- @subpage stse_platform_st1wire
