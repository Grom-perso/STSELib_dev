# STSELib Migration Guide

This document summarizes the naming convention changes made to STSELib and provides guidance on how to port applications using the previous version to the new version.

## Overview

All C source files (.c and .h) in STSELib have been updated to use snake_case naming convention for consistency and better readability. This affects type definitions, struct members, pointer variables, and variable names.

## Summary of Changes

### Type Definitions

| Before | After |
|--------|-------|
| `stse_ReturnCode_t` | `stse_return_code_t` |
| `stse_Handler_t` | `stse_handler_t` |

### Struct Members (stse_io_t)

| Before | After |
|--------|-------|
| `BusRecvStart` | `bus_recv_start` |
| `BusRecvContinue` | `bus_recv_continue` |
| `BusRecvStop` | `bus_recv_stop` |
| `BusSendStart` | `bus_send_start` |
| `BusSendContinue` | `bus_send_continue` |
| `BusSendStop` | `bus_send_stop` |
| `IOLineGet` | `io_line_get` |
| `BusWake` | `bus_wake` |
| `BusRecovery` | `bus_recovery` |
| `PowerLineOff` | `power_line_off` |
| `PowerLineOn` | `power_line_on` |
| `Devaddr` | `devaddr` |
| `BusSpeed` | `bus_speed` |
| `BusType` | `bus_type` |
| `busID` | `bus_id` |

### Pointer Variables

| Before | After |
|--------|-------|
| `pSTSE` | `p_stse` |
| `pStseHandler` | `p_stse_handler` |
| `pFrame` | `p_frame` |
| `pData` | `p_data` |
| `pSession` | `p_session` |
| `pBuffer` | `p_buffer` |
| `pKey` | `p_key` |
| `pSignature` | `p_signature` |
| `pCertificate` | `p_certificate` |
| `pPublic_key` | `p_public_key` |
| `pPrivate_key` | `p_private_key` |
| `pMessage` | `p_message` |
| `pDigest` | `p_digest` |
| `pNonce` | `p_nonce` |
| `pIV` | `p_iv` |
| All other `pXxx` patterns | `p_xxx` |

### Variable Names (Uppercase to Lowercase)

| Before | After |
|--------|-------|
| `IV_length` | `iv_length` |
| `Nonce_length` | `nonce_length` |
| `Message_length` | `message_length` |
| `Associated_data_length` | `associated_data_length` |
| `Partitioning_table_length` | `partitioning_table_length` |
| `Kek_session` | `kek_session` |
| `Mac_counter` | `mac_counter` |
| `Ecdhe_key_pair` | `ecdhe_key_pair` |
| `Ec_bp256r1` | `ec_bp256r1` |
| `Ec_bp384r1` | `ec_bp384r1` |
| `Ec_bp512r1` | `ec_bp512r1` |
| `Signature_R` | `signature_r` |
| `Signature_S` | `signature_s` |
| All other `Xxx_yyy` patterns | `xxx_yyy` |

## How to Port Your Application

### Step 1: Update Type Definitions

Replace all occurrences of the old type names with the new ones:

```c
// Before
stse_ReturnCode_t result;
stse_Handler_t *handler;

// After
stse_return_code_t result;
stse_handler_t *handler;
```

### Step 2: Update Pointer Variable Names

Replace pointer variable names following the new naming convention:

```c
// Before
stse_Handler_t *pSTSE;
uint8_t *pData;
stse_frame_t *pFrame;

// After
stse_handler_t *p_stse;
uint8_t *p_data;
stse_frame_t *p_frame;
```

### Step 3: Update Struct Member Access

Update all struct member accesses to use the new snake_case names:

```c
// Before
pSTSE->io.BusSendStart(pSTSE->io.busID, pSTSE->io.Devaddr, pSTSE->io.BusSpeed, length);
pSTSE->io.PowerLineOn(pSTSE->io.busID, pSTSE->io.Devaddr);

// After
p_stse->io.bus_send_start(p_stse->io.bus_id, p_stse->io.devaddr, p_stse->io.bus_speed, length);
p_stse->io.power_line_on(p_stse->io.bus_id, p_stse->io.devaddr);
```

### Step 4: Update Variable Names

Replace uppercase variable names with lowercase equivalents:

```c
// Before
uint16_t IV_length = 16;
uint16_t Nonce_length = 13;
uint32_t Message_length = 256;

// After
uint16_t iv_length = 16;
uint16_t nonce_length = 13;
uint32_t message_length = 256;
```

### Step 5: Update Function Parameters

When calling STSELib functions, ensure all parameter names match the new convention:

```c
// Before
stse_aes_ccm_encrypt(pSTSE, slot_number, Nonce_length, pNonce, 
                     Associated_data_length, pAssociated_data,
                     Message_length, pPlaintext, pCiphertext, pTag);

// After
stse_aes_ccm_encrypt(p_stse, slot_number, nonce_length, p_nonce,
                     associated_data_length, p_associated_data,
                     message_length, p_plaintext, p_ciphertext, p_tag);
```

## Using Find and Replace

For efficient migration, use the following find-and-replace patterns in your IDE or text editor:

### Regular Expression Patterns

1. **Type definitions:**
   - Find: `stse_ReturnCode_t` → Replace: `stse_return_code_t`
   - Find: `stse_Handler_t` → Replace: `stse_handler_t`

2. **Pointer variables (regex):**
   - Find: `\bpSTSE\b` → Replace: `p_stse`
   - Find: `\bpFrame\b` → Replace: `p_frame`
   - Find: `\bpData\b` → Replace: `p_data`
   - Find: `\bpSession\b` → Replace: `p_session`

3. **Struct members:**
   - Find: `\.BusSendStart` → Replace: `.bus_send_start`
   - Find: `\.BusRecvStart` → Replace: `.bus_recv_start`
   - Find: `\.PowerLineOn` → Replace: `.power_line_on`
   - Find: `\.PowerLineOff` → Replace: `.power_line_off`
   - Find: `\.busID` → Replace: `.bus_id`
   - Find: `\.Devaddr` → Replace: `.devaddr`
   - Find: `\.BusSpeed` → Replace: `.bus_speed`

4. **Variable names:**
   - Find: `\bIV_length\b` → Replace: `iv_length`
   - Find: `\bNonce_length\b` → Replace: `nonce_length`
   - Find: `\bMessage_length\b` → Replace: `message_length`

## Platform Abstraction Layer

If you have implemented custom platform functions, update the function pointer assignments:

```c
// Before
handler.io.BusSendStart = my_i2c_send_start;
handler.io.BusRecvStart = my_i2c_recv_start;
handler.io.PowerLineOn = my_power_on;
handler.io.PowerLineOff = my_power_off;

// After
handler.io.bus_send_start = my_i2c_send_start;
handler.io.bus_recv_start = my_i2c_recv_start;
handler.io.power_line_on = my_power_on;
handler.io.power_line_off = my_power_off;
```

## Verification

After making the changes:

1. **Compile your application** to identify any remaining naming issues
2. **Review compiler errors** - they will indicate any missed renames
3. **Test functionality** to ensure the application works correctly with the updated library

## Support

If you encounter issues during migration, please refer to the STSELib documentation or open an issue in the repository.
