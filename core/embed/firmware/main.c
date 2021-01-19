/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (c) SatoshiLabs
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include STM32_HAL_H

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "lib/utils/pyexec.h"
#include "py/compile.h"
#include "py/gc.h"
#include "py/mperrno.h"
#include "py/nlr.h"
#include "py/repl.h"
#include "py/runtime.h"
#include "py/stackctrl.h"

#include "ports/stm32/gccollect.h"
#include "ports/stm32/pendsv.h"

#include "blake2s.h"
#include "bl_check.h"
#include "common.h"
#include "display.h"
#include "flash.h"
#include "mpu.h"
#ifdef RDI
#include "rdi.h"
#endif
#ifdef SYSTEM_VIEW
#include "systemview.h"
#endif
#include "rng.h"
#include "sdcard.h"
#include "supervise.h"
#include "touch.h"
#include "../bootloader/messages.h"
#include "usb.h"

#define USB_IFACE_NUM 0

extern uint8_t firmware_buffer[];
uint8_t firmware_buffer[32 * 1024];

static void usb_init_all(secbool usb21_landing) {
  usb_dev_info_t dev_info = {
      .device_class = 0x00,
      .device_subclass = 0x00,
      .device_protocol = 0x00,
      .vendor_id = 0x1209,
      .product_id = 0x53C0,
      .release_num = 0x0200,
      .manufacturer = "SatoshiLabs",
      .product = "TREZOR",
      .serial_number = "000000000000000000000000",
      .interface = "TREZOR Interface",
      .usb21_enabled = sectrue,
      .usb21_landing = usb21_landing,
  };

  static uint8_t rx_buffer[USB_PACKET_SIZE];

  static const usb_webusb_info_t webusb_info = {
      .iface_num = USB_IFACE_NUM,
      .ep_in = USB_EP_DIR_IN | 0x01,
      .ep_out = USB_EP_DIR_OUT | 0x01,
      .subclass = 0,
      .protocol = 0,
      .max_packet_len = sizeof(rx_buffer),
      .rx_buffer = rx_buffer,
      .polling_interval = 1,
  };

  usb_init(&dev_info);

  ensure(usb_webusb_add(&webusb_info), NULL);

  usb_start();
}

static secbool bootloader_usb_loop(void) {
  usb_init_all(sectrue);

  uint8_t buf[USB_PACKET_SIZE];

  for (;;) {
    int r = usb_webusb_read_blocking(USB_IFACE_NUM, buf, USB_PACKET_SIZE,
                                     USB_TIMEOUT);
    if (r != USB_PACKET_SIZE) {
      continue;
    }
    uint16_t msg_id;
    uint32_t msg_size;
    if (sectrue != msg_parse_header(buf, &msg_id, &msg_size)) {
      // invalid header -> discard
      continue;
    }
    switch (msg_id) {
      case 0:  // Initialize
        process_msg_Initialize(USB_IFACE_NUM, msg_size, buf, NULL, NULL);
        break;
      case 1:  // Ping
        send_user_abort(USB_IFACE_NUM, "derp");
        break;
      case 55:  // GetFeatures
        process_msg_GetFeatures(USB_IFACE_NUM, msg_size, buf, NULL, NULL);
        break;
      default:
        process_msg_unknown(USB_IFACE_NUM, msg_size, buf);
        break;
    }
  }
  return sectrue;
}

int main(void) {
  // initialize pseudo-random number generator
  drbg_init();
#ifdef RDI
  rdi_start();
#endif

  // reinitialize HAL for Trezor One
#if TREZOR_MODEL == 1
  HAL_Init();
#endif

  collect_hw_entropy();

#ifdef SYSTEM_VIEW
  enable_systemview();
#endif

#if TREZOR_MODEL == T
#if PRODUCTION
  check_and_replace_bootloader();
#endif
  // Enable MPU
  mpu_config_firmware();
#endif

  // Init peripherals
  pendsv_init();

#if TREZOR_MODEL == 1
  display_init();
  touch_init();
#endif

#if TREZOR_MODEL == T
  sdcard_init();
  touch_init();
  touch_power_on();

  // jump to unprivileged mode
  // http://infocenter.arm.com/help/topic/com.arm.doc.dui0552a/CHDBIBGJ.html
  //__asm__ volatile("msr control, %0" ::"r"(0x1));
  //__asm__ volatile("isb");

  // for more info:
  // https://github.com/mcudev/drivers-input-touchscreen-FTS_driver/blob/master/ft5x06.c
  // https://github.com/mcudev/ft5x06-tool/blob/master/ft5x06-tool.c
  display_clear();
  display_backlight(255);
  display_printf("started firmware\n\n");
/*
  uint8_t first_read[256];
  memset(first_read, 0, 256);
  for (uint32_t row = 0; row < 16; row++) {
    display_printf("%02X ", (unsigned int) row * 16);
    for (uint32_t col = 0; col < 16; col++) {
      uint32_t result = ctpm_read_register(row * 16 + col);
      if (result > 0xff) {
        display_printf("\nbad response from ctpm\n");
        break;
      }
      first_read[row * 16 + col] = (uint8_t) result;
      display_printf("%02X", (unsigned int) result);
      if (col == 7) {
        display_printf(" ");
      }
    }
    display_printf("\n");
  }
  display_printf("\n");
*/
  uint8_t buffer[256];
  memset(buffer, 0, 256);
  if(1 == ctpm_read_all(0, buffer, 256)) {
    for (uint32_t row = 0; row < 16; row++) {
      display_printf("%02X ", (unsigned int) row * 16);
      for (uint32_t col = 0; col < 16; col++) {
        display_printf("%02X", (unsigned int) buffer[row * 16 + col]);
        if (col == 7) {
          display_printf(" ");
        }
      }
      display_printf("\n");
    }
  } else {
    display_printf("bad response from ctpm\n");
  }
/*
  if (0 == memcmp(first_read, buffer, 256)) {
    display_printf("reads matched\n");
  } else {
    display_printf("reads did not match\n");
  }
*/
  if (buffer[0xa3] == 0x36) {
    display_printf("found chip device id for FT6X36_ID\n");
    if (buffer[0x00] == 0) {
      display_printf("device in work mode\n");
    }
    display_printf("firmware version %d.%d.%d\n", buffer[0xa6], buffer[0xb2], buffer[0xb3]);
    display_printf("firmware vendor id 0x%02X\n", buffer[0xa8]);
    display_printf("firmware library version %d.%d\n", buffer[0xa1], buffer[0xa2]);
    display_printf("release code version %d\n", buffer[0xaf]);
    display_printf("current operating mode %02X\n", buffer[0xbc]);

    for(uint32_t try_again = 1; try_again <= 30; try_again++) {
      // reset the ctpm
      ctpm_write_register(0xbc, 0xaa);
      HAL_Delay(50);
      ctpm_write_register(0xbc, 0x55);
      HAL_Delay(50);
      // enter upgrade mode
      uint8_t write_buffer [] = { 0x55, 0xaa };
      ctpm_write(write_buffer, 2);
      HAL_Delay(50);
      // check READ_ID register
      uint8_t read_id[4] = { 0x90, 0, 0, 0 };
      uint8_t read_id_result[2] = { 0, 0 };
      ctpm_read(read_id, 4, read_id_result, 2);
      if ((read_id_result[0] == 0x79) && (read_id_result[1] == 0x18)) {
        display_printf("entered ctpm upgrade mode\ncopying firmware");
        // the FT6236 MCU has a 32KiB flash memory
        // valid firmwares have:
        // a length between 288 and 32768 bytes
        // the first byte equaling 0x02
        // the length of the firmware is stored in bytes 0x100 and 0x101 of the firmware itself fw_length = ((uint32_t) buffer[0x100]<<8) + buffer[0x101]
        memset(firmware_buffer, 0, 32 * 1024);
        // read the ctpm firmware from the FT6236 MCU's flash memory
        for (uint32_t index = 0; index < 32 * 1024; index += 256) {
          uint8_t temp_read_buffer[256];
          memset(temp_read_buffer, 0, 256);
          display_printf(".");
          HAL_Delay(10);
          uint8_t command_buffer[] = { 0x03, 0, (uint8_t) (index >> 8), (uint8_t) index };
          ctpm_read(command_buffer, 4, temp_read_buffer, 256);
          memcpy(firmware_buffer + index, temp_read_buffer, 256);
        }
        display_printf("\ndone reading ctpm firmware\n");
        if (firmware_buffer[0] == 0x02) {
          const uint32_t firmware_length = ((uint32_t) firmware_buffer[0x100] << 8) + firmware_buffer[0x101];
          if ((firmware_length >= 288) && (firmware_length <= 32768)) {
            // not sure these following correct. wish i had a better way to verify. these are based on looking at the code referenced above in the links.
            display_printf("valid firmware found\n  size %d\n  major version %d\n  vendor id %02X\n", (int) firmware_length, (int) firmware_buffer[0x10a], (unsigned int) firmware_buffer[0x108]);
            if (((firmware_buffer[0x104] ^ firmware_buffer[0x105]) == 0xff) && ((firmware_buffer[0x106] ^ firmware_buffer[0x107]) == 0xff)) {
              display_printf("further check passed\n");
            }
            uint8_t computed_checksum = 0;
            for (uint32_t i = 0; i < firmware_length; i++) {
              computed_checksum ^= firmware_buffer[i];
            }
            display_printf("computed_checksum %02X\n", (unsigned int) computed_checksum);
            uint8_t h[32];
            blake2s(firmware_buffer, 32 * 1024, h, 32); // openssl dgst -blake2s256
            static const char* hexdigits = "0123456789abcdef";
            uint8_t h_str[32 * 2 + 1];
            h_str[64] = 0;
            for (uint32_t i = 0; i < 32; i++) {
              h_str[i * 2] = hexdigits[(h[i] >> 4) & 0xF];
              h_str[i * 2 + 1] = hexdigits[h[i] & 0xF];
            }
            display_printf("blake2s hash\n%s\n", h_str);
            bootloader_usb_loop();
          }
        }
        // done, reset the ctpm
        uint8_t reset_buffer[] = { 0x07 };
        ctpm_write(reset_buffer, 1);
        HAL_Delay(400);
        break;
      } else {
        display_printf("try %d failed read id check %02X %02X\n", (int) try_again, (unsigned int) read_id_result[0], (unsigned int) read_id_result[1]);
      }
    }
  }
#endif
  return 0;
}

// MicroPython default exception handler

void __attribute__((noreturn)) nlr_jump_fail(void *val) {
  error_shutdown("Internal error", "(UE)", NULL, NULL);
}

// interrupt handlers

void NMI_Handler(void) {
  // Clock Security System triggered NMI
  if ((RCC->CIR & RCC_CIR_CSSF) != 0) {
    error_shutdown("Internal error", "(CS)", NULL, NULL);
  }
}

void HardFault_Handler(void) {
  error_shutdown("Internal error", "(HF)", NULL, NULL);
}

void MemManage_Handler(void) {
  error_shutdown("Internal error", "(MM)", NULL, NULL);
}

void BusFault_Handler(void) {
  error_shutdown("Internal error", "(BF)", NULL, NULL);
}

void UsageFault_Handler(void) {
  error_shutdown("Internal error", "(UF)", NULL, NULL);
}

void SVC_C_Handler(uint32_t *stack) {
  uint8_t svc_number = ((uint8_t *)stack[6])[-2];
  switch (svc_number) {
    case SVC_ENABLE_IRQ:
      HAL_NVIC_EnableIRQ(stack[0]);
      break;
    case SVC_DISABLE_IRQ:
      HAL_NVIC_DisableIRQ(stack[0]);
      break;
    case SVC_SET_PRIORITY:
      NVIC_SetPriority(stack[0], stack[1]);
      break;
#ifdef SYSTEM_VIEW
    case SVC_GET_DWT_CYCCNT:
      cyccnt_cycles = *DWT_CYCCNT_ADDR;
      break;
#endif
    default:
      stack[0] = 0xffffffff;
      break;
  }
}

__attribute__((naked)) void SVC_Handler(void) {
  __asm volatile(
      " tst lr, #4    \n"    // Test Bit 3 to see which stack pointer we should
                             // use.
      " ite eq        \n"    // Tell the assembler that the nest 2 instructions
                             // are if-then-else
      " mrseq r0, msp \n"    // Make R0 point to main stack pointer
      " mrsne r0, psp \n"    // Make R0 point to process stack pointer
      " b SVC_C_Handler \n"  // Off to C land
  );
}

// MicroPython builtin stubs

mp_import_stat_t mp_import_stat(const char *path) {
  return MP_IMPORT_STAT_NO_EXIST;
}

mp_obj_t mp_builtin_open(uint n_args, const mp_obj_t *args, mp_map_t *kwargs) {
  return mp_const_none;
}
MP_DEFINE_CONST_FUN_OBJ_KW(mp_builtin_open_obj, 1, mp_builtin_open);
