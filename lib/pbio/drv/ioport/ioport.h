// SPDX-License-Identifier: MIT
// Copyright (c) 2023 The Pybricks Authors

#ifndef _INTERNAL_PBDRV_IOPORT_H
#define _INTERNAL_PBDRV_IOPORT_H

#include <pbdrv/config.h>
#include <stdbool.h>

#if PBDRV_CONFIG_IOPORT

void pbdrv_ioport_init(void);

/**
 * Enables or disables VCC on pin 4 of all ioports.
 *
 * @param [in]  enable        Whether to enable or disable power.
 */
void pbdrv_ioport_enable_vcc(bool enable);

void pbdrv_ioport_deinit(void);

#else // PBDRV_CONFIG_IOPORT

static inline void pbdrv_ioport_init(void) {
}

static inline void pbdrv_ioport_enable_vcc(bool enable) {
}

static inline void pbdrv_ioport_deinit(void) {
}

#endif // PBDRV_CONFIG_IOPORT

#endif // _INTERNAL_PBDRV_IOPORT_H
