/***************************************************************************
 *   Copyright (C) 2013 Franck Jullien                                     *
 *   elec4fun@gmail.com                                                    *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>. *
 ***************************************************************************/

#ifndef OPENOCD_TARGET_RISCV_RV_DU_H
#define OPENOCD_TARGET_RISCV_RV_DU_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#define CPU_STALL	0
#define CPU_UNSTALL	1

#define CPU_RESET	0
#define CPU_NOT_RESET	1

int rv_du_adv_register(void);

/* Linear list over all available rv debug unit */
extern struct list_head du_list;

struct rv_du {
	const char *name;
	struct list_head list;
	int options;

	int (*rv_jtag_init)(struct rv_jtag *jtag_info);

	int (*rv_is_cpu_running)(struct rv_jtag *jtag_info, int *running);

	int (*rv_cpu_stall)(struct rv_jtag *jtag_info, int action);

	int (*rv_cpu_reset)(struct rv_jtag *jtag_info, int action);

	int (*rv_jtag_read_cpu)(struct rv_jtag *jtag_info,
				  uint32_t addr, int count, uint32_t *value);

	int (*rv_jtag_write_cpu)(struct rv_jtag *jtag_info,
				   uint32_t addr, int count, const uint32_t *value);

	int (*rv_jtag_read_memory)(struct rv_jtag *jtag_info, uint32_t addr, uint32_t size,
					int count, uint8_t *buffer);

	int (*rv_jtag_write_memory)(struct rv_jtag *jtag_info, uint32_t addr, uint32_t size,
					 int count, const uint8_t *buffer);
};

static inline struct rv_du *rv_jtag_to_du(struct rv_jtag *jtag_info)
{
	return (struct rv_du *)jtag_info->du_core;
}

static inline struct rv_du *rv_to_du(struct rv_state *rv)
{
	struct rv_jtag *jtag = &rv->jtag;
	return (struct rv_du *)jtag->du_core;
}

int rv_adv_jtag_jsp_xfer(struct rv_jtag *jtag_info,
				  int *out_len, unsigned char *out_buffer,
				  int *in_len, unsigned char *in_buffer);


#endif /* OPENOCD_TARGET_RISCV_RV_DU_H */
