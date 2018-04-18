/***************************************************************************
 *   Copyright (C) 2011 by Julius Baxter                                   *
 *   julius@opencores.org                                                  *
 *                                                                         *
 *   Copyright (C) 2013 by Marek Czerski                                   *
 *   ma.czerski@gmail.com                                                  *
 *                                                                         *
 *   Copyright (C) 2013 by Franck Jullien                                  *
 *   elec4fun@gmail.com                                                    *
 *                                                                         *
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

#ifndef OPENOCD_TARGET_RISCV_RV_H
#define OPENOCD_TARGET_RISCV_RV_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <target/target.h>

/* RV registers */
#include "rv_gdb_regs.h"

#define NO_SINGLE_STEP		0
#define SINGLE_STEP		1

#define RV_COREREGSCOUNT GDB_REGNO_FPR31 + 1
#define RV_ALLREGSCOUNT GDB_REGNO_COUNT + 1

#define RV_TSELECT GDB_REGNO_TSELECT
#define RV_TDATA1 GDB_REGNO_TDATA1
#define RV_TDATA2 GDB_REGNO_TDATA2
#define RV_DEBUGREGSCOUNT 3

#define RV_TDATA1_MASK 1
#define RV_TDATA2_MASK 2
#define RV_STEP_MASK 0x00000100

enum debug_regs {
    RV_TSELECT_IDX = 0,
    RV_TDATA1_IDX,
    RV_TDATA2_IDX
};

#define RV_MAX_BREAKPOINTS 2


struct rv_jtag {
	struct jtag_tap *tap;
	int rv_jtag_inited;
	int rv_jtag_module_selected;
	uint8_t *current_reg_idx;
	struct rv_tap_ip *tap_ip;
	struct rv_du *du_core;
    struct target * target;
};

struct rv_breakpoints {
    uint8_t status[4];
    uint32_t address[2];
    uint8_t num;
};

struct rv_state {
	struct rv_jtag jtag;
    struct target *target;
    struct reg_cache * core_cache;
    uint32_t core_regs[RV_COREREGSCOUNT];
    struct rv_breakpoints breakpoints;
};

static inline struct rv_state *
target_to_rv(struct target *target)
{
	return (struct rv_state *)target->arch_info;
}


#endif /* OPENOCD_TARGET_RISCV_RV_H */
