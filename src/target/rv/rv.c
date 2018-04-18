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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <jtag/jtag.h>
#include <target/register.h>
#include <target/target.h>
#include <target/breakpoints.h>
#include <target/target_type.h>
#include <helper/time_support.h>
#include <helper/fileio.h>
#include "rv_tap.h"
#include "rv.h"
#include "rv_du.h"

LIST_HEAD(tap_list);
LIST_HEAD(du_list);

const char *gdb_regno_name(enum gdb_regno regno)
{
	static char buf[32];

	switch (regno) {
		case GDB_REGNO_ZERO:
			return "zero";
		case GDB_REGNO_S0:
			return "s0";
		case GDB_REGNO_S1:
			return "s1";
		case GDB_REGNO_PC:
			return "pc";
		case GDB_REGNO_FPR0:
			return "fpr0";
		case GDB_REGNO_FPR31:
			return "fpr31";
		case GDB_REGNO_CSR0:
			return "csr0";
		case GDB_REGNO_TSELECT:
			return "tselect";
		case GDB_REGNO_TDATA1:
			return "tdata1";
		case GDB_REGNO_TDATA2:
			return "tdata2";
		case GDB_REGNO_MISA:
			return "misa";
		case GDB_REGNO_DPC:
			return "dpc";
		case GDB_REGNO_DCSR:
			return "dcsr";
		case GDB_REGNO_DSCRATCH:
			return "dscratch";
		case GDB_REGNO_MSTATUS:
			return "mstatus";
		case GDB_REGNO_NPC:
			return "npc";
		case GDB_REGNO_PPC:
			return "ppc";
		case GDB_REGNO_PRIV:
			return "priv";
		default:
			if (regno <= GDB_REGNO_XPR31)
				sprintf(buf, "x%d", regno - GDB_REGNO_ZERO);
			else if (regno >= GDB_REGNO_CSR0 && regno <= GDB_REGNO_CSR4095)
				sprintf(buf, "csr%d", regno - GDB_REGNO_CSR0);
			else if (regno >= GDB_REGNO_FPR0 && regno <= GDB_REGNO_FPR31)
				sprintf(buf, "f%d", regno - GDB_REGNO_FPR0);
			else
				sprintf(buf, "gdb_regno_%d", regno);
			return buf;
	}
}

static int rv_remove_breakpoint(struct target *target,
				  struct breakpoint *breakpoint);

static int rv_read_core_reg(struct target *target, int num);
static int rv_write_core_reg(struct target *target, int num);

static int rv_jtag_read_regs(struct rv_state *rv, uint32_t *regs)
{
	struct rv_du *du_core = rv_jtag_to_du(&rv->jtag);
	LOG_DEBUG("-");
	return du_core->rv_jtag_read_cpu(&rv->jtag, 0, RV_COREREGSCOUNT, regs);
}

static int rv_jtag_write_regs(struct rv_state *rv, uint32_t *regs)
{
	struct rv_du *du_core = rv_jtag_to_du(&rv->jtag);
	LOG_DEBUG("-");
	return du_core->rv_jtag_write_cpu(&rv->jtag, 0, RV_COREREGSCOUNT, regs);
}

static int rv_save_context(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
	int regs_read = 0;
	int retval;

	LOG_DEBUG("-");

	for (int i = 0; i < RV_COREREGSCOUNT; i++) {
		if (!rv->core_cache->reg_list[i].valid) {
			if (i == GDB_REGNO_PC) {
		        retval = du_core->rv_jtag_read_cpu(&rv->jtag, i, 1, &rv->core_regs[i]);
				if (retval != ERROR_OK)
					return retval;
			} else if (!regs_read) {
				/* read gpr registers at once (but only one time in this loop) */
				retval = rv_jtag_read_regs(rv, rv->core_regs);
				if (retval != ERROR_OK)
					return retval;
				/* prevent next reads in this loop */
				regs_read = 1;
			}
			/* We've just updated the core_reg[i], now update
			   the core cache */
			rv_read_core_reg(target, i);
		}
	}

	return ERROR_OK;
}

static int rv_restore_context(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
	int reg_write = 0;
	int retval;

	LOG_DEBUG("-");

	for (int i = 0; i < RV_COREREGSCOUNT; i++) {
		if (rv->core_cache->reg_list[i].dirty) {
			rv_write_core_reg(target, i);

			if (i == GDB_REGNO_PC) {
		        retval = du_core->rv_jtag_write_cpu(&rv->jtag, i, 1, &rv->core_regs[i]);
				if (retval != ERROR_OK) {
					LOG_ERROR("Error while restoring context");
					return retval;
				}
			} else
				reg_write = 1;
		}
	}

	if (reg_write) {
		retval = rv_jtag_write_regs(rv, rv->core_regs);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while restoring context");
			return retval;
		}
	}

	return ERROR_OK;
}

static int rv_read_core_reg(struct target *target, int num)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
	uint32_t reg_value;

	LOG_DEBUG("-");

	if ((num < 0) || (num >= RV_ALLREGSCOUNT))
		return ERROR_COMMAND_SYNTAX_ERROR;



	if ((num >= 0) && (num < RV_COREREGSCOUNT)) {
		reg_value = rv->core_regs[num];
		buf_set_u32(rv->core_cache->reg_list[num].value, 0, 32, reg_value);
		LOG_DEBUG("Read reg %s value 0x%08" PRIx32, gdb_regno_name(num) , reg_value);
		rv->core_cache->reg_list[num].valid = 1;
		rv->core_cache->reg_list[num].dirty = 0;
	} else {
		/* This is an csr, always read value from HW */
		int retval = du_core->rv_jtag_read_cpu(&rv->jtag, num, 1, &reg_value);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while reading csr %s", gdb_regno_name(num));
			return retval;
		}
		buf_set_u32(rv->core_cache->reg_list[num].value, 0, 32, reg_value);
		LOG_DEBUG("Read csr reg %s value 0x%08" PRIx32, gdb_regno_name(num) , reg_value);
	}

	return ERROR_OK;
}

static int rv_write_core_reg(struct target *target, int num)
{
	struct rv_state *rv = target_to_rv(target);

	LOG_DEBUG("-");

	if ((num < 0) || (num >= GDB_REGNO_COUNT))
		return ERROR_COMMAND_SYNTAX_ERROR;

	uint32_t reg_value = buf_get_u32(rv->core_cache->reg_list[num].value, 0, 32);
	LOG_DEBUG("Write reg %s value 0x%08" PRIx32, gdb_regno_name(num) , reg_value);

	rv->core_cache->reg_list[num].valid = 1;
	rv->core_cache->reg_list[num].dirty = 0;

	return ERROR_OK;
}

static int rv_get_core_reg(struct reg *reg)
{
	struct rv_state *rv = reg->arch_info;
	struct target *target = rv->target;

	LOG_DEBUG("-");

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	return rv_read_core_reg(target, reg->number);
}

static int rv_set_core_reg(struct reg *reg, uint8_t *buf)
{
	struct rv_state *rv = reg->arch_info;
	struct target *target = rv->target;
	struct rv_du *du_core = rv_to_du(rv);
	uint32_t value = buf_get_u32(buf, 0, 32);

	LOG_DEBUG("-");

	if (target->state != TARGET_HALTED)
		return ERROR_TARGET_NOT_HALTED;

	if (reg->number < RV_COREREGSCOUNT) {
		buf_set_u32(reg->value, 0, 32, value);
		reg->dirty = 1;
		reg->valid = 1;
	} else {
		/* This is an csr, write it to the HW */
		int retval = du_core->rv_jtag_write_cpu(&rv->jtag, reg->number, 1, &value);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while writing csr %s", gdb_regno_name(reg->number));
			return retval;
		}
	}

	return ERROR_OK;
}

static const struct reg_arch_type rv_reg_type = {
	.get = rv_get_core_reg,
	.set = rv_set_core_reg,
};

static struct reg_cache *rv_build_reg_cache(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct reg_cache **cache_p = register_get_last_cache_p(&target->reg_cache);
	struct reg_cache *cache = malloc(sizeof(struct reg_cache));
	struct reg *reg_list = calloc(RV_ALLREGSCOUNT, sizeof(struct reg));

	LOG_DEBUG("-");

	/* Build the process context cache */
	cache->name = "RISC-V registers";
	cache->next = NULL;
	cache->reg_list = reg_list;
	cache->num_regs = RV_ALLREGSCOUNT;
	*cache_p = cache;
    memcpy(rv->core_regs, cache->reg_list, 4 * RV_COREREGSCOUNT);

	for (int i = 0; i < RV_COREREGSCOUNT; i++) {
		reg_list[i].name = gdb_regno_name(i);
		reg_list[i].size = 32;
		reg_list[i].value = calloc(1, 4);
		reg_list[i].dirty = 0;
		reg_list[i].valid = 0;
		reg_list[i].type = &rv_reg_type;
		reg_list[i].arch_info = rv;
		reg_list[i].number = i;
		reg_list[i].exist = true;
	}

	return cache;
}

static int rv_debug_entry(struct target *target)
{
	LOG_DEBUG("-");

	int retval = rv_save_context(target);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling rv_save_context");
		return retval;
	}

	struct rv_state *rv = target_to_rv(target);
	uint32_t addr = GDB_REGNO_PC;

	if (breakpoint_find(target, addr))
		/* Halted on a breakpoint, step back to permit executing the instruction there */
		retval = rv_set_core_reg(&rv->core_cache->reg_list[GDB_REGNO_PC],
					   (uint8_t *)&addr);

	return retval;
}

static int rv_halt(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("target->state: %s",
		  target_state_name(target));

	if (target->state == TARGET_HALTED) {
		LOG_DEBUG("Target was already halted");
		return ERROR_OK;
	}

	if (target->state == TARGET_UNKNOWN)
		LOG_WARNING("Target was in unknown state when halt was requested");

	if (target->state == TARGET_RESET) {
		if ((jtag_get_reset_config() & RESET_SRST_PULLS_TRST) &&
		    jtag_get_srst()) {
			LOG_ERROR("Can't request a halt while in reset if nSRST pulls nTRST");
			return ERROR_TARGET_FAILURE;
		} else {
			target->debug_reason = DBG_REASON_DBGRQ;
			return ERROR_OK;
		}
	}

	int retval = du_core->rv_cpu_stall(&rv->jtag, CPU_STALL);
	if (retval != ERROR_OK) {
		LOG_ERROR("Impossible to stall the CPU");
		return retval;
	}

	target->debug_reason = DBG_REASON_DBGRQ;

	return ERROR_OK;
}

static int rv_is_cpu_running(struct target *target, int *running)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
	int retval;
	int tries = 0;
	const int RETRIES_MAX = 5;

	/* Have a retry loop to determine of the CPU is running.
	   If target has been hard reset for any reason, it might take a couple
	   of goes before it's ready again.
	*/
	while (tries < RETRIES_MAX) {

		tries++;

		retval = du_core->rv_is_cpu_running(&rv->jtag, running);
		if (retval != ERROR_OK) {
			LOG_WARNING("Debug IF CPU control reg read failure.");
			/* Try once to restart the JTAG infrastructure -
			   quite possibly the board has just been reset. */
			LOG_WARNING("Resetting JTAG TAP state and reconnectiong to debug IF.");
			du_core->rv_jtag_init(&rv->jtag);

			LOG_WARNING("...attempt %d of %d", tries, RETRIES_MAX);

			alive_sleep(2);

			continue;
		} else
			return ERROR_OK;
	}

	LOG_ERROR("Could not re-establish communication with target");
	return retval;
}

static int rv_poll(struct target *target)
{
	int retval;
	int running;

	retval = rv_is_cpu_running(target, &running);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling rv_is_cpu_running");
		return retval;
	}

	/* check for processor halted */
	if (!running) {
		/* It's actually stalled, so update our software's state */
		if ((target->state == TARGET_RUNNING) ||
		    (target->state == TARGET_RESET)) {

			target->state = TARGET_HALTED;

			retval = rv_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling rv_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_HALTED);
		} else if (target->state == TARGET_DEBUG_RUNNING) {
			target->state = TARGET_HALTED;

			retval = rv_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling rv_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_DEBUG_HALTED);
		}
	} else { /* ... target is running */

		/* If target was supposed to be stalled, stall it again */
		if  (target->state == TARGET_HALTED) {

			target->state = TARGET_RUNNING;

			retval = rv_halt(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling rv_halt");
				return retval;
			}

			retval = rv_debug_entry(target);
			if (retval != ERROR_OK) {
				LOG_ERROR("Error while calling rv_debug_entry");
				return retval;
			}

			target_call_event_callbacks(target,
						    TARGET_EVENT_DEBUG_HALTED);
		}

		target->state = TARGET_RUNNING;

	}

	return ERROR_OK;
}

static int rv_assert_reset(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("-");

	int retval = du_core->rv_cpu_reset(&rv->jtag, CPU_RESET);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while asserting RESET");
		return retval;
	}

	return ERROR_OK;
}

static int rv_deassert_reset(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("-");

	int retval = du_core->rv_cpu_reset(&rv->jtag, CPU_NOT_RESET);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while desasserting RESET");
		return retval;
	}

	return ERROR_OK;
}

static int rv_soft_reset_halt(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("-");

	int retval = du_core->rv_cpu_stall(&rv->jtag, CPU_STALL);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while stalling the CPU");
		return retval;
	}

	retval = rv_assert_reset(target);
	if (retval != ERROR_OK)
		return retval;

	retval = rv_deassert_reset(target);
	if (retval != ERROR_OK)
		return retval;

	return ERROR_OK;
}

static int rv_resume_or_step(struct target *target, int current,
			       uint32_t address, int handle_breakpoints,
			       int debug_execution, int step)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
	struct breakpoint *breakpoint = NULL;
	uint32_t resume_pc;
	uint32_t reg_tselect;

	LOG_DEBUG("Addr: 0x%" PRIx32 ", stepping: %s, handle breakpoints %s\n",
		  address, step ? "yes" : "no", handle_breakpoints ? "yes" : "no");

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	if (!debug_execution)
		target_free_all_working_areas(target);

	/* current ? continue on current pc : continue at <address> */
	if (!current)
		buf_set_u32(rv->core_cache->reg_list[GDB_REGNO_PC].value, 0,
			    32, address);

	int retval = rv_restore_context(target);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while calling rv_restore_context");
		return retval;
	}

	/* read debug registers (starting from DMR1 register) */
	retval = du_core->rv_jtag_read_cpu(&rv->jtag, RV_TSELECT, 
            1, &reg_tselect);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while reading debug registers");
		return retval;
	}

	if (step)   reg_tselect |= RV_STEP_MASK;
	else        reg_tselect &= ~(RV_STEP_MASK);

	retval = du_core->rv_jtag_write_cpu(&rv->jtag, RV_TSELECT,
					      1, &reg_tselect);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing back debug registers");
		return retval;
	}

	resume_pc = buf_get_u32(rv->core_cache->reg_list[GDB_REGNO_PC].value,
				0, 32);

	/* The front-end may request us not to handle breakpoints */
	if (handle_breakpoints) {
		/* Single step past breakpoint at current address */
		breakpoint = breakpoint_find(target, resume_pc);
		if (breakpoint) {
			LOG_DEBUG("Unset breakpoint at 0x%08" TARGET_PRIxADDR, breakpoint->address);
			retval = rv_remove_breakpoint(target, breakpoint);
			if (retval != ERROR_OK)
				return retval;
		}
	}

	/* Unstall time */
	retval = du_core->rv_cpu_stall(&rv->jtag, CPU_UNSTALL);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while unstalling the CPU");
		return retval;
	}

	if (step)
		target->debug_reason = DBG_REASON_SINGLESTEP;
	else
		target->debug_reason = DBG_REASON_NOTHALTED;

	/* Registers are now invalid */
	register_cache_invalidate(rv->core_cache);

	if (!debug_execution) {
		target->state = TARGET_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_RESUMED);
		LOG_DEBUG("Target resumed at 0x%08" PRIx32, resume_pc);
	} else {
		target->state = TARGET_DEBUG_RUNNING;
		target_call_event_callbacks(target, TARGET_EVENT_DEBUG_RESUMED);
		LOG_DEBUG("Target debug resumed at 0x%08" PRIx32, resume_pc);
	}

	return ERROR_OK;
}

static int rv_resume(struct target *target, int current,
		       target_addr_t address, int handle_breakpoints,
		       int debug_execution)
{
	return rv_resume_or_step(target, current, address,
				   handle_breakpoints,
				   debug_execution,
				   NO_SINGLE_STEP);
}

static int rv_step(struct target *target, int current,
		     target_addr_t address, int handle_breakpoints)
{
	return rv_resume_or_step(target, current, address,
				   handle_breakpoints,
				   0,
				   SINGLE_STEP);

}

static int rv_add_breakpoint(struct target *target,
			       struct breakpoint *breakpoint)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
    int retval;

	LOG_DEBUG("Adding breakpoint: addr 0x%08" TARGET_PRIxADDR ", len %d, type %d, set: %d, id: %" PRId32,
		  breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_HARD)
		LOG_ERROR("HW breakpoints not supported for now. Doing SW breakpoint.");

    if (rv->breakpoints.num == RV_MAX_BREAKPOINTS) {
		LOG_ERROR("RV supports 2 breakpoints");
        return ERROR_FAIL;
    }

    rv->breakpoints.num++;
    rv->breakpoints.status[0] = (rv->breakpoints.status[0]<<1) | 1;
    rv->breakpoints.address[rv->breakpoints.num - 1] = breakpoint->address;
    
    uint32_t data = buf_get_u32(rv->breakpoints.status, 0, 32);
    retval = du_core->rv_jtag_write_cpu(&rv->jtag, RV_TSELECT, 1, &data);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while updating RV_TSELECT");
		return retval;
	}
   
    uint8_t csr_offset = rv->breakpoints.num - 1;
    retval = du_core->rv_jtag_write_cpu(&rv->jtag, RV_TDATA1 + csr_offset, 1, (uint32_t*)&breakpoint->address);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing RV_TDATA");
		return retval;
	}


	return ERROR_OK;
}

static int rv_remove_breakpoint(struct target *target,
				  struct breakpoint *breakpoint)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("Removing breakpoint: addr 0x%08" TARGET_PRIxADDR ", len %d, type %d, set: %d, id: %" PRId32,
		  breakpoint->address, breakpoint->length, breakpoint->type,
		  breakpoint->set, breakpoint->unique_id);

	/* Only support SW breakpoints for now. */
	if (breakpoint->type == BKPT_HARD)
		LOG_ERROR("HW breakpoints not supported for now. Doing SW breakpoint.");


    int idx = breakpoint->address == rv->breakpoints.address[0] ? 0 : 1;
    rv->breakpoints.status[0] &= ~(1 << idx);
    rv->breakpoints.num--;

    uint32_t data = buf_get_u32(rv->breakpoints.status, 0, 32);
    int retval = du_core->rv_jtag_write_cpu(&rv->jtag, RV_TSELECT, 1, &data);
	if (retval != ERROR_OK) {
		LOG_ERROR("Error while writing back the instruction at 0x%08" TARGET_PRIxADDR,
			   breakpoint->address);
		return retval;
	}

	return ERROR_OK;
}

static int rv_add_watchpoint(struct target *target,
			       struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

static int rv_remove_watchpoint(struct target *target,
				  struct watchpoint *watchpoint)
{
	LOG_ERROR("%s: implement me", __func__);
	return ERROR_OK;
}

static int rv_read_memory(struct target *target, target_addr_t address,
		uint32_t size, uint32_t count, uint8_t *buffer)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("Read memory at 0x%08" TARGET_PRIxADDR ", size: %" PRIu32 ", count: 0x%08" PRIx32, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_ERROR("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* Sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !buffer) {
		LOG_ERROR("Bad arguments");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u))) {
		LOG_ERROR("Can't handle unaligned memory access");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	return du_core->rv_jtag_read_memory(&rv->jtag, address, size, count, buffer);
}

static int rv_write_memory(struct target *target, target_addr_t address,
		uint32_t size, uint32_t count, const uint8_t *buffer)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	LOG_DEBUG("Write memory at 0x%08" TARGET_PRIxADDR ", size: %" PRIu32 ", count: 0x%08" PRIx32, address, size, count);

	if (target->state != TARGET_HALTED) {
		LOG_WARNING("Target not halted");
		return ERROR_TARGET_NOT_HALTED;
	}

	/* Sanitize arguments */
	if (((size != 4) && (size != 2) && (size != 1)) || (count == 0) || !buffer) {
		LOG_ERROR("Bad arguments");
		return ERROR_COMMAND_SYNTAX_ERROR;
	}

	if (((size == 4) && (address & 0x3u)) || ((size == 2) && (address & 0x1u))) {
		LOG_ERROR("Can't handle unaligned memory access");
		return ERROR_TARGET_UNALIGNED_ACCESS;
	}

	return du_core->rv_jtag_write_memory(&rv->jtag, address, size, count, buffer);
}


static int rv_create_reg_list(struct target *target)
{
	//struct rv_state *rv = target_to_rv(target);

	LOG_DEBUG("-");


	return ERROR_OK;
}

static int rv_init_target(struct command_context *cmd_ctx,
		struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);
	struct rv_jtag *jtag = &rv->jtag;

	if (du_core == NULL) {
		LOG_ERROR("No debug unit selected");
		return ERROR_FAIL;
	}

	if (jtag->tap_ip == NULL) {
		LOG_ERROR("No tap selected");
		return ERROR_FAIL;
	}

	rv->jtag.tap = target->tap;
	rv->jtag.rv_jtag_inited = 0;
	rv->jtag.rv_jtag_module_selected = -1;
	rv->jtag.target = target;
    rv->target = target;

	rv_build_reg_cache(target);

	return ERROR_OK;
}

static int rv_target_create(struct target *target, Jim_Interp *interp)
{
	if (target->tap == NULL)
		return ERROR_FAIL;

	struct rv_state *rv = calloc(1, sizeof(struct rv_state));

	target->arch_info = rv;
	rv_create_reg_list(target);
	rv_tap_vjtag_register();
	rv_du_adv_register();

	return ERROR_OK;
}

static int rv_examine(struct target *target)
{
	struct rv_state *rv = target_to_rv(target);
	struct rv_du *du_core = rv_to_du(rv);

	if (!target_was_examined(target)) {

		target_set_examined(target);

		int running;

		int retval = du_core->rv_is_cpu_running(&rv->jtag, &running);
		if (retval != ERROR_OK) {
			LOG_ERROR("Couldn't read the CPU state");
			return retval;
		} else {
			if (running)
				target->state = TARGET_RUNNING;
			else {
				LOG_DEBUG("Target is halted");

				/* This is the first time we examine the target,
				 * it is stalled and we don't know why. Let's
				 * assume this is because of a debug reason.
				 */
				if (target->state == TARGET_UNKNOWN)
					target->debug_reason = DBG_REASON_DBGRQ;

				target->state = TARGET_HALTED;
			}
		}
	}

	return ERROR_OK;
}

static int rv_arch_state(struct target *target)
{
	return ERROR_OK;
}

static int rv_get_gdb_reg_list(struct target *target, struct reg **reg_list[],
			  int *reg_list_size, enum target_register_class reg_class)
{
	struct rv_state *rv = target_to_rv(target);

	if (reg_class == REG_CLASS_GENERAL) {
		/* We will have this called whenever GDB connects. */
		int retval = rv_save_context(target);
		if (retval != ERROR_OK) {
			LOG_ERROR("Error while calling rv_save_context");
			return retval;
		}
		*reg_list_size = RV_COREREGSCOUNT;

		/* this is free()'d back in gdb_server.c's gdb_get_core_register_packet() */
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < *reg_list_size; i++)
			(*reg_list)[i] = &rv->core_cache->reg_list[i];
	} else {
		*reg_list_size = RV_ALLREGSCOUNT;
		*reg_list = malloc((*reg_list_size) * sizeof(struct reg *));

		for (int i = 0; i < *reg_list_size; i++)
			(*reg_list)[i] = &rv->core_cache->reg_list[i];
	}

	return ERROR_OK;

}

int rv_get_gdb_fileio_info(struct target *target, struct gdb_fileio_info *fileio_info)
{
	return ERROR_FAIL;
}

static int rv_checksum_memory(struct target *target, target_addr_t address,
		uint32_t count, uint32_t *checksum) {

	return ERROR_FAIL;
}

COMMAND_HANDLER(rv_tap_select_command_handler)
{
	struct target *target = get_current_target(CMD_CTX);
	struct rv_state *rv = target_to_rv(target);
	struct rv_jtag *jtag = &rv->jtag;
	struct rv_tap_ip *rv_tap;

	if (CMD_ARGC != 1)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rv_tap, &tap_list, list) {
		if (rv_tap->name) {
			if (!strcmp(CMD_ARGV[0], rv_tap->name)) {
				jtag->tap_ip = rv_tap;
				LOG_INFO("%s tap selected", rv_tap->name);
				return ERROR_OK;
			}
		}
	}

	LOG_ERROR("%s unknown, no tap selected", CMD_ARGV[0]);
	return ERROR_COMMAND_SYNTAX_ERROR;
}

COMMAND_HANDLER(rv_tap_list_command_handler)
{
	struct rv_tap_ip *rv_tap;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rv_tap, &tap_list, list) {
		if (rv_tap->name)
			command_print(CMD_CTX, "%s", rv_tap->name);
	}

	return ERROR_OK;
}

COMMAND_HANDLER(rv_du_select_command_handler)
{
	struct target *target = get_current_target(CMD_CTX);
	struct rv_state *rv = target_to_rv(target);
	struct rv_jtag *jtag = &rv->jtag;
	struct rv_du *rv_du;

	if (CMD_ARGC > 2)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rv_du, &du_list, list) {
		if (rv_du->name) {
			if (!strcmp(CMD_ARGV[0], rv_du->name)) {
				jtag->du_core = rv_du;
				LOG_INFO("%s debug unit selected", rv_du->name);

				if (CMD_ARGC == 2) {
					int options;
					COMMAND_PARSE_NUMBER(int, CMD_ARGV[1], options);
					rv_du->options = options;
					LOG_INFO("Option %x is passed to %s debug unit"
						 , options, rv_du->name);
				}

				return ERROR_OK;
			}
		}
	}

	LOG_ERROR("%s unknown, no debug unit selected", CMD_ARGV[0]);
	return ERROR_COMMAND_SYNTAX_ERROR;
}

COMMAND_HANDLER(rv_du_list_command_handler)
{
	struct rv_du *rv_du;

	if (CMD_ARGC != 0)
		return ERROR_COMMAND_SYNTAX_ERROR;

	list_for_each_entry(rv_du, &du_list, list) {
		if (rv_du->name)
			command_print(CMD_CTX, "%s", rv_du->name);
	}

	return ERROR_OK;
}

static const struct command_registration rv_hw_ip_command_handlers[] = {
	{
		"tap_select",
		.handler = rv_tap_select_command_handler,
		.mode = COMMAND_ANY,
		.usage = "tap_select name",
		.help = "Select the TAP core to use",
	},
	{
		"tap_list",
		.handler = rv_tap_list_command_handler,
		.mode = COMMAND_ANY,
		.usage = "tap_list",
		.help = "Display available TAP core",
	},
	{
		"du_select",
		.handler = rv_du_select_command_handler,
		.mode = COMMAND_ANY,
		.usage = "du_select name",
		.help = "Select the Debug Unit core to use",
	},
	{
		"du_list",
		.handler = rv_du_list_command_handler,
		.mode = COMMAND_ANY,
		.usage = "select_tap name",
		.help = "Display available Debug Unit core",
	},
	COMMAND_REGISTRATION_DONE
};

static const struct command_registration rv_command_handlers[] = {
	{
		.chain = rv_hw_ip_command_handlers,
	},
	COMMAND_REGISTRATION_DONE
};


struct target_type rv_target = {
	.name = "rv",

	.poll = rv_poll,
	.arch_state = rv_arch_state,

	.target_request_data = NULL,

	.halt = rv_halt,
	.resume = rv_resume,
	.step = rv_step,

	.assert_reset = rv_assert_reset,
	.deassert_reset = rv_deassert_reset,
	.soft_reset_halt = rv_soft_reset_halt,

	.get_gdb_reg_list = rv_get_gdb_reg_list,

	.read_memory = rv_read_memory,
	.write_memory = rv_write_memory,
	.checksum_memory = rv_checksum_memory,

	.commands = rv_command_handlers,
	.add_breakpoint = rv_add_breakpoint,
	.remove_breakpoint = rv_remove_breakpoint,
	.add_watchpoint = rv_add_watchpoint,
	.remove_watchpoint = rv_remove_watchpoint,

	.target_create = rv_target_create,
	.init_target = rv_init_target,
	.examine = rv_examine,

	.get_gdb_fileio_info = NULL,

	.profiling = NULL
};
