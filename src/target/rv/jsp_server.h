#ifndef OPENOCD_TARGET_RISCV_JSP_SERVER_H
#define OPENOCD_TARGET_RISCV_JSP_SERVER_H

#include "rv_tap.h"
#include "rv.h"
#include "rv_du.h"

struct jsp_service {
	char *banner;
	struct rv_jtag *jtag_info;
	struct connection *connection;
};

int jsp_init(struct rv_jtag *jtag_info, char *banner);
int jsp_register_commands(struct command_context *cmd_ctx);
void jsp_service_free(void);

#endif /* OPENOCD_TARGET_RISCV_JSP_SERVER_H */
