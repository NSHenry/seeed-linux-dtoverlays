#include <asm/io.h>
#include <linux/delay.h>
#include <linux/kprobes.h>
#include <linux/slab.h>
#include <linux/tty.h>

#ifndef MODULE_NAME
#define MODULE_NAME "rs485_autoflow"
#endif

#ifndef MODULE_VER
#define MODULE_VER "custom"
#endif

MODULE_DESCRIPTION("This module fixes RS-485 flow control issue on reComputer R1000 v1.0 by hooking `uart_write` function.");
MODULE_AUTHOR("Joshua Lee <chengxun.li@seeed.cc>");
MODULE_LICENSE("Dual MIT/GPL");
MODULE_VERSION(MODULE_VER);

static void hook_uart_write_onreturn(struct kprobe *p, struct pt_regs *regs, unsigned long flags)
{
    struct tty_struct *tty = (struct tty_struct *)regs->regs[0];
    struct uart_state *state;
    struct uart_port *port;
    if (tty->driver_data->port->rs485_term_gpio)
    {
        gpiod_set_value(port->rs485_term_gpio, 0);
    }
    return 0;
}

static int hook_uart_write_onstart(struct kprobe *p, struct pt_regs *regs)
{
    struct tty_struct *tty = (struct tty_struct *)regs->regs[0];
    struct uart_state *state;
    struct uart_port *port;
    if (tty->driver_data->port->rs485_term_gpio)
    {
        gpiod_set_value(port->rs485_term_gpio, 1);
    }
    return 0;
}

static unsigned long get_fn_addr(const char *symbol_name)
{
    struct kprobe temp_kp = {.symbol_name = symbol_name};
    int ret = register_kprobe(&temp_kp);
    unsigned long fn_addr = (unsigned long)temp_kp.addr;

    unregister_kprobe(&temp_kp);
    if (ret < 0)
    {
        return ret;
    }
    if (temp_kp.addr == NULL)
    {
        return -EFAULT;
    }

    return fn_addr;
}

#define LOG_PREFIX MODULE_NAME ": "
struct kprobe hook_uart_write;

static int module_init_fn(void)
{
    // Hook `uart_write` function
    unsigned long target_fn_addr = get_fn_addr("uart_write");
    if (target_fn_addr < 0)
    {
        printk(KERN_ERR LOG_PREFIX "Failed to get address for `uart_write`, returned code: %ld\n", target_fn_addr);
        return target_fn_addr;
    }
    hook_uart_write.addr = (kprobe_opcode_t *)target_fn_addr;
    hook_uart_write.pre_handler = (void *)hook_uart_write_onstart;
    hook_uart_write.post_handler = (void *)hook_uart_write_onreturn;
    int ret = register_kprobe(&hook_uart_write);
    if (ret < 0)
    {
        printk(KERN_ERR LOG_PREFIX "Failed to register kprobe for `uart_write`, returned code: %d\n", ret);
        return ret;
    }

    printk(KERN_INFO LOG_PREFIX "RS-485 interface has been hooked successfully\n");
    return 0;
}

static void module_exit_fn(void)
{
    unregister_kprobe(&hook_uart_write);
    for (int i = 0; i < sizeof(rs485_worker_queues) / sizeof(rs485_worker_queues[0]); i++)
    {
        if (rs485_worker_queues[i])
        {
            destroy_workqueue(rs485_worker_queues[i]);
        }
    }
    rs485_dtr_deinit();

    printk(KERN_INFO LOG_PREFIX "RS-485 interface has been unhooked successfully\n");
}

module_init(module_init_fn);
module_exit(module_exit_fn);