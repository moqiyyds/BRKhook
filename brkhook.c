//TIM内核讨论群 203430053
#include <linux/version.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <asm/pgtable.h>

#include "shadow_hook.h"
#include "asm/page-def.h"
#include <linux/module.h>
#include <linux/export.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/debug-monitors.h>//struct break_hook, struct step_hook
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/fpsimd.h>
#include <asm/esr.h>
#include <asm/memory.h>

#ifndef untagged_addr
# define untagged_addr(addr) __untagged_addr(addr)
#endif

#define SHADOW_BRK_IMM   0x5A5AU
#define SHADOW_BRK_INSN  (0xD4200000U | (SHADOW_BRK_IMM << 5))

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 0, 0)
typedef unsigned long hook_esr_t;
#else
typedef unsigned int  hook_esr_t;
#endif

// vma_lookup可用于高版本内核
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
# define COMPAT_VMA_LOOKUP(mm, addr)  vma_lookup((mm), (addr))
#else
static inline struct vm_area_struct *
_compat_vma_lookup(struct mm_struct *mm, unsigned long addr)
{
    struct vm_area_struct *vma = find_vma(mm, addr);
    if (!vma || addr < vma->vm_start)
        return NULL;
    return vma;
}
# define COMPAT_VMA_LOOKUP(mm, addr)  _compat_vma_lookup((mm), (addr))
#endif

extern unsigned long util_kallsyms_lookup_name(const char *name);

void (*x_register_user_step_hook)(struct step_hook *hook);
void (*x_unregister_user_step_hook)(struct step_hook *hook);
void (*x_user_enable_single_step)(struct task_struct *task);
void (*x_user_disable_single_step)(struct task_struct *task);
void (*x_fpsimd_preserve_current_state)(void);
void (*x_fpsimd_update_current_state)(struct user_fpsimd_state const *state);

typedef void (*reg_break_hook_fn_t)(struct break_hook *);
static reg_break_hook_fn_t x_register_user_break_hook   = NULL;
static reg_break_hook_fn_t x_unregister_user_break_hook = NULL;


static void flush_insn_cache_all(void)
{
    asm volatile(
        "ic  ialluis\n"   // Invalidate all I-cache, Inner Shareable
        "dsb ish\n"
        "isb\n"
        : : : "memory");
}

static int patch_insn_user(struct task_struct *task,
                            unsigned long addr,
                            u32 new_insn,
                            u32 *old_insn_out,
                            bool write_insn)
{
    int ret;

    //读取原始指令
    if (old_insn_out) {
        ret = access_process_vm(task, addr, old_insn_out,
                                sizeof(u32), 0);
        if (ret != sizeof(u32)) {
            pr_err("[Hook] read insn at 0x%lx failed: %d\n", addr, ret);
            return -EFAULT;
        }
    }

    if (write_insn) {
        ret = access_process_vm(task, addr, &new_insn,
                                sizeof(u32), FOLL_WRITE | FOLL_FORCE);
        if (ret != sizeof(u32)) {
            pr_err("[hook] write insn at 0x%lx failed: %d\n", addr, ret);
            return -EFAULT;
        }
        flush_insn_cache_all();
    }

    return 0;
}

static int patch_insn_current(unsigned long addr, u32 insn)
{
    int ret = access_process_vm(current, addr, &insn,
                                sizeof(u32), FOLL_WRITE | FOLL_FORCE);
    if (ret != sizeof(u32)) {
        pr_err_ratelimited("[hook] patch_insn_current 0x%lx failed: %d\n",
                           addr, ret);
        return -EFAULT;
    }
    flush_insn_cache_all();
    return 0;
}

struct shadow_entry {
    unsigned long    vaddr;
    unsigned long    target_vaddr;
    struct mm_struct *mm;
    pid_t            pid;
    u32              orig_insn;
    atomic_t         step_pending;
    struct list_head list;
    spinlock_t       entry_lock;
    u32              custom_rot[3];
    int              is_rot_hook;
};

LIST_HEAD(shadow_page_list);
EXPORT_SYMBOL(shadow_page_list);

DEFINE_SPINLOCK(shadow_page_lock);
EXPORT_SYMBOL(shadow_page_lock);

static int shadow_break_handler(struct pt_regs *regs, hook_esr_t esr)
{
    struct shadow_entry *entry;
    unsigned long flags;
    unsigned long pc = regs->pc;
    bool found = false;

    if (!user_mode(regs))
        return DBG_HOOK_ERROR;

    spin_lock_irqsave(&shadow_page_lock, flags);
    list_for_each_entry(entry, &shadow_page_list, list) {
        if (entry->mm != current->mm)
            continue;

        if ((pc & 0xFFFFFFFFFFFFUL) !=
            (entry->target_vaddr & 0xFFFFFFFFFFFFUL))
            continue;

        pr_err_ratelimited(
            "[hook] BRK hit: target=0x%lx pc=0x%llx is_rot=%d\n",
            entry->target_vaddr, (unsigned long long)pc,
            entry->is_rot_hook);

        spin_lock(&entry->entry_lock);

        switch (entry->is_rot_hook) {
        case 0:
            regs->regs[8] = 0;
            pr_err_ratelimited("[hook] case0: set regs[8]=0\n");
            break;

        case 1: {
            u32 new_rot[3] = {
                entry->custom_rot[0],
                entry->custom_rot[1],
                entry->custom_rot[2]
            };
            pr_err_ratelimited("[hook] case1: rot=%u %u %u\n",
                               new_rot[0], new_rot[1], new_rot[2]);

            if (!(new_rot[0] == 0 && new_rot[1] == 0 && new_rot[2] == 0)) {
                struct user_fpsimd_state new_fp_state;

                preempt_disable();
                if (x_fpsimd_preserve_current_state)
                    x_fpsimd_preserve_current_state();

                memcpy(&new_fp_state,
                       &current->thread.uw.fpsimd_state,
                       sizeof(struct user_fpsimd_state));
                ((u32 *)&new_fp_state.vregs[3])[0] = new_rot[0];
                ((u32 *)&new_fp_state.vregs[4])[0] = new_rot[1];
                ((u32 *)&new_fp_state.vregs[5])[0] = new_rot[2];

                if (x_fpsimd_update_current_state)
                    x_fpsimd_update_current_state(&new_fp_state);
                preempt_enable();


                if (copy_to_user((void __user *)regs->sp,
                                 new_rot, sizeof(new_rot)))
                    pr_err_ratelimited(
                        "[hook] case1 copy_to_user failed\n");
                else
                    pr_err_ratelimited(
                        "[hook] case1 copy_to_user ok sp=0x%llx\n",
                        (unsigned long long)regs->sp);
            } else {
                pr_err_ratelimited("[hook] rot all zero, skip\n");
            }
            break;
        }

        case 2:

            regs->pc      = regs->regs[30];
            regs->regs[0] = 0;
            pr_err_ratelimited(
                "[hook] case2: pc=LR=0x%llx x0=0\n",
                (unsigned long long)regs->pc);

            spin_unlock(&entry->entry_lock);
            spin_unlock_irqrestore(&shadow_page_lock, flags);
            return DBG_HOOK_HANDLED;

        default:
            pr_err_ratelimited("[hook] unknown is_rot=%d\n",
                               entry->is_rot_hook);
            break;
        }
      
        spin_unlock(&entry->entry_lock);
        spin_unlock_irqrestore(&shadow_page_lock, flags);

        if (patch_insn_current(entry->target_vaddr, entry->orig_insn) == 0) {
            atomic_set(&entry->step_pending, 1);
            if (x_user_enable_single_step)
                x_user_enable_single_step(current);
        } else {
            pr_err_ratelimited(
                "[hook] restore orig_insn failed, re-arm BRK\n");
            patch_insn_current(entry->target_vaddr, SHADOW_BRK_INSN);
        }

        return DBG_HOOK_HANDLED;
    }

    if (found) {}
    spin_unlock_irqrestore(&shadow_page_lock, flags);
    return DBG_HOOK_ERROR;
}

static int shadow_step_handler(struct pt_regs *regs, hook_esr_t esr)
{
    struct shadow_entry *entry;
    bool handled = false;
    unsigned long flags;

    if (!user_mode(regs))
        return DBG_HOOK_ERROR;

    spin_lock_irqsave(&shadow_page_lock, flags);
    list_for_each_entry(entry, &shadow_page_list, list) {
        if (entry->mm != current->mm)
            continue;
        if (!atomic_read(&entry->step_pending))
            continue;

        atomic_set(&entry->step_pending, 0);
        handled = true;

        spin_unlock_irqrestore(&shadow_page_lock, flags);

        // 重新写入 BRK下次拦截
        if (patch_insn_current(entry->target_vaddr, SHADOW_BRK_INSN))
            pr_err_ratelimited(
                "[hook] step re-arm BRK failed at 0x%lx\n",
                entry->target_vaddr);
        else
            pr_err_ratelimited(
                "[hook] step re-arm BRK ok at 0x%lx\n",
                entry->target_vaddr);

        if (x_user_disable_single_step)
            x_user_disable_single_step(current);

        return DBG_HOOK_HANDLED;
    }
    spin_unlock_irqrestore(&shadow_page_lock, flags);

    return handled ? DBG_HOOK_HANDLED : DBG_HOOK_ERROR;
}

static struct break_hook shadow_break_hook = {
    .fn   = shadow_break_handler,
    .imm  = SHADOW_BRK_IMM,
    .mask = 0,
};
static struct step_hook shadow_step_hook = {
    .fn = shadow_step_handler,
};

static int install_fault_info_hook(void)
{
    if (!x_register_user_break_hook) {
        pr_err("[hook_fault] register_user_break_hook not found\n");
        return -ENOENT;
    }
    x_register_user_break_hook(&shadow_break_hook);
    pr_info("[hook_fault] BRK hook installed (imm=0x%04x, insn=0x%08x)\n",
            SHADOW_BRK_IMM, SHADOW_BRK_INSN);
    return 0;
}

static void uninstall_fault_info_hook(void)
{
    if (x_unregister_user_break_hook)
        x_unregister_user_break_hook(&shadow_break_hook);
    pr_info("[hook_fault] BRK hook removed\n");
}

int add_shadow(struct shadow_request *req)
{
    struct shadow_entry *entry;
    struct task_struct  *task;
    struct mm_struct    *mm;
    unsigned long        vaddr = req->vaddr & PAGE_MASK;
    unsigned long        target = req->target_vaddr;
    u32                  orig_insn = 0;
    int                  ret;

    rcu_read_lock();
    task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
    if (!task) {
        rcu_read_unlock();
        return -ESRCH;
    }
    get_task_struct(task);
    mm = get_task_mm(task);
    rcu_read_unlock();

    if (!mm) {
        put_task_struct(task);
        return -EINVAL;
    }
    
    ret = patch_insn_user(task, target,
                          SHADOW_BRK_INSN, &orig_insn, true);
    if (ret) {
        mmput(mm);
        put_task_struct(task);
        return ret;
    }

    entry = kzalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry) {
        patch_insn_user(task, target, orig_insn, NULL, true);
        mmput(mm);
        put_task_struct(task);
        return -ENOMEM;
    }

    entry->vaddr         = vaddr;
    entry->target_vaddr  = target;
    entry->mm            = mm;
    entry->pid           = req->pid;
    entry->orig_insn     = orig_insn;
    entry->custom_rot[0] = req->custom_rot[0];
    entry->custom_rot[1] = req->custom_rot[1];
    entry->custom_rot[2] = req->custom_rot[2];
    entry->is_rot_hook   = req->is_rot_hook;

    atomic_set(&entry->step_pending, 0);
    spin_lock_init(&entry->entry_lock);

    pr_err_ratelimited(
        "[hook] add_shadow: pid=%d target=0x%lx "
        "orig_insn=0x%08x BRK=0x%08x rot=%u %u %u is_rot=%d\n",
        req->pid, target, orig_insn, SHADOW_BRK_INSN,
        req->custom_rot[0], req->custom_rot[1], req->custom_rot[2],
        req->is_rot_hook);

    spin_lock_bh(&shadow_page_lock);
    list_add(&entry->list, &shadow_page_list);
    spin_unlock_bh(&shadow_page_lock);

    put_task_struct(task);
    return 0;
}

int update_shadow_rot(struct shadow_request *req)
{
    struct shadow_entry *entry;
    unsigned long vaddr = req->vaddr & PAGE_MASK;
    unsigned long flags;

    spin_lock_irqsave(&shadow_page_lock, flags);
    list_for_each_entry(entry, &shadow_page_list, list) {
        if (entry->pid == req->pid && entry->vaddr == vaddr) {
            pr_err_ratelimited(
                "[hook] update_rot: pid=%d vaddr=0x%lx new=%u %u %u\n",
                req->pid, vaddr,
                req->custom_rot[0], req->custom_rot[1], req->custom_rot[2]);

            spin_lock(&entry->entry_lock);
            entry->custom_rot[0] = req->custom_rot[0];
            entry->custom_rot[1] = req->custom_rot[1];
            entry->custom_rot[2] = req->custom_rot[2];
            spin_unlock(&entry->entry_lock);

            spin_unlock_irqrestore(&shadow_page_lock, flags);
            return 0;
        }
    }
    spin_unlock_irqrestore(&shadow_page_lock, flags);

    pr_err_ratelimited("[hook] update_rot not found: pid=%d vaddr=0x%lx\n",
                       req->pid, vaddr);
    return -ENOENT;
}

int del_shadow(struct shadow_request *req)
{
    struct shadow_entry *entry, *tmp;
    unsigned long vaddr = req->vaddr & PAGE_MASK;
    unsigned long flags;

    spin_lock_irqsave(&shadow_page_lock, flags);
    list_for_each_entry_safe(entry, tmp, &shadow_page_list, list) {
        if (entry->pid != req->pid || entry->vaddr != vaddr)
            continue;

        list_del(&entry->list);
        spin_unlock_irqrestore(&shadow_page_lock, flags);

        {
            struct task_struct *task;
            rcu_read_lock();
            task = pid_task(find_vpid(req->pid), PIDTYPE_PID);
            if (task) get_task_struct(task);
            rcu_read_unlock();

            if (task) {
                patch_insn_user(task, entry->target_vaddr,
                                entry->orig_insn, NULL, true);
                put_task_struct(task);
            } else {
                pr_warn("[hook] del: task gone, orig_insn not restored "
                        "at 0x%lx\n", entry->target_vaddr);
            }
        }

        mmput(entry->mm);
        kfree(entry);
        pr_err_ratelimited("[hook] del_shadow ok: 0x%lx\n", vaddr);
        return 0;
    }
    spin_unlock_irqrestore(&shadow_page_lock, flags);

    pr_err_ratelimited("[hook] del_shadow not found: 0x%lx\n", vaddr);
    return -ENOENT;
}

int shadow_fault_init(void)
{
    x_register_user_step_hook   =
        (void *)util_kallsyms_lookup_name("register_user_step_hook");
    x_unregister_user_step_hook =
        (void *)util_kallsyms_lookup_name("unregister_user_step_hook");
    x_user_enable_single_step   =
        (void *)util_kallsyms_lookup_name("user_enable_single_step");
    x_user_disable_single_step  =
        (void *)util_kallsyms_lookup_name("user_disable_single_step");
    x_fpsimd_preserve_current_state =
        (void *)util_kallsyms_lookup_name("fpsimd_preserve_current_state");
    x_fpsimd_update_current_state =
        (void *)util_kallsyms_lookup_name("fpsimd_update_current_state");

    x_register_user_break_hook   =
        (reg_break_hook_fn_t)util_kallsyms_lookup_name(
            "register_user_break_hook");
    x_unregister_user_break_hook =
        (reg_break_hook_fn_t)util_kallsyms_lookup_name(
            "unregister_user_break_hook");

    if (!x_register_user_break_hook) {
        pr_err("[hook_fault] register_user_break_hook not found via kallsyms\n");
        return -ENOENT;
    }

    if (install_fault_info_hook() < 0) {
        pr_err("[hook_fault] install hook failed\n");
        return -1;
    }

    if (x_register_user_step_hook)
        x_register_user_step_hook(&shadow_step_hook);

    pr_info("[hook_fault] init success (kernel %d.%d, BRK patch, imm=0x%04x)\n",(LINUX_VERSION_CODE >> 16) & 0xFF,(LINUX_VERSION_CODE >>  8) & 0xFF,SHADOW_BRK_IMM);
    return 0;
}
EXPORT_SYMBOL(shadow_fault_init);

void shadow_fault_exit(void)
{
    if (x_unregister_user_step_hook)
        x_unregister_user_step_hook(&shadow_step_hook);

    uninstall_fault_info_hook();
    pr_info("[hook_fault] exit\n");
}
EXPORT_SYMBOL(shadow_fault_exit);

void shadow_register_step_hook(void)
{
    if (x_register_user_step_hook) {
        x_register_user_step_hook(&shadow_step_hook);
        pr_info("[hook_fault] Step hook registered\n");
    }
}
EXPORT_SYMBOL(shadow_register_step_hook);

void shadow_unregister_step_hook(void)
{
    if (x_unregister_user_step_hook) {
        x_unregister_user_step_hook(&shadow_step_hook);
        pr_info("[hook_fault] Step hook unregistered\n");
    }
}
EXPORT_SYMBOL(shadow_unregister_step_hook);
