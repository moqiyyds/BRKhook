# Shadow Hook 内核模块使用手册

**仅供参考切勿用于运行受保护的程序 若运行受保护程序一律与此项目无关
**破坏计算机的 或者用于某讯游戏 与作者和本项目没任何关系 仅供参考
**仅供参考学习研究使用

**作者**：daidai  
**版本**：1.0  
**更新日期**：2026-04-09  
**适用平台**：Linux aarch64（ARMv8 / ARM64）  
**内核兼容**：Linux 5.x ~ 6.x（动态适配 API）
**TIM 2934402954 QQ 2934402954
**内核讨论群 2034300530
---

## 1. 概述

`shadow_hook` 是一个基于 ARM64 硬件断点（`BRK` 指令）实现的轻量级用户态指令级 Hook 框架。它通过临时替换目标进程代码段中的一条指令为自定义 `BRK` 指令，在内核陷入异常时完成自定义逻辑处理，然后利用单步执行恢复原始指令并重新武装 Hook，形成对用户态函数的**无侵入式拦截**。

该模块最初为特定游戏引擎的 `Rot`（旋转数据）拦截场景设计，但其架构通用，可扩展用于任意用户态指令插桩。

> **设计哲学**：  
> - 不修改原二进制文件  
> - 不依赖 `ptrace` 暂停进程  
> - 利用内核断点机制，对目标进程完全透明

---

## 2. 核心机制简述

### 2.1 替换策略

- **指令替换**：将目标地址处的原始 4 字节指令替换为 `BRK #0x5A5A`（硬件编码 `0xD4200000 | (0x5A5A << 5)`）。
- **权限绕过**：使用 `access_process_vm(..., FOLL_WRITE | FOLL_FORCE)` 直接写入进程代码段，绕过 VMA 只读/可执行保护。
- **缓存一致性**：每次写入后调用内联汇编刷新所有 I-Cache（`ic ialluis` + 屏障）。

### 2.2 断点分发与处理

- **Break Hook**：当目标进程执行到替换后的 `BRK` 指令时，CPU 陷入 EL1（内核），进入 `shadow_break_handler`。
- **身份校验**：检查当前进程的 `mm_struct` 与注册时的记录是否匹配，防止误触发。
- **行为分支**：根据注册时传入的 `is_rot_hook` 类型执行不同逻辑：
    - **类型 0**：简单置零操作（`x8 = 0`）。
    - **类型 1**：将 `custom_rot` 数值写入用户栈，并更新进程 FPSIMD 状态中的 `vregs[3-5]`。
    - **类型 2**：直接跳转到 LR（`x30`），并清零 `x0`，实现函数返回劫持。

### 2.3 单步恢复与重新武装

处理完断点后，模块会：
1. 将断点位置的 `BRK` 指令恢复为原始指令。
2. 设置一个 `step_pending` 标志，并启用当前进程的单步调试（`user_enable_single_step`）。
3. 当进程执行完原始指令并触发单步异常时，`shadow_step_handler` 被调用，此时：
   - 清除 `step_pending` 标志。
   - **再次写入 `BRK` 指令**（重新武装），使下一次执行到该地址时仍能拦截。
   - 关闭单步调试。

整个过程对目标线程是**原子化**的，既保证了原始指令被完整执行一次，又维持了 Hook 的持续性。

> **注意**：单步相关的内核函数（`register_user_step_hook` 等）由模块通过 `kallsyms` 动态查找，不依赖内核头文件导出。若内核未开启相关 `CONFIG`，单步部分会静默失效，但 Hook 主功能仍可工作（需自行构造恢复逻辑）。

---

## 3. 模块导出的核心接口

模块通过 `EXPORT_SYMBOL` 导出了以下函数，供其他内核模块调用：

| 函数名 | 功能描述 |
| :--- | :--- |
| `int add_shadow(struct shadow_request *req)` | 为一个指定进程的目标地址安装 Hook |
| `int update_shadow_rot(struct shadow_request *req)` | 更新已注册 Hook 的 `custom_rot` 数值（仅对类型 1 有效） |
| `int del_shadow(struct shadow_request *req)` | 移除指定 Hook 并恢复原始指令 |
| `int shadow_fault_init(void)` | 初始化模块（注册 break/step hooks） |
| `void shadow_fault_exit(void)` | 清理模块（卸载 hooks 并释放资源） |
| `void shadow_register_step_hook(void)` | 单独注册单步钩子（用于手动控制） |
| `void shadow_unregister_step_hook(void)` | 单独注销单步钩子 |

### 3.1 数据结构 `shadow_request`

该结构体用于向模块传递参数，定义于 `shadow_hook.h`（未在本文件中列出，以下为参考定义）：

struct shadow_request {
    pid_t   pid;                // 目标进程 PID
    unsigned long vaddr;        // 虚拟地址（用作唯一标识，实际使用页对齐）
    unsigned long target_vaddr; // 需要替换指令的目标地址（精确地址）
    u32      custom_rot[3];     // 自定义旋转数据（用于类型 1）
    int      is_rot_hook;       // Hook 行为类型：0, 1, 2
};