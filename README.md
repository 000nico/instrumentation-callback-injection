# PICII 🕳️
### Process Instrumentation Callback Injection Interface

PICII is a shellcode injection technique that leverages `NtSetInformationProcess` with `_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION` to execute arbitrary shellcode in a remote process — without `CreateThread` or any standard execution primitive.

---

## How it works 🧠

`NtSetInformationProcess` lets you change how a process behaves, setting up internal structures at a low level.

By using it with `_PROCESS_INSTRUMENTATION_CALLBACK_INFORMATION`, we tell the system: *"before this process returns from a syscall, execute this first"* — and *"this"* is our shellcode.

This is also known as a **Nirvana Hook** — something in the middle of usermode and kernelmode. Dark power that shouldn't be accessible from usermode, but it is.

---
```
process syscall
    └─ kernel handles it
        └─ before returning to usermode → executes our callback 🪝
            └─ our shellcode runs
                └─ returns to normal execution flow
```
---

## Architecture 🏗️

PICII uses two separate memory allocations in the target process:

- **Wrapper** — a small ASM stub that preserves registers, calls the payload, restores context and returns correctly via `jmp r10`
- **Payload** — your shellcode

The wrapper address is registered as the Nirvana callback. It calls the payload internally.

---

## Usage 🚀
```cpp
PICII::inject(HANDLE handle, size_t size, unsigned char* payload, unsigned int length, bool debug)
```

| Parameter | Description |
|---|---|
| `handle` | Handle to the target process |
| `size` | Memory pages to allocate for the payload (`0x1000`, `0x2000`) |
| `payload` | The shellcode to inject |
| `length` | Size in bytes of the payload |
| `debug` | `true` to enable output, `false` to run silent |
```cpp
// example
HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
PICII::inject(handle, 0x1000, bin_payload, bin_payload_len, true);
```

To clean up:
```cpp
PICII::exit(handle, true);
```

---

## Requirements ⚠️

- Must run as **administrator** (elevated)
- `SeDebugPrivilege` is required to hook remote processes
- Target process must be **x64**

---

## Disclaimer 🛡️

- Wrapper by https://github.com/OtterHacker
- https://www.riskinsight-wavestone.com/en/2023/10/process-injection-using-ntsetinformationprocess/
- This project is for **security research and EDR/antivirus development only**. Use it in controlled environments. 
