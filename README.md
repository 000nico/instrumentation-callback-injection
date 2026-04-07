# PICII 🕳️
### Process Instrumentation Callback Instrumentation Injection

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
PICII::inject(
    HANDLE handle,
    size_t size,
    unsigned char* payload,
    unsigned int length,
    void* structPointer,
    size_t structSize,
    BYTE* pattern,
    unsigned int patternSize,
    bool debug
);
```

| Parameter | Description |
|---|---|
| `handle` | Handle to the target process |
| `size` | Memory size to allocate for the payload (`0x1000`, `0x2000`) |
| `payload` | The shellcode to inject |
| `length` | Size in bytes of the payload |
| `structPointer` | Pointer to a structure copied into the remote process |
| `structSize` | Size of the structure |
| `pattern` | Byte pattern inside the payload to replace with the structure address |
| `patternSize` | Size of the pattern |
| `debug` | `true` to enable output, `false` to run silent |

```cpp
// example
HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

// example structure
MyStruct data = { ... };

// placeholder pattern inside payload
BYTE pattern[] = { 0xDE, 0xAD, 0xBE, 0xEF };

PICII::inject(
    handle,
    0x1000,
    bin_payload,
    bin_payload_len,
    &data,
    sizeof(data),
    pattern,
    sizeof(pattern),
    true
);
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
- Its recommendable to set your payload as ```vextern "C" oid payload()```

---

## Disclaimer 🛡️

- https://www.riskinsight-wavestone.com/en/2023/10/process-injection-using-ntsetinformationprocess/
- This project is for **security research and EDR/antivirus development only**. Use it in controlled environments. 
