# Faulty Oops

## Explanation

The command `echo "hello_world" > /dev/faulty` causes a write to the "faulty" kernel module.
The `write` calls `faulty_write` which is defined in the `file_operations` defined in the module's source.
The `faulty_write` function dereferences a `NULL` pointer and attempts to write a value to that memory space.
The memory address of a `NULL` pointer is an invalid address, so the "faulty" module crashes and crashes the system.
