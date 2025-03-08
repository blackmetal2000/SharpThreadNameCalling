# Sharp Thread Name-Calling
Thread Name-Calling Injection written in C#.
All credits to creator of the technique: [hasherezade](https://github.com/hasherezade/thread_namecalling).

#### POC Image:
![alt text](https://i.imgur.com/yg7MO97.png)

There's no use of `VirtualAllocEx` API in this case. The written memory is in `SpareULongs` field in PEB. By default, this field has `PAGE_READ_WRITE` permissions.

![alt text](https://i.imgur.com/ZdCWgiJ.png)

The process handle is opened with:
- `PROCESS_QUERY_LIMITED_INFORMATION`
- `PROCESS_VM_READ`
- `PROCESS_VM_OPERATION`

The thread handle is opened with:
- `SYNCHRONIZE`
- `THREAD_SET_CONTEXT`
- `THREAD_SET_LIMITED_INFORMATION`.

#### How to use?
```
.\thread-name-calling.exe PROCESS_NAME SHELLCODE_FILE
```

#### To-Do

- [ ] Implement `NtQueueApcThread` API
- [ ] Implement DLL Injection
- [ ] Implement `CreateRemoteThread` API
- [ ] Implement Local Process Injection
- [ ] More...

#### References
- https://research.checkpoint.com/2024/thread-name-calling-using-thread-name-for-offense/
- https://github.com/hasherezade/thread_namecalling/
