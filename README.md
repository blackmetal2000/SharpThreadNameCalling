# Thread Name Calling
Thread Name Calling Injection technique written in C#.
All credits to creator of the technique: [hasherezade](https://github.com/hasherezade/thread_namecalling).

#### POC Image:
![alt text](https://i.imgur.com/yg7MO97.png)

#### How to use?
In file "FileOperations.cs", change the first API "CreateFileW" parameter.
```c#
IntPtr hCreateFile = Win32.CreateFileW(
  @"C:\path\to\shellcode",
  FileAccess.Read,
  FileShare.Read,
  IntPtr.Zero,
  FileMode.OpenOrCreate,
  FileAttributes.Normal,
  IntPtr.Zero
);
```

If you want to change the icon and name window, go to file "ProcessOperations.cs".
```c#
string systemDirPath = Path.Combine(winDir, "System32");
string targetPath = Path.Combine(winDir, "System32", "calc.exe");
string windowName = "aespa";
string desktopInfoValue = @"WinSta0\Default";
```
#### References
- https://github.com/hasherezade/process_ghosting
- https://github.com/Wra7h/SharpGhosting
- https://whokilleddb.github.io/blogs/posts/process-ghosting/
