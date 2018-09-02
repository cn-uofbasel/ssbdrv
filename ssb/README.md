# Content of directory ssb/

dir   | content
---:  | ---
adt   | abstract data types
app   | application logic
cmd   | app main programs with UI
local | access to local files (log, indices)
peer  | peer connection
rpc   | SSB RPC protocol
shs   | SSB secure handshake protocol

and their dependencies:

```txt
.-----------------------------.
|            cmd              |
+     .------------------.    |
|     |      app         |    |
+-----+-----+-------.    |    |
|    peer   |  adt  |    |    |
+-----.     +-------+----+----+
| rpc |     |                 |
+-----+-----+      local      |
|    shs    |                 |
`-----------+-----------------'
```

---
