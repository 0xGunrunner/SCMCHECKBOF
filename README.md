# scmcheck

A Beacon Object File (BOF) that checks for dangerous permissions on the Windows Service Control Manager (SCM). Part of the [SAL-BOF](https://github.com/0xGunrunner/SAL-BOF) collection.

## What it does

Windows assigns a DACL to the SCM object itself, separate from individual service DACLs. If a low-privileged user holds `CreateService` or `AllAccess` on the SCM, they can register and start an arbitrary service binary — a direct path to SYSTEM without touching any existing service.

`scmcheck` queries the SCM's security descriptor and walks the DACL against the current token (user SID + all group SIDs), evaluating deny ACEs before allow ACEs to match Windows access-check semantics. It reports three rights:

| Right | Value | Impact |
|---|---|---|
| `CreateService` | `0x0002` | Register a new service with an arbitrary binary path |
| `ModifyBootConfig` | `0x0020` | Alter boot configuration — persistence primitive |
| `AllAccess` | `0x000F003F` | Full control over the SCM |

For each finding it resolves and prints the identity (account name) that the granting ACE applies to.

## Usage

```
privcheck scmcheck
```

### Example output

```
[*] scmcheck BOF — SCM Permission Check
[*] ----------------------------------------

=== Service Control Manager Permissions ===

[!] SCM: current user has CreateService
    Identity : CORP\lowpriv

[+] No dangerous SCM permissions found.   ← clean result
```

## Building

Requires `mingw-w64` cross-compiler on Linux/macOS.

```bash
# x64
x86_64-w64-mingw32-gcc -c scmcheck.c -masm=intel -o _bin/scmcheck.x64.o

# x86
i686-w64-mingw32-gcc -c scmcheck.c -masm=intel -o _bin/scmcheck.x86.o
```

Place the compiled `.o` files in your `_bin/` directory alongside the rest of SAL-BOF.

### Dependencies

- `beacon.h` — standard Cobalt Strike / AdaptixC2 BOF header (not included, place in the same directory as `scmcheck.c`)
- No external libraries — all API calls use the BOF `DLL$Function` dynamic resolution convention

## Integration — AdaptixC2 (SAL-BOF.axs)

`scmcheck` is registered as a subcommand of `privcheck` in the AXS extension file:

```javascript
var _cmd_privcheck_scmcheck = ax.create_command(
    "scmcheck",
    "Checks for dangerous permissions on the Service Control Manager",
    "privcheck scmcheck"
);
_cmd_privcheck_scmcheck.setPreHook(function (id, cmdline, parsed_json, ...parsed_lines) {
    let bof_path = ax.script_dir() + "_bin/scmcheck." + ax.arch(id) + ".o";
    ax.execute_alias(id, cmdline, `execute bof "${bof_path}"`, "Task: Checks SCM Permissions");
});
```

## Technical notes

**Why a separate BOF from `modsvc`?**
`modsvc` enumerates per-service DACLs and also runs the SCM check in one shot. `scmcheck` exists as a focused standalone for situations where you only need to confirm SCM-level exposure quickly, without iterating over every service on a large host.

**DACL walk implementation**
The BOF does not use `AccessCheck()` (which requires an impersonation token and a mapping structure). Instead it manually walks ACEs in two passes — deny first, then allow — which matches the documented Windows access-check algorithm for discretionary access and avoids the token duplication requirement.

**No `va_list` / `vsnprintf`**
All output uses `BeaconFormatPrintf` directly. Variadic CRT wrappers are unreliable in the BOF execution context and are avoided throughout.

## Related

- `modsvc` — per-service DACL check + SCM check combined
- `privcheck all` — runs all SAL-BOF privilege escalation checks sequentially

## Disclaimer

This tool is provided for authorized penetration testing and security research only. You are responsible for ensuring you have explicit written permission before running this or any offensive security tool against any system. The author accepts no liability for misuse or damage caused by this software.

## Author

[0xGunrunner](https://github.com/0xGunrunner)
