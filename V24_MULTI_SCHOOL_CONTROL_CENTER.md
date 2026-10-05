# V24 — Multi-School Control Center

V24 adds a Super Admin platform-wide control center at `/platform/control-center`.

It provides non-sensitive health information for every school:
- School ID and Tenant ID
- activation/account status
- readiness status and setup percentage
- tenant identity integrity
- number of setup/identity issues requiring attention
- direct link to the existing school verification page

The control center does not expose student records, passwords, or individual result data.

## Safety
- Uses the existing authenticated Super Admin guard.
- Reuses the existing school readiness and tenant verification logic.
- Does not reset, delete, migrate, or replace school data.
- Does not grant access to another school's records.
