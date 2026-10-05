# V21 — First Login & School Activation

Newly provisioned School Admin accounts are marked `first_login_required=1`.
After activation or first login, the admin is shown a school identity check and then sent to the existing non-destructive setup wizard.

Existing school accounts default to `first_login_required=0`, so current production users are not unexpectedly redirected.

Flow:

Super Admin creates school → School/Tenant IDs generated → Admin account created → activation code → Admin activates account → first-login orientation → setup wizard → school ready.

The flow does not reset, delete, or replace school data.
