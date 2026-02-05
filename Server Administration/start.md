# AGENTS.md

## Passwordless sudo
When setting up a new VM, always configure passwordless sudo for all users using a sudoers.d drop-in.

### Steps
1. Create a dedicated sudoers.d file with `visudo`:
   ```bash
   sudo visudo -f /etc/sudoers.d/99-nopasswd
   ```
2. Add exactly this line:
   ```text
   ALL ALL=(ALL:ALL) NOPASSWD: ALL
   ```
3. Save and exit.

### Verify
- Confirm the file contents:
  ```bash
  sudo cat /etc/sudoers.d/99-nopasswd
  ```
- Test non-interactive sudo:
  ```bash
  sudo -n true
  ```

### Notes
- Use `/etc/sudoers.d/` instead of editing `/etc/sudoers` directly.
- `visudo` validates syntax before saving.
