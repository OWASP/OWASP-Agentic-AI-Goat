# Local Docker storage outage and recovery

The local backend stopped after PostgreSQL reported `No space left on device`. The Docker VM's additional data filesystem was full at 8 GiB, and the learner PostgreSQL container was restarting. The frontend and nodemon supervisor remained alive. No unknown Docker volumes were pruned.

Root paused the verified nodemon supervisor, stopped the VM, and retained an APFS clone of the original 8,589,934,592-byte data disk. SHA-256 of the complete original and clone matched. The private recovery directory is `/var/folders/p2/dchrxd612l9_58pkt64n41gc0000gp/T/owasp-ai-goat-vm-disk-recovery-9a0t5mnp`; the backup disk is mode0600 and the directory mode0700. Do not publish its contents or remove the backup during ongoing recovery qualification.

The first expansion/restart produced an empty filesystem with a different UUID. Root immediately stopped the VM. Both Lima's enabled formatting path and a saved Colima dependency script could initialize a disk under missing-label/mount conditions; the available logs do not establish which executed. The saved script contained `sfdisk`, `mkfs.ext4` and `e2label`, guarded only by a mount check.

Root restored the original backup into a 32 GiB raw image, then verified that **all original 8 GiB bytes still matched the backup hash before boot**. Automatic additional-disk formatting was disabled. The next boot retained the original ext4 UUID, `4f2c7147-c182-4825-90e7-d4e60d7a58dd`, and grew the filesystem to32 GiB with approximately23 GiB free. Original learner PostgreSQL and four sidecar containers reappeared. PostgreSQL accepted connections; after the verified nodemon supervisor was resumed and restarted through its documented signal, backend health returned HTTP200.

The saved VM dependency script now validates that exact UUID and ext4 type before its mount checks, and contains no partitioning, formatting or relabeling commands. Unexpected filesystem identity fails closed. Lima YAML validation and shell syntax checks pass. This is a repair to the existing local VM configuration, not an AWS or repository deployment change.

The stopped-disk backup remains retained. Full post-repair restart qualification of the saved guard and per-table application verification remain separate checks; successful health and recovered filesystem identity are not substitutes for every application workflow. Temporary owned PostgreSQL tests continue using explicit tmpfs storage and exact-container cleanup.

Primary implementation references: [Lima disk management](https://lima-vm.io/docs/config/disk/), [Lima2.2.0 guest disk setup](https://github.com/lima-vm/lima/blob/v2.2.0/pkg/cidata/cidata.TEMPLATE.d/boot.Linux/05-lima-disks.sh), and [format:false design](https://github.com/lima-vm/lima/pull/1516).
