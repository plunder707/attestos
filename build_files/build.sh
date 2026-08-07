#!/bin/bash
# The attestation layer. Everything here is additive to the Bazzite base.
set -ouex pipefail

cp -avf "/ctx/system_files"/. /

### Packages the agent needs at runtime.
# tpm2-tools provides tpm2_quote, tpm2_pcrread, tpm2_createak and tpm2_nvread.
# tpm2-tss is the stack underneath them.
dnf5 install -y tpm2-tools tpm2-tss

### Kernel command line, recorded for the UKI build.
#
# This is the load-bearing configuration. lockdown=confidentiality blocks
# /dev/mem, kprobes against a live kernel, and unsigned module loading.
# module.sig_enforce=1 is the same guarantee stated twice, deliberately.
#
# The command line only means something if it is SEALED INSIDE the signed
# UKI. If it lives in an editable bootloader config, a user deletes
# lockdown=confidentiality, boots a kernel whose measurement is unchanged,
# and attests perfectly clean while loading whatever module they like.
install -D -m 0444 /dev/stdin /usr/lib/attestos/cmdline <<'CMDLINE'
lockdown=confidentiality module.sig_enforce=1 rd.shell=0 rd.emergency=halt
CMDLINE

### Record which image this is, so the running system can name itself.
echo "${IMAGE_DIGEST:-unknown}" > /usr/lib/attestos/image-digest
chmod 0444 /usr/lib/attestos/image-digest
echo "${ATTESTOS_SOURCE_COMMIT:-unknown}" > /usr/lib/attestos/source-commit
chmod 0444 /usr/lib/attestos/source-commit

chmod 0755 /usr/libexec/attestos-boot-evidence-canary

systemctl enable attestos-provision.service
systemctl enable attestos-agent.socket
