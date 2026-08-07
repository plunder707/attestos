from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "uki-base-admission-canary.yml"
DISK_LAYOUT = (
    ROOT
    / "system_files"
    / "usr"
    / "lib"
    / "image-builder"
    / "bootc"
    / "disk.yaml"
)


def test_qcow2_layout_has_bounded_boot_partitions_and_root_capacity():
    layout = yaml.safe_load(DISK_LAYOUT.read_text(encoding="utf-8"))
    partitions = layout["partition_table"]["partitions"]

    assert layout["mount_configuration"] == "units"
    assert layout["partition_table"]["type"] == "gpt"
    assert [part.get("size") for part in partitions] == [
        "1 MiB",
        "501 MiB",
        "1 GiB",
        "20 GiB",
    ]

    mounted = {
        part.get("payload", {}).get("mountpoint"): part
        for part in partitions
        if part.get("payload_type") == "filesystem"
    }
    assert mounted["/boot/efi"]["payload"]["type"] == "vfat"
    assert mounted["/boot"]["payload"]["type"] == "ext4"

    root = mounted["/"]
    assert root["payload"]["type"] == "ext4"
    assert root["payload"]["label"] == "root"


def test_bluefin_builder_uses_the_layout_root_filesystem():
    workflow = WORKFLOW.read_text(encoding="utf-8")
    assert "--rootfs=ext4" in workflow
    assert "--rootfs=btrfs" not in workflow
