# Copyright (c) 2026 Alexander Speka (DerAlex90)
# SPDX-License-Identifier: LicenseRef-myCVE-Attribution-1.0

"""Conservative package roles and exact kernel-release evidence, including older agents."""

import re


def package_context(inventory: dict, component: dict, host: dict | None = None) -> dict:
    host = host or {}
    name = inventory.get("name") or component.get("name", "")
    lower = name.lower().split(":", 1)[0]
    role = inventory.get("component_type") or "unknown"
    if role not in {"runtime", "development", "unknown"}:
        role = "unknown"
    if (
        role == "unknown"
        and "component_type" not in inventory
        and inventory.get("name")
        and host.get("os", "").lower() in {"linux", "windows"}
    ):
        role = "runtime"
    development = bool(
        lower == "linux-libc-dev"
        or re.search(r"(?:-dev|-devel)$", lower)
        or re.match(r"^(?:linux|pve|proxmox|kernel)-headers(?:-|$)", lower)
    )
    if development:
        role = "development"
    kernel = component.get("name", "").lower() in {"linux", "kernel", "linux-lts", "linux-virt"}
    image = re.match(r"^(?:linux-image|pve-kernel|proxmox-kernel)-(?P<release>\d.+)$", lower)
    release = inventory.get("kernel_release") or ""
    if image:
        release = image["release"].removesuffix("-signed").removesuffix("-unsigned")
        kernel = True
        role = "runtime"
    if lower in {"kernel", "kernel-core", "kernel-rt-core"}:
        kernel, role = True, "runtime"
        if not release and inventory.get("version") and inventory.get("architecture"):
            release = f"{inventory['version']}.{inventory['architecture']}"
    running = host.get("kernel", "")
    kernel_status = "not_kernel"
    if (
        kernel
        or lower == "linux-libc-dev"
        or re.match(r"^(?:linux|pve|proxmox|kernel)-headers(?:-|$)", lower)
    ):
        kernel_status = (
            "development"
            if development
            else "running"
            if release and running and release == running
            else "installed"
            if release and running
            else "unknown"
        )
    return {
        "component_type": role,
        "kernel_status": kernel_status,
        "kernel_release": release or None,
        "running_kernel": running or None,
    }
