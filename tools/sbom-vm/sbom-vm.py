#!/usr/bin/env python3

import subprocess
import logging
import os
import sys
from datetime import datetime
from pathlib import Path
import time
import shutil
import tempfile

#edit: added output_dir parameter so log files are written to the correct folder
#regardless of where the script is called from (fixes path issues when running talos from outside its folder)
def setup_logging(image_path: Path, output_dir: Path) -> logging.Logger:
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = output_dir / f"{timestamp}_{image_path.stem}.log"  #edit: was just f"{timestamp}_{image_path.stem}.log" (relative path, wrote to cwd)
    
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.DEBUG)
    
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger

logger = None  # Will be initialized in main()

class ImageMounter:
    #edit: added output_dir parameter so sbom files are written to the correct folder
    #regardless of where the script is called from (fixes path issues when running talos from outside its folder)
    def __init__(self, image_path: str, output_dir: Path, mount_point: str = "/mnt/image_analysis"):
        self.image_path = Path(image_path)
        self.output_dir = output_dir  #edit: store output dir for use in generate_sbom()
        self.mount_point = Path(mount_point)
        self.nbd_device = "/dev/nbd0"
        self.mounted_partition = None
        self.mounted_fs_type = None  #edit: store fs_type alongside partition
        self.temp_dir = None
        self.temp_image = None

    def parse_size(self, size_str):
        """Parse size strings with units into numeric values."""
        try:
            size_str = str(size_str).strip().upper()
            if 'GB' in size_str:
                return float(size_str.rstrip('GB')) * 1024
            elif 'MB' in size_str:
                return float(size_str.rstrip('MB'))
            elif 'KB' in size_str:
                return float(size_str.rstrip('KB')) / 1024
            else:
                return float(size_str)
        except (ValueError, AttributeError):
            return 0

    def _run_command(self, command: list, check: bool = True, **kwargs) -> subprocess.CompletedProcess:
        try:
            result = subprocess.run(command, check=check, capture_output=True, text=True, **kwargs)
            return result
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {' '.join(command)}")
            logger.error(f"Error output: {e.stderr}")
            raise

    def _detect_image_format(self) -> str:
        """Detect the format of the input image."""
        logger.info(f"Detecting format of {self.image_path}")
        
        try:
            result = self._run_command(["qemu-img", "info", str(self.image_path)])
            for line in result.stdout.split('\n'):
                if line.startswith('file format:'):
                    fmt = line.split(':')[1].strip()
                    logger.info(f"qemu-img detected format: {fmt}")
                    return fmt
        except subprocess.CalledProcessError as e:
            logger.warning(f"qemu-img info failed: {e}")

        # Fallback to extension-based detection
        suffix = self.image_path.suffix.lower()
        if suffix == '.vmdk':
            return 'vmdk'
        elif suffix in ['.ami', '.raw']:
            # Check if gzipped
            try:
                with open(self.image_path, 'rb') as f:
                    if f.read(2).startswith(b'\x1f\x8b'):
                        return 'gzip'
            except Exception as e:
                logger.warning(f"Failed to check if file is gzipped: {e}")
        
        return 'raw'  # Default to raw format

    def _prepare_image(self) -> Path:
        """Prepare image for mounting, converting if necessary."""
        self.temp_dir = tempfile.mkdtemp(prefix='sbomvm_')
        image_format = self._detect_image_format()
        
        if image_format == 'gzip':
            logger.info("Decompressing gzipped image")
            self.temp_image = Path(self.temp_dir) / f"{self.image_path.stem}.raw"
            self._run_command(
                ["gunzip", "-c", str(self.image_path)],
                stdout=open(self.temp_image, 'wb'),
                text=False
            )
            return self.temp_image
            
        elif image_format in ['vmdk', 'vhd', 'vpc']:
            logger.info(f"Converting {image_format} to qcow2")
            self.temp_image = Path(self.temp_dir) / f"{self.image_path.stem}.qcow2"
            self._run_command([
                "qemu-img", "convert",
                "-f", image_format,
                "-O", "qcow2",
                str(self.image_path),
                str(self.temp_image)
            ])
            return self.temp_image
        
        return self.image_path

    #edit added more sleep time for wsl crashes
    def setup_nbd(self):
        #edit: added nbd device cleanup due to crashes
        #cleanup any leftover NBD state from previous crashed runs
        logger.info("Cleaning up any leftover NBD state")
        self._run_command(["qemu-nbd", "--disconnect", self.nbd_device], check=False)
        time.sleep(2) #edit 1->2
        self._run_command(["rmmod", "nbd"], check=False)
        time.sleep(3) #edit 1->3 more kernel time to unload
        
        #edit ensure mount point exists (img analysis doesnt exist)
        self.mount_point.mkdir(parents=True, exist_ok=True)
        
        #now load fresh
        logger.info("Loading NBD kernel module")
        self._run_command(["modprobe", "nbd", "max_part=8"])
        time.sleep(2) #edit 1->2

    def connect_image(self):
        prepared_image = self._prepare_image()
        logger.info(f"Connecting image {prepared_image} to NBD device")
        self._run_command(["qemu-nbd", "--connect", self.nbd_device, str(prepared_image)])
        # Increase delay to allow NBD device to stabilize
        time.sleep(5) #edit from 2-> 5
        # Trigger partition rescanning
        self._run_command(["partprobe", self.nbd_device], check=False)  #edit: check=False (fixed fail "busy NBD devices" in wsl)
        time.sleep(1)
        #edit check for partition devices to appear for 10seconds
        partition = f"{self.nbd_device}p1"
        for i in range(10):  # try for up to 10 seconds
            if Path(partition).exists():
                logger.info(f"Partition {partition} is ready")
                break
            logger.info(f"Waiting for partition to appear... ({i+1}/10)")
            time.sleep(1)
        #edit if it fails, try anyway maybe bad timing
        else:
            logger.warning("Partition did not appear after 10 seconds, proceeding anyway")

    """edit: returns a tuple of (partition_path, fs_type) for the best candidate partition. fixed blkid failed on nbd devices
    in wsl. fs_type is determined from parted output or blkid fallback, so mount_filesystem() and generate_sbom()
    dont need to call blkid again (which fails on NBD devices in WSL due to permissions probably even when using sudo).
    """
    def find_filesystem_partition(self) -> tuple:
        logger.info("Analyzing partitions")
        
        # Add extra delay and retry logic for partition analysis
        max_retries = 3
        for attempt in range(max_retries):
            try:
                # Use parted for detailed partition info
                parted_result = self._run_command(["parted", "-s", self.nbd_device, "print"])
                break
            except subprocess.CalledProcessError as e:
                if attempt < max_retries - 1:
                    logger.warning(f"Partition analysis failed, attempt {attempt + 1}/{max_retries}")
                    time.sleep(2)
                    continue
                raise
        
        logger.debug("parted output:\n%s", parted_result.stdout)
        
        # Parse parted output to find partitions
        partitions = []
        for line in parted_result.stdout.split('\n'):
            if not line.strip() or any(x in line for x in ['Number', 'Disk', 'Model:', 'Partition Table:']):
                continue
                
            parts = line.strip().split()
            if len(parts) >= 4:  # Need at least number, start, end, and size
                number = parts[0]
                partition = f"{self.nbd_device}p{number}"
                
                # Find filesystem type - it's usually after the size
                fs_type = ''
                for i, part in enumerate(parts):
                    if part.lower() in ['ext3', 'ext4', 'ntfs', 'hfsplus', 'apfs', 'fat32', 'vfat', 'btrfs']:
                        fs_type = part.lower()
                        break
                
                size = parts[3] if len(parts) > 3 else '0'
                
                # Skip known system partitions
                if any(x in line for x in ['Microsoft reserved', 'hidden, diag']):
                    logger.info(f"Skipping system partition {partition}")
                    continue
                
                # Handle EFI system partition
                if 'esp' in line.lower() or 'EFI' in line:
                    logger.info(f"Found EFI system partition {partition}")
                    if fs_type.lower() in ['vfat', 'fat32']:
                        partitions.append((partition, fs_type.lower(), size, 0))  # Priority 0 (lowest)
                    continue
                
                # Skip swap partitions
                if 'swap' in line.lower():
                    logger.info(f"Skipping swap partition {partition}")
                    continue
                
                # Check filesystem type
                if fs_type and fs_type.lower() in ['ntfs', 'hfsplus', 'apfs', 'ext3', 'ext4', 'vfat', 'fat32', 'btrfs']:
                    # Assign priority based on filesystem type
                    priority = {
                        'ext4': 3,    # Highest priority for Linux root
                        'ext3': 3,    # High priority for Linux
                        'btrfs': 3,   # High priority for Linux root
                        'ntfs': 2,    # High priority for Windows
                        'hfsplus': 2, # High priority for macOS
                        'apfs': 2,    # High priority for macOS
                        'vfat': 1,    # Lower priority
                        'fat32': 1    # Lower priority
                    }.get(fs_type.lower(), 0)
                    
                    partitions.append((partition, fs_type.lower(), size, priority))
                    logger.info(f"Found usable partition {partition} of type {fs_type}")
                else:
                    # Try blkid for aditional detection
                    try:
                        blkid_result = self._run_command(["blkid", partition], check=False)
                        if blkid_result.returncode == 0 and blkid_result.stdout.strip():
                            blkid_output = blkid_result.stdout.lower()
                            for fs in ['ntfs', 'hfsplus', 'apfs', 'ext4', 'ext3', 'vfat', 'zfs_member', 'btrfs']:
                                if fs in blkid_output:
                                    priority = 3 if fs in ['ext4', 'ext3', 'btrfs'] else 2 if fs in ['ntfs', 'hfsplus', 'apfs'] else 1
                                    partitions.append((partition, fs, size, priority))
                                    logger.info(f"Found usable partition {partition} of type {fs} (via blkid)")
                                    break
                        else:
                            logger.debug(f"blkid returned no output for {partition} (may be WSL limitation), skipping")
                    except Exception as e:
                        logger.debug(f"Error running blkid on {partition}: {e}")

        if not partitions:
            logger.error("Partition analysis for debugging:")
            logger.error("parted output:\n%s", parted_result.stdout)
            raise RuntimeError("No supported filesystem partitions found")
        
        logger.info(f"Found filesystem partition(s): {', '.join(f'{p[0]} ({p[1]})' for p in partitions)}")
        
        # Sort by priority (highest first), then by size (largest first)
        sorted_partitions = sorted(partitions,
                                   key=lambda x: (x[3], self.parse_size(x[2])),
                                   reverse=True)
        
        selected = sorted_partitions[0]
        logger.info(f"Selected partition {selected[0]} (priority: {selected[3]}, size: {selected[2]})")
        
        # Return both partition path and fs_type so mount_filesystem() doesn't need blkid
        return selected[0], selected[1]

    def mount_filesystem(self):
        #edit: unpack both partition and fs_type — no blkid call needed
        self.mounted_partition, fs_type = self.find_filesystem_partition()
        self.mounted_fs_type = fs_type  # store it for generate_sbom()
        self.mount_point.mkdir(parents=True, exist_ok=True)
        
        time.sleep(3) #edit wait before mounting. ndb disappears between partition detection and mount in wsl

        logger.info(f"Mounting {fs_type} filesystem")
        
        if fs_type == "zfs_member":
            self._handle_zfs(self.mounted_partition)
        elif fs_type == "btrfs":
            mount_opts = ["mount", "-t", "btrfs", "-o", "ro"]
            self._run_command(mount_opts + [self.mounted_partition, str(self.mount_point)])
        elif fs_type == "hfsplus":
            self._run_command(["mount", "-t", "hfsplus", "-o", "ro,force",
                               self.mounted_partition, str(self.mount_point)])
        elif fs_type == "apfs":
            self._run_command(["modprobe", "apfs"], check=False)
            mount_opts = ["mount", "-t", "apfs", "-o", "ro"]
            self._run_command(mount_opts + [self.mounted_partition, str(self.mount_point)])
        else:
            mount_opts = ["mount", "-o", "ro"]
            if fs_type in ["ntfs", "vfat", "ufs"]:
                mount_opts.extend(["-t", fs_type])
            self._run_command(mount_opts + [self.mounted_partition, str(self.mount_point)])

    def _handle_zfs(self, zfs_partition):
        logger.info(f"Attempting to import ZFS pool from {zfs_partition}")
        
        scan_result = self._run_command([
            "zpool", "import", "-d", zfs_partition
        ])
        
        pool_name = None
        for line in scan_result.stdout.split('\n'):
            if line.strip().startswith('pool:'):
                pool_name = line.split(':', 1)[1].strip()
                break
        
        if not pool_name:
            raise RuntimeError(f"No ZFS pool found in {zfs_partition}")
            
        logger.info(f"Found ZFS pool: {pool_name}")
        
        self._run_command([
            "zpool", "import", "-f", "-d", zfs_partition,
            "-R", str(self.mount_point), "-o", "readonly=on", pool_name
        ])

    def generate_sbom(self):
        #edit: use stored fs_type instead of calling blkid again. fixed blkid failed on nbd devices in wsl.
        fs_type = self.mounted_fs_type if self.mounted_fs_type else "unknown"
        
        # Extract partition device name
        partition_name = self.mounted_partition.split('/')[-1]
        
        # Generate filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        image_name = self.image_path.stem
        
        #edit: was f"./{filename}" (relative path, wrote to cwd). now uses output_dir for correct location
        output_file = self.output_dir / f"{timestamp}_sbom_{image_name}_{partition_name}_{fs_type}.json"  
        
        logger.info(f"Generating SBOM for mounted filesystem at {self.mount_point}")
        logger.info(f"Filesystem type: {fs_type}")
        
        # Debug mount contents
        self._run_command(["ls", "-la", str(self.mount_point)])
        self._run_command(["mount"])
        
        # Generate SBOM
        self._run_command([
            "syft",
            "--override-default-catalogers", "image",
            str(self.mount_point),
            "-o", f"cyclonedx-json={output_file}"  #edit: changed from: "-o", f"syft-json=./{output_file}" (osv cannot detect). also removed ./ prefix now using full path via output_dir
        ])
        
        logger.info(f"SBOM generated: {output_file}")

    def cleanup(self):
        logger.info("Starting cleanup")
        
        # Export ZFS pools
        try:
            pools = self._run_command(["zpool", "list", "-H"], check=False)
            if pools.returncode == 0 and pools.stdout.strip():
                for pool in pools.stdout.strip().split('\n'):
                    pool_name = pool.split()[0]
                    logger.info(f"Exporting ZFS pool {pool_name}")
                    self._run_command(["zpool", "export", pool_name], check=False)
        except Exception as e:
            logger.debug(f"Error during ZFS cleanup: {e}")

        if self.mount_point.is_mount():
            logger.info(f"Unmounting {self.mount_point}")
            self._run_command(["umount", str(self.mount_point)], check=False)
        
        logger.info("Disconnecting NBD device")
        self._run_command(["qemu-nbd", "--disconnect", self.nbd_device], check=False)
        
        logger.info("Removing NBD kernel module")
        self._run_command(["rmmod", "nbd"], check=False)
        
        # Clean up temporary files
        if self.temp_image and self.temp_image.exists():
            logger.info(f"Removing temporary image: {self.temp_image}")
            self.temp_image.unlink()
        
        if self.temp_dir and Path(self.temp_dir).exists():
            logger.info(f"Removing temporary directory: {self.temp_dir}")
            shutil.rmtree(self.temp_dir)

def main():
    #edit: updated to accept optional output_dir argument passed from talos
    #if not provided falls back to cwd (so it can run standalone)
    if len(sys.argv) < 2:
        print("Usage: script.py <path_to_image> [output_dir]")
        sys.exit(1)

    if os.geteuid() != 0:
        print("This script must be run as root")
        sys.exit(1)

    image_path = Path(sys.argv[1])
    #edit: now accepts output_dir from talos.py
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path.cwd()  
    
    global logger
    logger = setup_logging(image_path, output_dir)
    mounter = ImageMounter(image_path, output_dir)

    try:
        mounter.setup_nbd()
        mounter.connect_image()
        mounter.mount_filesystem()
        mounter.generate_sbom()
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)
    finally:
        mounter.cleanup()

if __name__ == "__main__":
    main()