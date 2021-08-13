##################################################
## PyDefenderCheck - Python implementation of DefenderCheck
##################################################
## Author: daddycocoaman
## Based on: https://github.com/matterpreter/DefenderCheck
##################################################


import argparse
import enum
import json
import subprocess
import tempfile
from itertools import zip_longest
from dataclasses import asdict, dataclass
from pathlib import Path

# Taken from https://docs.python.org/3/library/itertools.html#itertools-recipes
def grouper(iterable, n, fillvalue=None):
    args = [iter(iterable)] * n
    return zip_longest(*args, fillvalue=fillvalue)


# Modified from https://www.geoffreybrown.com/blog/a-hexdump-program-in-python/
def hexdump(hexBytes: bytes, startingByte: int = 0, bytesPerLine: int = 16) -> str:
    result = []

    hexStringWidth = bytesPerLine * 3
    for idx, line in enumerate(grouper(hexBytes, bytesPerLine)):
        s1 = " ".join([f"{i:02x}" for i in line])  # hex string
        s1 = (
            s1[0:23] + " " + s1[23:]
        )  # insert extra space between groups of 8 hex values

        s2 = "".join(
            [chr(i) if 32 <= i <= 127 else "." for i in line]
        )  # ascii string; chained comparison

        result.append(
            f"{startingByte - 256 + (idx * 16):08x}  {s1:<{hexStringWidth}}  {s2}"
        )
    return "\n".join(result)


class ScanResult(enum.Enum):
    NoThreatFound = 0
    ThreatFound = 2


@dataclass
class DefenderScannerResult:
    filename: str
    signature: str
    offendingOffset: int
    hexdump: str

    def __repr__(self) -> str:
        if self.signature and self.offendingOffset and self.hexdump:
            sig = f"\nSignature: {self.signature}\n"
            offset = f"Offset: {self.offendingOffset}\n\n"
            return sig + offset + self.hexdump
        return "No threat found!"

    def to_json(self):
        return json.dumps(asdict(self))


class DefenderScanner:
    def __init__(self, filename: Path) -> None:
        self.filename = filename
        self.signature = None
        self.lastgood = 0
        self.complete = False
        self.offendingOffset = 0
        self.hexdump = None
        self.scan()

    @property
    def result(self) -> DefenderScannerResult:
        return DefenderScannerResult(
            str(self.filename), self.signature, self.offendingOffset, self.hexdump
        )

    def _scan(self, filename: Path, getsig=False) -> ScanResult:
        procArguments = f"C:\Program Files\Windows Defender\MpCmdRun.exe -Scan -ScanType 3 -File {filename.absolute()} -DisableRemediation -Trace -Level 0x10"
        process = subprocess.run(procArguments.split(), timeout=30, capture_output=True)
        if not self.signature:
            for line in process.stdout.splitlines():
                if line.startswith(b"Threat"):
                    self.signature = line.split()[-1].decode()
        return ScanResult(process.returncode)

    def _halfSplit(self, originalBytes: bytes) -> bytes:
        splitBytesLen = (len(originalBytes) - self.lastgood) // 2 + self.lastgood
        if len(originalBytes) == splitBytesLen + 1:
            self.offendingOffset = hex(len(originalBytes))

            if len(originalBytes) < 256:
                self.hexdump = hexdump(originalBytes, int(self.offendingOffset, 16))
            else:
                self.hexdump = hexdump(
                    originalBytes[-256:], int(self.offendingOffset, 16)
                )
            self.complete = True
        return originalBytes[:splitBytesLen]

    def _overshot(self, originalBytes: bytes, splitbytessize: int) -> bytes:
        newsize = (len(originalBytes) - splitbytessize) // 2 + splitbytessize
        if newsize == len(originalBytes) - 1:
            return None
        return originalBytes[:newsize]

    def scan(self):
        originalPath = Path(self.filename)
        originalFileStatus = self._scan(originalPath, True)

        # No threat found. Exit.
        if originalFileStatus == ScanResult.NoThreatFound:
            self.complete = True

        # Start half-splitting
        originalFileBytes = originalPath.read_bytes()
        fileBytebytesPerLine = len(originalFileBytes) // 2
        splitArray1 = originalFileBytes[:fileBytebytesPerLine]
        while not self.complete and splitArray1:
            if splitArray1 is None:
                print("Exhausted the search. The binary looks good to go!")
                break

            split1TempFile = tempfile.TemporaryFile()
            split1TempFile.write(splitArray1)
            result = self._scan(Path(split1TempFile.name))

            if result == ScanResult.ThreatFound:
                splitArray1 = self._halfSplit(splitArray1)
            # If threat not found, scan second half and continue recursion
            elif result == ScanResult.NoThreatFound:
                self.lastgood = len(splitArray1)
                splitArray1 = self._overshot(originalFileBytes, len(splitArray1))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python version of DefenderCheck")
    parser.add_argument("filename", type=argparse.FileType("r"))
    args = parser.parse_args()

    scanner = DefenderScanner(Path(args.filename.name))
    print(scanner.result)