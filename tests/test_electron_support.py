"""Exercise Electron discovery and tray tracking without real app binaries."""

from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from gamma22_patcher import HDR_OUTPUT_HOOK_ORIGINAL
import runtime_gamma22 as runtime
import tray_gamma22 as tray
from tray_gamma22 import BrowserGenerations


class ElectronImage:
    FIRST_INITIALIZER = 0x1100
    GAMUT = 0x6100
    FACTORY = 0x3000
    POINTER = 0x8000
    HOOK = 0x2600
    HELPER = 0x2800
    CAVE = 0x3800

    def __init__(self, count=52, packed=False, hooks=(HOOK,), cave_size=97):
        self.SRGB = self.GAMUT + (36 if packed else 40)
        self.GAMMA22 = self.SRGB + (28 if packed else 32)
        self.data = bytearray(0x9000)
        self.data[:2] = b"MZ"
        struct.pack_into("<I", self.data, 0x3C, 0x80)
        self.put(0x80, b"PE\0\0")
        struct.pack_into("<HH", self.data, 0x84, 0x8664, 3)
        for index, (name, base, size) in enumerate(
            ((b".text", 0x1000, 0x4000), (b".rdata", 0x6000, 0x1000),
             (b".data", 0x8000, 0x1000))
        ):
            offset = 0x98 + index * 40
            self.put(offset, name.ljust(8, b"\0"))
            struct.pack_into("<IIII", self.data, offset + 8, size, base, size, base)
        # NOP filler keeps the single INT3 run below the only code cave.
        self.put(0x1000, b"\x90" * 0x4000)
        self.put(self.GAMUT, runtime.SRGB_GAMUT)
        self.put(self.SRGB, runtime.SRGB_TRANSFER_FUNCTION)
        self.put(self.GAMMA22, runtime.GAMMA22_TRANSFER_FUNCTION)
        self.put(self.FACTORY, b"\xC3")
        self.put(self.HELPER, runtime.HDR_OUTPUT_HELPER_BYTES)
        self.put(self.CAVE, b"\xCC" * cave_size)
        for index in range(count):
            base = self.FIRST_INITIALIZER + index * 32
            self.put(base, b"\x48\x8D\x0D" + runtime.rel32(base, 7, self.SRGB))
            self.put(base + 7, b"\x48\x8D\x15" + runtime.rel32(base + 7, 7, self.GAMUT))
            self.put(base + 14, b"\xE8" + runtime.rel32(base + 14, 5, self.FACTORY))
            self.put(base + 19, b"\x48\x89\x05" + runtime.rel32(base + 19, 7, self.POINTER))
        for hook in hooks:
            self.put(hook - 16, b"\x48\x8D\x8C\x24" + struct.pack("<I", 0x230))
            self.put(hook - 8, b"\x4C\x8D\x8C\x24" + struct.pack("<I", 0x660))
            self.put(hook, HDR_OUTPUT_HOOK_ORIGINAL)
            self.put(hook + 5, b"\xE8" + runtime.rel32(hook + 5, 5, self.HELPER))

    def put(self, address, value):
        self.data[address:address + len(value)] = value


class ElectronRuntimeLayoutTests(unittest.TestCase):
    def plan(self, fixture):
        with tempfile.TemporaryDirectory() as directory:
            exe = Path(directory) / "Code.exe"
            exe.write_bytes(fixture.data)
            result = runtime.make_runtime_plan(exe)
            self.assertEqual(exe.read_bytes(), fixture.data)
            return result

    def test_packed_and_aligned_constants_produce_complete_plan(self):
        for packed in (True, False):
            with self.subTest(packed=packed):
                fixture = ElectronImage(packed=packed)
                plan = self.plan(fixture)
                self.assertEqual(plan.layout["kind"], "electron-singleton-trampoline")
                self.assertEqual(len(plan.writes), 52 + 2)
                for item in plan.writes[:52]:
                    self.assertTrue(item.label.startswith("sRGB initializer "))
                    target = item.rva + 7 + struct.unpack_from("<i", item.patched, 3)[0]
                    self.assertEqual(target, fixture.GAMMA22)
                trampoline, hook = plan.writes[-2:]
                self.assertEqual(trampoline.label, "SDR scRGB/F16 trampoline")
                self.assertEqual(trampoline.rva, fixture.CAVE + 1)
                self.assertEqual(hook.label, "ScreenWin SDR output hook")
                self.assertEqual(hook.rva, fixture.HOOK)
                self.assertEqual(hook.patched[0], 0xE9)
                self.assertEqual(hook.rva + 5 + struct.unpack_from("<i", hook.patched, 1)[0], fixture.CAVE + 1)

    def test_unverified_counts_are_rejected(self):
        for count in (0, 39, 81):
            with self.subTest(count=count), self.assertRaisesRegex(
                runtime.PatchError, "Unexpected Electron singleton constructors"
            ):
                self.plan(ElectronImage(count))

    def test_ambiguous_or_missing_output_hook_is_rejected(self):
        for hooks, expected in (((), "found 0"), ((0x2600, 0x2700), "found 2")):
            with self.subTest(hooks=hooks), self.assertRaisesRegex(
                runtime.PatchError, f"output hook, {expected}"
            ):
                self.plan(ElectronImage(hooks=hooks))

    def test_inexact_code_cave_is_rejected(self):
        for size in (96, 98):
            with self.subTest(size=size), self.assertRaisesRegex(
                runtime.PatchError, "97-byte executable code cave"
            ):
                self.plan(ElectronImage(cave_size=size))


class FakeKey:
    def __init__(self, name):
        self.name = name

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False


class ElectronTrayTests(unittest.TestCase):
    @staticmethod
    def fake_plan(path):
        return mock.Mock(dll=path, dll_hash=path.read_bytes().hex().ljust(64, "0"))

    def test_newest_squirrel_version_is_numeric(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for version in ("1.0.9266", "1.0.10000", "1.0.999"):
                (root / f"app-{version}").mkdir()
                (root / f"app-{version}" / "Discord.exe").write_bytes(b"x")
            (root / "app-broken").mkdir()
            (root / "app-broken" / "Discord.exe").write_bytes(b"x")
            found = tray.newest_squirrel_executable(root, "Discord.exe")
            self.assertEqual(found.parent.name, "app-1.0.10000")
            self.assertIsNone(tray.newest_squirrel_executable(root / "missing", "Discord.exe"))

    def test_newest_package_matches_name_architecture_and_publisher(self):
        with tempfile.TemporaryDirectory() as directory:
            roots = {}
            for full_name in (
                "Claude_4.29.0.0_x64__pzs8sxrjxfjjc",
                "Claude_4.30.0.0_x64__pzs8sxrjxfjjc",
                "Claude_9.0.0.0_x64__otherpublisher",
                "Claude_9.0.0.0_arm64__pzs8sxrjxfjjc",
                "ClaudeHelper_9.0.0.0_x64__pzs8sxrjxfjjc",
            ):
                root = Path(directory) / full_name
                (root / "app").mkdir(parents=True)
                (root / "app" / "Claude.exe").write_bytes(b"x")
                roots[full_name] = str(root)
            names = list(roots)

            def enum_key(_key, index):
                if index >= len(names):
                    raise OSError("no more keys")
                return names[index]

            with mock.patch.object(tray.winreg, "OpenKey", side_effect=lambda _root, name: FakeKey(name)), \
                    mock.patch.object(tray.winreg, "EnumKey", side_effect=enum_key), \
                    mock.patch.object(tray.winreg, "QueryValueEx", side_effect=lambda key, _value: (roots[key.name], 1)):
                found = tray.newest_package_executable("Claude", "pzs8sxrjxfjjc", r"app\Claude.exe")
            self.assertEqual(found.parent.parent.name, "Claude_4.30.0.0_x64__pzs8sxrjxfjjc")

    def test_install_root_tracks_versioned_executables(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "Discord"
            first = root / "app-1.0.1" / "Discord.exe"
            second = root / "app-1.0.2" / "Discord.exe"
            for exe in (first, second):
                exe.parent.mkdir(parents=True)
                exe.write_bytes(exe.parent.name.encode())
            selected = [first]
            generations = BrowserGenerations(
                first,
                locator=lambda _exe, _explicit: selected[0],
                planner=self.fake_plan,
                clock=lambda: 100.0,
                install_root=root,
            )
            generations.activate(first)
            selected[0] = second
            kind, _detail = generations.poll(force=True)
            self.assertEqual(kind, "updated")
            self.assertEqual(generations.active_dll, second.resolve())

            wrong_name = root / "app-1.0.2" / "chrome.dll"
            wrong_name.write_bytes(b"x")
            with self.assertRaises(runtime.PatchError):
                generations.activate(wrong_name)
            with tempfile.TemporaryDirectory() as other:
                outside = Path(other) / "Discord.exe"
                outside.write_bytes(b"x")
                with self.assertRaises(runtime.PatchError):
                    generations.activate(outside)


if __name__ == "__main__":
    unittest.main()
