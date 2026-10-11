#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SekiroSaveFileImporter
======================

把《只狼：影逝二度》(Sekiro: Shadows Die Twice) 的存档文件 `S0000.sl2`
重新绑定到**你自己的 Steam 账号**，并修正存档所需的 MD5 校验和。

典型用途：
  * 使用了别人分享的存档 / 网上下载的存档，游戏提示存档无法使用；
  * 从非 Steam 版本（或其他机器）迁移存档到自己的 Steam 账号。

实现原理（S0000.sl2 的结构）
----------------------------
1. 文件是一个 BND4 容器：
   * `0x00` 处 4 字节为 magic `BND4`；
   * `0x0C` 处 4 字节为分块数量（Sekiro 为 12）；
   * 从 `0x40` 开始，每个分块头占 `0x20` 字节，其中 `+0x10` 处 4 字节
     为该分块在文件中的起始偏移。
2. 容器内存放 `USER_DATA0000` ~ `USER_DATA0011`，每个分块：
   * 开头 16 字节 = 该分块数据的 MD5；
   * 其后 `[起始 + 0x10, 下一个分块起始)` 为真正的数据区；
   * 也就是说 `md5(数据区)` 必须等于开头那 16 字节，否则游戏会提示存档损坏。
3. 存档里以 8 字节小端整数的形式保存了 SteamID64，游戏读取存档时会
   校验它是否与当前登录的 Steam 账号一致。SteamID64 的高 32 位恒为
   `0x01100001`，据此可以在文件中找出全部 SteamID64。

本脚本只使用 Python 标准库，无需任何第三方依赖。
"""

from __future__ import annotations

import argparse
import hashlib
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

# ---------------------------------------------------------------- 常量 / 结构

BND4_MAGIC = b"BND4"

BND4_FILE_COUNT_OFFSET = 0x0C  # uint32：分块数量
BND4_FIRST_HEADER = 0x40       # 第一个分块头的位置
BND4_HEADER_SIZE = 0x20        # 每个分块头的大小
BND4_HEADER_OFFSET_FIELD = 0x10  # 分块头内「数据起始偏移」字段的位置

CHECKSUM_SIZE = 0x10           # 每个分块开头的 MD5 长度

STEAMID64_HIGH_MASK = 0x01100001  # SteamID64 恒定的高 32 位
STEAMID64_BASE = STEAMID64_HIGH_MASK << 32  # 76561197960265728
MAX_ACCOUNT_ID = 0x40000000    # 用于过滤误判的合理账号 ID 上限


@dataclass(frozen=True)
class Block:
    """BND4 容器中的一个分块。"""

    index: int
    name: str
    start: int          # 分块起始（MD5 校验和所在位置）
    end: int            # 分块结束（不含）

    @property
    def data_start(self) -> int:
        """数据区起始（跳过 16 字节校验和）。"""
        return self.start + CHECKSUM_SIZE

    def __str__(self) -> str:  # pragma: no cover - 仅用于展示
        return f"#{self.index:02d} {self.name} [{self.start:#010x}, {self.end:#010x})"


class SaveFileError(Exception):
    """存档文件不是预期的 Sekiro S0000.sl2 格式。"""


# ---------------------------------------------------------------- 解析


def _read_u32(data: bytes, offset: int) -> int:
    if offset + 4 > len(data):
        raise SaveFileError(f"偏移 {offset:#x} 超出文件范围")
    return struct.unpack_from("<I", data, offset)[0]


def parse_blocks(data: bytes) -> List[Block]:
    """解析 BND4 容器，返回全部分块（按文件中的先后顺序）。"""
    if len(data) < BND4_FIRST_HEADER + BND4_HEADER_SIZE:
        raise SaveFileError("文件太小，不是有效的 BND4 容器")
    if data[:4] != BND4_MAGIC:
        raise SaveFileError(f"magic 不是 BND4（实际为 {data[:4]!r}），不是只狼存档")

    count = _read_u32(data, BND4_FILE_COUNT_OFFSET)
    if not 1 <= count <= 64:
        raise SaveFileError(f"分块数量异常：{count}")

    starts: List[int] = []
    for i in range(count):
        header = BND4_FIRST_HEADER + i * BND4_HEADER_SIZE
        if header + BND4_HEADER_SIZE > len(data):
            raise SaveFileError(f"分块头 #{i} 超出文件范围")
        starts.append(_read_u32(data, header + BND4_HEADER_OFFSET_FIELD))

    if any(b <= a for a, b in zip(starts, starts[1:])):
        raise SaveFileError("分块偏移不是递增的，文件结构异常")
    if starts[0] < BND4_FIRST_HEADER + count * BND4_HEADER_SIZE:
        raise SaveFileError("第一个分块与分块头区域重叠，文件结构异常")

    names = _read_names(data, BND4_FIRST_HEADER + count * BND4_HEADER_SIZE, starts[0], count)
    bounds = starts + [len(data)]
    return [
        Block(i, names[i], starts[i], bounds[i + 1])
        for i in range(count)
    ]


def _read_names(data: bytes, begin: int, end: int, count: int) -> List[str]:
    """读取分块名（UTF-16LE，以 \\x00 结尾）。读不出来就退回默认名字。"""
    if begin >= end:
        return [f"USER_DATA{i:04d}" for i in range(count)]
    try:
        raw = data[begin:end].decode("utf-16-le", errors="strict")
    except UnicodeDecodeError:
        return [f"USER_DATA{i:04d}" for i in range(count)]

    parts = [p for p in raw.split("\x00") if p]
    if len(parts) != count:
        return [f"USER_DATA{i:04d}" for i in range(count)]
    return parts


# ---------------------------------------------------------------- SteamID


def to_steam3(steam_id64: int) -> int:
    """SteamID64 -> SteamID3（账号 ID）。"""
    return steam_id64 - STEAMID64_BASE


def from_steam3(account_id: int) -> int:
    """SteamID3（账号 ID）-> SteamID64。"""
    return STEAMID64_BASE + account_id


def find_steam_ids(data: bytes) -> List[Tuple[int, int]]:
    """
    找出文件中所有 SteamID64（8 字节小端）。

    识别依据是 SteamID64 的高 32 位恒为 ``0x01100001``，
    再要求低 32 位落在合理账号 ID 区间内以排除误判。
    """
    marker = struct.pack("<I", STEAMID64_HIGH_MASK)
    found: List[Tuple[int, int]] = []
    pos = 0
    while True:
        pos = data.find(marker, pos)
        if pos < 0:
            break
        account_offset = pos - 4
        if account_offset >= 0:
            account_id = _read_u32(data, account_offset) if account_offset + 4 <= len(data) else 0
            if 0 < account_id < MAX_ACCOUNT_ID:
                found.append((account_offset, from_steam3(account_id)))
        pos += 1
    return found


# ---------------------------------------------------------------- 校验和


def compute_checksum(data: bytes, block: Block) -> bytes:
    """计算某个分块应有的 MD5（对整个数据区取 MD5）。"""
    return hashlib.md5(data[block.data_start:block.end]).digest()


def verify_checksums(data: bytes, blocks: Sequence[Block]) -> List[Tuple[Block, bool, bytes, bytes]]:
    """逐块核对校验和，返回 (分块, 是否正确, 当前值, 应有值)。"""
    result = []
    for block in blocks:
        stored = data[block.start:block.data_start]
        expected = compute_checksum(data, block)
        result.append((block, stored == expected, stored, expected))
    return result


def fix_checksums(data: bytearray, blocks: Sequence[Block]) -> List[Block]:
    """把校验和不对的分块重写，返回被修正的分块列表。"""
    fixed = []
    for block in blocks:
        expected = compute_checksum(bytes(data), block)
        if bytes(data[block.start:block.data_start]) != expected:
            data[block.start:block.data_start] = expected
            fixed.append(block)
    return fixed


# ---------------------------------------------------------------- 主流程


def rebind(
    source: bytes,
    new_steam_id64: int,
) -> Tuple[bytearray, List[Tuple[int, int, int]], List[Block]]:
    """
    把存档重新绑定到新的 SteamID64。

    返回 ``(新数据, [(偏移, 旧值, 新值), ...], 被修正校验和的分块)``。
    """
    blocks = parse_blocks(source)
    data = bytearray(source)
    payload = struct.pack("<Q", new_steam_id64)

    replacements: List[Tuple[int, int, int]] = []
    for offset, old_value in find_steam_ids(bytes(data)):
        if old_value == new_steam_id64:
            continue
        data[offset:offset + 8] = payload
        replacements.append((offset, old_value, new_steam_id64))

    fixed = fix_checksums(data, blocks)
    return data, replacements, fixed


# ---------------------------------------------------------------- 命令行


def _cmd_info(args: argparse.Namespace) -> int:
    data = Path(args.save).read_bytes()
    blocks = parse_blocks(data)
    steam_ids = find_steam_ids(data)
    results = verify_checksums(data, blocks)

    print(f"文件        : {args.save}")
    print(f"大小        : {len(data)} 字节 ({len(data):#x})")
    print(f"分块数量    : {len(blocks)}")
    print()
    print("分块（* 表示该分块除校验和之外还有实际数据）：")
    for block, ok, _stored, _expected in results:
        used = sum(1 for b in data[block.start:block.end] if b)
        mark = "*" if used > CHECKSUM_SIZE else " "
        print(
            f" {mark} {block.index:02d} {block.name:<16} "
            f"[{block.start:#010x}, {block.end:#010x}) "
            f"校验和 {'OK ' if ok else 'BAD'}  非零字节 {used:>8}"
        )
    print()
    if steam_ids:
        print("存档中的 SteamID64：")
        for offset, value in steam_ids:
            print(f"  {offset:#010x}  {value}  (SteamID3: {to_steam3(value)})")
    else:
        print("存档中未发现 SteamID64（可能该存档尚未写入，或格式与本工具不匹配）")

    bad = [b for b, ok, _, _ in results if not ok]
    print()
    if bad:
        print(f"校验和不匹配的分块：{[b.index for b in bad]}")
    else:
        print("全部分块校验和均正确")
    return 0


def _resolve_output(args: argparse.Namespace) -> Optional[Path]:
    if args.in_place:
        return Path(args.save)
    if args.output:
        return Path(args.output)
    return None


def _cmd_convert(args: argparse.Namespace) -> int:
    src = Path(args.save)
    if not src.is_file():
        print(f"错误：找不到文件 {src}", file=sys.stderr)
        return 1

    out = _resolve_output(args)
    if out is None:
        print("错误：请用 -o/--output 指定输出文件，或使用 --in-place 原地修改", file=sys.stderr)
        return 1

    data = src.read_bytes()
    try:
        new_data, replacements, fixed = rebind(data, args.steam_id)
    except SaveFileError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    if not replacements:
        print("存档中没有需要替换的 SteamID（可能已经是你自己的存档）。")

    print(f"目标 SteamID64 : {args.steam_id}  (SteamID3: {to_steam3(args.steam_id)})")
    for offset, old, new in replacements:
        print(f"  替换 {offset:#010x}: {old} -> {new}")
    for block in fixed:
        print(f"  修正分块 #{block.index:02d} {block.name} 的校验和")

    if args.dry_run:
        print("\n--dry-run：未写入任何文件")
        return 0

    if out == src and not args.force:
        print("错误：原地修改会覆盖原文件，如确认请加 --force（建议先备份）", file=sys.stderr)
        return 1

    if out == src:
        backup = src.with_suffix(src.suffix + ".bak")
        backup.write_bytes(data)
        print(f"已备份原文件到：{backup}")

    out.write_bytes(bytes(new_data))
    print(f"\n已写出：{out}")

    # 写出后立即复核
    written = out.read_bytes()
    ok = all(ok for _, ok, _, _ in verify_checksums(written, parse_blocks(written)))
    ids_ok = all(v == args.steam_id for _, v in find_steam_ids(written))
    print(f"复核：校验和 {'全部正确' if ok else '仍有问题'}，SteamID {'全部正确' if ids_ok else '仍有问题'}")
    return 0 if ok and ids_ok else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sekiro_save.py",
        description="把只狼 S0000.sl2 存档重新绑定到自己的 Steam 账号并修正校验和",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_info = sub.add_parser("info", help="查看存档结构、SteamID 与校验和状态（只读）")
    p_info.add_argument("save", help="存档文件路径，例如 S0000.sl2")
    p_info.set_defaults(func=_cmd_info)

    p_conv = sub.add_parser("convert", help="替换 SteamID 并修正校验和")
    p_conv.add_argument("save", help="输入存档文件")
    p_conv.add_argument("-o", "--output", help="输出文件；省略时需配合 --in-place")
    p_conv.add_argument("--steam-id", required=True, type=int, help="你的 SteamID64（17 位数字）")
    p_conv.add_argument("--in-place", action="store_true", help="原地修改（默认会先生成 .bak 备份）")
    p_conv.add_argument("--force", action="store_true", help="与 --in-place 同用时跳过确认提示")
    p_conv.add_argument("--dry-run", action="store_true", help="只打印将要做的改动，不写文件")
    p_conv.set_defaults(func=_cmd_convert)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
