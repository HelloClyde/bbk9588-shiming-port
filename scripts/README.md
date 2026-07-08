# scripts

这里保留《使命》S1 -> 9588 迁移过程中比较有复用价值的脚本。

这些脚本主要用于归档、分析和复现实验步骤；不是完整的一键构建系统。部分脚本需要原始固件、原始 BDA、9588 字库或本仓库没有分发的逆向中间文件。

## 通用 BDA 工具

- `bda_validate.py`：校验 9588 BDA header、checksum、entry offset 和图标区。
- `bda_extract_icons.py`：从 BDA 中导出 VX/RGB565 图标为 PNG。
- `bda_set_icon_png.py`：把 PNG 图标写回 BDA，并修正 header checksum。
- `bda_fix_header_checksum.py`：只修正 BDA header checksum。
- `bda_set_category.py`：修改 9588 BDA category。
- `bda_set_title.py`：修改 9588 BDA 标题。
- `bda_header.py`、`bda_layout.py`、`minimips.py`：上面脚本和补丁脚本使用的 helper。

常用示例：

```powershell
python scripts\bda_validate.py 应用\程序\使命_9588兼容版_v1.1.bda
python scripts\bda_extract_icons.py 应用\程序\使命_9588兼容版_v1.1.bda out_icons
```

## 《使命》迁移相关脚本

- `mission_api_compat_matrix.py`：扫描《使命》实际调用的 API 表项，并对照 S1/9588 固件表项。
- `mission_build_direct_compat.py`：早期直接兼容补丁构建脚本。
- `mission_build_gui_table_shim.py`：GUI 表 shim 构建脚本。
- `mission_build_timing_compat.py`：稳定进入主菜单阶段使用的 timing 兼容补丁。
- `mission_patch_no834.py`：跳过 `GUI+0x834` 字形生成调用，用于验证文字缺失但流程可运行。
- `mission_patch_glyph_embed_gbk_b0f7.py`：v1.1 使用的字形内嵌方案，把 9588 `HZK_LIB.BIN` 的 GBK `A1-F7` 字形和 ASCII `6x12` 字形内嵌到 BDA。
- `s1_font_decode.py`：按 S1 字库索引方式解码/预览字形，用于确认 GBK index 和 glyph 格式。

`mission_api_compat_matrix.py` 需要 `capstone`：

```powershell
pip install capstone
```

字形内嵌脚本示例：

```powershell
python scripts\mission_patch_glyph_embed_gbk_b0f7.py input.bda HZK_LIB.BIN output.bda
```

## 版本说明

当前发布的可用 BDA 是 `应用/程序/使命_9588兼容版_v1.1.bda`。如果只想安装游戏，不需要运行这些脚本。
