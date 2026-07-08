# Changelog

## v1.1

- 修复 ASCII 字符渲染路径。
- ASCII 单字节字形改为 `6x12` 行格式，并让 wrapper 返回 `0x0c`，避免被后续 `12x24` 绘制路径按 48 byte 读取导致英文下半部分截断或污染。
- 兼容版 BDA 文件名更新为 `使命_9588兼容版_v1.1.bda`。

## v1.0

- 首个可用的 BBK 9588《使命》S1 移植兼容版。
- 重封装 9588 可识别 BDA header、分类、入口和图标区。
- 修复 S1/9588 GUI/API 表不兼容导致的启动死机。
- 为 `GUI+0x834` 增加 BDA 内字形兼容 shim。
- 内嵌 `A1-F7` GBK 字形和半角 ASCII 字模，修复游戏内文字渲染。
- 使用 gpt-image2 高清化使命 logo，并以 VX/RGB565 `0xf81f` 紫色 colorkey 写入透明图标。
- 附带 16:9 项目头图。
