---
aliases:
tags:
  - tool
date created: Wednesday, March 30th 2022,3:15:57 pm
date modified: Sunday, April 10th 2022, 12:30:56 pm
---
## 1. 介绍

- [Obsidian](https://obsidian.md/) 是一款支持 Zettelkasten 笔记法的笔记管理软件，它同时支持 Windows、Mac 和 Linux 三大平台。
- Obsidian 支持 MarkDown 语法，入手也较为简单，可以快速编辑并格式化内容，具备一定的美观性。
- Obsidian 通过 ` 库文件夹 ` 管理笔记，可以将 ` 库文件夹 ` 存储到任何网盘目录。

## 2. 使用
已完成的插件使用

一、Advanced Tables 表格插件使用

| Name   | Age | Address |
| ------ | --- | ------- |
| 郝立鹏 | 33  | 成都市  |



Ctrl + Shift + D 唤出高级表格插件的空子面板
![[Pasted image 20220421102438.png]]

### 2.1. 快捷键

| 快捷键 | 说明 |
| ---- | ---- |
| Command+E | 编辑模式/阅读模式切换 |
| Command+Enter | 待办事项状态切换 |
| Command+Shift+F | 查找 |
| Command+P | 调出命令窗口 |
| Command+O | 快速打开笔记 |

### 2.2. 反向链接

- `[[档名]]`
- `[[档名#标题名]]`
- `[[档名#标题名|显示文字]]`

### 2.3. 待办事项

#### 2.3.1. 添加代办事项

1.  直接输入待办事项，输入完成后按两次 `Ctrl+Enter`
2.  在待办事项上按 `Ctrl+Enter` 以切换完成状态
3.  启用【设定】-> 【编辑器】-> 【智慧列表】后，在待办事项最末处按 `Enter` 会自动再新增待办事项
4.  另一个快速复制待办事项的方法：安装 `Min3ditorHotkeys` 插件并启用后，在待办事项处按 `Command+D` 以复制成为下一个事项

#### 2.3.2. 查询语法

示例： [https://github.com/schemar/obsidian-tasks#layout-options](https://github.com/schemar/obsidian-tasks#layout-options)

### 2.4. Frontmatter

- 用于在文章开头用 yaml 设定笔记的属性
- 必须在笔记最开头，以三个 `---` 开始，三个 `---` 结束

### 2.5. 快速简历索引笔记

根据标签检索，复制检索结果即可。

## 3. 第三方插件推荐

| 分类 | 插件 | 说明 |
| ---- |----|-----|
| 功能增强 | Obsidian Charts | 丰富图表 |
| 功能增强 | Mind Map | 思维导图 |
| 功能增强 | Emoji Tookbar | 表情输入 |
| 功能增强 | Annotator | PDF 标注 |
| 功能增强 | Media Extended | 嵌入视频 |
| 功能增强 | Timelines | 时间轴 |
| 功能增强 | Ozan's Image in Editor | 在编辑区直接显示图片，可以不用开启预览面板 |
| 功能增强 | Clear Unused Images | 清理不需要的废弃图片。操作方法：按 `CMD+P`，再输入 clear，点击 `Clear Unused Images` 即可。 |
| 功能增强 | Title Index | 如果文件标题要标上流水号，Title Index 就能自动将标题加上号码。操作方式：按 `CMD+P`，再输入 title-index |
| 功能增强 | Outliner | 快捷键调整列表及缩紧<br>Commond+向上/向下<br>Shift+Commond+向上/向下 |
| 功能增强 | Readwise Official | 将各种源导入到 Obsidian |
| 功能增强 | Hover Editor | 浮动窗格 |
| 面板增强 | Recent Files | 最近使用 |
| 功能增强 | Key Sequence Shortcut | 快捷启动器，类似 Alfred |
| 面板增强 | Calendar | 日历面板 |
| 面板增强 | Dictionary | 字典查询 |
| 面板增强 | Bartender | 让侧边不再拥挤，也强化档案浏览器过滤与自定义排序 |
| 面板增强 | Customizable SideBar | 可自定义侧边栏显示 |
| 细节体验 | Better Word Count | 字数统计 |
| 细节体验 | CodeMirror Options | 所见所得 |
| 细节体验 | Advanced Tables | 增强表格 |
| 细节增强 | Markdown Table Editor | 可视表格制作、编辑、编辑 csv 表格 |
| 细节体验 | Remember cursor position | 记录位置 |
| 细节体验 | Auto pair Chinese | 补全标点 |
| 细节体验 | Better footnote | 脚注增强 |
| 任务自动化 | Tasks | 任务管理 |
| 任务自动化 | Kanban | 看板功能 |
| 任务自动化 | Day Planner | 时间管理 |
| 任务自动化 | Dataview | 增强查询 |
| 任务自动化 | QuickAdd | 增强模版 |
| 任务自动化 | Templater | 自动模版 |
| 代码增强 | Editor Syntax Highlight | 编辑区程序代码块语法高亮显示。 |
| 代码增强 | Embedded Code Title | 在编程语言名称后附加[:文件名]即可显示辨识用的文件。例如 `html: index.html` |
| 插件管理 | BRAT | 抢先体验未上架插件<br>跳转到插件的 github 主页 |
| 功能增强 | Auto Note Mover | 依规则将笔记自动搬移到特定文件夹 |
| 功能增强 | upgit | 上传图片文档到 github 做图床 |
| 细节增强 | PaneRelief | 左上角面包屑导航 |
| 功能增强 | Show Current File Path | 点击显示的路径可复制完整的文件路径 |
| 功能增强 | Customizable Page Header | 可以在右上角增加常用的操作命令按钮 |
| 功能增强 | Force view mode | 通过 yaml 指定打开是编辑模式还是预览模式 |
| 功能增强 | obsidian-homepage | 指定当作首页的笔记，每次启动后自动开启 |
| 功能增强 | Linter | 自动插入 Yaml frontmatter |
| 功能增强 | Hotkeys for specific files | 设置快捷键以快速打开特定文件 |
| 细节增强 | Advanced Obsidian URI | 将链接改成按钮形式 |
| 功能增强 | Text Transporter | 设置书签、将内容复制到特定书签 |
| 功能增强 | Table of Contents | 可以用它在预览状态下动态生成目录，类似以前的[toc] |
| 功能增强 | NOVEL WORD COUNT | 支持按目录统计字数 |
| 细节体验 | OBSIDIAN PANGU | 通过快捷键 Comman+Shift+s 可以使得英文跟中文之前强制出现空格 |
| 体验增强 | [obsidian-admonition](https://github.com/valentine195/obsidian-admonition) | 警告样式块 |
| 体验增强 | [obsidian-icon-folder](https://github.com/FlorianWoelki/obsidian-icon-folder) | 允许将图标添加到文件夹 |
| 改善超链接 | Paste URL into Selection | - |
| 改善超链接 | Auto Link Title | - |
| markdow更统一 | **Markdown Prettifier** | - |
|  |  | - |
|  |  | - |
|  |  | - |
|  |  | - |
|  |  | - |
|  |  | - |

## 4. 注意事项

- 正文中如果出现 `#字符 `，会被 obsidian 当作标签，所以要对#进行转义，或者用特殊符号包裹起来

## 5. Summary

1. 痛点：插件之间无法联动，比如，我安装了一个格式化插件，在按下Command+Shift+S的时候自动进行格式化，而实际上我期望在我按Command+S的时候就可以自动替我把Command+Shift+S也进行。

## 6. Reference

- [如何在 Markdown 中双语写作，输出英文或中文文件？ \- 少数派](https://sspai.com/post/65305)
