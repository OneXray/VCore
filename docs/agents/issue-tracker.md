# Issue 跟踪器：GitHub

Issue 和规格存放在仓库 `OneXray/VCore` 的 GitHub Issues 中。工作区包含多个仓库时，命令必须显式传入 `--repo OneXray/VCore`。

## 常用操作

- 创建：`gh issue create --repo OneXray/VCore --title "..." --body "..."`
- 读取：`gh issue view <number> --repo OneXray/VCore --comments`
- 列表：`gh issue list --repo OneXray/VCore --state open --json number,title,body,labels,comments`
- 评论：`gh issue comment <number> --repo OneXray/VCore --body "..."`
- 标签：`gh issue edit <number> --repo OneXray/VCore --add-label "..."`
- 关闭：`gh issue close <number> --repo OneXray/VCore --comment "..."`

Pull Request 不作为需求入口。

## Skill 约定

- “发布到 issue 跟踪器”表示创建 GitHub Issue。
- “读取相关 ticket”表示读取对应 Issue 的正文、评论和标签。

## Wayfinder 约定

- 地图：带 `wayfinder:map` 标签的总 Issue。
- 子项：带 `wayfinder:<type>` 标签的子 Issue。
- 阻塞：优先使用 GitHub 原生依赖；不可用时写入 `Blocked by: #<n>`。
- 前沿：按地图顺序找到第一个未关闭、未阻塞、未分配的子项。
- 认领：开始工作前把 Issue 分配给执行者。
- 完成：评论结论、关闭 Issue，并更新地图中的既有决策。
