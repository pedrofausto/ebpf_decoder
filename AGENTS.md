## Codex Agent Directives (Repo-Local)

Primary goal: minimize token use and avoid unnecessary codebase-wide search.

### Always Consult the Code Index First
- Before using `rg`, `find`, or reading large files, open and use:
  - `obsidian_space/50_CODE_INDEX_CONCISE.md`
- Prefer jumping to the indexed `Location` and `Anchor` for the relevant `IDX-*` row.
- If the index contains a matching concept/ID, do not run a broad grep.

### When Answering Questions
- Reference relevant `IDX-*` entries (ID + `Location`) when describing where logic lives.
- If you must read code, read only the smallest section needed around the indexed anchor.

### When Changing Code
- If edits add/move core entrypoints, maps, or security/perf-critical paths, update:
  - `obsidian_space/50_CODE_INDEX_CONCISE.md`
  - and, if needed, `obsidian_space/00_INDEX.md`

### Search Policy
- Allow `rg` only when:
  - The index has no relevant entry, or
  - Line numbers drift and the anchor cannot be found quickly, or
  - You need to validate assumptions across multiple files.
