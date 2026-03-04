# Release Command

Review all changes in the repository and create a release with proper commit message, version tag, and push to remote.

## Argument: $ARGUMENTS

The argument should be one of:
- `patch` - Bump the patch version (e.g., v0.0.1 -> v0.0.2)
- `minor` - Bump the minor version and reset patch to 0 (e.g., v0.0.2 -> v0.1.0)
- `major` - Bump the major version and reset minor and patch to 0 (e.g., v0.1.0 -> v1.0.0)

If no argument provided, default to `patch`.

## Steps to perform:

1. **Read the current version** from `pkg/version/version`

2. **Calculate the new version** based on the argument:
   - Parse the current version (format: vMAJOR.MINOR.PATCH)
   - If `patch`: increment PATCH by 1
   - If `minor`: increment MINOR by 1, set PATCH to 0
   - If `major`: increment MAJOR by 1, set MINOR and PATCH to 0

3. **Update the version file** (`pkg/version/version`) with the new version

4. **Verify the build compiles** before proceeding:
   ```
   CGO_ENABLED=0 go build -o /dev/null ./...
   ```
   If build fails, fix issues before proceeding.

5. **Review changes** using `git status` and `git diff --stat HEAD`

6. **Compose a commit message** following this format:
   - First line: 72 chars max, imperative mood summary (e.g., "Release v0.0.1")
   - Blank line
   - Bullet points describing each significant change since last release
   - Footer with Claude Code attribution

7. **Stage all changes** with `git add -A`

8. **Create the commit** with the composed message

9. **Create a git tag** with the new version (e.g., `v0.0.1`)

10. **Push to remote** with tags:
    ```
    git push origin main --tags
    ```

11. **Report completion** with the new version and commit hash
