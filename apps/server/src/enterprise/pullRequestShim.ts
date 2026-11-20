/**
 * The `gh` the organization's agents see when its policy limits what they do with pull requests.
 * It finds the real `gh` further along PATH; an agent that calls the API another way is not
 * stopped, so branch protection on the repository host stays the real gate.
 */
export const pullRequestShim = (organization: string) => {
  const name = organization.replace(/["$`\\]/g, "");
  return `#!/bin/sh
# Installed by T3 Code for ${name}. Agents' pull requests follow the organization's policy.
self_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
mode="\${T3E_AGENT_PULL_REQUESTS:-allowed}"
real=""
old_ifs=$IFS
IFS=:
for dir in $PATH; do
  [ "$dir" = "$self_dir" ] && continue
  if [ -x "$dir/gh" ]; then real="$dir/gh"; break; fi
done
IFS=$old_ifs
if [ -z "$real" ]; then echo "gh: command not found" >&2; exit 127; fi
if [ "$1" = "pr" ]; then
  case "$2" in
    create)
      if [ "$mode" = "human-only" ]; then
        echo "${name}'s policy lets only people open pull requests. Push the branch and ask the user to open the pull request." >&2
        exit 1
      fi
      if [ "$mode" = "draft" ]; then
        for arg in "$@"; do
          if [ "$arg" = "--draft" ] || [ "$arg" = "-d" ]; then exec "$real" "$@"; fi
        done
        shift 2
        echo "${name}'s policy opens agents' pull requests as drafts; a person marks them ready." >&2
        exec "$real" pr create --draft "$@"
      fi
      ;;
    ready|merge)
      if [ "$mode" != "allowed" ]; then
        echo "${name}'s policy leaves marking pull requests ready and merging them to people. Ask the user." >&2
        exit 1
      fi
      ;;
  esac
fi
exec "$real" "$@"
`;
};
