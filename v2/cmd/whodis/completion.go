package main

import (
	"fmt"
	"io"
	"strings"
)

func runCompletion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "whodis: usage: whodis completion bash|zsh|fish|powershell")
		return 2
	}
	commands := "lookup registration inspect dns diagnose investigate check snapshot diff expires get config help completion"
	options := "--format --dashboard --tree --geekboys --plain --json --yaml --csv --ndjson --markdown --raw --output --input --jobs --timeout --color --details --summary --force --save --label --active --passive --against --snapshot --scrutiny --policy --webhook-env --webhook-file --live --allow-snapshot-endpoints --include-ttl --server --strict --try-both --refresh --allow-private --allow-insecure-http --resolver --strategy --class --dnssec --no-dnssec --bufsize --nsid --ecs --cookie --padding --no-recursion --checking-disabled --ixfr --serial --tls --tsig-name --tsig-secret-env --tsig-secret-file --tsig-algorithm --globalping --from --limit --trace --remote --enrich --related-limit --research-links --investigation-link --otx-endpoint --help --version"
	switch strings.ToLower(args[0]) {
	case "bash":
		fmt.Fprintf(stdout, `_whodis_complete() {
  local cur prev
  COMPREPLY=()
  cur="${COMP_WORDS[COMP_CWORD]}"
  prev="${COMP_WORDS[COMP_CWORD-1]}"
  if [[ "$prev" == "dns" ]]; then COMPREPLY=( $(compgen -W "query inventory compare trace transfer" -- "$cur") ); return; fi
  if [[ "$cur" == -* ]]; then COMPREPLY=( $(compgen -W %q -- "$cur") ); return; fi
  COMPREPLY=( $(compgen -W %q -- "$cur") )
}
complete -F _whodis_complete whodis
`, options, commands)
	case "zsh":
		fmt.Fprintf(stdout, `#compdef whodis
_arguments '*:argument:->args'
case $state in
  args) _values 'command or option' %s %s ;;
esac
`, strings.ReplaceAll(commands, " ", " "), strings.ReplaceAll(options, " ", " "))
	case "fish":
		for _, command := range strings.Fields(commands) {
			fmt.Fprintf(stdout, "complete -c whodis -f -a %s\n", command)
		}
		for _, option := range strings.Fields(options) {
			fmt.Fprintf(stdout, "complete -c whodis -l %s\n", strings.TrimPrefix(option, "--"))
		}
	case "powershell":
		fmt.Fprintf(stdout, `Register-ArgumentCompleter -Native -CommandName whodis -ScriptBlock {
  param($wordToComplete)
  @(%s) | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`, powershellCompletionValues(append(strings.Fields(commands), strings.Fields(options)...)))
	default:
		fmt.Fprintf(stderr, "whodis: unsupported completion shell %q\n", args[0])
		return 2
	}
	return 0
}

func powershellCompletionValues(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = "'" + strings.ReplaceAll(value, "'", "''") + "'"
	}
	return strings.Join(quoted, ",")
}
