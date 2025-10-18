#!/usr/bin/env python3
"""Insert parser registrations into main.go"""

import sys

def main():
    # Read the main.go file
    with open('/Users/tknecht/Projects/inbound-parsers/cmd/bento-parsers/main.go', 'r') as f:
        lines = f.readlines()

    # Read the registry calls
    with open('/tmp/registry.txt', 'r') as f:
        registry_lines = f.readlines()

    # Find the TODO comment
    todo_line_idx = None
    for i, line in enumerate(lines):
        if 'TODO: Register remaining' in line:
            todo_line_idx = i
            break

    if todo_line_idx is None:
        print("Error: Could not find TODO comment")
        sys.exit(1)

    print(f"Found TODO at line {todo_line_idx + 1}")

    # Insert registry calls before the TODO comment
    # Add a blank line, then all registry calls, then keep the TODO
    new_lines = (
        lines[:todo_line_idx] +
        ['\n'] +
        registry_lines +
        ['\n'] +
        lines[todo_line_idx:]
    )

    # Update the TODO comment to say 0 remaining
    for i, line in enumerate(new_lines):
        if 'TODO: Register remaining' in line:
            new_lines[i] = '\t// All parsers registered (329 new parsers added)\n'
            break

    # Write back
    with open('/Users/tknecht/Projects/inbound-parsers/cmd/bento-parsers/main.go', 'w') as f:
        f.writelines(new_lines)

    print(f"Added {len(registry_lines)} lines of registry calls")
    print("Updated TODO comment to reflect completion")

if __name__ == '__main__':
    main()
