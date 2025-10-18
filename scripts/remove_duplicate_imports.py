#!/usr/bin/env python3
"""Remove duplicate imports from main.go"""

def main():
    # Read the main.go file
    with open('/Users/tknecht/Projects/inbound-parsers/cmd/bento-parsers/main.go', 'r') as f:
        lines = f.readlines()

    # Find the import block
    import_start = None
    import_end = None
    for i, line in enumerate(lines):
        if line.strip() == 'import (':
            import_start = i + 1
        elif import_start is not None and line.strip() == ')':
            import_end = i
            break

    if import_start is None or import_end is None:
        print("Error: Could not find import block")
        return

    print(f"Import block: lines {import_start + 1} to {import_end + 1}")

    # Extract imports
    import_lines = lines[import_start:import_end]

    # Remove duplicates while preserving order
    seen = set()
    unique_imports = []
    for line in import_lines:
        stripped = line.strip()
        if stripped and stripped not in seen:
            seen.add(stripped)
            unique_imports.append(line)
        elif stripped in seen:
            print(f"Removing duplicate: {stripped[:80]}...")

    # Reconstruct the file
    new_lines = (
        lines[:import_start] +
        unique_imports +
        lines[import_end:]
    )

    # Write back
    with open('/Users/tknecht/Projects/inbound-parsers/cmd/bento-parsers/main.go', 'w') as f:
        f.writelines(new_lines)

    print(f"Removed {len(import_lines) - len(unique_imports)} duplicate imports")
    print(f"Total imports: {len(unique_imports)}")

if __name__ == '__main__':
    main()
