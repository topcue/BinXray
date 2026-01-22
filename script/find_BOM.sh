
# grep -rl $'\xEF\xBB\xBF' .

find . -type f -print0 | while IFS= read -r -d '' f; do
  head -c 3 "$f" 2>/dev/null | grep -q $'\xEF\xBB\xBF' && printf '%s\n' "$f"
done

