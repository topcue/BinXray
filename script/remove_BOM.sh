find . -type f -name "*.csv" -print0 | while IFS= read -r -d '' f; do
  if head -c 3 "$f" 2>/dev/null | grep -q $'\xEF\xBB\xBF'; then
    tail -c +4 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
    echo "[FIXED] $f"
  fi
done
