if command -v shg &>/dev/null; then
  shg scan --env=true --hist=true --one-line --level high 2>/dev/null || _shg_rc=$?
  [ "${_shg_rc:-0}" -eq 1 ] && echo "Run shg for more info"
  unset _shg_rc
fi
