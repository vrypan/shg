if command -q shg
    shg scan --env=true --hist=true --one-line --level high 2>/dev/null
    if test $status -eq 1
        echo "Run shg for more info"
    end
end
