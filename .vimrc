set path+=src/**
set path+=benches/**


autocmd BufRead *.rs :setlocal tags=rusty-tags.vi;/
