
sho: shohmac.md md.yaml style.css
	pandoc shohmac.md --metadata-file=md.yaml --mathjax --standalone --css=style.css -f markdown -t html -o shohmac.html

sho-pdf: shohmac.md md.yaml style.css
	pandoc shohmac.md --metadata-file=md.yaml --standalone -M link-citations=true --citeproc --template eisvogel --from markdown --listings -V linkcolor=blue -V header-includes:'\usepackage[export]{adjustbox} \let\includegraphicsbak\includegraphics \renewcommand*{\includegraphics}[2][]{\includegraphicsbak[frame,#1]{#2}}' -o shohmac.pdf

clean:
	rm -f shohmac.html
