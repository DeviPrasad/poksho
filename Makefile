
sho: shohmac.md md.yaml style.css
	pandoc shohmac.md --metadata-file=md.yaml --mathjax --standalone --css=style.css -f markdown -t html -o shohmac.html

clean:
	rm -f shohmac.html
