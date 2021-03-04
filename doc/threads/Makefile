all: 00_the_name_of_the_game.pdf

00_the_name_of_the_game.pdf: 00_filter_structure.png

%.pdf: %.md
	pandoc -f markdown -t latex -o $@ $<
