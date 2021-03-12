all: 00_the_name_of_the_game.pdf 01_the_route_and_its_attributes.pdf 02_asynchronous_export.pdf

00_the_name_of_the_game.pdf: 00_filter_structure.png

%.pdf: %.md
	pandoc -f markdown -t latex -o $@ $<

%.html: %.md
	pandoc -f markdown -t html5 -o $@ $<
