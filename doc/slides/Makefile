all: slides.dvi

%.dvi: %.tex
	csplain $<

%.ps: %.dvi
	dvips -o $@ -D600 -ta4 $<

%.pdf: %.ps
	ps2pdf $<

%-utf8.tex: %.tex
	iconv -fiso8859-2 -tutf-8 $< >$@

view: slides.dvi
	xdvi -expert -geometry 1100x700 -l -s 4 -paper a4 -margins 1in slides.dvi

viewlarge: slides.dvi
	xdvi -expert -geometry 1024x700 -l -s 1 -paper a4 -margins 1in slides.dvi

viewreal: slides.dvi
	xdvi -expert -geometry 1024x700 -l -s 6 -paper a4 -margins 1in slides.dvi

clean:
	rm -f *~ *.log *.tfm *.*pk *.*gf *.ps *.dvi
