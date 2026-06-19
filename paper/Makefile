# paper/Makefile — build the PDF and regenerate figures/tables from data.
#
# Requires a LaTeX toolchain (not installed at scaffold time). Install with:
#   sudo apt install texlive-latex-recommended texlive-latex-extra \
#                    texlive-fonts-recommended latexmk
# (acmart is in texlive-publishers; add it if acmart.cls is missing.)
#
# Targets:
#   make            -> main.pdf (runs latexmk: latex + bibtex passes)
#   make figures    -> regenerate figures + density_table.tex from the CSV
#   make watch      -> rebuild on save (latexmk -pvc)
#   make clean      -> remove LaTeX build artifacts (keeps main.pdf)
#   make distclean  -> also remove main.pdf

MAIN    := main
DIST    := frisanco-fastest-engine-2026
PYTHON  := python3
SWEEP   := data/density_sweep.csv

.PHONY: all dist figures watch clean distclean

all: $(MAIN).pdf

# Build and copy to a descriptive, submission-ready filename (the name to
# upload to arXiv / attach to a journal submission).
dist: $(MAIN).pdf
	cp $(MAIN).pdf $(DIST).pdf
	@echo "wrote $(DIST).pdf"

$(MAIN).pdf: $(MAIN).tex refs.bib data/density_table.tex \
             figures/density_overview.pdf figures/density_crossover.pdf
	latexmk -pdf -interaction=nonstopmode -halt-on-error $(MAIN).tex

# Regenerate the figures + the booktabs table from the sweep CSV.
figures: $(SWEEP)
	$(PYTHON) plot_density_sweep.py --csv $(SWEEP)

# The figure/table prerequisites are produced by `make figures`; if they are
# missing, build them.
data/density_table.tex figures/density_overview.pdf figures/density_crossover.pdf: $(SWEEP)
	$(PYTHON) plot_density_sweep.py --csv $(SWEEP)

watch: data/density_table.tex
	latexmk -pdf -pvc -interaction=nonstopmode $(MAIN).tex

clean:
	latexmk -c $(MAIN).tex 2>/dev/null || true
	rm -f $(MAIN).bbl $(MAIN).run.xml

distclean: clean
	rm -f $(MAIN).pdf $(DIST).pdf
