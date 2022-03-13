PACKAGE=edl-mod
EPACKAGE=edl_mod
CODE=edl.py
SRC=src/edl/$(CODE)
CHEATTARGET=/usr/lib/python3.8
VENV=tests
PLATFORM=linux
RECFILE=requirements.txt

.prereqs:
	@python3 -m pip install --upgrade pip
	@python3 -m pip install --upgrade testresources
	@python3 -m pip install --upgrade build
	@python3 -m pip install --upgrade twine
	@touch .prereqs

prereqs: .prereqs

build: .prereqs
	@python3 -m build

upload_test: build
	@python3 -m twine upload --repository testpypi dist/*

upload: build
	@python3 -m twine upload --repository pypi dist/*

venv:
ifeq ($(PLATFORM),linux)
	python3 -m venv $(VENV)
	source $(VENV)/activate
else
	# Assume Windows
	py -m venv $(VENV)
	$(VENV)\Scripts\activate
endif

clean:
	@test -d dist && rm -fR dist || true
	@test -d $(EPACKAGE).egg-info && rm -fR $(EPACKAGE).egg-info || true

cheatinstall:
	@sudo cp $(SRC) $(CHEATTARGET)/$(CODE)
	@sudo chmod +rx $(CHEATTARGET)/$(CODE)

cheatrm:
	@sudo rm $(CHEATTARGET)/$(CODE)

install_test:
	@python3 -m pip install --index-url https://test.pypi.org/simple --no-deps $(PACKAGE)

localwedit:
ifeq ($(PLATFORM),linux)
	@python -m pip install -e .
else
	@py -m pip install -e .
endif

local:
ifeq ($(PLATFORM),linux)
	@python -m pip install .
else
	@py -m pip install .
endif

install:
ifeq ($(PLATFORM),linux)
	python3 -m pip install $(PACKAGE)
else
	py -m pip install $(PACKAGE)
endif

installreq: requirements.txt
ifeq ($(PLATFORM),linux)
	python3 -m pip install -r $(RECFILE)
else

endif

installuser:
ifeq ($(PLATFORM),linux)
	python -m pip install --user $(PACKAGE)
else
	py -m pip install --user $(PACKAGE)
endif

upgrade:
ifeq ($(PLATFORM),linux)
	python3 -m pip install --upgrade $(PACKAGE)
else
	py -m pip install --upgrade $(PACKAGE)
endif

actions:
	@printf "prereqs\t\tInstall prereqs\n"
	@printf "build\t\tBuild Package\n"
	@printf "upload_test\tUpload to testpypi\n"
	@printf "upload\t\tUpload to pypi\n"
	@printf "venv\t\tCreate venv in tests\n"
	@printf "install_test\tInstall package from testpypi\n"
	@printf "localwedit\tInstall from local source with edit\n"
	@printf "local\t\tInstall from local source with no edit\n"
	@printf "install\t\tInstall from Pypi\n"
	@printf "installreq\tInstall with requirements file\n"
	@printf "installuser\tInstall for current user only\n"
	@printf "upgrade\t\tUpgrade the package\n"
	@printf "actions\t\tThis list\n"
	@printf "cheatinstall\tDo the cp /usr/lib thing\n"
	@printf "clean\t\tClean build dist\n"
